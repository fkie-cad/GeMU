import datetime
import shutil
import string
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

class GemuInstance:
    def __init__(self, image):
        self.image = image
        self.process = None

    def _launch(self, cmd, cwd):
        self._try_to_free_image()
        print("Executing command:", cmd)
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, shell=True, cwd=cwd
        )
        time.sleep(5)

    def _kill(self):
        try:
            self.write_to_qemu_console(b"system_powerdown\n")
            self.write_to_qemu_console(b"quit\n")
        except BrokenPipeError:
            pass
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        self.process.kill()

    def _try_to_free_image(self):
        lock_found, qemu_pid = self._check_qcow_lock()
        while lock_found:
            self._kill_other_qemu_process(qemu_pid)
            print("checking lock again")
            lock_found, qemu_pid = self._check_qcow_lock()
        print("No QEMU process holding write lock on", self.image, "found.")

    def _check_qcow_lock(self):
        try:
            output = subprocess.check_output(["lsof", "-F", "npk", self.image])
            print(output)
            lines = output.decode().split("\n")
            pid = None
            locked = False
            for line in lines:
                if line.startswith("p"):
                    pid = line[1:]
                elif line.startswith("k") and "1" in line[1:]:  # Check if locked
                    locked = True
            return locked, pid
        except subprocess.CalledProcessError:
            return False, None

    def _kill_other_qemu_process(self, pid):
        try:
            subprocess.run(["kill", "-9", pid], check=True)
            print("QEMU process with PID", pid, "has been terminated. Sleeping for 5 seconds")
            time.sleep(5)
        except subprocess.CalledProcessError:
            print("Failed to terminate QEMU process with PID", pid)

    @contextmanager
    def launch_gemu(self, cmd, cwd):
        try:
            self._launch(cmd, cwd)
            yield True
        finally:
            self._kill()

    def write_to_qemu_console(self, command):
        self.process.stdin.write(command)
        self.process.stdin.flush()

    def wait(self, timeout):
        self.process.wait(timeout)

    def get_return_code(self):
        return self.process.returncode

    def type_into_guest(self, command):
        keymap = {
            "-": "minus",
            "=": "equal",
            "[": "bracket_left",
            "]": "bracket_right",
            ";": "semicolon",
            "'": "apostrophe",
            "\\": "backslash",
            ",": "comma",
            ".": "dot",
            "/": "slash",
            "*": "asterisk",
            " ": "spc",
            "_": "shift-minus",
            "+": "shift-equal",
            "{": "shift-bracket_left",
            "}": "shift-bracket_right",
            ":": "shift-semicolon",
            '"': "shift-apostrophe",
            "|": "shift-backslash",
            "<": "shift-comma",
            ">": "shift-dot",
            "?": "shift-slash",
            "\n": "ret",
        }

        for c in command:
            if c in string.ascii_uppercase:
                key = "shift-" + c.lower()
            else:
                key = keymap.get(c, c)

            self.write_to_qemu_console(b"sendkey " + key.encode(encoding="utf-8") + b"\n")
            time.sleep(0.001)

def build_iso_from_file(sample: Path, sample_name: str, tmpdir: str = "/tmp/"):
    tmpdir = Path(tmpdir)
    tmp_sample = tmpdir / sample_name
    shutil.copy(sample.absolute(), tmp_sample)
    temp_iso = tmpdir / Path(sample.name.replace(" ", "") + ".iso")
    subprocess.check_call([
        "/usr/bin/genisoimage",
        "-quiet",
        "-iso-level",
        "4",
        "-l",
        "-R",
        "-J",
        "-o",
        temp_iso.as_posix(),
        tmp_sample.as_posix(),
    ])
    return temp_iso
