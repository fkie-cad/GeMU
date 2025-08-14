import datetime
import os
import shutil
import string
import subprocess
import sys
from threading import Lock
import time
from contextlib import contextmanager
from pathlib import Path

class AnalysisFolder:
    def __init__(self, runname, path):
        self.analysis_folder = self._build_analysis_folder(runname, path)
        self.runlog = self.analysis_folder / "runlog"
        self.dumps_folder = self.analysis_folder / "dumps"
        self.dumps_zip = self.analysis_folder / "dumps.zip"

    def _build_analysis_folder(self, runname, sample_path) -> Path:
        analysis_folder = Path(
            f"{sample_path.as_posix()}_{runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        )
        analysis_folder.mkdir(exist_ok=True)
        os.symlink(sample_path, f"{self.analysis_folder}/sample")
        return analysis_folder

    def zip_dumps_folder(self):
        if self.dumps_folder.exists():
            subprocess.run(f"sync '{self.dumps_folder.as_posix()}'", shell=True)
            shutil.make_archive(self.dumps_folder.as_posix(), "zip", self.dumps_folder.as_posix())
            shutil.rmtree(self.dumps_folder, ignore_errors=True)

class GemuInstance:
    def __init__(self, image, gemu_path, analysis_folder: AnalysisFolder):
        self.image = image
        self.gemu_path = gemu_path
        self.analysis_folder = analysis_folder
        self.process = None
        self._lock = Lock()

    def _launch(self, parameters):
        self._try_to_free_image()
        cmd = f"{self.gemu_path} {parameters} > {self.analysis_folder.runlog}",
        print("Executing command:", cmd)
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, shell=True, cwd=self.analysis_folder.analysis_folder,
        )
        time.sleep(5)

    def kill(self, reason: str|None = None):
        if reason:
            self.return_status = reason 
        with self._lock:
            if self.process.poll() is not None: # if process is NOT running
                return
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
        self._log_return_status()

    def _log_return_status(self):
        with open(self.analysis_folder.runlog, "a+") as file:
            file.write(f"return_status:\n{self.return_status}\n")
            
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
    def launch_gemu(self, params_string):
        try:
            self._launch(params_string)
            yield True
        finally:
            self.kill()

        if self.return_status == "normal" and self.gemu_instance.get_return_code() != 0:
            self.return_status = f"error({self.gemu_instance.get_return_code()})" #die variable ist blöd -> return code pro decorator?

    def write_to_qemu_console(self, command):
        self.process.stdin.write(command)
        self.process.stdin.flush()

    def wait(self, timeout):
        try:
            print(
                f"{datetime.datetime.now()} sleeping for {timeout}"
            )
            self.process.wait(timeout)
            print("sleep over.. shutting down")
        except subprocess.TimeoutExpired:
            print("timeout expired.. shutting down")
            self.return_status = "timeout"


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
