import datetime
import json
import os
import shutil
import string
import subprocess
import traceback
from threading import Lock
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable

class AnalysisFolder:
    def __init__(self, runname: str|None = None, input_binary: Path|str|None = None, existing: Path|str|None = None):
        if existing:
            self.analysis_folder = Path(existing)
        else:
            self.analysis_folder = self._build_analysis_folder(runname, str(input_binary))
        self.runlog = self.analysis_folder / "runlog"
        self.dumps_folder = self.analysis_folder / "dumps"
        self.dumps_zip = self.analysis_folder / "dumps.zip"
        self.dumps_json = self.analysis_folder / "dumps.json"

    def _build_analysis_folder(self, runname: str, input_binary: str) -> Path:
        analysis_folder = Path(
            f"{input_binary}_{runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        )
        analysis_folder.mkdir(exist_ok=True)
        os.symlink(input_binary, f"{analysis_folder}/sample")
        return analysis_folder

    def zip_dumps_folder(self):
        if self.dumps_folder.exists():
            subprocess.run(f"sync '{self.dumps_folder}'", shell=True)
            shutil.make_archive(str(self.dumps_folder), "zip", str(self.dumps_folder))
            shutil.rmtree(self.dumps_folder, ignore_errors=True)


# Not in function def for efficiency
KEYMAP = {
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

class GemuInstance:
    def __init__(self, image: Path|str, gemu_path: Path|str, analysis_folder: AnalysisFolder):
        self._image = Path(image)
        self._gemu_path = Path(gemu_path)
        self.analysis_folder = analysis_folder
        self._process: subprocess.Popen|None = None
        self._lock = Lock()
        self._reason_for_gemu_end = "normal"

    def _launch(self, parameters: str):
        self._try_to_free_image()
        cmd = f"{self._gemu_path} {parameters} > {self.analysis_folder.runlog}",
        print("Executing command:", cmd)
        self._process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, shell=True, cwd=self.analysis_folder.analysis_folder,
        )
        time.sleep(5)

    def kill(self):
        if self._lock.acquire_lock(blocking=False): #only first kill will be executed and logged
            try:
                self.write_to_qemu_console(b"system_powerdown\n")
                self.write_to_qemu_console(b"quit\n")
            except BrokenPipeError:
                pass
            try:
                self._process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            self._process.kill()

    def log_return_status(self, decorator_state: dict):
        with open(self.analysis_folder.runlog, "a") as f:
            f.write(f"EXIT STATES OF DECORATORS: {json.dumps(decorator_state)}\n")
            f.write(f"PROCESS RETURN CODE: {str(self._process.poll())}\n")
            f.write(f"REASON FOR GEMU EXIT: {self._reason_for_gemu_end}\n")
            
    def _try_to_free_image(self):
        qemu_locking_pid = self._check_qcow_lock()
        while qemu_locking_pid is not None:
            self._kill_other_qemu_process(qemu_locking_pid)
            print("checking lock again")
            qemu_locking_pid = self._check_qcow_lock()
        print("No QEMU process holding write lock on", self._image, "found.")

    def _check_qcow_lock(self) -> str|None:
        try:
            output = subprocess.check_output(["lsof", "-F", "npk", str(self._image)])
            print(output)
            lines = output.decode().split("\n")
            pid = None
            locked = False
            for line in lines:
                if line.startswith("p"):
                    pid = line[1:]
                elif line.startswith("k") and "1" in line[1:]:  # Check if locked
                    locked = True
            if locked is True:
                return pid
            else:
                return None
        except subprocess.CalledProcessError:
            return None

    def _kill_other_qemu_process(self, pid: str):
        try:
            subprocess.run(["kill", "-9", pid], check=True)
            print("QEMU process with PID", pid, "has been terminated. Sleeping for 5 seconds")
            time.sleep(5)
        except subprocess.CalledProcessError:
            print("Failed to terminate QEMU process with PID", pid)

    @contextmanager
    def launch_gemu(self, params_string: str):
        try:
            self._launch(params_string)
            yield True
        except Exception as e:
            self._reason_for_gemu_end = f"error({traceback.format_exc()})"
        finally:
            self.kill()

    def write_to_qemu_console(self, command: bytes):
        self._process.stdin.write(command)
        self._process.stdin.flush()

    def wait(self, timeout: int|float|None):
        try:
            print(
                f"{datetime.datetime.now()} sleeping for {timeout}"
            )
            self._process.wait(timeout)
            print("sleep over.. shutting down")
        except subprocess.TimeoutExpired:
            print("timeout expired.. shutting down")
            self._reason_for_gemu_end = "timeout"

    def type_into_guest(self, command: str):
        for c in command:
            if c in string.ascii_uppercase:
                key = "shift-" + c.lower()
            else:
                key = KEYMAP.get(c, c)

            self.write_to_qemu_console(b"sendkey " + key.encode(encoding="utf-8") + b"\n")
            time.sleep(0.001)

def build_iso_from_files(samples: Iterable[Path], tmpdir: str|Path) -> Path:
    tmpdir = Path(tmpdir)
    for sample in samples:
        if " " in sample.name:
            raise RuntimeError(f"Sample {sample.name} contains spaces. This is not supported.")
        tmp_sample = tmpdir / sample.name
        shutil.copy(sample.absolute(), tmp_sample)
    temp_iso = tmpdir / (tmpdir.name + ".iso")
    subprocess.check_call([
        "/usr/bin/genisoimage",
        "-quiet",
        "-iso-level",
        "4",
        "-l",
        "-R",
        "-J",
        "-o",
        str(temp_iso),
        str(tmpdir)
    ])
    return temp_iso
