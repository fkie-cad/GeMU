import os
import subprocess
import traceback
from pathlib import Path

from gemuinteractor.scheduler import Scheduler

import gemuinteractor.config

FORBIDDEN = [".log", ".txt", "dump", "pandalog", "dmp7", "dumps", "elf", "pandalog", "unpacked"]

class GemuRunnerMultipleFiles:
    def __init__(self, samples: Path, time, runname, yararules, trackingmode, dotnet, allowmultipleruns, configs, malpedia_mode):
        self.malpedia_mode = malpedia_mode
        self.configs = configs
        self.dotnet = dotnet
        self.yararules = yararules
        self.time = time
        self.runname = runname
        self.trackingmode = trackingmode
        self.samples = samples
        self.allowmultipleruns = allowmultipleruns

    def run(self):
        scheduler = Scheduler(self._executeAnalysisLive, getattr(gemuinteractor.config, self.configs))
        scheduler.process_samples(self.get_samples())

    def get_samples(self):
        if not self.samples.exists():
            raise RuntimeError(f"The {self.samples} does not exist")
        if self.samples.is_file():
            return self._samples_as_list()
        if self.samples.is_dir():
            return self._crawl_folder(self.samples)

    def _samples_as_list(self):
        with open(self.samples, "r") as f:
            for line in f:
                path_line = Path(line.strip())
                print(f"running {path_line}")
                if path_line.is_file():
                    if not self._already_ran(path_line):
                        yield path_line
                if path_line.is_dir():
                    yield from self._crawl_folder(path_line)

    def _crawl_folder(self, target_folder):
        for root, dirs, files in os.walk(target_folder):
            for file in files:
                path = Path(os.path.join(root, file))
                if self._should_run_file(path):
                    yield path

    def _already_ran(self, path):
        if self.allowmultipleruns:
            return False
        for i in os.listdir(path.parent):
            if self.runname in i and path.name in i:
                return True
        return False

    def _should_run_file(self, path: Path):
        if self._already_ran(path):
            return False
        if self.malpedia_mode:
            for f in FORBIDDEN:
                if f in path.as_posix():
                    return False
        fileout = subprocess.check_output(["file", path.absolute()])
        # TODO: Handle DLLs gracefully?
        if b"DLL" in fileout:
            return False
        if b"PE32 executable" in fileout or b"PE32+ executable" in fileout:
            return True
        return False

    def _executeAnalysisLive(self, path, vm):
        try:
            print(self.trackingmode, self.dotnet, self.yararules)
            call = [
                "python3", "unpack_single_file.py",
                "--sample", str(path),
                "--time", str(self.time),
                "--runname", self.runname,
                "--config", vm,
                "--trackingmode", self.trackingmode,
                ]
            if self.dotnet is not None:
                call += ["--dotnet", self.dotnet]
            if self.yararules is not None:
                call.extend(["--yararules", self.yararules])

            print(" ".join(call))
            subprocess.check_call(call)
        except Exception:
            print(traceback.format_exc())