import os
import subprocess
import traceback
from pathlib import Path
from typing import Iterable

from gemuinteractor.scheduler import Scheduler

from gemuinteractor.config_parser import get_vm_pool

FORBIDDEN = [".log", ".txt", "dump", "pandalog", "dmp7", "dumps", "elf", "pandalog", "unpacked"]

class GemuRunnerMultipleFiles:
    def __init__(self, samples: Path|str, time: int, runname: str, yararules: Path|str|None, trackingmode: str, dotnet: str|None,
                 allowmultipleruns: bool, configs: str, malpedia_mode: bool, codecarver: bool, tracing: bool):
        self._samples = Path(samples)
        self._malpedia_mode = malpedia_mode
        self._configs = configs
        self._dotnet = dotnet
        self._yararules = str(yararules) if yararules else None
        self._time = time
        self._runname = runname
        self._trackingmode = trackingmode
        self._allowmultipleruns = allowmultipleruns
        self._codecarver = codecarver
        self._tracing = tracing

    def run(self):
        scheduler = Scheduler(self._executeAnalysisLive, get_vm_pool(self._configs))
        scheduler.process_samples(self.get_samples())

    def get_samples(self) -> Iterable[Path]:
        if not self._samples.exists():
            raise RuntimeError(f"The {self._samples} does not exist")
        if self._samples.is_file():
            return self._samples_as_list()
        if self._samples.is_dir():
            return self._crawl_folder(self._samples)
        else:
            raise RuntimeError(f"{self._samples} is neither file or folder.")


    def _samples_as_list(self):
        with open(self._samples, "r") as f:
            for line in f:
                path_str = line.strip()
                if not path_str:
                    continue
                path_line = Path(path_str)
                print(f"running {path_line}")
                if path_line.is_file():
                    if not self._already_ran(path_line):
                        yield path_line
                if path_line.is_dir():
                    yield from self._crawl_folder(path_line)

    def _crawl_folder(self, target_folder: Path):
        for root, dirs, files in os.walk(target_folder):
            for file in files:
                path = Path(os.path.join(root, file))
                if self._should_run_file(path):
                    yield path

    def _already_ran(self, path: Path):
        if self._allowmultipleruns:
            return False
        for i in os.listdir(path.parent):
            if self._runname in i and path.name in i:
                return True
        return False

    def _should_run_file(self, path: Path):
        if self._already_ran(path):
            return False
        if self._malpedia_mode:
            for f in FORBIDDEN:
                if f in str(path):
                    return False
        fileout = subprocess.check_output(["file", path.absolute()])
        # TODO: this could be single file runner's responsibility
        # TODO: Handle DLLs gracefully?
        if b"DLL" in fileout:
            return False
        if b"PE32 executable" in fileout or b"PE32+ executable" in fileout:
            return True
        return False

    def _executeAnalysisLive(self, path: Path|str, vm: str):
        try:
            print(self._trackingmode, self._dotnet, self._yararules)
            call = [
                "python3", str(Path(__file__).parents[1] / "unpack_single_file.py"),
                "--sample", str(path),
                "--time", str(self._time),
                "--runname", self._runname,
                "--config", vm,
                "--trackingmode", self._trackingmode,
                ]
            if self._tracing:
                call += ["--tracing"]
            if self._dotnet is not None:
                call += ["--dotnet", self._dotnet]
            if self._yararules is not None:
                call.extend(["--yararules", self._yararules])
            if self._codecarver:
                call.append("--codecarver")

            print(" ".join(call))
            subprocess.check_call(call)
        except Exception:
            print(traceback.format_exc())
