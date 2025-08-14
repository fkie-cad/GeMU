import datetime
import os
import shutil
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from gemuinteractor.config_parser import VMConfig, SAMPLE_NAME
from gemuinteractor.helpers import build_iso_from_file, GemuInstance


class GemuRunnerSingleFile:
    def __init__(self, sample: Path, recording_time, export, trackingmode, dotnet, vm_config: VMConfig,
                 gemu_instance: GemuInstance, sample_name=SAMPLE_NAME):
        self.sample = sample
        self.export = export
        self.sample_name = sample_name
        self.gemu_cmd = self._get_gemu_params(dotnet, trackingmode, vm_config)
        self.user = vm_config.user
        self.recording_time = recording_time
        self.gemu_instance = gemu_instance
        self.return_status = "normal"
        self._decorators = []
        self.stop_decorators = False

    def decorate_run(self, decorators):
        self._decorators = decorators

    def _get_gemu_params(self, dotnet, trackingmode, vm_config):
        trackingmode = "-trackingmode " + trackingmode if trackingmode else ""
        dotnet = "-dotnet " + dotnet if dotnet else ""
        return " ".join(
            [
                "-m", vm_config.ram_size,
                "-monitor stdio",
                *vm_config.additional_parameters,
                "-loadvm", vm_config.snapshot,
                "-symbolmapping", vm_config.symbolmapping.as_posix(),
                "-apidoc", vm_config.apidoc.as_posix(),
                "-watchedprograms", self.sample_name,
                "-syscalltable", vm_config.syscalltable.as_posix(),
                trackingmode,
                dotnet,
                vm_config.image.as_posix(),
            ]
        )

    @contextmanager
    def _mount_sample(self): # move to gemu instance?
        print("mounting sample...")
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                output_path = build_iso_from_file(self.sample,
                                                  sample_name=self.sample_name,
                                                  tmpdir=tmpdir)
                self.gemu_instance.write_to_qemu_console(f"change ide1-cd0 {output_path}\n".encode(encoding="utf-8"))
                self.gemu_instance.write_to_qemu_console(b"sendkey esc\n")
                yield
            finally:
                return

    def _launch_sample(self):
        if self.export:
            self._launch_sample_with_export()
            return
        self.gemu_instance.type_into_guest(f" copy D:\\{self.sample_name} {self.user}Desktop\\{self.sample_name}\n")
        time.sleep(1)
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print("starting...")
        self.gemu_instance.type_into_guest(f"start {self.user}Desktop\\{self.sample_name}\n")
        print("launched sample")

    def _launch_sample_with_export(self):
        if "PE32+" in subprocess.check_output(["file", self.sample]).decode("utf-8"):
            self.gemu_instance.type_into_guest(f" copy C:\\Windows\\system32\\rundll32.exe {self.user}Desktop\\{self.sample_name}\n")
        else:
            self.gemu_instance.type_into_guest(f" copy C:\\Windows\\SysWOW64\\rundll32.exe {self.user}Desktop\\{self.sample_name}\n")
        time.sleep(1)
        self.gemu_instance.type_into_guest(f" copy D:\\{self.sample_name} {self.user}Desktop\\ahsofidll.dll\n")
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print(f"starting PE with RUNDLL and {self.export}...")
        time.sleep(1)
        self.gemu_instance.type_into_guest(f"start {self.user}Desktop\\{self.sample_name} ahsofidll.dll,{self.export}\n")

    def _start_decorators(self):
        for decorator in self._decorators:
            decorator.thread = threading.Thread(target=decorator.run)
            decorator.thread.start()

    def _join_decorators(self):
        self.stop_decorators = True
        for decorator in self._decorators:
            decorator.thread.join()

    def run_sample(self):
        self._start_decorators()
        with self.gemu_instance.launch_gemu(self.gemu_cmd):
            print("launching gemu")
            with self._mount_sample():
                self._launch_sample()
                self.gemu_instance.wait(timeout=self.recording_time)
        self._join_decorators()
