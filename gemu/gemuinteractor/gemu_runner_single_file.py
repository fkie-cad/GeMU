import tempfile
import threading
import time
import traceback
from contextlib import contextmanager
from pathlib import Path

from gemuinteractor.config_parser import VMConfig, SAMPLE_NAME
from gemuinteractor.helpers import GemuInstance, build_iso_from_files


class GemuRunner:
    def __init__(self, sample: Path, recording_time, export, trackingmode, dotnet, vm_config: VMConfig, recipe: dict,
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
        self.recipe = recipe
        if "overwriteinitprocess" in self.recipe:
            self.sample_name = self.recipe["overwriteinitprocess"]
        self.replacings = {("$USER", vm_config.user), ("$SAMPLE_NAME", self.sample_name),
                           ("$INPUTBINARY", self.sample.as_posix()), ("$EXPORT", self.export if self.export else "")}

    def decorate_run(self, decorators):
        self._decorators = decorators

    def replace_constants(self, instring):
        for replacing in self.replacings:
            instring = instring.replace(replacing[0], replacing[1])
        return instring

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
    def _mount_samples(self):
        print("mounting samples...")
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = build_iso_from_files(self._gather_files(), tmpdir=tmpdir)
            self.gemu_instance.write_to_qemu_console(f"change ide1-cd0 {output_path}\n".encode(encoding="utf-8"))
            self.gemu_instance.write_to_qemu_console(b"sendkey esc\n")
            for mounting in self.recipe["samples"]:
                print(self.replace_constants(mounting))
                local, remote = self._split_mounting(self.replace_constants(mounting))
                self.gemu_instance.type_into_guest(f"copy D:\\{Path(local).name} {remote}\n")
            try:
                yield
            finally:
                return

    def _split_mounting(self, mounting):
        first_part = mounting.split(":")[0]
        second_part = ":".join(mounting.split(":")[1:])
        return first_part, second_part

    def _gather_files(self):
        mountings = self.recipe["samples"]
        files = set()
        for mounting in mountings:
            mounting = self.replace_constants(mounting)
            files.add(Path(mounting.split(":")[0]))
        return files

    def _launch_commands(self):
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print("starting...")
        for command in self.recipe["cmds"]:
            self.gemu_instance.type_into_guest(self.replace_constants(command))
            self.gemu_instance.type_into_guest("\n")
            time.sleep(1)
        print("launched commands")

    def _start_decorators(self):
        for decorator in self._decorators:
            decorator.start()

    def _join_decorators(self):
        for decorator in self._decorators:
            decorator.stop()
        for decorator in self._decorators:
            decorator.join()

    def run_sample(self):
        self._start_decorators()
        with self.gemu_instance.launch_gemu(self.gemu_cmd):
            print("launching gemu")
            with self._mount_samples():
                self._launch_commands()
                self.gemu_instance.wait(timeout=self.recording_time)
        self._join_decorators()
