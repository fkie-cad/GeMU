import tempfile
import time
from contextlib import contextmanager

from gemuinteractor.recipe import Recipe
from gemuinteractor.config_parser import VMConfig
from gemuinteractor.helpers import GemuInstance, build_iso_from_files


class GemuRunner:
    def __init__(self, recording_time, trackingmode, dotnet, vm_config: VMConfig, recipe: Recipe,
                 gemu_instance: GemuInstance):
        self.recipe = recipe
        self.gemu_cmd = self._get_gemu_params(dotnet, trackingmode, vm_config)
        self.recording_time = recording_time
        self.gemu_instance = gemu_instance
        self._decorators = []

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
                "-watchedprograms", self.recipe.sample_name,
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
            output_path = build_iso_from_files(self.recipe.requirements, tmpdir=tmpdir)
            self.gemu_instance.write_to_qemu_console(f"change ide1-cd0 {output_path}\n".encode(encoding="utf-8"))
            self.gemu_instance.write_to_qemu_console(b"sendkey esc\n")
            for local, remote in self.recipe.mountings:
                self.gemu_instance.type_into_guest(f"copy D:\\{local.name} {remote}\n")
            try:
                yield
            finally:
                return

    def _launch_commands(self):
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print("starting...")
        for command in self.recipe.commands:
            self.gemu_instance.type_into_guest(command+"\n")
            time.sleep(1)
        print("launched commands")

    def _start_decorators(self):
        for decorator in self._decorators:
            decorator.start()

    def _join_decorators(self):
        return_states = dict()
        for decorator in self._decorators:
            decorator.stop()
            return_states[type(decorator).__name__] = decorator.return_code
        return return_states

    def run_sample(self):
        self._start_decorators()
        with self.gemu_instance.launch_gemu(self.gemu_cmd):
            print("launching gemu")
            with self._mount_samples():
                self._launch_commands()
                self.gemu_instance.wait(timeout=self.recording_time)
        self.gemu_instance.log_return_status(self._join_decorators())
