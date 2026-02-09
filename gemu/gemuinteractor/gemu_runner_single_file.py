import tempfile
import time
from contextlib import contextmanager

from gemuinteractor.recipe import Recipe
from gemuinteractor.config_parser import VMConfig
from gemuinteractor.helpers import GemuInstance, build_iso_from_files
from gemuinteractor.gemu_run_decorator import RunDecorator


class GemuRunner:
    def __init__(self, recording_time: int, trackingmode: str|None, dotnet: str|None, vm_config: VMConfig, recipe: Recipe,
                 gemu_instance: GemuInstance, codecarver: bool = False, tracing: bool = False):
        self.recipe = recipe
        self.gemu_cmd = self._get_gemu_params(dotnet, trackingmode, tracing, vm_config, codecarver)
        self.recording_time = recording_time
        self.gemu_instance = gemu_instance
        self._decorators: list[RunDecorator] = []

    def decorate_run(self, decorators: list[RunDecorator]):
        self._decorators = decorators

    def _get_gemu_params(self, dotnet:str|None, trackingmode:str|None, tracing: bool, vm_config: VMConfig, codecarver: bool) -> str:
        optional_parameters = [
            "-trackingmode " + trackingmode if trackingmode else "",
            "-dotnet " + dotnet if dotnet else "",
            "-gemutracing" if tracing else "",
            "-codecarver" if codecarver else "",
        ]

        params = [
            "-m", vm_config.ram_size,
            "-monitor stdio",
            *vm_config.additional_parameters,
            *optional_parameters,
            "-loadvm", vm_config.snapshot,
            "-symbolmapping", str(vm_config.symbolmapping),
            "-apidoc", str(vm_config.apidoc),
            "-watchedprograms", self.recipe.sample_name,
            "-syscalltable", str(vm_config.syscalltable),
            str(vm_config.image),
        ]
        # Filter out empty strings
        return " ".join(p for p in params if p)

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

    def _join_decorators(self) -> dict[str, str]:
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
