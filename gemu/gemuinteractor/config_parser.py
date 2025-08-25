from dataclasses import dataclass
import os
from pathlib import Path

import gemuinteractor.config

@dataclass
class VMConfig:
    image: Path
    snapshot: str
    ram_size: str
    additional_parameters: list[str]
    user: str
    symbolmapping: Path
    apidoc: Path
    syscalltable: Path

def get_vm_settings(name: str, file=gemuinteractor.config) -> VMConfig:
    vm_settings = getattr(file, name)
    return VMConfig(
        Path(vm_settings["VM_IMAGE_PATH"]),
        vm_settings["SNAPSHOT"],
        vm_settings["RAM"],
        vm_settings.get("PARAMETERS", []),
        vm_settings["USER"],
        Path(vm_settings["SYMBOLMAPPING"]),
        Path(vm_settings["APIDOC"]),
        Path(vm_settings["SYSCALLTABLE"]),
    )

SAMPLE_NAME = "ahsofi.exe"
GEMU_FOLDER = Path(__file__).absolute().parents[2]
GEMU_PATH = GEMU_FOLDER / "build" / "qemu-system-x86_64"
