from dataclasses import dataclass
from pathlib import Path
import sys
import importlib

def load_config_file(module_name="gemuinteractor.config"):
    try:
        loaded_config = importlib.import_module(module_name)
    except ImportError as e:
        sys.exit(f"Config file not found!\nPlease set up gemu/{module_name.replace('.', '/')}.py based on the template.")
        return None
    return loaded_config

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

def get_vm_settings(name: str, file=None) -> VMConfig:
    if file is None:
        file = load_config_file()
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

def get_vm_pool(name: str, file=None) -> list[str]:
    if file is None:
        file = load_config_file()
    vm_pool = getattr(file, name)
    return vm_pool

SAMPLE_NAME = "ahsofi.exe"
GEMU_FOLDER = Path(__file__).absolute().parents[2]
GEMU_PATH = GEMU_FOLDER / "build" / "qemu-system-x86_64"
