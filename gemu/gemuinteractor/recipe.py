import subprocess
from pathlib import Path

import yaml

from gemuinteractor.config_parser import SAMPLE_NAME

RECIPE_FOLDER = Path(__file__).parent / "recipes"

class Recipe:
    def __init__(self, user: str, input_binary: str, export: str = "",  default_sample_name: str = SAMPLE_NAME):
        self._recipe_dict = self._get_recipe_dict(input_binary, export)
        self.sample_name: str = self._recipe_dict.get("overwriteinitprocess", default_sample_name)
        self._replacements = {
            "$USER": user,
            "$SAMPLE_NAME": self.sample_name, 
            "$INPUTBINARY": input_binary,
            "$EXPORT": export
        }
        self._process_recipe()
    
    def _process_recipe(self):
        self.commands = [self._substitute(cmd) for cmd in self._recipe_dict["cmds"]]
        self.mountings: list[tuple[Path, str]] = []
        for mounting in self._recipe_dict["samples"]:
            mounting = self._substitute(mounting)
            local_path = mounting.split(":")[0]
            remote_path = ":".join(mounting.split(":")[1:])
            self.mountings.append((Path(local_path), remote_path))
        self.requirements = set(local for local, _ in self.mountings)
    
    def _substitute(self, text):
        for old, new in self._replacements.items():
            text = text.replace(old, new)
        return text

    def _get_recipe_dict(self, sample, export):
        filetype = subprocess.check_output(["file", sample]).decode("utf-8")
        if "PE" in filetype:
            if export:
                if "PE32+" in filetype: # 64bit Library
                    return self.parse_yaml(RECIPE_FOLDER / "single_library_with_export_64bit.yml")
                else:  # 32bit Library
                    return self.parse_yaml(RECIPE_FOLDER / "single_library_with_export_32bit.yml")
            else:
                return self.parse_yaml(RECIPE_FOLDER / "single_native_binary.yml")
        raise NotImplementedError

    @staticmethod
    def parse_yaml(yamlfile: Path):
        return yaml.safe_load(yamlfile.read_text())