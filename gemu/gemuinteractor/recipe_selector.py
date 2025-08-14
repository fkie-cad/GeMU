import subprocess
from pathlib import Path

import yaml

RECIPE_FOLDER = Path(__file__).parent / "recipes"

def get_recipe(sample, export):
    filetype = subprocess.check_output(["file", sample]).decode("utf-8")
    if "PE" in filetype:
        if export:
            if "PE32+" in filetype: # 64bit Library
                return parse_yaml(RECIPE_FOLDER / "single_library_with_export_64bit.yml")
            else:  # 32bit Library
                return parse_yaml(RECIPE_FOLDER / "single_library_with_export_32bit.yml")
        else:
            return parse_yaml(RECIPE_FOLDER / "single_native_binary.yml")

def parse_yaml(yamlfile: Path):
    return yaml.safe_load(yamlfile.read_text())
