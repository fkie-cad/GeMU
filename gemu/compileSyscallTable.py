import json
import yaml
import sys
from collections import defaultdict
from pathlib import Path


def lookup_buildnumber(buildnumbers: dict, major: str, minor: str) -> str:
    return str(buildnumbers.get(major, {}).get(minor))


def main(syscalltable_path: Path, buildnumbers_path: Path, output_path: Path):
    with syscalltable_path.open() as f:
        syscalltable: dict = json.load(f)
    with buildnumbers_path.open() as f:
        buildnumbers: dict = yaml.safe_load(f)

    output = defaultdict(dict)

    for major, major_data in syscalltable.items():
        for minor, minor_data in major_data.items():
            for api, syscall in minor_data.items():
                output[lookup_buildnumber(buildnumbers, major, minor)][str(syscall)] = api

    with output_path.open("w") as f:
        json.dump(output, f, separators=(',', ':'))


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))
