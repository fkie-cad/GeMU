import datetime
import os
import shutil
import string
import subprocess
import sys
import time
from pathlib import Path


def guest_type(s, p):
    keymap = {
        "-": "minus",
        "=": "equal",
        "[": "bracket_left",
        "]": "bracket_right",
        ";": "semicolon",
        "'": "apostrophe",
        "\\": "backslash",
        ",": "comma",
        ".": "dot",
        "/": "slash",
        "*": "asterisk",
        " ": "spc",
        "_": "shift-minus",
        "+": "shift-equal",
        "{": "shift-bracket_left",
        "}": "shift-bracket_right",
        ":": "shift-semicolon",
        '"': "shift-apostrophe",
        "|": "shift-backslash",
        "<": "shift-comma",
        ">": "shift-dot",
        "?": "shift-slash",
        "\n": "ret",
    }

    for c in s:
        if c in string.ascii_uppercase:
            key = "shift-" + c.lower()
        else:
            key = keymap.get(c, c)

        p.stdin.write(b"sendkey " + key.encode(encoding="utf-8") + b"\n")
        p.stdin.flush()
        time.sleep(0.001)

def build_iso_from_file(path: Path, sample_name, iso_output_path: Path = Path("ahsofi.iso")):
    tmp = Path("/tmp/") / (path.name + "_" + datetime.datetime.now().strftime("%Y%m%d%H%M%S%f"))
    tmp.mkdir(exist_ok=True)
    tmp_sample = tmp / sample_name
    shutil.copy(path.absolute(), tmp_sample)
    temp_iso = tmp / iso_output_path
    cmd = [
        "/usr/bin/genisoimage",
        "-quiet",
        "-iso-level",
        "4",
        "-l",
        "-R",
        "-J",
        "-o",
        temp_iso.as_posix(),
        tmp_sample.as_posix(),
    ]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        print(sys.exc_info()[0])
        raise
    return temp_iso
