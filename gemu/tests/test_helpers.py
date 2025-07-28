import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from gemuinteractor.helpers import build_iso_from_file
from tests.test_gemu_runner_single_file import SMALL_BITNESS_PE, SAMPLE_NAME


def test_build_iso_from_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = build_iso_from_file(Path(SMALL_BITNESS_PE),
                                          SAMPLE_NAME,
                                          tmpdir=tmpdir)
        iso_path = Path(tmpdir) / (SMALL_BITNESS_PE.name + ".iso")
        assert output_path == Path(tmpdir) / iso_path
        output = subprocess.check_output(["isoinfo", "-f", "-i", iso_path])
        assert SAMPLE_NAME in output.decode()

def test_build_iso_from_file_with_whitespace():
    with tempfile.TemporaryDirectory() as tmpdir:
        new_name = os.path.join(tmpdir, SMALL_BITNESS_PE.name + " with_whitespace.exe")
        shutil.copy(SMALL_BITNESS_PE, new_name)
        output_path = build_iso_from_file(Path(new_name),
                                          SAMPLE_NAME,
                                          tmpdir=tmpdir)
        assert output_path == Path(tmpdir) / (new_name.replace(" ", "")  + ".iso")
