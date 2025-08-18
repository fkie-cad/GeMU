import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

from gemuinteractor.helpers import build_iso_from_files, AnalysisFolder, GemuInstance
from tests.test_gemu_runner_single_file import SMALL_BITNESS_PE, BIG_BITNESS_PE, RUNNAME, IMAGE_PATH


def test_build_iso_from_file(tmpdir):
    output_path = build_iso_from_files(set([Path(SMALL_BITNESS_PE)]),
                                      tmpdir=tmpdir)

    expected = Path(tmpdir) / (Path(tmpdir).name + ".iso")
    assert output_path == expected
    output = subprocess.check_output(["isoinfo", "-f", "-i", expected])
    assert SMALL_BITNESS_PE.name in output.decode()

def test_build_iso_from_multiple_files(tmpdir):
    output_path = build_iso_from_files(set([Path(SMALL_BITNESS_PE), Path(BIG_BITNESS_PE)]),
                                      tmpdir=tmpdir)

    expected = Path(tmpdir) / (Path(tmpdir).name + ".iso")
    assert output_path == expected
    output = subprocess.check_output(["isoinfo", "-f", "-i", expected])
    assert SMALL_BITNESS_PE.name in output.decode()
    assert BIG_BITNESS_PE.name in output.decode()

def test_build_iso_from_no_files(tmpdir):
    output_path = build_iso_from_files(set(),
                                       tmpdir=tmpdir)

    expected = Path(tmpdir) / (Path(tmpdir).name + ".iso")
    assert output_path == expected
    output = subprocess.check_output(["isoinfo", "-f", "-i", expected])
    assert "" == output.decode()

def test_build_iso_from_file_with_whitespace(tmpdir):
    with tempfile.TemporaryDirectory() as tmpdirouter:
        with pytest.raises(RuntimeError):
            new_name = os.path.join(tmpdirouter, SMALL_BITNESS_PE.name + " with_whitespace.exe")
            shutil.copy(SMALL_BITNESS_PE, new_name)
            build_iso_from_files([Path(new_name)], tmpdir=tmpdir)


def test_analysis_folder(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    name_of_sample = Path(SMALL_BITNESS_PE).name

    folder = AnalysisFolder(RUNNAME, Path(tmpdir) / name_of_sample)

    assert folder.analysis_folder.exists()
    assert "sample" in os.listdir(folder.analysis_folder)

def test_analysis_folder_dumps_get_zipped(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    name_of_sample = Path(SMALL_BITNESS_PE).name
    folder = AnalysisFolder(RUNNAME, Path(tmpdir) / name_of_sample)
    folder.dumps_folder.mkdir()
    (folder.dumps_folder / "dump1").write_text("GeMU Is Nice :)")

    folder.zip_dumps_folder()

    assert "dumps.zip" in os.listdir(folder.analysis_folder)
    with zipfile.ZipFile(folder.analysis_folder / "dumps.zip", "r") as zip_ref:
        assert zip_ref.filelist[0].filename == "dump1"

def test_analysis_folder_dumps_get_zipped_empty(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    name_of_sample = Path(SMALL_BITNESS_PE).name
    folder = AnalysisFolder(RUNNAME, Path(tmpdir) / name_of_sample)

    folder.zip_dumps_folder()

    assert "dumps.zip" not in os.listdir(folder.analysis_folder)

def test_GemuInstance_normal(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    name_of_sample = Path(SMALL_BITNESS_PE).name
    folder = AnalysisFolder(RUNNAME, Path(tmpdir) / name_of_sample)
    instance = GemuInstance(IMAGE_PATH, "cat -", folder)

    with instance.launch_gemu("hey ho"):
        instance.wait(1)

    expected = """system_powerdown
quit
EXIT STATUS: normal
PROCESS RETURN CODE: None"""
    assert folder.runlog.read_text(), expected

