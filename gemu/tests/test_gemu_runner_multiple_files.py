from itertools import chain
from pathlib import Path
import shutil

import pytest
from tests.test_gemu_runner_single_file import SMALL_BITNESS_PE
from gemuinteractor.gemu_runner_multiple_files import GemuRunnerMultipleFiles

@pytest.mark.emulation
def test_list(tmpdir):
    tmpdir = Path(tmpdir).absolute()
    file1 = shutil.copy(SMALL_BITNESS_PE, tmpdir/"file1.exe")
    inner_dir = tmpdir / "inner_dir"
    inner_dir.mkdir()
    file2 = shutil.copy(SMALL_BITNESS_PE, inner_dir/"file2.exe")

    sample_list = tmpdir/"list.txt"
    sample_list.write_text(f"{file1}\n{inner_dir}\n")

    runname = "gemu_list_test"
    runner = GemuRunnerMultipleFiles(
        samples=sample_list,
        time=3,
        configs="win10_pool",
        runname=runname,
        yararules=None,
        trackingmode="syscall",
        dotnet=None,
        allowmultipleruns=False,
        malpedia_mode=False,
        tracing=False,
    )

    runner.run()

    num_folders = 0
    for folder in chain(tmpdir.iterdir(), inner_dir.iterdir()):
        folder: Path
        if not folder.is_dir():
            continue
        runlog = (folder / "runlog")
        if not runlog.exists():
            continue
        assert "timeout" in runlog.read_text()
        num_folders += 1

    assert num_folders == 2

@pytest.mark.emulation
def test_folder(tmpdir):
    tmpdir = Path(tmpdir).absolute()
    shutil.copy(SMALL_BITNESS_PE, tmpdir/"file1.exe")
    shutil.copy(SMALL_BITNESS_PE, tmpdir/"file2.exe")
    runner = GemuRunnerMultipleFiles(
        samples=tmpdir,
        time=2,
        configs="win10_pool",
        runname="gemu_two_files_test",
        yararules=None,
        trackingmode="syscall",
        dotnet=None,
        allowmultipleruns=False,
        malpedia_mode=False,
        tracing=False,
    )

    runner.run()

    num_folders = 0
    for folder in tmpdir.iterdir():
        folder: Path
        if not folder.is_dir():
            continue
        assert "timeout" in (folder / "runlog").read_text()
        num_folders += 1

    assert num_folders == 2


def test_empty_line(tmpdir):
    tmpdir = Path(tmpdir).absolute()
    inner_dir = tmpdir / "inner_dir"
    inner_dir.mkdir()
    file1 = shutil.copy(SMALL_BITNESS_PE, inner_dir/"file1.exe")
    file2 = shutil.copy(SMALL_BITNESS_PE, inner_dir/"file2.exe")

    sample_list = tmpdir/"list.txt"
    sample_list.write_text(f"\n{file1}\n\n{file2}\n\n\n")

    runname = "gemu_list_test"
    runner = GemuRunnerMultipleFiles(
        samples=sample_list,
        time=2,
        configs="win10_pool",
        runname=runname,
        yararules=None,
        trackingmode="syscall",
        dotnet=None,
        allowmultipleruns=False,
        malpedia_mode=False,
        tracing=False,
    )
    assert len([*runner._samples_as_list()]) == 2
