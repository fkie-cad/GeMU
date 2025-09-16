import shutil
import subprocess
import threading
import time
from itertools import product
from pathlib import Path

import pytest

from unpack_single_file import unpack_single_file
from gemuinteractor.helpers import AnalysisFolder, GemuInstance
from gemuinteractor.recipe import Recipe
from gemuinteractor.gemu_runner_single_file import GemuRunner
from gemuinteractor.config_parser import GEMU_PATH, get_vm_settings
from tests.generate_shellcode import generate_shellcode_main
from tests.test_gemu_runner_single_file import SMALL_BITNESS_PE
import re

compilers = {32: "i686-w64-mingw32-gcc", 64: "x86_64-w64-mingw32-gcc"}

# needs packages: gcc-mingw-w64

TEST_FOLDER = Path(__file__).parent
RUNNAME = "gemu_testrun"

def compile(input_path: Path|str, output_path: Path|str, bitness: int, cwd=None):
    compiler = compilers[bitness]
    command = f"{compiler} -o {output_path} {input_path}"
    result = subprocess.run(command, shell=True, cwd=cwd)
    assert result.returncode == 0

@pytest.fixture(scope="session")
def compiled_tests_folder(tmp_path_factory):
    output_path = tmp_path_factory.mktemp("compiled_test_files")
    return output_path


def compile_test(compiled_tests_folder: Path, test_name: str, bitness) -> Path:
    output_name = f"{test_name}_{bitness}.exe"
    output_path = compiled_tests_folder / output_name
    compile(f"{test_name}.c", output_path, bitness, cwd=TEST_FOLDER)
    return output_path

def make_gemu():
    build_folder = Path(__file__).parent.parent.parent/"build"
    result = subprocess.run("make -j`nproc`", shell=True, cwd=build_folder)
    assert result.returncode == 0

# def clear_test_runs():
#     for run_folder in TEST_FOLDER.glob(f"*_{RUNNAME}_*"):
#         print("remove", run_folder.absolute())
#         shutil.rmtree(str(run_folder.absolute()))

# def clear_exes():
#     for exe_file in TEST_FOLDER.glob(f"*.exe"):
#         print("remove", exe_file.absolute())
#         exe_file.absolute().unlink()


@pytest.fixture(autouse=True, scope="session")
def setup_gemu_and_shellcode():
    make_gemu()
    generate_shellcode_main()
    yield
    # teardown here
    # clear_test_runs()
    # clear_exes()

SHELLCODE_TEST_NAMES = (
    "injection",
    "ntmapviewofsection_injection",
    "owninjection",
    "owninjectionmemcpy",
    "writeprocessmemory",
    "writefile",
)

@pytest.mark.emulation
@pytest.mark.parametrize("test_name,bitness,trackingmode", product(SHELLCODE_TEST_NAMES, (32,64), ("syscall", "basicblock")))
def test_shellcode_payload(compiled_tests_folder, test_name, bitness, trackingmode):
    sample_path = compile_test(compiled_tests_folder, test_name, bitness)
    yararules = (TEST_FOLDER/"shellcode.yarc")

    analysis_folder = unpack_single_file(
        sample=sample_path,
        config="win10",
        time=60,
        runname=f"gemutest-{trackingmode}",
        yararules=yararules,
        trackingmode=trackingmode,
        dotnet="off",
    )
    assert "match" in analysis_folder.runlog.read_text().split("\n")[-4]
    assert not analysis_folder.dumps_folder.exists()


@pytest.mark.emulation
def test_timeout(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    copied_pe = Path(tmpdir) / SMALL_BITNESS_PE.name
    analysis_folder = unpack_single_file(
        sample=copied_pe,
        time=10,
        runname="timeout_test",
        config="win10"
    )
    assert "REASON FOR GEMU EXIT: timeout" in analysis_folder.runlog.read_text()

@pytest.mark.emulation
def test_qcow_is_released_from_first_instance(tmpdir):
    shutil.copy(SMALL_BITNESS_PE, tmpdir)
    copied_pe = Path(tmpdir) / SMALL_BITNESS_PE.name
    vm_config = get_vm_settings("win10")
    recipe = Recipe(vm_config.user, copied_pe)
    analysis_folder = AnalysisFolder("tobekilled", copied_pe)
    gemu_instance = GemuInstance(vm_config.image, GEMU_PATH, analysis_folder)
    runner = GemuRunner(120, "syscall", "off", vm_config, recipe, gemu_instance)
    analysis_folder2 = AnalysisFolder("killing", copied_pe)
    gemu_instance2 = GemuInstance(vm_config.image, GEMU_PATH, analysis_folder2)

    first_gemu = threading.Thread(target=runner.run_sample)
    first_gemu.start()
    time.sleep(5)
    runner2 = GemuRunner(5, "syscall", "off", vm_config, recipe, gemu_instance2)

    runner2.run_sample()

    assert "PROCESS RETURN CODE: 137" in analysis_folder.runlog.read_text()
    assert "BrokenPipeError: [Errno 32] Broken pipe" in analysis_folder.runlog.read_text()
    assert "REASON FOR GEMU EXIT: timeout" in analysis_folder2.runlog.read_text()

@pytest.mark.emulation
def test_tracing_works(compiled_tests_folder):
    sample_path = compile_test(compiled_tests_folder, "injection", 32)
    yararules = (TEST_FOLDER/"shellcode.yarc")

    analysis_folder = unpack_single_file(
        sample=sample_path,
        config="win10",
        time=10,
        runname=f"gemutest-syscall",
        yararules=yararules,
        trackingmode="syscall",
        dotnet="off",
        tracing=True,
)

    assert_regular_expression_matches_on_file(analysis_folder.runlog,
                                              re.compile(r"^B:[0-9]*:[0-9]*:0x[0-9a-f]*,[0-9]*"))

def assert_regular_expression_matches_on_file(file_path: Path, regex: str):
    for line in file_path.open("r"):
        if regex.search(line):
            assert True
            return
    assert False
