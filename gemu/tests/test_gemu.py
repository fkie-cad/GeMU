import time
from itertools import product
from pathlib import Path
import pytest
# import shutil
import subprocess

from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile
from gemuinteractor.config_parser import get_vm_settings

from generate_shellcode import generate_shellcode_main

compilers = {32: "i686-w64-mingw32-gcc", 64: "x86_64-w64-mingw32-gcc"}

# needs packages: gcc-mingw-w64

TEST_FOLDER = Path(__file__).parent
RUNNAME = "gemu_testrun"

def compile(input_path, output_path, bitness, cwd=None):
    compiler = compilers[bitness]
    command = f"{compiler} -o {output_path} {input_path}"
    result = subprocess.run(command, shell=True, cwd=cwd)
    assert result.returncode == 0

@pytest.fixture(scope="session")
def compiled_tests_folder(tmp_path_factory):
    output_path = tmp_path_factory.mktemp("compiled_test_files")
    return output_path


def compile_test(compiled_tests_folder, test_name, bitness):
    output_name = f"{test_name}_{bitness}.exe"
    output_path = (compiled_tests_folder / output_name).as_posix()
    compile(f"{test_name}.c", output_path, bitness, cwd=TEST_FOLDER.as_posix())
    return output_path

def make_gemu():
    build_folder = Path(__file__).parent.parent.parent/"build"
    result = subprocess.run("make -j`nproc`", shell=True, cwd=build_folder.as_posix())
    assert result.returncode == 0

# def clear_test_runs():
#     for run_folder in TEST_FOLDER.glob(f"*_{RUNNAME}_*"):
#         print("remove", run_folder.absolute().as_posix())
#         shutil.rmtree(run_folder.absolute().as_posix())

# def clear_exes():
#     for exe_file in TEST_FOLDER.glob(f"*.exe"):
#         print("remove", exe_file.absolute().as_posix())
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


@pytest.mark.parametrize("test_name,bitness,trackingmode", product(SHELLCODE_TEST_NAMES, (32,64), ("syscall", "basicblock")))
def test_shellcode_payload(compiled_tests_folder, test_name, bitness,trackingmode):

    if trackingmode == "basicblock" and test_name == "writefile":
        pytest.skip(reason="known issue with bb tracking")

    sample_path = compile_test(compiled_tests_folder, test_name, bitness)
    yararules = (TEST_FOLDER/"shellcode.yarc").as_posix()
    runner = GemuRunnerSingleFile(
        sample_path,
        120,
        RUNNAME,
        None,
        yararules,
        trackingmode,
        "off",
        get_vm_settings("win10")
    )
    status = runner.run_sample() 
    assert status.split("(")[0] == "match"
    time.sleep(3)
    # assert not status.endswith("nr_0)")
