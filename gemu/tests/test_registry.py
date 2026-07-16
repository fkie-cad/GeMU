import subprocess
from itertools import product
from pathlib import Path
from typing import Literal

import pytest

from unpack_single_file import unpack_single_file

# needs packages: g++-mingw-w64 (the registry tests are C++, unlike the C shellcode tests)

TEST_FOLDER = Path(__file__).parent
REGISTRY_SRC_FOLDER = TEST_FOLDER


# needs packages: g++-mingw-w64
registry_compilers = {32: "i686-w64-mingw32-g++", 64: "x86_64-w64-mingw32-g++"}

REGISTRY_SOURCES = ("Registry Query Tester.cpp", )


def make_gemu():
    build_folder = Path(__file__).parent.parent.parent / "build"
    result = subprocess.run("make -j`nproc`", shell=True, cwd=build_folder)
    assert result.returncode == 0


@pytest.fixture(autouse=True, scope="session")
def setup_gemu():
    make_gemu()
    yield


@pytest.fixture(scope="session")
def compiled_tests_folder(tmp_path_factory: pytest.TempPathFactory):
    return tmp_path_factory.mktemp("compiled_registry_test_files")


def compile_registry_test(compiled_tests_folder: Path, bitness: int) -> Path:
    compiler = registry_compilers[bitness]
    output_path = compiled_tests_folder / f"Registry_Query_Tester_{bitness}.exe"
    command = [
        compiler,
        "-static", "-static-libgcc", "-static-libstdc++",
        "-o", str(output_path),
        *REGISTRY_SOURCES,
    ]
    result = subprocess.run(command, cwd=REGISTRY_SRC_FOLDER)
    assert result.returncode == 0
    return output_path


# Expected decoded "&NtQueryValueKey:" responses, extracted from
# gemu/Registry_Test/necessary_lines.md (one per registry value type queried by main() in
# "Registry Query Tester.cpp"). REG_BINARY and REG_QWORD produce no line (see below).

# REG_SZ (Normaler String)
# SOFTWARE\Microsoft\Windows\CurrentVersion\ProgramFilesDir is bitness-specific: a 32-bit
# (WOW64) process is redirected to WOW6432Node and sees "C:\Program Files (x86)", whereas a
# 64-bit process reads the native "C:\Program Files" (DataLength 34, no " (x86)" suffix).
EXPECTED_REG_SZ = {
    32: r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_STRING","DataLength":46,"Data":"C:\\Program Files (x86)"}',
    64: r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_STRING","DataLength":34,"Data":"C:\\Program Files"}',
}

# Bitness-independent expected lines:
EXPECTED_LINES = [
    # REG_EXPAND_SZ (Normaler String mit "%"-Pfaden)
    r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_EXPANDSTRING","DataLength":30,"Data":"%ProgramFiles%"}',
    # REG_BINARY: wurde nicht verarbeitet, weil die Verarbeitung zu Base64 abgeschaltet ist.
    # REG_DWORD
    r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_DWORD","DataLength":4,"Data":0}',
    # REG_QWORD: wurde nicht verarbeitet, weil nicht eingeschaltet in meiner Version.
    # REG_MULTI_SZ (Hat nur einen einzigen Eintrag)
    r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_MULTISTRING","DataLength":24,"Data":["BOCHS  - 1"]}',
]

# REG_MULTI_SZ (Hat mehrere Einträge)
# SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\LocalService is bitness-specific: the
# 32-bit (WOW64) view holds a short list, the 64-bit view the full service list.
EXPECTED_MULTI_SZ_SEVERAL = {
    32: r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_MULTISTRING","DataLength":80,"Data":["netprofm","WinHttpAutoProxySvc","WebClient"]}',
    64: r'&NtQueryValueKey: {"KeyValueInformationClass":"KeyValuePartialInformation","TitleIndex":0,"Type":"REG_VALUE_MULTISTRING","DataLength":516,"Data":["nsi","WdiServiceHost","w32time","EventSystem","RemoteRegistry","SstpSvc","netprofm","lltdsvc","FontCache","fdphost","bthserv","bthavctpsvc","CDPSvc","SharedRealitySvc","WpcMonSvc","WebClient","LicenseManager","tzautoupdate","SEMgrSvc","WinHttpAutoProxySvc","workfolderssvc","PhoneSvc","CaptureService"]}',
}


@pytest.mark.emulation
@pytest.mark.parametrize("bitness,trackingmode", product((32, 64), ("syscall", "basicblock")))
def test_registry_query_values(
    compiled_tests_folder,
    bitness: Literal[32, 64],
    trackingmode: Literal["syscall", "basicblock"],
):
    sample_path = compile_registry_test(compiled_tests_folder, bitness)

    analysis_folder = unpack_single_file(
        sample=sample_path,
        config="win10",
        time=120,
        runname=f"gemu_registrytest-{trackingmode}",
        trackingmode=trackingmode,
        dotnet="off",
        postprocess=False,
    )

    runlog_text = analysis_folder.runlog.read_text()
    expected_lines = [
        EXPECTED_REG_SZ[bitness],
        *EXPECTED_LINES,
        EXPECTED_MULTI_SZ_SEVERAL[bitness],
    ]

    missing = [line for line in expected_lines if line not in runlog_text]
    assert not missing, f"expected registry lines missing from runlog: {missing}"
