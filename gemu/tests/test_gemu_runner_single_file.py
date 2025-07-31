import shutil
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from gemuinteractor.config_parser import VMConfig
from gemuinteractor.gemu_run_decorator import RunDecorator
from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile

SAMPLE_NAME = "testsample.exe"
SAMPLE_PATH = "/path/to/sample"
GEMU_PATH = Path("/path/to/gemu")
UNPACKING_TIME = 666
RUNNAME = "test_run"
EXPORT = "export1"
YARARULES = "path/to/yara/rules"
TRACKINGMODE = "syscall"
DOTNET = "auto"
IMAGE_PATH = Path("/path/to/image")
SNAPSHOT = "snapshot"
RAM_SIZE = "1024"
ADDITIONAL_PARAMETERS = [
    "-addparameter",
    "IAmATest",
]
USER = "C:\\Users\\analyst\\"
SYMBOLMAPPING = Path("/path/to/symbolmapping")
APIDOC = Path("/path/to/apidoc")
SYSCALLTABLE = Path("/path/to/syscalltable")
TIMESTAMP = 1337
SMALL_BITNESS_PE = Path(__file__).parent / "testfiles" / "32bit.exe"
BIG_BITNESS_PE = Path(__file__).parent / "testfiles" / "64bit.exe"


TEST_CONFIG = {
    "VM_IMAGE_PATH": IMAGE_PATH,
    "SNAPSHOT": SNAPSHOT,
    "RAM": RAM_SIZE,
    "USER": "C:\\Users\\analyst\\",
    "SYMBOLMAPPING": SYMBOLMAPPING.as_posix(),
    "APIDOC": APIDOC.as_posix(),
    "SYSCALLTABLE": SYSCALLTABLE.as_posix(),
    "PARAMETERS": ADDITIONAL_PARAMETERS
}

class GemuInstanceMock:
    def __init__(self, image):
        self.image = image
        self.return_code = 0
        self.written_to_qemu_console = []
        self.typed_into_guest = []
        self.sent_to_gemu = []
        self.cmd = None
        self.cwd = None
        self.waited = None

    @contextmanager
    def launch_gemu(self, cmd, cwd):
        try:
            self.cmd = cmd
            self.cwd = cwd
            yield True
        finally:
            return False

    def write_to_qemu_console(self, command):
        self.written_to_qemu_console.append(command)
        self.sent_to_gemu.append(command.decode())

    def wait(self, timeout):
        self.waited = timeout

    def get_return_code(self):
        return self.return_code

    def type_into_guest(self, command):
        self.typed_into_guest.append(command)
        self.sent_to_gemu.append(command)


class MockDecorator(RunDecorator):
    def _decorate(self):
        return


class TestGemuRunnerSingleFile:

    def get_mock_vm_config(self):
        return VMConfig(image=IMAGE_PATH,
        snapshot=SNAPSHOT,
        ram_size=RAM_SIZE,
        additional_parameters=ADDITIONAL_PARAMETERS,
        user=USER,
        symbolmapping=SYMBOLMAPPING,
        apidoc=APIDOC,
        syscalltable=SYSCALLTABLE
        )

    def mock_gemu_instance(self):
        return GemuInstanceMock(IMAGE_PATH)

    def gemu_single_file_runner(self, gemu_instance, sample_path, export=None):
        vm_config = self.get_mock_vm_config()
        with patch('datetime.datetime') as mock_datetime:
            mock_now = mock_datetime.now.return_value
            mock_now.strftime.return_value = TIMESTAMP
            return GemuRunnerSingleFile(sample_path, UNPACKING_TIME, RUNNAME, export, TRACKINGMODE, DOTNET, vm_config,
                                        gemu_instance, gemu_path=GEMU_PATH, sample_name=SAMPLE_NAME)

    def test_command_without_export(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path)

        gemu_runner.run_sample()

        assert mock_gemu_instance.cmd == (f"{GEMU_PATH.as_posix()} -m {RAM_SIZE} -monitor stdio -addparameter IAmATest "
                                          f"-loadvm {SNAPSHOT} -symbolmapping {SYMBOLMAPPING} -apidoc {APIDOC} "
                                          f"-watchedprograms {SAMPLE_NAME} -syscalltable {SYSCALLTABLE} "
                                          f"-trackingmode {TRACKINGMODE} -dotnet {DOTNET} {IMAGE_PATH} "
                                          f"> {sample_path}_{RUNNAME}_{TIMESTAMP}/runlog")
        assert mock_gemu_instance.cwd == Path(f"{sample_path}_{RUNNAME}_{TIMESTAMP}")
        assert mock_gemu_instance.waited == UNPACKING_TIME

    def test_command_with_export(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path, export=EXPORT)

        gemu_runner.run_sample()

        assert mock_gemu_instance.cmd == (f"{GEMU_PATH.as_posix()} -m {RAM_SIZE} -monitor stdio -addparameter IAmATest "
                                          f"-loadvm {SNAPSHOT} -symbolmapping {SYMBOLMAPPING} -apidoc {APIDOC} "
                                          f"-watchedprograms {SAMPLE_NAME} -syscalltable {SYSCALLTABLE} "
                                          f"-trackingmode {TRACKINGMODE} -dotnet {DOTNET} {IMAGE_PATH} "
                                          f"> {sample_path}_EXPORT:{EXPORT}_{RUNNAME}_{TIMESTAMP}/runlog")
        assert mock_gemu_instance.cwd == Path(f"{sample_path}_EXPORT:{EXPORT}_{RUNNAME}_{TIMESTAMP}")

    def test_with_one_decorator(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path)
        gemu_runner.decorate_run([(MockDecorator(2, gemu_runner))])

        ret = gemu_runner.run_sample()

        assert ret == "normal"

    def test_with_multiple_decorators(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path)
        gemu_runner.decorate_run([MockDecorator(2, gemu_runner), MockDecorator(2, gemu_runner)])

        ret = gemu_runner.run_sample()

        assert ret == "normal"

    def test_correct_messages_are_sent_to_gemu(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path)
        gemu_runner.decorate_run([MockDecorator(2, gemu_runner), MockDecorator(2, gemu_runner)])

        gemu_runner.run_sample()

        expected = [f'change ide1-cd0 {tmpdir}/{SMALL_BITNESS_PE}.iso\n', 'sendkey esc\n',
                    f' copy D:\\{SAMPLE_NAME} C:\\Users\\analyst\\Desktop\\{SAMPLE_NAME}\n',
                    'gemurec\n', f'start C:\\Users\\analyst\\Desktop\\{SAMPLE_NAME}\n']
        self.assert_messages_to_gemu(expected, mock_gemu_instance.sent_to_gemu)

    def test_correct_messages_are_sent_to_gemu_with_export(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, sample_path, export=EXPORT)
        gemu_runner.decorate_run([MockDecorator(2, gemu_runner), MockDecorator(2, gemu_runner)])

        gemu_runner.run_sample()

        expected = [f'change ide1-cd0 {tmpdir}/{SMALL_BITNESS_PE}.iso\n', 'sendkey esc\n',
                    f' copy C:\\Windows\\SysWOW64\\rundll32.exe C:\\Users\\analyst\\Desktop\\{SAMPLE_NAME}\n',
                    f' copy D:\\{SAMPLE_NAME} C:\\Users\\analyst\\Desktop\\ahsofidll.dll\n',
                    'gemurec\n', f'start C:\\Users\\analyst\\Desktop\\{SAMPLE_NAME} ahsofidll.dll,export1\n']
        self.assert_messages_to_gemu(expected, mock_gemu_instance.sent_to_gemu)

    def assert_messages_to_gemu(self, expected, actual):
        assert len(actual) == len(expected)
        for i in range(len(actual)):
            if "change ide1-cd0" in actual[i]:
                assert "change ide1-cd0" in expected[i]
                continue
            assert actual[i] == expected[i]

