import shutil
import yaml
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import Mock, patch

from gemuinteractor.recipe import Recipe
from gemuinteractor.config_parser import VMConfig
from gemuinteractor.gemu_run_decorator import RunDecorator
from gemuinteractor.gemu_runner_single_file import GemuRunner

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
USER = "C:\\Users\\testuser"
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
    "USER": "C:\\Users\\testuser",
    "SYMBOLMAPPING": SYMBOLMAPPING.as_posix(),
    "APIDOC": APIDOC.as_posix(),
    "SYSCALLTABLE": SYSCALLTABLE.as_posix(),
    "PARAMETERS": ADDITIONAL_PARAMETERS
}

class GemuInstanceMock:
    def __init__(self):
        self.return_code = 0
        self.written_to_qemu_console = []
        self.typed_into_guest = []
        self.sent_to_gemu = []
        self.waited = None

    @contextmanager
    def launch_gemu(self, params_string):
        try:
            self.params_string = params_string
            yield True
        except Exception as e:
            print("EXCEPTION", e)
            raise e
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
        return GemuInstanceMock()

    def gemu_single_file_runner(self, gemu_instance, recipe):
        vm_config = self.get_mock_vm_config()
        with patch('datetime.datetime') as mock_datetime:
            mock_now = mock_datetime.now.return_value
            mock_now.strftime.return_value = TIMESTAMP
            return GemuRunner(UNPACKING_TIME, TRACKINGMODE, DOTNET, vm_config, recipe, gemu_instance)

    def test_command_without_export(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        recipe = Recipe(USER, sample_path.as_posix(), default_sample_name=SAMPLE_NAME)
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)

        gemu_runner.run_sample()

        assert mock_gemu_instance.params_string == (f"-m {RAM_SIZE} -monitor stdio -addparameter IAmATest "
                                          f"-loadvm {SNAPSHOT} -symbolmapping {SYMBOLMAPPING} -apidoc {APIDOC} "
                                          f"-watchedprograms {SAMPLE_NAME} -syscalltable {SYSCALLTABLE} "
                                          f"-trackingmode {TRACKINGMODE} -dotnet {DOTNET} {IMAGE_PATH}")
        assert mock_gemu_instance.waited == UNPACKING_TIME

    def test_command_with_export(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        recipe = Recipe(USER, sample_path.as_posix(), default_sample_name=SAMPLE_NAME, export=EXPORT)
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)

        gemu_runner.decorate_run([])
        gemu_runner.run_sample()

        assert mock_gemu_instance.params_string == (f"-m {RAM_SIZE} -monitor stdio -addparameter IAmATest "
                                          f"-loadvm {SNAPSHOT} -symbolmapping {SYMBOLMAPPING} -apidoc {APIDOC} "
                                          f"-watchedprograms {SAMPLE_NAME} -syscalltable {SYSCALLTABLE} "
                                          f"-trackingmode {TRACKINGMODE} -dotnet {DOTNET} {IMAGE_PATH}")

    def test_with_one_decorator(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        recipe = Recipe(USER, sample_path.as_posix(), default_sample_name=SAMPLE_NAME)
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)
        mock_decorator = Mock()

        gemu_runner.decorate_run([mock_decorator])
        gemu_runner.run_sample()

        mock_decorator.start.assert_called_once()
        mock_decorator.stop.assert_called_once()
        mock_decorator.join.assert_called_once()

    def test_with_multiple_decorators(self, tmpdir):
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = Path(tmpdir) / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        recipe = Recipe(USER, sample_path.as_posix(), default_sample_name=SAMPLE_NAME)
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)
        mock_decorators = [Mock(), Mock()]

        gemu_runner.decorate_run(mock_decorators)
        gemu_runner.run_sample()

        for mock_decorator in mock_decorators:
            mock_decorator.start.assert_called_once()
            mock_decorator.stop.assert_called_once()
            mock_decorator.join.assert_called_once()

    def test_correct_messages_are_sent_to_gemu(self, tmpdir):
        tmpdir = Path(tmpdir)
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = tmpdir / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()
        recipe = Recipe(USER, sample_path.as_posix(), default_sample_name=SAMPLE_NAME)
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)

        gemu_runner.run_sample()

        expected = [
            f'change ide1-cd0 {tmpdir}/{tmpdir.name}.iso\n', 'sendkey esc\n',
            f'copy D:\\{SMALL_BITNESS_PE.name} {USER}\\Desktop\\{recipe.sample_name}\n',
            'gemurec\n',
            *[cmd+"\n" for cmd in recipe.commands],
        ]
        self.assert_messages_to_gemu(expected, mock_gemu_instance.sent_to_gemu)

    def test_correct_messages_are_sent_to_gemu_multiple_commands(self, tmpdir):
        tmpdir = Path(tmpdir)
        shutil.copy(SMALL_BITNESS_PE, tmpdir)
        sample_path = tmpdir / SMALL_BITNESS_PE.name
        mock_gemu_instance = self.mock_gemu_instance()

        recipe_file = {"samples": [f"{SMALL_BITNESS_PE.as_posix()}:test2", f"{BIG_BITNESS_PE.as_posix()}:test4"], "cmds": ["echo hey", "echo ho"]}
        recipe_file_name = Path(tmpdir) / "test.yml"
        with open(recipe_file_name, "w") as f:
            yaml.dump(recipe_file, f)
        recipe = Recipe(USER, sample_path.as_posix(), recipe=recipe_file_name)
        
        gemu_runner = self.gemu_single_file_runner(mock_gemu_instance, recipe)
        gemu_runner.run_sample()

        expected = [
            f'change ide1-cd0 {tmpdir}/{tmpdir.name}.iso\n', 'sendkey esc\n',
            *[f'copy D:\\{mount[0].name} {mount[1]}\n' for mount in recipe.mountings],
            'gemurec\n',
            *[cmd+"\n" for cmd in recipe.commands],
        ]
        self.assert_messages_to_gemu(expected, mock_gemu_instance.sent_to_gemu)

    def assert_messages_to_gemu(self, expected, actual):
        assert len(actual) == len(expected)
        for i in range(len(actual)):
            if "change ide1-cd0" in actual[i]:
                assert "change ide1-cd0" in expected[i]
                continue
            assert actual[i] == expected[i]

