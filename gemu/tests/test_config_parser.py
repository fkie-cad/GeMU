import sys

from gemuinteractor.config_parser import get_vm_pool, get_vm_settings, load_config_file
from tests.test_gemu_runner_single_file import TEST_CONFIG, IMAGE_PATH, SNAPSHOT, RAM_SIZE, USER, SYMBOLMAPPING, APIDOC, \
    SYSCALLTABLE, ADDITIONAL_PARAMETERS


def test_get_vm_settings():
    current_module = sys.modules[__name__]
    setattr(current_module, "TEST_CONFIG", TEST_CONFIG)
    config = get_vm_settings("TEST_CONFIG", current_module)
    assert config.image == IMAGE_PATH
    assert config.snapshot == SNAPSHOT
    assert config.ram_size == RAM_SIZE
    assert config.additional_parameters == ADDITIONAL_PARAMETERS
    assert config.user == USER
    assert config.symbolmapping == SYMBOLMAPPING
    assert config.apidoc == APIDOC
    assert config.syscalltable == SYSCALLTABLE


def test_get_vm_pool():
    current_module = sys.modules[__name__]
    test_pool = ["TEST_CONFIG_1", "TEST_CONFIG_2"]
    setattr(current_module, "test_pool", test_pool)
    result_pool = get_vm_pool("test_pool", current_module)
    assert result_pool == test_pool

def test_load_config_file_missing():
    from unittest.mock import patch

    with patch('sys.exit') as mock_exit:
        load_config_file("non_existent_module")
        mock_exit.assert_called_once_with("Config file not found!\nPlease set up gemu/non_existent_module.py based on the template.")

def test_load_config_file_success():
    module = load_config_file("tests.test_gemu_runner_single_file")
    assert module is not None
    assert hasattr(module, "TEST_CONFIG")