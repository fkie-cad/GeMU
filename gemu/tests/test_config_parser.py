import sys

from gemuinteractor.config_parser import get_vm_settings
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