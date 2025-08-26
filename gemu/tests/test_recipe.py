from pathlib import Path

import pytest
import yaml

from gemuinteractor.config_parser import SAMPLE_NAME
from gemuinteractor.recipe import Recipe, RECIPE_FOLDER
from tests.test_gemu_runner_single_file import USER, SMALL_BITNESS_PE, BIG_BITNESS_PE


def test_recipe_get_native_binary():
    recipe = Recipe(USER, SMALL_BITNESS_PE)

    assert recipe.sample_name == SAMPLE_NAME
    assert recipe.commands == ['start C:\\Users\\testuser\\Desktop\\ahsofi.exe']
    assert recipe.mountings == [(SMALL_BITNESS_PE, 'C:\\Users\\testuser\\Desktop\\ahsofi.exe')]
    assert recipe.requirements == {SMALL_BITNESS_PE}

def test_recipe_get_native_binary_with_export():
    recipe = Recipe(USER, SMALL_BITNESS_PE, export="TestExport")

    assert recipe.sample_name == SAMPLE_NAME
    assert recipe.commands == ['copy C:\\Windows\\SysWOW64\\rundll32.exe '
                               'C:\\Users\\testuser\\Desktop\\ahsofi.exe',
                               'start C:\\Users\\testuser\\Desktop\\ahsofi.exe ahsofidll.dll,TestExport']
    assert recipe.mountings == [(SMALL_BITNESS_PE,
                                 'C:\\Users\\testuser\\Desktop\\ahsofidll.dll')]
    assert recipe.requirements == {SMALL_BITNESS_PE}

def test_recipe_get_native_binary_with_export_big_bitness():
    recipe = Recipe(USER, BIG_BITNESS_PE, export="TestExport")

    assert recipe.sample_name == SAMPLE_NAME
    assert recipe.commands == ['copy C:\\Windows\\system32\\rundll32.exe '
                               'C:\\Users\\testuser\\Desktop\\ahsofi.exe',
                               'start C:\\Users\\testuser\\Desktop\\ahsofi.exe ahsofidll.dll,TestExport']
    assert recipe.mountings == [(BIG_BITNESS_PE,
                                 'C:\\Users\\testuser\\Desktop\\ahsofidll.dll')]
    assert recipe.requirements == {BIG_BITNESS_PE}

def test_recipe_get_forced_recipe(tmpdir):
    recipe_file = {"samples": ["test1:test2"], "cmds": ["echo hey"], "overwriteinitprocess": "TestSample"}
    recipe_file_name = Path(tmpdir) / "test.yml"
    with open(recipe_file_name, "w") as f:
        yaml.dump(recipe_file, f)
    recipe = Recipe(USER, SMALL_BITNESS_PE, recipe=recipe_file_name, export="TestExport")

    assert recipe.sample_name == "TestSample"
    assert recipe.commands == ["echo hey"]
    assert recipe.mountings == [(Path("test1"), 'test2')]
    assert recipe.requirements == {Path("test1")}

def test_recipe_not_implemented_error(tmpdir):
    sample_name = Path(tmpdir) / "test.yml"
    with open(sample_name, "wb") as f:
        f.write(b"test")
    with pytest.raises(NotImplementedError):
        Recipe(USER, sample_name)
