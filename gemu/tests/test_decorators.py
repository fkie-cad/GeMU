import shutil
import shutil
import subprocess
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import os
import pytest

from gemuinteractor.gemu_run_decorator import WrittenFileMerger, YaraEarlyExiter


@pytest.fixture
def mock_gemu():
    return Mock()


@pytest.fixture
def yara_rule_file():
    yara_content = '''rule TestRule
{
    strings:
        $a = "test_string"
    condition:
        any of them
}
'''
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(yara_content.encode())
        temp_file.flush()
        subprocess.check_output(["yarac", "-w", temp_file.name, temp_file.name])
        yield temp_file.name
    os.unlink(temp_file.name)


class TestYaraEarlyExiter:
    def test_decorate_no_dumps_folder(self, mock_gemu, yara_rule_file):
        exiter = YaraEarlyExiter(1, yara_rule_file, mock_gemu)
        exiter.dump_folder = Path("/does/not/exist")
        exiter._decorate()
        mock_gemu.kill.assert_not_called()

    def test_decorate_with_match(self, mock_gemu, yara_rule_file):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "testdump"), 'w') as f:
                f.write("This file contains test_string to match")

            exiter = YaraEarlyExiter(1, yara_rule_file, mock_gemu)
            exiter.dump_folder = Path(tmpdir)
            exiter._decorate()

            mock_gemu.kill.assert_called_once()

    def test_decorate_without_match(self, mock_gemu, yara_rule_file):
        with tempfile.TemporaryDirectory() as tmpdir:
            testdump = os.path.join(tmpdir, "testdump")
            with open(testdump, 'w') as f:
                f.write("This file contains test_string to match")

            exiter = YaraEarlyExiter(1, yara_rule_file, mock_gemu)
            exiter.dump_folder = Path(tmpdir)
            exiter.checked_files.add(testdump)
            exiter._decorate()

            mock_gemu.kill.assert_not_called()


class TestWrittenFileMerger:
    @pytest.fixture
    def merger(self, mock_gemu):
        return WrittenFileMerger(1, mock_gemu)

    def test_decorate_no_dumps_folder(self, merger):
        merger.dump_folder = Path("/does/not/existttt")
        merger._decorate()
            # No further processing should occur

    def test_decorate_merge_files(self, merger):
        with patch('pathlib.Path.exists', return_value=True), \
                patch('pathlib.Path.iterdir') as mock_iterdir, \
                patch('builtins.open'):
            # Create mock files
            files = [
                Mock(name="handle1_writtenfile_123_nr_1"),
                Mock(name="handle1_writtenfile_123_nr_2"),
                Mock(name="handle2_writtenfile_123_nr_1")
            ]

            for f in files:
                f.name = f.name
                f.parent = Path("/fake/path")

            mock_iterdir.return_value = files

            merger._decorate()

            # Verify that iterdir was called
            mock_iterdir.assert_called_once()

    def test_decorate_single_file_no_merge(self, merger):
        with patch('pathlib.Path.exists', return_value=True), \
                patch('pathlib.Path.iterdir') as mock_iterdir:
            # Create single mock file
            mock_file = Mock(name="handle1_writtenfile_123_nr_1")
            mock_file.name = mock_file.name
            mock_iterdir.return_value = [mock_file]

            merger._decorate()

            # Verify iterdir was called
            mock_iterdir.assert_called_once()
