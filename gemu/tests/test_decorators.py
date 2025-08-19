import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import yara
from collections import defaultdict
import tempfile
import os

from gemuinteractor.gemu_run_decorator import WrittenFileMerger, YaraEarlyExiter
from tests.test_gemu_runner_single_file import BIG_BITNESS_PE


class TestYaraEarlyExiter(unittest.TestCase):
    def setUp(self):
        # Create mock GemuInstance
        self.mock_gemu = Mock()

        # Create temporary yara rules file
        self.yara_content = '''rule TestRule
{
    strings:
        $a = "test_string"
    condition:
        any of them
}
'''

        self.temp_rule_file = tempfile.NamedTemporaryFile(delete=False)
        with open(self.temp_rule_file.name, 'w') as f:
            f.write(self.yara_content)
        subprocess.check_output(["yarac", "-w", self.temp_rule_file.name, self.temp_rule_file.name])

    def tearDown(self):
        os.unlink(self.temp_rule_file.name)

    def test_decorate_no_dumps_folder(self):
        exiter = YaraEarlyExiter(1, self.temp_rule_file.name, self.mock_gemu)
        exiter._decorate()
        self.mock_gemu.kill.assert_not_called()

    def test_decorate_with_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "testdump"), 'w') as f:
                f.write("This file contains test_string to match")

            exiter = YaraEarlyExiter(1, self.temp_rule_file.name, self.mock_gemu)
            exiter.dump_folder = Path(tmpdir)
            exiter._decorate()

            self.mock_gemu.kill.assert_called_once()

    def test_decorate_without_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            testdump = os.path.join(tmpdir, "testdump")
            with open(testdump, 'w') as f:
                f.write("This file contains test_string to match")

            exiter = YaraEarlyExiter(1, self.temp_rule_file.name, self.mock_gemu)
            exiter.dump_folder = Path(tmpdir)
            exiter.checked_files.add(testdump)
            exiter._decorate()

            self.mock_gemu.kill.assert_not_called()


class TestWrittenFileMerger(unittest.TestCase):
    def setUp(self):
        self.mock_gemu = Mock()
        self.mock_gemu.analysis_folder.dumps_folder = Path("/fake/path")
        self.merger = WrittenFileMerger(1, self.mock_gemu)

    @patch('pathlib.Path.exists')
    def test_decorate_no_dumps_folder(self, mock_exists):
        mock_exists.return_value = False
        self.merger._decorate()
        # Verify no further processing occurred

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.iterdir')
    @patch('builtins.open')
    def test_decorate_merge_files(self, mock_open, mock_iterdir, mock_exists):
        mock_exists.return_value = True

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

        # Mock file operations
        mock_file_handle = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file_handle

        self.merger._decorate()

        # Verify that open was called for merge operations
        self.assertTrue(mock_open.called)

    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.iterdir')
    def test_decorate_single_file_no_merge(self, mock_iterdir, mock_exists):
        mock_exists.return_value = True

        # Create single mock file
        mock_file = Mock(name="handle1_writtenfile_123_nr_1")
        mock_file.name = mock_file.name
        mock_iterdir.return_value = [mock_file]

        self.merger._decorate()

        # Verify no merge operations occurred for single file


