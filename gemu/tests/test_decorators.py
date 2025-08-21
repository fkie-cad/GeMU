import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import Mock

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
        exiter.start()
        exiter.stop()
        mock_gemu.kill.assert_not_called()

    def test_decorate_with_match(self, tmpdir, mock_gemu, yara_rule_file):
        with open(os.path.join(tmpdir, "testdump"), 'w') as f:
            f.write("This file contains test_string to match")

        exiter = YaraEarlyExiter(1, yara_rule_file, mock_gemu)
        exiter.dump_folder = Path(tmpdir)

        exiter.start()
        exiter.stop()

        mock_gemu.kill.assert_called_once()

    def test_decorate_without_match(self, tmpdir, mock_gemu, yara_rule_file):
        testdump = os.path.join(tmpdir, "testdump")
        with open(testdump, 'w') as f:
            f.write("This file contains test_string to match")

        exiter = YaraEarlyExiter(1, yara_rule_file, mock_gemu)
        exiter.dump_folder = Path(tmpdir)
        exiter.checked_files.add(testdump)

        exiter.start()
        exiter.stop()

        mock_gemu.kill.assert_not_called()


class TestWrittenFileMerger:
    @pytest.fixture
    def merger(self, mock_gemu):
        return WrittenFileMerger(1, mock_gemu)

    def test_decorate_no_dumps_folder(self, merger):
        merger._gemu_instance.analysis_folder.dumps_folder = Path("/does/not/exist")
        merger._decorate()
        # No further processing should occur

    def test_decorate_merge_files(self, merger, tmpdir):
        tmpdir = Path(tmpdir)
        merger._gemu_instance.analysis_folder.dumps_folder = tmpdir

        file1 = tmpdir/"handle1_1_writtenfile_123_nr_1"
        file2 = tmpdir/"handle1_1_writtenfile_124_nr_2"
        file3 = tmpdir/"handle2_3_writtenfile_125_nr_6"
        result_file = tmpdir/"handle1_1_writtenfilemerge_124_nr_2"

        file1.write_text("file1")
        file2.write_text("file2")
        file3.write_text("file3")
        expected_result = "file1file2"

        merger.start()
        merger.stop()

        assert result_file.exists()
        assert result_file.read_text() == expected_result

    def test_decorate_expand_file(self, merger, tmpdir):
        tmpdir = Path(tmpdir)
        merger._gemu_instance.analysis_folder.dumps_folder = tmpdir

        file1 = tmpdir/"handle1_1_writtenfile_123_nr_1"
        file2 = tmpdir/"handle1_1_writtenfile_124_nr_2"
        file3 = tmpdir/"handle2_3_writtenfile_125_nr_6"
        file4 = tmpdir/"handle1_1_writtenfile_126_nr_7"
        result_file = tmpdir/"handle1_1_writtenfilemerge_126_nr_7"

        file1.write_text("file1")
        file2.write_text("file2")
        file3.write_text("file3")
        expected_result = "file1file2file4"

        merger.start()
        time.sleep(2)

        file4.write_text("file4")

        merger.stop()

        assert result_file.exists()
        assert result_file.read_text() == expected_result

    def test_decorate_single_file_no_merge(self, merger, tmpdir):
        tmpdir = Path(tmpdir)
        merger._gemu_instance.analysis_folder.dumps_folder = tmpdir

        file1 = tmpdir/"handle1_1_writtenfile_123_nr_1"
        file2 = tmpdir/"handle1_2_writtenfile_125_nr_6"
        file3 = tmpdir/"handle2_1_writtenfile_125_nr_6"

        file1.write_text("file1")
        file2.write_text("file2")
        file3.write_text("file3")

        merger.start()
        merger.stop()

        for f in tmpdir.iterdir():
            assert "writtenfilemerge" not in f.name


