import shutil
import time
from collections import defaultdict
from pathlib import Path

from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile


class RunDecorator:
    def __init__(self, sleep: int, runner: GemuRunnerSingleFile):
        self.sleep = sleep
        self.runner = runner
        self._stop_decorator = False
        self.thread = None

    def run(self):
        while True:
            self._decorate()
            time.sleep(self.sleep)
            if self._stop_decorator:
                break
        self._decorate()

    def stop(self):
        self._stop_decorator = True

    # abstract...    
    def _decorate(self):
        pass

class YaraEarlyExiter(RunDecorator):
    def __init__(self, sleep, yara_rules, runner: GemuRunnerSingleFile):
        super().__init__(sleep, runner)
        self.yara_rules = yara_rules
        self.return_status = None
        self._init_scanner()

    def _init_scanner(self):
        import yara
        print("getting rules")
        self.rules = yara.load(self.yara_rules)
        self.checked_files = set()
        self.dump_folder = self.runner.analysis_folder.dumps_folder / "dumps"

    def _decorate(self):
        if not self.dump_folder.exists():
            return
        for i in self.dump_folder.iterdir():
            if i.as_posix() in self.checked_files:
                continue
            print(f"checking file {i.as_posix()}")
            matches = self.rules.match(i.as_posix())
            if not matches:
                self.checked_files.add(i.as_posix())
            else:
                print(f"Found {[match.rule for match in matches]} in {i}")
                print("Exiting early")
                self.return_status = f"match({[match.rule for match in matches]},{i})"
                self.runner.gemu_instance.kill(self.return_status)
                self.stop()
                return
    
class WrittenFileMerger(RunDecorator):
    def _decorate(self):
        dump_folder = self.runner.analysis_folder.dumps_folder
        if not dump_folder.exists():
            return

        dumps_by_handle = defaultdict(list)
        merge_by_handle = dict()
        for path in dump_folder.iterdir():
            if "_writtenfile_" in path.name:
                handle = path.name[:path.name.find("_writtenfile_")]
                number = int(path.name.split("_nr_")[-1])
                dumps_by_handle[handle].append((number, path))
            if "_writtenfilemerge_" in path.name:
                handle = path.name[:path.name.find("_writtenfilemerge_")]
                number = int(path.name.split("_nr_")[-1])
                merge_by_handle[handle] = number, path

        for handle, dumps in dumps_by_handle.items():
            dumps: list[tuple[int, Path]]
            if len(dumps) < 2:
                continue

            old_merge_file: Path
            old_merge_num, old_merge_file = merge_by_handle.get(handle, (-1, None))

            dumps.sort(key=lambda x: x[0])  # sort by number
            new_merge_num = dumps[-1][0]
            if old_merge_num >= new_merge_num:
                continue

            # Extract timestamp from the newest dump file name
            latest_dump = dumps[-1][1].name
            try:
                timestamp_part = latest_dump.split("_nr_")[0].split("_")[-1]
            except IndexError:
                # This shouldn't happen
                continue

            # Build the new merge filename
            new_merge_filename = f"{handle}_writtenfilemerge_{timestamp_part}_nr_{new_merge_num}"
            new_merge_file = dumps[0][1].parent / new_merge_filename

            if old_merge_file is not None:
                new_merge_file = old_merge_file.rename(new_merge_file)

            with open(new_merge_file, "ab") as file_out:
                for dump_number, dump_path in dumps:
                    if dump_number <= old_merge_num:
                        continue
                    with open(dump_path, "rb") as file_in:
                        shutil.copyfileobj(file_in, file_out)