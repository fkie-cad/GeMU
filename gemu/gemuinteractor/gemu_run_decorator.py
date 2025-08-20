import shutil
import threading
import time
from collections import defaultdict
from pathlib import Path

from gemuinteractor.helpers import GemuInstance


class RunDecorator:
    def __init__(self, sleep: int, gemu_instance: GemuInstance):
        self._sleep = sleep
        self._gemu_instance = gemu_instance
        self._stop_decorator = False
        self._thread = None
        self.return_code = ""

    def _run(self):
        while True:
            self._decorate()
            time.sleep(self._sleep)
            if self._stop_decorator:
                break
        self._decorate()

    def stop(self):
        self._stop_decorator = True

    def join(self):
        self._thread.join()

    def start(self):
        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _decorate(self):
        raise NotImplementedError

class YaraEarlyExiter(RunDecorator):
    def __init__(self, sleep, yara_rules, gemu_instance: GemuInstance):
        super().__init__(sleep, gemu_instance)
        self.yara_rules = yara_rules
        self._init_scanner()

    def _init_scanner(self):
        import yara
        print("getting rules")
        self.rules = yara.load(self.yara_rules)
        self.checked_files = set()
        self.dump_folder = self._gemu_instance.analysis_folder.dumps_folder
        self._yara_error = yara.Error

    def _decorate(self):
        if not self.dump_folder.exists():
            return
        for i in self.dump_folder.iterdir():
            if i.as_posix() in self.checked_files:
                continue
            print(f"checking file {i.as_posix()}")
            try:
                matches = self.rules.match(i.as_posix())
                self.checked_files.add(i.as_posix())
                if matches:
                    print(f"Found {[match.rule for match in matches]} in {i}")
                    print("Exiting early")
                    self.return_code = f"match({[match.rule for match in matches]},{i})"
                    self._gemu_instance.kill()
                    return
            except self._yara_error: #File might not be readable (because of WrittenFileMerger)
                continue
    
class WrittenFileMerger(RunDecorator):
    def _decorate(self):
        dump_folder = self._gemu_instance.analysis_folder.dumps_folder
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
