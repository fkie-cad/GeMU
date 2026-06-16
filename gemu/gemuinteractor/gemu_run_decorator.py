import math
import random
import shutil
import subprocess
import threading
import time
from collections import defaultdict
from pathlib import Path

from gemuinteractor.helpers import GemuInstance


class RunDecorator:
    def __init__(self, sleep: int|float, gemu_instance: GemuInstance):
        self._sleep = sleep
        self._gemu_instance = gemu_instance
        self._stop_decorator = False
        self._thread = None
        self.return_code: str = ""

    def _run(self):
        try:
            while True:
                self._decorate()
                time.sleep(self._sleep)
                if self._stop_decorator:
                    break
            self._decorate()
        except BrokenPipeError:
            # QEMU monitor socket was closed underneath us during shutdown
            # (kill() races with this thread). Stop decorating.
            print(f"{type(self).__name__}: monitor socket closed during shutdown, stopping decorator")
            self._stop_decorator = True

    def stop(self):
        self._stop_decorator = True
        self._thread.join()

    def start(self):
        self._thread = threading.Thread(target=self._run)
        self._thread.start()

    def _decorate(self):
        raise NotImplementedError

class YaraEarlyExiter(RunDecorator):
    def __init__(self, sleep: int|float, yara_rules: Path|str, gemu_instance: GemuInstance):
        super().__init__(sleep, gemu_instance)
        self._init_scanner(str(yara_rules))

    def _init_scanner(self, yara_rules: str):
        import yara
        print("getting rules")
        self.rules = yara.load(yara_rules)
        self.checked_files: set[Path] = set()
        self.dump_folder: Path = self._gemu_instance.analysis_folder.dumps_folder
        self._yara_error = yara.Error

    def _decorate(self):
        if not self.dump_folder.exists():
            return
        for dump in self.dump_folder.iterdir():
            if dump in self.checked_files:
                continue
            print(f"checking file {dump}")
            try:
                try:
                    subprocess.check_output(f"sync '{str(dump)}'", shell=True)
                except subprocess.CalledProcessError:
                    continue
                matches = self.rules.match(str(dump))
                self.checked_files.add(dump)
                if matches:
                    print(f"Found {[match.rule for match in matches]} in {dump}")
                    print("Exiting early")
                    self.return_code = f"match({[match.rule for match in matches]},{dump})"
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


class MouseMover(RunDecorator):
    """Moves mouse in a figure-eight and opens Task Manager after a delay.

    Anti-evasion technique: malware often checks for human-like activity.
    """

    def __init__(self, sleep: float, gemu_instance: GemuInstance, taskmgr_delay: float = 10.0):
        super().__init__(sleep, gemu_instance)
        self._t = 0.0
        self._sent_x = 0
        self._sent_y = 0
        self._randomize_loop() # select initial loop parameters from same distribution
        self._taskmgr_delay = taskmgr_delay
        self._taskmgr_sent = False
        self._elapsed = 0.0

    def _randomize_loop(self):
        """Pick new random parameters for the next figure-eight loop."""
        self._amplitude_x = random.uniform(150, 250)
        self._amplitude_y = random.uniform(100, 200)
        self._speed = random.uniform(0.08, 0.12)

    def _decorate(self):
        if self._gemu_instance._monitor_sock is None:
            return

        # Randomize shape each full loop (t crosses a 2*pi boundary)
        old_loop = int(self._t / (2 * math.pi))
        self._t += self._speed
        new_loop = int(self._t / (2 * math.pi))
        if new_loop > old_loop:
            self._randomize_loop()

        # Figure-eight (lemniscate): x = Ax*sin(t), y = Ay*sin(t)*cos(t)
        target_x = int(self._amplitude_x * math.sin(self._t))
        target_y = int(self._amplitude_y * math.sin(self._t) * math.cos(self._t))
        dx = target_x - self._sent_x
        dy = target_y - self._sent_y
        self._sent_x = target_x
        self._sent_y = target_y

        if dx != 0 or dy != 0:
            self._gemu_instance.write_to_qemu_console(f"mouse_move {dx} {dy}\n".encode())

        self._elapsed += self._sleep
        if not self._taskmgr_sent and self._elapsed >= self._taskmgr_delay:
            self._gemu_instance.write_to_qemu_console(b"sendkey ctrl-shift-esc\n")
            self._taskmgr_sent = True
