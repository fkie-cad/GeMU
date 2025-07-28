import datetime
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path

from gemuinteractor.config_parser import VMConfig, SAMPLE_NAME, GEMU_PATH
from gemuinteractor.helpers import build_iso_from_file, GemuInstance


class GemuRunnerSingleFile:
    def __init__(self, sample: Path, recording_time, runname, export, yararules, trackingmode,
                 dotnet, vm_config:VMConfig, gemu_instance:GemuInstance, gemu_path: GEMU_PATH, sample_name: SAMPLE_NAME):
        self.sample = sample
        self.export = export
        self.gemu_path = gemu_path
        self.sample_name = sample_name
        self.analysis_folder = self._build_analysis_folder(runname)
        self.gemu_cmd = self._build_gemu_cmd(dotnet, trackingmode, vm_config)
        self.user = vm_config.user
        self.recording_time = recording_time
        self.gemu_instance = gemu_instance
        self.return_status = "normal"
        self.early_exiter = None
        self.stop_threads = False
        if yararules:
            self.early_exiter = threading.Thread(target=self._check_for_early_exit_yara_rules, args=(yararules,))
            self.early_exiter.start()

    def _check_for_early_exit_yara_rules(self, yararules):
        import yara
        self.rules = yara.load(yararules)
        checked_files = set()
        dump_folder = self.analysis_folder / "dumps"
        print("getting rules")
        while not self.stop_threads:
            time.sleep(2)
            if not dump_folder.exists():
                continue
            self._merge_writtenfiles()
            for i in dump_folder.iterdir():
                if i.as_posix() in checked_files:
                    continue
                print(f"checking file {i.as_posix()}")
                matches = self.rules.match(i.as_posix())
                if not matches:
                    checked_files.add(i.as_posix())
                else:
                    print(f"Found {[match.rule for match in matches]} in {i}")
                    print("Exiting early")
                    self.return_status = f"match({[match.rule for match in matches]},{i})"
                    self.gemu_instance._kill()
                    return

    def merger_manager(self):
        while not self.stop_merging:
            time.sleep(2)
            self._merge_writtenfiles()
        self._merge_writtenfiles()

    # not thread safe
    def _merge_writtenfiles(self):
        dump_folder = self.analysis_folder / "dumps"
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

    def _build_gemu_cmd(self, dotnet, trackingmode, vm_config):
        trackingmode = "-trackingmode " + trackingmode if trackingmode else ""
        dotnet = "-dotnet " + dotnet if dotnet else ""
        return " ".join(
            [
                self.gemu_path.as_posix(),
                "-m", vm_config.ram_size,
                "-monitor stdio",
                *vm_config.additional_parameters,
                "-loadvm", vm_config.snapshot,
                "-symbolmapping", vm_config.symbolmapping.as_posix(),
                "-apidoc", vm_config.apidoc.as_posix(),
                "-watchedprograms", self.sample_name,
                "-syscalltable", vm_config.syscalltable.as_posix(),
                trackingmode,
                dotnet,
                vm_config.image.as_posix(),
                f"> {self.analysis_folder}/runlog",
            ]
        )

    def _zip_dumps_folder(self):
        dumps_folder = self.analysis_folder / "dumps"
        if dumps_folder.exists():
            subprocess.run(f"sync '{dumps_folder.as_posix()}'", shell=True)
            shutil.make_archive(dumps_folder.as_posix(), "zip", dumps_folder.as_posix())
            shutil.rmtree(dumps_folder, ignore_errors=True)

    def _build_analysis_folder(self, runname):
        if self.export:
            analysis_folder = Path(
                f"{self.sample.as_posix()}_EXPORT:{self.export}_{runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        else:
            analysis_folder = Path(
                f"{self.sample.as_posix()}_{runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        return analysis_folder

    @contextmanager
    def _mount_sample(self):
        print("mounting sample...")
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                output_path = build_iso_from_file(self.sample,
                                                  sample_name=self.sample_name,
                                                  tmpdir=tmpdir)
                self.gemu_instance.write_to_qemu_console(f"change ide1-cd0 {output_path}\n".encode(encoding="utf-8"))
                self.gemu_instance.write_to_qemu_console(b"sendkey esc\n")
                yield
            finally:
                return

    def _launch_sample(self):
        self.analysis_folder.mkdir(exist_ok=True)
        os.symlink(self.sample, f"{self.analysis_folder}/sample")
        if self.export:
            self._launch_sample_with_export()
            return
        self.gemu_instance.type_into_guest(f" copy D:\\{self.sample_name} {self.user}Desktop\\{self.sample_name}\n")
        time.sleep(1)
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print("starting...")
        self.gemu_instance.type_into_guest(f"start {self.user}Desktop\\{self.sample_name}\n")
        print("launched sample")

    def _launch_sample_with_export(self):
        self.gemu_instance.stdin.flush()
        if "PE32+" in subprocess.check_output(["file", self.sample]).decode("utf-8"):
            self.gemu_instance.type_into_guest(f" copy C:\\Windows\\system32\\rundll32.exe {self.user}Desktop\\{self.sample_name}\n")
        else:
            self.gemu_instance.type_into_guest(f" copy C:\\Windows\\SysWOW64\\rundll32.exe {self.user}Desktop\\{self.sample_name}\n")
        time.sleep(1)
        self.gemu_instance.type_into_guest(f" copy D:\\{self.sample_name} {self.user}Desktop\\ahsofidll.dll\n")
        self.gemu_instance.write_to_qemu_console(b"gemurec\n")
        print(f"starting PE with RUNDLL and {self.export}...")
        time.sleep(1)
        self.gemu_instance.type_into_guest(f"start {self.user}Desktop\\{self.sample_name} ahsofidll.dll,{self.export}\n")

    def run_sample(self):
        with self.gemu_instance.launch_gemu(self.gemu_cmd, self.analysis_folder):
            print("launching gemu")
            with self._mount_sample():
                self._launch_sample()
                try:
                    print(
                        f"{datetime.datetime.now()} sleeping for {self.recording_time}"
                    )
                    self.gemu_instance.wait(timeout=self.recording_time)
                    print("sleep over.. shutting down")
                except BrokenPipeError:
                    self.return_status = "brokenpipeerror"
                    pass
                except subprocess.TimeoutExpired:
                    print("timeout expired.. shutting down")
                    self.return_status = "timeout"
        if self.return_status == "normal" and self.gemu_instance.get_return_code() != 0:
            self.return_status = f"error({self.gemu_instance.get_return_code()})"
        self.stop_threads = True
        for thread in self.threads:
            thread.join()
        self._zip_dumps_folder()
        return self.return_status
