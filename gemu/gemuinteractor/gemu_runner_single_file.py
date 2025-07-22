from collections import defaultdict
import datetime
import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path
import threading

from gemuinteractor.config_parser import GEMU_PATH, SAMPLE_NAME, VMConfig
from gemuinteractor.helpers import guest_type, build_iso_from_file


class GemuRunnerSingleFile:
    def __init__(self, sample, recording_time, runname, export, yararules, trackingmode, dotnet, vm_config:VMConfig):
        self.sample = sample
        self.runname = runname
        self.vm_config = vm_config
        self.export = export
        self.sample_is_64bit = "PE32+" in subprocess.check_output(["file", self.sample]).decode("utf-8")
        self.analysis_folder = self.build_analysis_folder()
        self.recording_time = recording_time
        self.log = dict()
        self.log_message({"vm": self.vm_config.image.as_posix()})
        self.process = None
        self.output_path = None
        self.trackingmode = trackingmode
        self.dotnet = dotnet
        self.rules = None
        self.sample_name = SAMPLE_NAME
        self.early_exiter = None
        self.stop_early_exiter = False
        self.return_status = "normal"
        if yararules:
            import yara
            self.rules = yara.load(yararules)

    def check_for_early_exit_yara_rules(self):
        checked_files = set()
        dump_folder = self.analysis_folder / "dumps"
        print("getting rules")
        while not self.stop_early_exiter:
            time.sleep(2)
            if not dump_folder.exists():
                continue
            self.merge_writtenfiles()
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
                    self.process.kill()
                    return

    # not thread safe
    def merge_writtenfiles(self):
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

    def run_sample(self):
        self.try_to_free_image()
        try:
            self.launch_gemu()
            self.mount_sample()
            self.launch_sample()
            print("launched sample")
            if self.rules:
                self.early_exiter = threading.Thread(target=self.check_for_early_exit_yara_rules)
                self.early_exiter.start()
            while True:
                try:
                    print(
                        f"{datetime.datetime.now()} sleeping for {self.recording_time}"
                    )
                    self.process.wait(self.recording_time)
                    print("sleep over.. shutting down")
                    break
                except BrokenPipeError:
                    continue
                except subprocess.TimeoutExpired:
                    print("timeout expired.. shutting down")
                    self.return_status = "timeout"
                    break
        finally:
            traceback.print_exc()
            if self.return_status == "normal" and self.process.returncode != 0:
                self.return_status = f"error({self.process.returncode})"
            if self.early_exiter:
                self.stop_early_exiter = True
                self.early_exiter.join()
            else:
                self.merge_writtenfiles()
            self.process.stdin.write(b"system_powerdown\n")
            self.process.stdin.write(b"quit\n")
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            self.process.kill()
            # Cleanup ISO directory
            if self.output_path.parent.exists():
                shutil.rmtree(self.output_path.parent)
            self.zip_dumps_folder()
            return self.return_status

    def zip_dumps_folder(self):
        dumps_folder = self.analysis_folder / "dumps"
        if dumps_folder.exists():
            subprocess.run(f"sync '{dumps_folder.as_posix()}'", shell=True)
            shutil.make_archive(dumps_folder.as_posix(), "zip", dumps_folder.as_posix())
            shutil.rmtree(dumps_folder, ignore_errors=True)

    def log_message(self, message):
        self.log.update(message)
        with open(self.analysis_folder / "log", "w") as f:
            f.write(json.dumps(self.log))

    def build_analysis_folder(self):
        if self.export:
            analysis_folder = Path(
                f"{self.sample}_EXPORT:{self.export}_{self.runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        else:
            analysis_folder = Path(
                f"{self.sample}_{self.runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        analysis_folder.mkdir(exist_ok=True)
        os.symlink(self.sample, f"{analysis_folder}/sample")
        return analysis_folder

    def launch_gemu(self):
        trackingmode = "-trackingmode " + self.trackingmode if self.trackingmode else ""
        dotnet = "-dotnet " + self.dotnet if self.dotnet else ""
        cmd = " ".join(
            [
                GEMU_PATH,
                "-m", self.vm_config.ram_size,
                "-monitor stdio",
                *self.vm_config.additional_parameters,
                "-loadvm", self.vm_config.snapshot,
                "-symbolmapping", self.vm_config.symbolmapping.as_posix(),
                "-apidoc", self.vm_config.apidoc.as_posix(),
                "-watchedprograms", self.sample_name,
                "-syscalltable", self.vm_config.syscalltable.as_posix(),
                trackingmode,
                dotnet,
                self.vm_config.image.as_posix(),
                f"> {self.analysis_folder}/runlog",
            ]
        )
        print("Executing command:", cmd)
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, shell=True, cwd=self.analysis_folder
        )
        time.sleep(5)

    def launch_sample_with_export(self):
        user = self.vm_config.user
        self.process.stdin.flush()
        if self.sample_is_64bit:
            guest_type(f" copy C:\\Windows\\system32\\rundll32.exe {user}Desktop\\{self.sample_name}\n",
                       self.process)
        else:
            guest_type(f" copy C:\\Windows\\SysWOW64\\rundll32.exe {user}Desktop\\{self.sample_name}\n",
                       self.process)
        time.sleep(1)
        guest_type(f" copy D:\\{self.sample_name} {user}Desktop\\ahsofidll.dll\n", self.process)
        self.process.stdin.write(b"gemurec\n")
        self.process.stdin.flush()
        print(f"starting PE with RUNDLL and {self.export}...")
        time.sleep(1)
        self.log_message({"starttimestamp": time.time()})
        guest_type(f"start {user}Desktop\\{self.sample_name} ahsofidll.dll,{self.export}\n", self.process)

    def mount_sample(self):
        self.output_path = Path(Path(self.sample).name.replace(" ", "") + ".iso")
        self.output_path = build_iso_from_file(
            Path(self.sample), sample_name=self.sample_name, iso_output_path=self.output_path
        )
        cmd = f"change ide1-cd0 {self.output_path}\n".encode(encoding="utf-8")
        print(cmd)
        self.process.stdin.write(cmd)
        self.process.stdin.flush()
        print("mounting")
        self.process.stdin.write(b"sendkey esc\n")
        return self.output_path

    def launch_sample(self):
        user = self.vm_config.user
        if self.export:
            self.launch_sample_with_export()
            return
        guest_type(
            f" copy D:\\{self.sample_name} {user}Desktop\\{self.sample_name}\n",
            self.process,
        )
        self.process.stdin.flush()
        time.sleep(1)
        self.process.stdin.write(b"gemurec\n")
        self.process.stdin.flush()
        print("starting...")
        guest_type(f"start {user}Desktop\\{self.sample_name}", self.process)
        guest_type("\n", self.process)

    def try_to_free_image(self):
        lock_found, qemu_pid = self.check_qcow_lock()
        while lock_found:
            self.kill_qemu_process(qemu_pid)
            print("checking lock again")
            lock_found, qemu_pid = self.check_qcow_lock()
        print("No QEMU process holding write lock on", self.vm_config.image, "found.")

    def check_qcow_lock(self):
        try:
            output = subprocess.check_output(["lsof", "-F", "npk", self.vm_config.image])
            print(output)
            lines = output.decode().split("\n")
            pid = None
            locked = False
            for line in lines:
                if line.startswith("p"):
                    pid = line[1:]
                elif line.startswith("k") and "1" in line[1:]:  # Check if locked
                    locked = True
            return locked, pid
        except subprocess.CalledProcessError:
            return False, None

    def kill_qemu_process(self, pid):
        try:
            subprocess.run(["kill", "-9", pid], check=True)
            print("QEMU process with PID", pid, "has been terminated. Sleeping for 5 seconds")
            time.sleep(5)
        except subprocess.CalledProcessError:
            print("Failed to terminate QEMU process with PID", pid)
