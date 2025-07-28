import os
import shutil
from pathlib import Path
import datetime
import yaml
import time

from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile
from gemuinteractor.helpers import build_iso_from_file, guest_type

from gemuinteractor.config_parser import VMConfig, SAMPLE_NAME


class GemuRunnerWithRecipe(GemuRunnerSingleFile):
    def __init__(self, sampleyaml: Path, recording_time, runname, yararules, trackingmode, dotnet, vm_config: VMConfig):
        self.vm_config = vm_config
        self.sampleyamlfile = sampleyaml
        self.sampleyaml = yaml.safe_load(sampleyaml.read_text())
        print(self.sampleyaml)
        self.recording_time = recording_time
        self.runname = runname
        self.analysis_folder = self._build_analysis_folder()
        self.trackingmode = trackingmode
        self.dotnet = dotnet
        self.rules = None
        self.sample_name = SAMPLE_NAME
        self.early_exiter = None
        self.stop_early_exiter = False
        if "overwriteinitprocess" in self.sampleyaml:
            self.sample_name = self.sampleyaml["overwriteinitprocess"]
        self.replacings = {("$USER", self.vm_config.user), ("$SAMPLE_NAME", self.sample_name)}
        if yararules:
            import yara
            self.rules = yara.load(yararules)

    def replace_constants(self, instring):
        for replacing in self.replacings:
            instring = instring.replace(replacing[0], replacing[1])
        return instring

    def _build_analysis_folder(self):
        analysis_folder = Path(f"{self.sampleyamlfile}_{self.runname}_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}")
        analysis_folder.mkdir(exist_ok=True)
        return analysis_folder

    def _mount_sample(self):
        time.sleep(5)
        output_paths = set()
        for sample in self.sampleyaml["samples"]:
            host_sample = self.sampleyamlfile.parent / sample.split(":")[0]
            guest_sample = self.replace_constants(sample.split(":")[1])
            guest_sample_name = guest_sample.split("\\")[-1]
            output_path = Path(Path(host_sample).absolute().name.replace(" ", "") + ".iso")
            output_path = build_iso_from_file(
                Path(host_sample).absolute(), sample_name=guest_sample_name, iso_output_path=output_path
            )
            output_paths.add(output_path)
            cmd = f"change ide1-cd0 {output_path}\n".encode(encoding="utf-8")
            print(cmd)
            self.gemu_instance.stdin.write(cmd)
            self.gemu_instance.stdin.flush()
            print("mounting")
            time.sleep(2)
            self.gemu_instance.stdin.write(b"sendkey esc\n")
            guest_type(
                f"   copy D:\\{guest_sample_name} {guest_sample}\n",
                self.gemu_instance,
            )
            time.sleep(2)
        time.sleep(5)
        for p in output_paths:
            shutil.rmtree(p.parent)

    def _launch_sample(self):
        time.sleep(5)
        self.gemu_instance.stdin.write(b"gemurec\n")
        self.gemu_instance.stdin.flush()
        print("starting...")
        self.gemu_instance.stdin.write(b"sendkey esc\n")
        self.gemu_instance.stdin.flush()
        for command in self.sampleyaml["cmds"]:
            normalized_cmd = self.replace_constants(command)
            guest_type(normalized_cmd + "\n", self.gemu_instance)
