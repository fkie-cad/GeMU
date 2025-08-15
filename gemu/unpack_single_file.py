import argparse
import os
from pathlib import Path

from gemuinteractor.config_parser import get_vm_settings, GEMU_PATH
from gemuinteractor.gemu_run_decorator import RunDecorator, YaraEarlyExiter, WrittenFileMerger
from gemuinteractor.gemu_runner_single_file import GemuRunner
from gemuinteractor.helpers import AnalysisFolder, GemuInstance
from gemuinteractor.recipe import Recipe

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sample",
        help="The sample to executed",
        required=True
    )
    parser.add_argument(
        "--time",
        help="The number of seconds to record an execution",
        type=int,
        default=30,
    )
    parser.add_argument("--config", help="Give the config to the virtual machine", default="win10")
    parser.add_argument("--runname", help="Name of the run", type=str, default="gemu")
    parser.add_argument("--export", help="Give the export of the PE file that shall be launched", type=str, default=None)
    parser.add_argument("--yararules", help="Give binary with compiles rules to exit early if the yara rules match", type=str, default=None)
    parser.add_argument("--dotnet", help="dotnet tracking mode", metavar="on|off|auto", type=str)
    parser.add_argument("--trackingmode", help="WinAPI tracking mode", metavar= "syscall|basicblock|both", type=str)
    args = parser.parse_args()
    vm_config = get_vm_settings(args.config)
    sample_path = Path(os.path.abspath(args.sample))
    recipe = Recipe(vm_config.user, sample_path.as_posix(), args.export or "")
    analysis_folder = AnalysisFolder(args.runname, sample_path)
    gemu_instance = GemuInstance(vm_config.image, GEMU_PATH, analysis_folder)
    runner = GemuRunner(recording_time=args.time, trackingmode=args.trackingmode,
                        dotnet=args.dotnet, vm_config=vm_config, gemu_instance=gemu_instance, recipe=recipe)
    decorators: list[RunDecorator] = [WrittenFileMerger(sleep=2, gemu_instance=gemu_instance)]
    if args.yararules:
        decorators.append(YaraEarlyExiter(sleep=0.1, yara_rules=args.yararules, gemu_instance=gemu_instance))
    runner.decorate_run(decorators)
    runner.run_sample()
    analysis_folder.zip_dumps_folder()
