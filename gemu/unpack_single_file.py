import argparse
import os
from pathlib import Path

from gemuinteractor.config_parser import get_vm_settings
from gemuinteractor.gemu_run_decorator import YaraEarlyExiter, WrittenFileMerger
from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile
from gemuinteractor.helpers import GemuInstance

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
    runner = GemuRunnerSingleFile(Path(os.path.abspath(args.sample)), args.time, args.runname, args.export, args.trackingmode,
                                  args.dotnet, vm_config, GemuInstance(vm_config.image))
    decorators = [WrittenFileMerger(sleep=2, runner=runner)]
    if args.yararules:
        decorators.append(YaraEarlyExiter(sleep=0.1, yara_rules=args.yararules, runner=runner))
    runner.decorate_run(decorators)
    runner.run_sample()
