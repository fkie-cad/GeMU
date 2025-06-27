import argparse
import os

from gemuinteractor.config_parser import get_vm_settings
from gemuinteractor.gemu_runner_single_file import GemuRunnerSingleFile

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
    runner = GemuRunnerSingleFile(os.path.abspath(args.sample), args.time, args.runname, args.export, args.yararules, args.trackingmode, args.dotnet, vm_config)
    runner.run_sample()
