import argparse
import os
from pathlib import Path

from gemuinteractor.config_parser import get_vm_settings
from gemuinteractor.gemu_runner_with_recipe import GemuRunnerWithRecipe

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sampleyml",
        help="Provide the sample yml. An example can be found in the gemu/gemuinteractor folder",
        required=True
    )
    parser.add_argument(
        "--time",
        help="The number of seconds to record an execution",
        type=int,
        default=30,
    )
    parser.add_argument("--config", help="Give the config to the virtual machine", default="win10")
    parser.add_argument(
        "--runname", help="Name of the run", type=str, default="gemu"
    )
    parser.add_argument("--yararules", help="Give binary with compiles rules to exit early if the yara rules match",
                        type=str, default=None)
    parser.add_argument("--dotnet", help="dotnet tracking mode", metavar="on|off|auto", type=str)
    parser.add_argument("--trackingmode", help="WinAPI tracking mode", metavar= "syscall|basicblock|both", type=str)

    args = parser.parse_args()
    vm_config = get_vm_settings(args.config)
    runner = GemuRunnerWithRecipe(Path(os.path.abspath(args.sampleyml)), args.time, args.runname, args.yararules, args.trackingmode, args.dotnet, vm_config)
    runner.run_sample()
