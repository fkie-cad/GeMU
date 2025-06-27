import argparse
import os
from pathlib import Path

from gemuinteractor.gemu_runner_multiple_files import GemuRunnerMultipleFiles

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--samples",
        help="Provide a list of samples or list of folders containing samples or a folder containing samples",
        required=True
    )
    parser.add_argument(
        "--time",
        help="The number of seconds to record an execution",
        type=int,
        default=30,
    )
    parser.add_argument("--runname", help="Name of the run", type=str, default="gemu")
    parser.add_argument("--yararules", help="Give binary with compiles rules to exit early if the yara rules match", type=str, default=None)
    parser.add_argument("--dotnet", help="dotnet tracking mode", metavar="on|off|auto", type=str)
    parser.add_argument("--trackingmode", help="WinAPI tracking mode", metavar= "syscall|basicblock|both", type=str, default="syscall")
    parser.add_argument("--allowduplicateruns", help="Shall samples that have been run be skipped", default=False, action="store_true")
    parser.add_argument("--configs", help="Name of config list in the config.py", default="win10_pool")
    parser.add_argument("--malpediamode", help="This mode is ensures that no dumps or unpackeds in malpedia are ran", default=False, action="store_true")

    args = parser.parse_args()
    runner = GemuRunnerMultipleFiles(Path(os.path.abspath(args.samples)), args.time, args.runname, args.yararules,
                                     args.trackingmode, args.dotnet, args.allowduplicateruns,
                                     args.configs, args.malpediamode)
    runner.run()
