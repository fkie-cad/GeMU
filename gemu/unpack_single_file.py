import argparse
from pathlib import Path

from gemuinteractor.config_parser import get_vm_settings, GEMU_PATH
from gemuinteractor.gemu_run_decorator import RunDecorator, YaraEarlyExiter, WrittenFileMerger
from gemuinteractor.gemu_runner_single_file import GemuRunner
from gemuinteractor.helpers import AnalysisFolder, GemuInstance
from gemuinteractor.recipe import Recipe

def unpack_single_file(
    sample: Path,
    config: str,
    time: int,
    runname: str,
    export: str|None = None,
    yararules: Path|str|None = None,
    dotnet: str|None = None,
    trackingmode: str|None = None,
    recipe: Path|str|None = None
) -> AnalysisFolder:
    """Main execution function for GEMU analysis.
    
    Args:
        sample: Path to the sample to be executed
        config: VM configuration name
        time: Recording time in seconds
        runname: Name of the analysis run
        export: PE file export to launch
        yararules: Path to compiled YARA rules for early exit
        dotnet: .NET tracking mode (on|off|auto)
        trackingmode: WinAPI tracking mode (syscall|basicblock|both)
        recipe: Path to specific recipe file
    """
    vm_config = get_vm_settings(config)
    
    recipe_obj = Recipe(user=vm_config.user, input_binary=sample, export=export or "", recipe=recipe)
    analysis_folder = AnalysisFolder(runname, sample)
    gemu_instance = GemuInstance(vm_config.image, GEMU_PATH, analysis_folder)
    
    runner = GemuRunner(
        recording_time=time,
        trackingmode=trackingmode,
        dotnet=dotnet,
        vm_config=vm_config,
        gemu_instance=gemu_instance,
        recipe=recipe_obj
    )
    
    decorators: list[RunDecorator] = [WrittenFileMerger(sleep=2, gemu_instance=gemu_instance)]
    if yararules:
        decorators.append(YaraEarlyExiter(sleep=0.1, yara_rules=yararules, gemu_instance=gemu_instance))
    runner.decorate_run(decorators)

    runner.run_sample()
    analysis_folder.zip_dumps_folder()
    return analysis_folder

def existing_path(path_str: str) -> Path:
    path = Path(path_str).expanduser().absolute()
    if not path.exists():
        raise FileNotFoundError()
    return path

def optional_existing_path(path_str: str) -> Path|None:
    if not path_str:
        return None
    return existing_path(path_str)

def cli_main() -> None:
    """CLI entry point that handles argument parsing."""
    parser = argparse.ArgumentParser(description="GEMU malware analysis tool")
    
    parser.add_argument("--sample", help="The sample to be executed", required=True, type=existing_path)
    parser.add_argument("--time", help="Number of seconds to record execution", type=int, default=30)
    parser.add_argument("--config", help="VM configuration name", default="win10")
    parser.add_argument("--runname", help="Name of the analysis run", default="gemu")
    parser.add_argument("--export", help="PE file export to launch", default=None)
    parser.add_argument("--yararules", help="Path to compiled YARA rules for early exit", type=optional_existing_path, default=None)
    parser.add_argument("--dotnet", help=".NET tracking mode", metavar="on|off|auto")
    parser.add_argument("--trackingmode", help="WinAPI tracking mode", metavar="syscall|basicblock|both")
    parser.add_argument("--recipe", help="Path to specific recipe file", type=optional_existing_path, default=None)
    
    
    args = parser.parse_args()
    
    unpack_single_file(
        sample=args.sample,
        config=args.config,
        time=args.time,
        runname=args.runname,
        export=args.export,
        yararules=args.yararules,
        dotnet=args.dotnet,
        trackingmode=args.trackingmode,
        recipe=args.recipe
    )


if __name__ == "__main__":
    cli_main()