import argparse
from pathlib import Path

from gemuinteractor.config_parser import get_vm_settings, GEMU_PATH
from gemuinteractor.gemu_run_decorator import RunDecorator, YaraEarlyExiter, WrittenFileMerger, MouseMover
from gemuinteractor.gemu_runner_single_file import GemuRunner
from gemuinteractor.helpers import AnalysisFolder, GemuInstance
from gemuinteractor.recipe import Recipe
from postprocessing import (
    PostProcessingPipeline, DumpIndexer, SimilarityGrouper,
    ProcessTreeBuilder, YaraScanner, DumpExtractor,
)



def unpack_single_file(
    sample: Path,
    config: str,
    time: int,
    runname: str,
    export: str | None = None,
    yararules: Path | str | None = None,
    dotnet: str | None = None,
    trackingmode: str | None = None,
    recipe: Path | str | None = None,
    codecarver: bool = False,
    tracing: bool = False,
    postprocess: bool = True,
) -> AnalysisFolder:
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
        recipe=recipe_obj,
        codecarver=codecarver,
        tracing=tracing,
    )

    decorators: list[RunDecorator] = [
        WrittenFileMerger(sleep=2, gemu_instance=gemu_instance),
        MouseMover(sleep=0.05, gemu_instance=gemu_instance),
    ]
    if yararules:
        decorators.append(YaraEarlyExiter(sleep=0.1, yara_rules=yararules, gemu_instance=gemu_instance))
    runner.decorate_run(decorators)

    runner.run_sample()

    analysis_folder.zip_dumps_folder()
    if postprocess:
        _run_postprocessing(analysis_folder, yararules)
        DumpExtractor(analysis_folder).extract()
    return analysis_folder


def _run_postprocessing(analysis_folder: AnalysisFolder, yara_rules_path: Path|str|None) -> None:
    print("Running post-processing pipeline...")
    yara_path = Path(yara_rules_path) if yara_rules_path else None
    pipeline = PostProcessingPipeline([
        DumpIndexer(),
        SimilarityGrouper(),
        ProcessTreeBuilder(),
        YaraScanner(),
    ])
    manifest = pipeline.run(analysis_folder, yara_rules_path=yara_path)
    print(f"Post-processing complete. Indexed {manifest.get('dump_count', 0)} "
          f"dumps, {manifest.get('process_count', 0)} processes.")
    if manifest.get("errors"):
        for error in manifest["errors"]:
            print(f"Post-processing error: {error}")


def existing_path(path_str: str) -> Path:
    path = Path(path_str).expanduser().absolute()
    if not path.exists():
        raise FileNotFoundError()
    return path


def optional_existing_path(path_str: str) -> Path | None:
    if not path_str:
        return None
    return existing_path(path_str)


def cli_main() -> None:
    parser = argparse.ArgumentParser(description="GEMU malware analysis tool")

    parser.add_argument("--sample", help="The sample to be executed", required=True, type=existing_path)
    parser.add_argument("--time", help="Number of seconds to record execution", type=int, default=30)
    parser.add_argument("--config", help="VM configuration name", default="win10")
    parser.add_argument("--runname", help="Name of the analysis run", default="gemu")
    parser.add_argument("--export", help="PE file export to launch", default=None)
    parser.add_argument("--yararules", help="Path to compiled YARA rules for early exit", type=optional_existing_path,
                        default=None)
    parser.add_argument("--dotnet", help=".NET tracking mode", metavar="on|off|auto")
    parser.add_argument("--trackingmode", help="WinAPI tracking mode", metavar="syscall|basicblock|both")
    parser.add_argument("--recipe", help="Path to specific recipe file", type=optional_existing_path, default=None)
    parser.add_argument("--tracing", help="Activate BasicBlock tracing in GeMU", action="store_true")
    parser.add_argument("--codecarver", help="Activate the codecarving feature", action="store_true", default=False)
    parser.add_argument(
        "--postprocess",
        help="Run post-processing pipeline (default: True)",
        action=argparse.BooleanOptionalAction,
        default=True,
    )

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
        recipe=args.recipe,
        codecarver=args.codecarver,
        tracing=args.tracing,
        postprocess=args.postprocess,
    )


if __name__ == "__main__":
    cli_main()
