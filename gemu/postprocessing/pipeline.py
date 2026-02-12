import json
import traceback
from pathlib import Path

from gemuinteractor.helpers import AnalysisFolder
from .runlog_parser import ParsedRunlog


class ProcessingContext:
    def __init__(self, analysis_folder: AnalysisFolder, yara_rules_path: Path | None = None):
        self.analysis_folder = analysis_folder
        self.yara_rules_path = yara_rules_path
        self.results = {}
        self.errors = []
        self._parsed_runlog: ParsedRunlog | None = None

    def get_parsed_runlog(self) -> ParsedRunlog:
        if self._parsed_runlog is None:
            print(f"Parsing runlog: {self.analysis_folder.runlog}")
            self._parsed_runlog = ParsedRunlog.from_file(self.analysis_folder.runlog)
            print(f"Parsed runlog: {len(self._parsed_runlog.unique_pids)} PIDs")
        return self._parsed_runlog


class PostProcessor:
    def process(self, context: ProcessingContext) -> None:
        raise NotImplementedError


class PostProcessingPipeline:
    def __init__(self, processors: list[PostProcessor] | None = None):
        self.processors = processors or []

    def run(self, analysis_folder: AnalysisFolder, yara_rules_path: Path | None = None) -> dict:
        context = ProcessingContext(analysis_folder, yara_rules_path)

        context.results = {
            "analysis_folder": str(context.analysis_folder.analysis_folder),
            "processors_run": [],
            "errors": []
        }

        for processor in self.processors:
            processor_name = processor.__class__.__name__
            print(f"Running processor: {processor_name}")
            try:
                processor.process(context)
                context.results["processors_run"].append(processor_name)
            except Exception as e:
                context.results["errors"].append((f"Processor {processor_name} failed: {traceback.format_exc()}"
                                       f"Continue with next processor..."))

        with open(context.analysis_folder.analysis_folder / "dumps.json", "w") as f:
            json.dump(context.results, f, indent=2)

        return context.results
