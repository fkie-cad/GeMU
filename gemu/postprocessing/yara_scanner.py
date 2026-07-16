import zipfile
from pathlib import Path

from .pipeline import PostProcessor, ProcessingContext


class YaraScanner(PostProcessor):
    def process(self, context: ProcessingContext) -> None:
        context.results["yara_matches"] = []

        if context.yara_rules_path is None:
            print("YARA scan skipped: no YARA rules provided")
            return

        rules = self._load_rules(context.yara_rules_path)

        if context.analysis_folder.dumps_zip.exists():
            context.results["yara_matches"] = self._scan_zip(rules, context.analysis_folder.dumps_zip)

        print(f"YARA scan complete: {len(context.results['yara_matches'])} matches found")

    def _scan_zip(self, rules, dumps_zip: Path) -> list[dict]:
        matches = []
        with zipfile.ZipFile(dumps_zip, "r") as zf:
            for info in sorted(zf.infolist(), key=lambda i: i.filename):
                data = zf.read(info.filename)
                file_matches = rules.match(data=data)
                for match in file_matches:
                    matches.append({
                        "rule_name": match.rule,
                        "filename": Path(info.filename).name,
                    })
                    print(f"YARA match: {match.rule} in {info.filename}")
        return matches

    def _load_rules(self, rules_path: Path):
        import yara
        return yara.load(filepath=str(rules_path))
