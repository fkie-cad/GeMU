import json
import zipfile
from collections import defaultdict

from gemuinteractor.helpers import AnalysisFolder

TYPE_WEIGHT = {
    "write_then_execute": 5,
    "codecarver": 4,
    "injection": 3,
    "file_write": 1,
    "file_write_merged": 1,
}


class DumpExtractor:
    def __init__(self, analysis_folder: AnalysisFolder):
        self.analysis_folder = analysis_folder
        self.manifest = json.loads(self.analysis_folder.dumps_json.read_text())
        self._dumps_to_extract = set()

    def _get_yara_matches(self):
        for match in self.manifest.get("yara_matches", []):
            self._dumps_to_extract.add(match["filename"])

    def _get_similarity_representatives(self):
        dumps_by_filename = {d["filename"]: d for d in self.manifest.get("dumps", [])}
        for group in self.manifest.get("similarity_groups", []):
            members = [dumps_by_filename[f] for f in group["files"] if f in dumps_by_filename]
            if members:
                self._dumps_to_extract -= set(group["files"])
                self._dumps_to_extract.add(max(members, key=lambda d: d["size_bytes"])["filename"])

    def _score(self, filename: str) -> int:
        dump = self._dumps_by_filename.get(filename, {})
        yara_count = len(self._yara_counts.get(filename, []))
        type_weight = TYPE_WEIGHT.get(dump.get("dump_type", ""), 0)
        return (yara_count * 10) + type_weight

    def _build_indexes(self):
        self._dumps_by_filename = {d["filename"]: d for d in self.manifest.get("dumps", [])}
        self._yara_counts = defaultdict(list)
        for match in self.manifest.get("yara_matches", []):
            self._yara_counts[match["filename"]].append(match["rule_name"])

    def extract(self):
        self._get_yara_matches()
        self._get_similarity_representatives()
        self._build_indexes()

        ranked = sorted(self._dumps_to_extract, key=self._score, reverse=True)

        with zipfile.ZipFile(self.analysis_folder.dumps_zip, "r") as zf_src:
            with zipfile.ZipFile(self.analysis_folder.analysis_folder / "essential_dumps.zip", "w", zipfile.ZIP_DEFLATED) as zf_out:
                for rank, filename in enumerate(ranked, 1):
                    data = zf_src.read(filename)
                    zf_out.writestr(f"{rank:03d}/{filename}", data)
