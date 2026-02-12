import hashlib
import re
import zipfile
from collections import defaultdict
from pathlib import Path

from .pipeline import PostProcessor, ProcessingContext

# {PID}_0x{address}_{module_name}_{timestamp_ms}_dump_nr_{counter}
UNPACKING_DUMP_PATTERN = re.compile(
    r"^(\d+)_0x([0-9a-fA-F]+)_(.+?)_(\d+)_dump_nr_(\d+)$"
)

# {PID}_{target_pid}_zwwritevirtualmemory_0x{address}_{timestamp_ms}_dump_nr_{counter}
INJECTION_DUMP_PATTERN = re.compile(
    r"^(\d+)_(\d+)_zwwritevirtualmemory_0x([0-9a-fA-F]+)_(\d+)_dump_nr_(\d+)$"
)

# {PID}_{filehandle}_writtenfile_{timestamp_ms}_nr_{counter}
WRITEFILE_DUMP_PATTERN = re.compile(
    r"^(\d+)_(\d+)_writtenfile_(\d+)_nr_(\d+)$"
)

# {PID}_{filehandle}_writtenfilemerge_{timestamp_ms}_nr_{counter}
WRITEFILE_MERGE_PATTERN = re.compile(
    r"^(\d+)_(\d+)_writtenfilemerge_(\d+)_nr_(\d+)$"
)


def parse_dump_filename(filename: str) -> dict | None:
    match = UNPACKING_DUMP_PATTERN.match(filename)
    if match:
        module_name = match.group(3)
        if module_name == "code":
            dump_type = "codecarver"
        else:
            dump_type = "write_then_execute"
        return {
            "pid": int(match.group(1)),
            "address": int(match.group(2), 16),
            "module_name": module_name if module_name not in ("mw", "code") else None,
            "timestamp_ms": int(match.group(4)),
            "dump_nr": int(match.group(5)),
            "dump_type": dump_type,
        }

    match = INJECTION_DUMP_PATTERN.match(filename)
    if match:
        return {
            "pid": int(match.group(1)),
            "target_pid": int(match.group(2)),
            "address": int(match.group(3), 16),
            "timestamp_ms": int(match.group(4)),
            "dump_nr": int(match.group(5)),
            "dump_type": "injection",
        }

    match = WRITEFILE_DUMP_PATTERN.match(filename)
    if match:
        return {
            "pid": int(match.group(1)),
            "file_handle": int(match.group(2)),
            "address": 0,
            "timestamp_ms": int(match.group(3)),
            "dump_nr": int(match.group(4)),
            "dump_type": "file_write",
        }

    match = WRITEFILE_MERGE_PATTERN.match(filename)
    if match:
        return {
            "pid": int(match.group(1)),
            "file_handle": int(match.group(2)),
            "address": 0,
            "timestamp_ms": int(match.group(3)),
            "dump_nr": int(match.group(4)),
            "dump_type": "file_write_merged",
        }

    return None


class DumpIndexer(PostProcessor):

    def process(self, context: ProcessingContext) -> None:
        dumps: list[dict] = []
        stats = defaultdict(int)

        self._index_from_zip(context.analysis_folder.dumps_zip, dumps, stats)

        dumps.sort(key=lambda d: (d["timestamp_ms"], d["dump_nr"]))
        context.results["dumps"] = dumps
        context.results["dump_count"] = len(dumps)
        context.results["dump_stats"] = stats

    def _index_from_zip(self, dumps_zip: Path, dumps: list[dict], stats: dict) -> None:
        with zipfile.ZipFile(dumps_zip, "r") as zf:
            entries = sorted(zf.infolist(), key=lambda i: i.filename)
            for entry in entries:
                filename = Path(entry.filename).name
                parsed = parse_dump_filename(filename)
                if not parsed:
                    stats["unknown"] += 1
                    continue
                sha256hash = hashlib.sha256(zf.read(entry)).hexdigest()
                dumps.append({
                    "filename": filename,
                    "pid": parsed["pid"],
                    "address": parsed["address"],
                    "timestamp_ms": parsed["timestamp_ms"],
                    "dump_nr": parsed["dump_nr"],
                    "size_bytes": entry.file_size,
                    "sha256": sha256hash,
                    "dump_type": parsed["dump_type"],
                    "module_name": parsed.get("module_name"),
                    "target_pid": parsed.get("target_pid"),
                    "file_handle": parsed.get("file_handle")
                })
                stats[parsed["dump_type"]] += 1
