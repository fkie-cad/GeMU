import subprocess
from dataclasses import dataclass, field
from pathlib import Path


def _grep(pattern: str, path: Path, regex: bool = False) -> list[str]:
    cmd = ["grep", "-E" if regex else "-F", pattern, str(path)]
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return r.stdout.splitlines() if r.returncode == 0 else []


def _extract_image_name(s: str) -> str:
    # Input:  'C:\\Windows\\System32\\cmd.exe /c whoami' or '"C:\\foo\\bar.exe"'
    # Output: 'cmd.exe' or 'bar.exe' (basename of the first token, quotes stripped)
    s = s.strip().strip('"').strip("'")
    if not s:
        return "unknown"
    return s.split()[0].replace("\\", "/").rsplit("/", 1)[-1]


@dataclass
class ParsedRunlog:
    unique_pids: set[int] = field(default_factory=set)
    process_creation_events: list[dict] = field(default_factory=list)
    injection_events: list[dict] = field(default_factory=list)
    dotnet_detected: bool = False

    @classmethod
    def from_file(cls, path: Path) -> "ParsedRunlog":
        result = cls()
        result.dotnet_detected = len(_grep("FOUND .NET", path)) > 0
        result.unique_pids = _extract_pids(path)
        result.injection_events = _extract_injections(path)
        result.process_creation_events = _extract_creations(path)
        return result


def _extract_pids(path: Path) -> set[int]:
    # Input lines:  '1234:0:$+{"func":"CreateFileW"}'  or  '5678:0:$-{"func":"NtReadFile"} -> 0'
    # Output:       {1234, 5678}  (set of all PIDs that appear before the first colon)
    pids = set()
    for line in _grep(":$", path):
        colon = line.find(":")
        if colon > 0:
            try:
                pids.add(int(line[:colon]))
            except ValueError:
                pass
    return pids


def _extract_injections(path: Path) -> list[dict]:
    # Input lines:  'found injection into PID 5678'
    #               'ZwMapViewOfSection injection into PID 9999'
    # Output:       [{"target_pid": 5678, "injection_type": "ZwWriteVirtualMemory"},
    #                {"target_pid": 9999, "injection_type": "ZwMapViewOfSection"}]
    events = []
    for line in _grep("injection into PID ", path):
        for prefix, inj_type in (("found injection into PID ", "ZwWriteVirtualMemory"),
                                  ("ZwMapViewOfSection injection into PID ", "ZwMapViewOfSection")):
            if line.strip().startswith(prefix):
                try:
                    events.append({"target_pid": int(line.strip()[len(prefix):]), "injection_type": inj_type})
                except ValueError:
                    pass
    return events


def _extract_creations(path: Path) -> list[dict]:
    # Parses three related line types to reconstruct process creation events:
    #
    # 1) 'PROCESS_CREATING parent=1234 command=C:\Windows\cmd.exe /c whoami'
    #    Stores the command for the parent PID (the child PID is not yet known).
    #
    # 2) 'PROCESS_CREATED parent=1234 child=5678 image=unknown'
    #    Creates the event, linking parent to child. Uses the command from step 1
    #    to extract the image name. Marks child as pending for step 3.
    #
    # 3) 'ADDING TO THE LOOKUPS, 5678, 5303697408, 5303697408, C:\Windows\cmd.exe'
    #    Backfills the image name if it was "unknown" after step 2.
    #
    # Output: [{"parent_pid": 1234, "child_pid": 5678, "image_name": "cmd.exe",
    #           "command": "C:\Windows\cmd.exe /c whoami", "creation_method": "CreateProcess"}]
    events = []
    creating_command: dict[int, str] = {}
    pending_image: dict[int, dict] = {}

    for line in _grep("PROCESS_CREAT|ADDING TO THE LOOKUPS, ", path, regex=True):
        line = line.strip()
        if line.startswith("(qemu) "):
            line = line[7:]

        if line.startswith("PROCESS_CREATING "):
            # command= is last field and may contain spaces
            cmd_pos = line.find(" command=")
            parent_pos = line.find("parent=")
            if cmd_pos != -1 and parent_pos != -1:
                try:
                    parent_str = line[parent_pos + 7:cmd_pos]
                    command = line[cmd_pos + 9:]
                    parent_pid = int(parent_str)
                    if command != "unknown" or parent_pid not in creating_command:
                        creating_command[parent_pid] = command
                except ValueError:
                    pass

        elif line.startswith("PROCESS_CREATED "):
            parts = dict(kv.split("=", 1) for kv in line.split() if "=" in kv)
            try:
                child_pid = int(parts["child"])
                parent_pid = int(parts["parent"])
                if child_pid in pending_image:
                    # Duplicate from fill_processinformation being called multiple times
                    continue
                command = creating_command.pop(parent_pid, "unknown")
                event = {
                    "parent_pid": parent_pid,
                    "child_pid": child_pid,
                    "image_name": _extract_image_name(command),
                    "command": command,
                    "creation_method": "CreateProcess",
                }
                events.append(event)
                pending_image[child_pid] = event
            except (KeyError, ValueError):
                pass

        elif line.startswith("ADDING TO THE LOOKUPS, "):
            parts = line[len("ADDING TO THE LOOKUPS, "):].split(", ", 3)
            if len(parts) >= 4:
                try:
                    child_pid = int(parts[0])
                    if child_pid in pending_image and pending_image[child_pid]["image_name"] == "unknown":
                        pending_image[child_pid]["image_name"] = _extract_image_name(parts[3])
                    if child_pid in pending_image:
                        del pending_image[child_pid]
                except ValueError:
                    pass

    return events
