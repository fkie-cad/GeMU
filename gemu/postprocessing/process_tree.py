from .pipeline import PostProcessor, ProcessingContext

class ProcessTreeBuilder(PostProcessor):

    def process(self, context: ProcessingContext) -> None:
        if not context.analysis_folder.runlog.exists():
            context.results["process_tree"] = []
            context.results["process_count"] = 0
            context.results["injections"] = []
            context.results["dotnet_detected"] = False
            return

        parsed = context.get_parsed_runlog()

        all_pids = parsed.unique_pids
        parent_map: dict[int, int] = {}
        image_names: dict[int, str] = {}
        creation_methods: dict[int, str] = {}
        commands: dict[int, str] = {}
        children_map: dict[int, list[int]] = {pid: [] for pid in all_pids}

        for event in parsed.process_creation_events:
            parent_pid = event["parent_pid"]
            child_pid = event["child_pid"]
            parent_map[child_pid] = parent_pid
            image_names[child_pid] = event["image_name"]
            if event.get("creation_method"):
                creation_methods[child_pid] = event["creation_method"]
            if event.get("command"):
                commands[child_pid] = event["command"]
            if parent_pid in children_map:
                children_map[parent_pid].append(child_pid)

        roots = [
            pid for pid in all_pids
            if pid not in parent_map or parent_map[pid] not in all_pids
        ]

        # Determine root image name from sample symlink if possible
        sample_link = context.analysis_folder.analysis_folder / "sample"
        sample_name = None
        if sample_link.exists() and sample_link.is_symlink():
            sample_name = sample_link.resolve().name

        def build_tree(pid: int) -> dict:
            result = {
                "pid": pid,
                "image_name": image_names.get(pid, sample_name or "unknown") if pid in roots else image_names.get(pid, "unknown"),
                "parent_pid": parent_map.get(pid),
                "children": [build_tree(child) for child in children_map.get(pid, [])],
            }
            if pid in creation_methods:
                result["creation_method"] = creation_methods[pid]
            if pid in commands:
                result["command"] = commands[pid]
            return result

        process_tree = [build_tree(pid) for pid in roots]

        context.results["process_tree"] = process_tree
        context.results["process_count"] = len(all_pids)
        context.results["injections"] = parsed.injection_events
        context.results["dotnet_detected"] = parsed.dotnet_detected
