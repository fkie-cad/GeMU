import zipfile
from collections import defaultdict

from .pipeline import PostProcessor, ProcessingContext

MIN_TLSH_SIZE = 50
# In TLSH two hashes with a low similiarity score are more similar than those with a high similarity score
MAXIMUM_SIMILARITY_THRESHOLD = 100


def compute_tlsh_hash(data: bytes) -> str | None:
    #  hash returns a string. if hash could not be calculated, it is empty
    import tlsh
    if len(data) < MIN_TLSH_SIZE:
        return None
    h = tlsh.hash(data)
    return h if h else None


class SimilarityGrouper(PostProcessor):
    name = "similarity_grouper"

    def __init__(self, threshold: int = MAXIMUM_SIMILARITY_THRESHOLD):
        self.threshold = threshold

    def process(self, context: ProcessingContext) -> None:
        import tlsh
        dumps = context.results.get("dumps", [])

        if not dumps:
            context.results["similarity_groups"] = []
            context.results["tlsh_hashes"] = {}
            return

        tlsh_hashes: dict[str, str] = {}
        with zipfile.ZipFile(context.analysis_folder.dumps_zip, "r") as zf:
            for dump in dumps:
                filename = dump["filename"]
                data = zf.read(filename)
                h = compute_tlsh_hash(data)
                if h:
                    tlsh_hashes[filename] = h

        similar_pairs: list[tuple[str, str, int]] = []
        filenames = list(tlsh_hashes.keys())

        for i, file1 in enumerate(filenames):
            for file2 in filenames[i + 1:]:
                if tlsh_hashes[file1] == "TNULL" or tlsh_hashes[file2] == "TNULL":
                    distance = 99999
                else:
                    distance = tlsh.diff(tlsh_hashes[file1], tlsh_hashes[file2])
                if distance <= self.threshold:
                    similar_pairs.append((file1, file2, distance))

        groups = self._find_connected_components(similar_pairs)

        similarity_groups = []
        for group_id, (members, min_distance, max_distance) in enumerate(groups):
            if len(members) > 1:
                similarity_groups.append({
                    "group_id": group_id,
                    "files": sorted(members),
                    "count": len(members),
                    "min_distance": min_distance,
                    "max_distance": max_distance,
                })

        similarity_groups.sort(key=lambda g: g["count"], reverse=True)

        context.results["similarity_groups"] = similarity_groups
        context.results["tlsh_hashes"] = tlsh_hashes
        context.results["similarity_threshold"] = self.threshold

        total_grouped = sum(g["count"] for g in similarity_groups)
        print(f"Found {len(similarity_groups)} similarity groups containing {total_grouped} dumps")

    def _find_connected_components(self, pairs: list) -> list:
        # consider "pairs", i.e. dumps with distance below threshold as connected in a graph
        # build neighbor's lists for easy traversal of graph structure
        # GOAL: Find connected components
        neighbors = defaultdict(list)
        for file1, file2, distance in pairs:
            neighbors[file1].append((file2, distance))
            neighbors[file2].append((file1, distance))

        visited = set()
        result = []
        for start in neighbors:
            if start in visited:
                continue
            group = set()
            group_dists = []
            queue = [start]
            while queue:
                node = queue.pop()
                if node in visited:
                    continue
                visited.add(node)
                group.add(node)
                for neighbor, dist in neighbors[node]:
                    if neighbor not in visited:
                        queue.append(neighbor)
                        group_dists.append(dist)

            result.append((group, min(group_dists), max(group_dists)))

        return result

