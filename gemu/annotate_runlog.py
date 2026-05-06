#!/usr/bin/env python3
"""Annotate a GeMU runlog with function names from a symbol mapping file.

For each basic block entry (B:PID:TID:0xADDR,SIZE), resolves the address
to a module + function using the memory maps printed in the runlog and
the symbol offset table.

Usage:
    python annotate_runlog.py <runlog> <symbolmapping> [-o output]
"""

import sys
import re
import argparse
from bisect import bisect_right
from pathlib import PureWindowsPath


def parse_symbol_mapping(path: str) -> dict[str, list[tuple[int, str]]]:
    """Parse symbol mapping file into {dll_filename_lower: sorted [(offset, func_name), ...]}."""
    symbols: dict[str, list[tuple[int, str]]] = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(";")
            if len(parts) < 3:
                continue
            dll_path, func_name, offset_str = parts[0], parts[1], parts[2]
            try:
                offset = int(offset_str)
            except ValueError:
                continue
            dll_name = PureWindowsPath(dll_path).name.lower()
            symbols.setdefault(dll_name, []).append((offset, func_name))

    for dll_name in symbols:
        symbols[dll_name].sort(key=lambda x: x[0])
    return symbols


def build_offset_index(funcs: list[tuple[int, str]]) -> list[int]:
    """Pre-build offset list for binary search."""
    return [f[0] for f in funcs]


def resolve_function(funcs: list[tuple[int, str]], offsets: list[int], offset: int) -> tuple[str, int] | None:
    """Find the function at or before the given offset. Returns (name, func_base_offset)."""
    idx = bisect_right(offsets, offset) - 1
    if idx < 0:
        return None
    return funcs[idx][1], funcs[idx][0]


def main():
    parser = argparse.ArgumentParser(description="Annotate runlog with function names")
    parser.add_argument("runlog", help="Path to the runlog file")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    args = parser.parse_args()

    symbols = parse_symbol_mapping("symbolmapping")
    # pre-build offset indexes
    offset_indexes: dict[str, list[int]] = {
        dll: build_offset_index(funcs) for dll, funcs in symbols.items()
    }

    # module map per PID: {pid: [(base, end, dll_filename_lower), ...]}
    module_maps: dict[str, list[tuple[int, int, str]]] = {}

    bb_re = re.compile(r"^B:(\d+):(\d+):0x([0-9a-fA-F]+),(\d+)$")
    base_re = re.compile(r"^Base: 0x([0-9a-fA-F]+), Size: 0x([0-9a-fA-F]+), File: (.*)$")

    out = open(args.runlog + "_annotated", "w")

    last_pid = None
    module_section_pid = None
    in_module_section = False
    pending_modules: list[tuple[int, int, str]] = []

    with open(args.runlog) as f:
        for line in f:
            line = line.rstrip("\n")

            # check for BB line
            m = bb_re.match(line)
            if m:
                pid = m.group(1)
                addr = int(m.group(3), 16)
                last_pid = pid

                # flush any pending module section
                if in_module_section and pending_modules and module_section_pid:
                    module_maps[module_section_pid] = pending_modules
                    pending_modules = []
                    in_module_section = False
                    module_section_pid = None

                # resolve address to module + function
                annotation = ""
                mods = module_maps.get(pid)
                if mods:
                    for base, end, dll_name in mods:
                        if base <= addr < end:
                            offset = addr - base
                            funcs = symbols.get(dll_name)
                            offsets = offset_indexes.get(dll_name)
                            if funcs and offsets:
                                result = resolve_function(funcs, offsets, offset)
                                if result:
                                    func_name, func_offset = result
                                    delta = offset - func_offset
                                    annotation = f"  # {dll_name}!{func_name}+0x{delta:x}"
                            if not annotation:
                                annotation = f"  # {dll_name}+0x{offset:x}"
                            break

                out.write(line + annotation + "\n")
                continue

            # check for module section start
            module_match = re.match(r"^printing modules that have been saved(?: for pid (\d+))?$", line)
            if module_match:
                in_module_section = True
                module_section_pid = module_match.group(1) or last_pid
                pending_modules = []
                out.write(line + "\n")
                continue

            # check for Base line inside module section
            if in_module_section:
                bm = base_re.match(line)
                if bm:
                    base = int(bm.group(1), 16)
                    size = int(bm.group(2), 16)
                    full_path = bm.group(3).strip()
                    if full_path and size > 0:
                        dll_name = PureWindowsPath(full_path).name.lower()
                        pending_modules.append((base, base + size, dll_name))
                    out.write(line + "\n")
                    continue
                else:
                    # end of module section — flush
                    if pending_modules and module_section_pid:
                        module_maps[module_section_pid] = pending_modules
                    pending_modules = []
                    in_module_section = False
                    module_section_pid = None

            out.write(line + "\n")

    # final flush
    if in_module_section and pending_modules and module_section_pid:
        module_maps[module_section_pid] = pending_modules

    if args.output:
        out.close()
        print(f"Annotated runlog written to {args.output}")


if __name__ == "__main__":
    main()