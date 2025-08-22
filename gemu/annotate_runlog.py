import json
from collections import defaultdict
from pathlib import Path

import tqdm


class RunlogParser:
    def __init__(self, symbolmapping):
        self.modules = dict()
        self.symbolmapping = self.parse_symbolmapping(symbolmapping)
        self.function_lookup = dict()
        self.already_checked_bb = set()
        self.function_lookup = dict()

    def parse_symbolmapping(self, symbolmapping: Path):
        # C:\Windows\SysWOW64\ntdll.dll;RtlAllocateHeap;280096;32
        mapping = defaultdict(dict)
        for line in symbolmapping.open():
            parts = line.split(";")
            #mapping[int(parts[2])][parts[0]] = parts[1]
            mapping[parts[0].lower().replace("\\", "\\")][int(parts[2])] = parts[1]
        #print(mapping.keys())
        return mapping

    def read_runlog(self, runlog: Path):
        for line in runlog.open():
            yield line


    def parse_module_line(self, line):
        # Base: 0x76EC0000, Size: 0x190000, File: c:\windows\syswow64\ntdll.dll
        parts = line.split(", ")
        start = int(parts[0].split(": ")[1], 16)
        size = int(parts[1].split(": ")[1], 16)
        name = parts[2].split(": ")[1].strip()
        self.modules[name.lower()] = (start, size)

    def parse_bb(self, line):
        # B:6976:6964:0x7ffc9c46f130,39
        parts = line.split(":")
        pid = int(parts[1], 16)
        tid = int(parts[2], 16)
        addr = int(parts[3].split(",")[0], 16)
        lookup_addr = None
        infos = None
        current_module = None
        if addr in self.already_checked_bb:
            return
        for name, (start, size) in self.modules.items():
            if addr >= start and addr < start + size:
                #print(f"{name.lower()=}, {self.symbolmapping.keys()=}")
                if name.lower() in self.symbolmapping.keys():
                    lookup_addr = addr - start
                    current_module = name
                    break
        if lookup_addr:
            infos = self.symbolmapping[current_module].get(lookup_addr)
        if infos:
            self.function_lookup[addr] = infos
            #print(hex(addr), lookup_addr, current_module, infos)
        else:
            self.already_checked_bb.add(addr)
        return infos

    def main(self, runlog: Path):
        for line in self.read_runlog(runlog):
            if line.startswith("Base:"):
                self.parse_module_line(line)
        #print(f"{self.modules.keys()=}")
        with open("annotated_runlog.txt", "w") as f:
            for line in self.read_runlog(runlog):
                if line.startswith("B:"):
                    function = self.parse_bb(line)
                    if function:
                        line = f"{line.strip()},{function}\n"
                f.write(line)
        print(json.dumps(self.function_lookup, indent=4))

def main():
    parser = RunlogParser(Path("/home/thorsten/work/GeMU/gemu/symbol_mapping_win10_unfiltered.txt"))
    parser.main(Path("/home/thorsten/work/deep-packer-inspection/localdata/787d0eae3fb29883b8dba9c3bcc00793baa4a54fbad0921d1aee7f5e6ad86907_gemu_20250901134138/runlog"))

if __name__ == '__main__':
    main()
