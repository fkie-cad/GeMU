#!/usr/bin/python
########################################################################
# Copyright (c) 2017
# Daniel Plohmann <daniel.plohmann<at>mailbox<dot>org>
# All rights reserved.
########################################################################
#
#  This file is part of apiscout
#
#  apiscout is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################
# Copyright (c) 2025
# Manuel Blatt
#
# This file was modfied to fit GEMUs usecase.
#


import argparse
import logging
from operator import attrgetter
import os
import sys
import pefile

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format="%(asctime)-15s %(message)s")

folder_whitelist = (
    "SysWOW64",
    "System32",
    "dotnet",
    "Microsoft.NET"
)

dll_whitelist = {"advapi32.dll", "kernel32.dll", "KernelBase.dll", "msvcr110.dll", "msvcr120.dll", "ntdll.dll",
                 "shell32.dll", "shlwapi.dll", "winsta.dll", "wtsapi32.dll", "clrjit.dll"}

function_whitelist = {"CreateFileA", "CreateFileW", "CreateProcessA", "CreateProcessAsUserA", "CreateProcessAsUserW",
                      "CreateProcessInternalA", "CreateProcessInternalW", "CreateProcessW", "CreateProcessWithLogonW",
                      "CreateProcessWithTokenW", "__crtTerminateProcess", "LoadLibraryA", "LoadLibraryExA",
                      "LoadLibraryExW", "LoadLibraryW", "MLLoadLibraryA", "MLLoadLibraryW", "OpenProcess",
                      "OpenProcessToken", "RtlCreateProcessParameters", "RtlCreateProcessParametersEx",
                      "RtlCreateProcessReflection", "RtlDecompressBuffer", "SHCreateProcessAsUserW", "TerminateProcess",
                      "WinStationTerminateProcess", "WriteFile", "WriteFileEx", "WriteProcessMemory",
                      "WTSTerminateProcess", "ZwCreateProcess", "ZwCreateProcessEx", "ZwCreateSection",
                      "ZwMapViewOfSection", "ZwOpenProcess", "ZwOpenProcessToken", "ZwTerminateProcess", "ZwWriteFile",
                      "ZwWriteVirtualMemory", "getJit"}

def filter_folder(path) -> bool:
    for folder in folder_whitelist:
        if folder in path:
            return True
    return False

class DatabaseBuilder(object):

    def _extractPeExports(self, filepath):
        try:
            pe = pefile.PE(filepath)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                dll_entry = {"base_address": pe.OPTIONAL_HEADER.ImageBase,
                             "bitness": 32 if pe.FILE_HEADER.Machine == 0x14c else 64, "filepath": filepath,
                             "exports": []}
                for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=attrgetter("address")):
                    export_info = {"address": exp.address}

                    if exp.name == None:
                        export_info["name"] = "None"
                    else:
                        export_info["name"] = exp.name.decode("utf-8")
                    export_info["ordinal"] = exp.ordinal
                    dll_entry["exports"].append(export_info)

                return dll_entry
        except Exception as exc:
            return None

    def _buildDllKey(self, dll_info):
        return dll_info["filepath"]

    def _isInFilter(self, target_dll, filter_dlls):
        # since we want to maintain compatibility with Python 2.7, we can't casefold - upper+lower should suffice though.
        for check_dll in filter_dlls:
            if target_dll.upper().lower() == check_dll.upper().lower():
                return True
        return False

    def extractRecursively(self, paths):
        api_count = 0
        pe_count = 0
        duplicate_count = 0
        skipped_count = 0
        num_hit_dlls = 0
        api_db = {"dlls": {}}
        for base in paths:
            if not os.path.isdir(base):
                LOG.warn("%s is not a directory, skipping...", base)
                continue
            for root, _, files in os.walk(base):
                if not filter_folder(root):
                    continue
                for fn in files:
                    if not fn in dll_whitelist:
                    # if filter_dlls and not self._isInFilter(fn, DLL_FILTER):
                        skipped_count += 1
                        continue
                    elif not (fn.lower().endswith(".dll") or fn.lower().endswith(".drv") or fn.lower().endswith(".mui")):
                        continue
                    pe_count += 1
                    LOG.info("processing: %s %s", root, fn)
                    dll_summary = self._extractPeExports(root + os.sep + fn)
                    if dll_summary is not None:
                        dll_key = self._buildDllKey(dll_summary)
                        if dll_key not in api_db["dlls"]:
                            api_db["dlls"][dll_key] = dll_summary
                            num_hit_dlls += 1
                            api_count += len(dll_summary["exports"])
                            LOG.info("APIs: %d", len(dll_summary["exports"]))
                        else:
                            duplicate_count += 1
        LOG.info("PEs examined: %d (%d duplicates, %d skipped)", pe_count, duplicate_count, skipped_count)
        LOG.info("Successfully evaluated %d DLLs with %d APIs", num_hit_dlls, api_count)
        return api_db


def create_symbol_mapping(data, output_path, c_path):
    with open(output_path, "w") as file:
        for dll_name, dll_data in data['dlls'].items():
            dll_path:str = dll_data['filepath']
            dll_path_fixed = "C:\\" + "\\".join(os.path.relpath(dll_path, c_path).split(os.path.sep))
            bitness = dll_data["bitness"]
            for function_data in dll_data['exports']:
                function_offset = function_data['address']
                function_name = function_data['name']
                function_address = function_offset
                if not function_name in function_whitelist:
                    continue
                line = ";".join([dll_path_fixed, function_name, str(function_address), str(bitness)])
                file.write(line+"\n")


def main():
    parser = argparse.ArgumentParser(description='Build a symbol mapping to be used by gemu.')
    parser.add_argument('--path', metavar='P', type=str, default=None,
                        help='the path pointing to C:\\')
    parser.add_argument('--outfile', dest='output_file', type=str, default=None,
                        help='filepath where to put the resulting symbol mappings.')

    args = parser.parse_args()
    builder = DatabaseBuilder()
    if args.path and args.output_file:
        api_db = builder.extractRecursively((args.path, ))
        create_symbol_mapping(api_db, args.output_file, args.path)
    else:
        parser.print_help()


if __name__ == "__main__":
    sys.exit(main())
