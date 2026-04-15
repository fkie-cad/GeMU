
#ifndef GEMU_CALLING_CONVENTIONS_H
#define GEMU_CALLING_CONVENTIONS_H

#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "gemu/peb_teb.h"

typedef enum {
    CC_STDCALL_32,   // 32-bit Windows stdcall: all args on stack
    CC_WIN64,        // 64-bit MS ABI: rcx, rdx, r8, r9, then stack
    CC_SYSCALL_64,   // 64-bit Windows syscall: r10, rdx, r8, r9, then stack
    CC_FASTCALL_32,  // 32-bit __fastcall: ecx, edx, then stack (JIT .NET)
    CC_THISCALL_32,  // 32-bit __thiscall: this in ecx, rest on stack
} CallingConvention;

QWORD get_parameter(CPUState *cpu, int index, CallingConvention cc);

// Returns the return value register for the given calling convention.
QWORD get_return_value(CPUState *cpu, CallingConvention cc);

// Parses a convention string from the symbol mapping file.
// "32" and "stdcall32" → CC_STDCALL_32
// "64" and "win64"     → CC_WIN64
// "syscall64"          → CC_SYSCALL_64
// "fastcall32"         → CC_FASTCALL_32
// "thiscall32"         → CC_THISCALL_32
// Unknown strings log a warning and return CC_WIN64.
CallingConvention cc_from_string(const char *s);

static inline bool cc_is32bit(CallingConvention cc) {
    return cc == CC_STDCALL_32 || cc == CC_FASTCALL_32 || cc == CC_THISCALL_32;
}

#endif // GEMU_CALLING_CONVENTIONS_H
