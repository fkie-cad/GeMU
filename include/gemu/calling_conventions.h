
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

DWORD get_parameter32(CPUState *cpu, int index);

QWORD get_parameter64(CPUState *cpu, int index);

QWORD get_parameter(CPUState *cpu, int index, CallingConvention cc);

#endif // GEMU_CALLING_CONVENTIONS_H
