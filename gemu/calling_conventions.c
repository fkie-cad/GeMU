#include "gemu/calling_conventions.h"
#include "gemu/utils.h"
#include "target/i386/cpu.h"

static DWORD get_parameter_stdcall32(CPUState *cpu, int index) {
    DWORD result;
    gemu_virtual_memory_read(cpu, cpu->env_ptr->regs[R_ESP] + (4 + index * 4),
                             (uint8_t *) &result, 4);
    return result;
}

static QWORD get_parameter_win64(CPUState *cpu, int index) {
    QWORD result;
    switch (index) {
        case 0:
            result = cpu->env_ptr->regs[R_ECX];
            break;
        case 1:
            result = cpu->env_ptr->regs[R_EDX];
            break;
        case 2:
            result = cpu->env_ptr->regs[8];
            break;
        case 3:
            result = cpu->env_ptr->regs[9];
            break;
        default:
            gemu_virtual_memory_read(cpu, cpu->env_ptr->regs[R_ESP] + (8 + index * 8),
                                     (uint8_t *) &result, 8);
            break;
    }
    return result;
}

// Windows syscalls: the stub executes "mov r10, rcx" before the syscall
// instruction, so at kernel entry arg0 is in r10 (regs[10]), not rcx.
static QWORD get_parameter_syscall64(CPUState *cpu, int index) {
    QWORD result;
    switch (index) {
        case 0:
            result = cpu->env_ptr->regs[10]; // r10
            break;
        case 1:
            result = cpu->env_ptr->regs[R_EDX];
            break;
        case 2:
            result = cpu->env_ptr->regs[8];
            break;
        case 3:
            result = cpu->env_ptr->regs[9];
            break;
        default:
            gemu_virtual_memory_read(cpu, cpu->env_ptr->regs[R_ESP] + (8 + index * 8),
                                     (uint8_t *) &result, 8);
            break;
    }
    return result;
}

static DWORD get_parameter_thiscall32(CPUState *cpu, int index) {
    DWORD result;
    if (index == 0) {
        result = (DWORD)cpu->env_ptr->regs[R_ECX];
    } else {
        gemu_virtual_memory_read(cpu, cpu->env_ptr->regs[R_ESP] + (index * 4),
                                 (uint8_t *) &result, 4);
    }
    return result;
}

static DWORD get_parameter_fastcall32(CPUState *cpu, int index) {
    DWORD result;
    switch (index) {
        case 0:
            result = (DWORD)cpu->env_ptr->regs[R_ECX];
            break;
        case 1:
            result = (DWORD)cpu->env_ptr->regs[R_EDX];
            break;
        default:
            gemu_virtual_memory_read(cpu, cpu->env_ptr->regs[R_ESP] + (4 + (index - 2) * 4),
                                     (uint8_t *) &result, 4);
            break;
    }
    return result;
}

QWORD get_parameter(CPUState *cpu, int index, CallingConvention cc) {
    switch (cc) {
        case CC_STDCALL_32:
            return (QWORD)get_parameter_stdcall32(cpu, index);
        case CC_WIN64:
            return get_parameter_win64(cpu, index);
        case CC_SYSCALL_64:
            return get_parameter_syscall64(cpu, index);
        case CC_FASTCALL_32:
            return (QWORD)get_parameter_fastcall32(cpu, index);
        case CC_THISCALL_32:
            return (QWORD)get_parameter_thiscall32(cpu, index);
        default:
            return 0;
    }
}

QWORD get_return_value(CPUState *cpu, CallingConvention cc) {
    // All currently supported conventions return in EAX/RAX.
    // This function exists so convention-specific return-register knowledge
    // stays in one place if future conventions differ.
    (void)cc;
    return cpu->env_ptr->regs[R_EAX];
}

CallingConvention cc_from_string(const char *s) {
    if (strcmp(s, "32") == 0 || strcmp(s, "stdcall32") == 0) {
        return CC_STDCALL_32;
    } else if (strcmp(s, "64") == 0 || strcmp(s, "win64") == 0) {
        return CC_WIN64;
    } else if (strcmp(s, "syscall64") == 0) {
        return CC_SYSCALL_64;
    } else if (strcmp(s, "fastcall32") == 0) {
        return CC_FASTCALL_32;
    } else if (strcmp(s, "thiscall32") == 0) {
        return CC_THISCALL_32;
    } else {
        fprintf(stderr, "calling_conventions: unknown convention string \"%s\", defaulting to win64\n", s);
        return CC_WIN64;
    }
}
