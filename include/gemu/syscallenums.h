#ifndef GEMU_SYSCALLENUMS_H
#define GEMU_SYSCALLENUMS_H

typedef enum {
    UNKNOWN_SYSCALL,
    NtTerminateProcess,
    NtOpenProcess,
    NtWriteVirtualMemory,
    NtAllocateVirtualMemory,
    NtWriteFile,
    NtMapViewOfSection,
    NtCreateUserProcess,
    NtOpenFile,
    NUM_SYSCALLS
} syscall_t;

#ifdef USE_SYSCALL_NAMES
static const char* SYSCALL_NAMES[] = {
    "UNKNOWN_SYSCALL",
    "NtTerminateProcess",
    "NtOpenProcess",
    "NtWriteVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtWriteFile",
    "NtMapViewOfSection",
    "NtCreateUserProcess",
    "NtOpenFile",
    "NUM_SYSCALLS"
};
#endif

#endif //GEMU_SYSCALLENUMS_H



