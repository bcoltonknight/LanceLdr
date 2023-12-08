#pragma once
size_t KERNELHASH = 16602396236623191500;
size_t VIRTUALPROTECTHASH = 7157003931739585196;
size_t CREATETHREADHASH = 4011463126652645628;
size_t VIRTUALALLOCHASH = 205147645817062751;


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