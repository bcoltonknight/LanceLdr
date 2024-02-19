#include <chrono>
#include <fileapi.h>

void antiSleep()
{
    auto startTime = std::chrono::high_resolution_clock::now();
	Sleep(5000);
	auto endTime = std::chrono::high_resolution_clock::now();

	double elapsed = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    printf("%f\n", elapsed);

    if (elapsed < 5000)
    {
        // recursion_bomb(100000);
		bail();
    }
}

void auditProcesses()
{
	//LPCWCHAR susProcs[] = { L"joeboxserver.exe", L"Wireshark.exe",  L"vmware.exe", L"vmsrvc.exe", L"prl_cc.exe"};
	size_t susProcHashes[] = {4117792738986545659, 17088474225186969531, 127634907165549051, 127634907165549051, 124842525090963963};


	for (int i = 0; i < sizeof(susProcHashes)/sizeof(size_t); i++)
	{
		// wprintf(L"%s\n", susProcs[i]);
		if (getPidByHash(susProcHashes[i]) != -1)
		{
			// recursion_bomb(10000000);
			bail();
		}
	}
}

void auditDrives()
{
    unsigned long long threshholdGb = 65;
    unsigned long long totalBytes = 0;

    GetDiskFreeSpaceExA(/*letter.c_str()*/NULL, NULL, (ULARGE_INTEGER*) & totalBytes, NULL);
    printf("Total bytes: %llu\n", totalBytes);
    printf("In gbs: %f\n", totalBytes / (float) 1000000000);
    if (totalBytes <= threshholdGb * 1000000000)
    {
        bail();
    }
    return;
}

void auditRam()
{
    ULONGLONG threshholdGb = 4.5;
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    ULONGLONG totalPhysMem = memInfo.ullTotalPhys;
    printf("%llu\n", totalPhysMem);
    if (totalPhysMem <= threshholdGb * (ULONGLONG)1000000000)
    {
        bail();
    }
}

void antiSandbox() 
{
	antiSleep();
	auditProcesses();
	auditDrives();
	auditRam();
}