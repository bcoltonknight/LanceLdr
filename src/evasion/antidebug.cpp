
void antiDebug()
{
	PPEB pebPtr;
	// Thread Environment Block (TEB)
	#if defined(_M_X64) // x64
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
	#else // x86
	PTEB tebPtr = reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
	#endif
	// Process Environment Block (PEB)
	pebPtr = tebPtr->ProcessEnvironmentBlock;
	if (pebPtr->BeingDebugged)
    {
        recursion_bomb(100000000);
        exit(1);
    }
}