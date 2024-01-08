# LanceLdr
A basic shellcode loader I built which includes a builder to XOR encrypt your shellcode and build a loader PE. I implemented some things to dynamically pull function addresses from the PEB ldr table so it doesn't need signatured Windows functions. 

## Usage
### BE SURE MSBUILD IS IN YOUR PATH, IF YOU DO NOT HAVE IT THERE FOLLOW THIS GUIDE https://stackoverflow.com/questions/6319274/how-do-i-run-msbuild-from-the-command-line-using-windows-sdk-7-1

```usage: builder.py [-h] -b BIN [-x XOR] [-ad] [-as] [-m {dinvoke,pebwalk}] [-l {createthread,inject,callback}]

Build an executable payload with encrypted shellcode from a bin file

options:
  -h, --help            show this help message and exit
  -b BIN, --bin BIN     The binary file to convert to nice unsigned char shellcode
  -x XOR, --xor XOR     XOR key to encrypt with. Will default to 512 byte randomized key if not supplised
  -ad, --anti-debug     Enable anti debugging option
  -as, --anti-sandbox   Enable anti sandboxing/virtualization option
  -m {dinvoke,pebwalk}, --method {dinvoke,pebwalk}
                        Method to use to dynamically load functions. 
                            DInvoke: Use LoadLibraryA and GetProcAddress to get function pointers. (Default)
                            PEBWalk: Grab a handle to the PEB and walk through the LDR table to find the hash for desired functions.
  -l {createthread,inject,callback}, --load {createthread,inject,callback}
                        Method to use to load and execute shellcode. 
                            CreateThread: Generic invocation of CreateThread to start running the shellcode.
                            Inject: Spawn a notepad.exe process in a suspended state with a spoofed PPID targeting explorer.exe then inject into it before using CreateRemoteThread. 
                            Callback: Register the shellcode as a callback function to indirectly transfer execution flow from the main process to the shellcode. (Default)
```
Once executed the payload will be output to the x64/release directory

### Examples

```
// Generate a PE payload with default settings
python .\builder.py -b .\beacon.bin 
// Generate a PE payload with default settings and a specific XOR key for the strings and payload
python .\builder.py -b .\beacon.bin -x coolxorkey 
// Generate a PE that will use DInvoke and CreateThread to execute the shellcode after performing anti-debug and sandbox checks 
python .\builder.py -b .\beacon.bin -m dinvoke -l createthread -ad -as
```

