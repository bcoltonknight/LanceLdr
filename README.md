# Shellcode_Loader_Builder
A super basic project I built which includes a builder to XOR encrypt your shellcode and build the loader which does some basic dynamic invoke stuff to try to evade signature. Wouldn't recomend for an actual engagement but works ok for academic stuff.

## Usage
### BE SURE MSBUILD IS IN YOUR PATH, IF YOU DO NOT HAVE IT THERE FOLLOW THIS GUIDE https://stackoverflow.com/questions/6319274/how-do-i-run-msbuild-from-the-command-line-using-windows-sdk-7-1
You just need to run ```python builder.py -b SHELLCODE_BIN_FILE -x XOR_KEY``` and it will output to the x64/Release directory. 
