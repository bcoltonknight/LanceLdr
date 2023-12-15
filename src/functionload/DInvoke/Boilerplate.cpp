HINSTANCE kernelHandle;
unsigned char kern[] = <KERNEL32>
xor_data(kern, sizeof(kern), key, key_len);
kernelHandle = LoadLibraryA((LPCSTR) kern);
xor_data(kern, sizeof(kern), key, key_len);

if (kernelHandle == NULL)
{
    return 1;
}