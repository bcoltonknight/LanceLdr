PPEB pebPtr;
HINSTANCE kernelHandle;
pebPtr = getPeb();
kernelHandle = getLibByHash(pebPtr, KERNELHASH);