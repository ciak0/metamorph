
#ifndef PIC_H

#define PIC_H

#include "engine\eng_pe.h"

#define INSENSITIVE_CRC

dword calculateCRC(char* str, dword chars);
	
byte* getImageBase(dword crcModule);
dword getImageSize(dword crcModule);
byte* getEntryPoint(dword crcModule);
byte* getExportedFunction(dword crcModule, dword crcFunc);

#endif