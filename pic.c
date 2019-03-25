
#include "pic.h"

typedef union largeInteger_u {
  struct {
    dword LowPart;
    long HighPart;
  } ;
  struct {
    dword LowPart;
    long HighPart;
  } u;
  long long QuadPart;
} largeInteger;

typedef struct unicodeString_s 
{
	word Length;
	word MaximumLength;
	short* Buffer;
} unicodeString;

typedef struct listEntry_s 
{
	struct listEntry_s *Flink;
	struct listEntry_s *Blink;
} listEntry;

typedef struct driveLetter_s 
{
	word Flags;
	word Length;
	dword TimeStamp;
	unicodeString DosPath;
} driveLetter;

typedef struct userProcessParameters_s 
{
	dword MaximumLength;
	dword Length;
	dword Flags;
	dword DebugFlags;
	void* ConsoleHandle;
	dword ConsoleFlags;
	void* StdInputHandle;
	void* StdOutputHandle;
	void* StdErrorHandle;
	unicodeString CurrentDirectoryPath;
	void* CurrentDirectoryHandle;
	unicodeString DllPath;
	unicodeString ImagePathName;
	unicodeString CommandLine;
	void* Environment;
	dword StartingPositionLeft;
	dword StartingPositionTop;
	dword Width;
	dword Height;
	dword CharWidth;
	dword CharHeight;
	dword ConsoleTextAttributes;
	dword WindowFlags;
	dword ShowWindowFlags;
	unicodeString WindowTitle;
	unicodeString DesktopName;
	unicodeString ShellInfo;
	unicodeString RuntimeData;
	driveLetter DLCurrentDirectory[0x20];
} userProcessParameters;

typedef struct pebFreeBlock_s
{
	struct pebFreeBlock_s *Next;
	dword Size;
} pebFreeBlock;

typedef struct pebLoaderData_s 
{
	dword Length;
	byte Initialized;
	void* SsHandle;
	listEntry InLoadOrderModuleList;
	listEntry InMemoryOrderModuleList;
	listEntry InInitializationOrderModuleList;
} pebLoaderData;

typedef struct loaderModule_s 
{
	listEntry InLoadOrderModuleList;
	listEntry InMemoryOrderModuleList;
	listEntry InInitializationOrderModuleList;
	void* BaseAddress;
	void* EntryPoint;
	dword SizeOfImage;
	unicodeString FullDllName;
	unicodeString BaseDllName;
	dword Flags;
	short LoadCount;
	short TlsIndex;
	listEntry HashTableEntry;
	dword TimeDateStamp;
} loaderModule;

typedef void (*PPEBLOCKROUTINE)(void* PebLock); 

typedef struct peb_s 
{
	byte InheritedAddressSpace;
	byte ReadImageFileExecOptions;
	byte BeingDebugged;
	byte Spare; 
	void* Mutant;
	void* ImageBaseAddress;
	pebLoaderData* LoaderData;
	userProcessParameters* ProcessParameters; 
	void* SubSystemData;
	void* ProcessHeap; 
	void* FastPebLock;
	PPEBLOCKROUTINE FastPebLockRoutine; 
	PPEBLOCKROUTINE FastPebUnlockRoutine; 
	dword EnvironmentUpdateCount; 
	void* *KernelCallbackTable;
	void* EventLogSection;
	void* EventLog;
	pebFreeBlock* FreeList;
	dword TlsExpansionCounter;
	void* TlsBitmap;
	dword TlsBitmapBits[0x2];
	void* ReadOnlySharedMemoryBase;
	void* ReadOnlySharedMemoryHeap;
	void* *ReadOnlyStaticServerData;
	void* AnsiCodePageData;
	void* OemCodePageData;
	void* UnicodeCaseTableData; 
	dword NumberOfProcessors;
	dword NtGlobalFlag;
	byte Spare2[0x4];
	largeInteger CriticalSectionTimeout; 
	dword HeapSegmentReserve;
	dword HeapSegmentCommit;
	dword HeapDeCommitTotalFreeThreshold; 
	dword HeapDeCommitFreeBlockThreshold;
	dword NumberOfHeaps;
	dword MaximumNumberOfHeaps;
	void* **ProcessHeaps; 
	void* GdiSharedHandleTable;
	void* ProcessStarterHelper;
	void* GdiDCAttributeList; 
	void* LoaderLock;
	dword OSMajorVersion;
	dword OSMinorVersion;
	dword OSBuildNumber;
	dword OSPlatformId;
	dword ImageSubSystem;
	dword ImageSubSystemMajorVersion; 
	dword ImageSubSystemMinorVersion;
	dword GdiHandleBuffer[0x22];
	dword PostProcessInitRoutine;
	dword TlsExpansionBitmap;
	byte TlsExpansionBitmapBits[0x80]; 
	dword SessionId;
} peb;


//private funcs
dword wcalculateCRC(short* str, dword chars)
{
	char buff[260 + 1];
	register char* cur;
	register dword len;

	cur = buff;
	len = chars;
	while (chars--) 
		*cur++ = (char)(*str++);
	
	*cur = 0;
	return calculateCRC(buff, len);
}

peb* getPEB()
{
	peb* proc;

	__asm{
		push ecx
		mov ecx, fs:[30h];
		mov [proc], ecx;
		pop ecx
	}

	return proc;
}

loaderModule* getModule(dword crcName)
{
	peb* proc;
	listEntry *base, *cur;
	loaderModule *mod;
	dword crc;
	
	proc = getPEB();
	base = &proc->LoaderData->InMemoryOrderModuleList;
	cur = base->Flink;
	while (cur != base)
	{
		mod = (loaderModule*)(cur-1);
		if (crcName == 0)
			return mod; //crc is zero: requested module is the first one: the main executable

		crc = wcalculateCRC(mod->BaseDllName.Buffer, mod->BaseDllName.Length / sizeof(short));
		if (crc == crcName)
			return mod;

		cur = cur->Flink;
	}

	return NULL;
}

//public funcs
dword calculateCRC(char* str, dword chars)
{
	register dword crc = 0xFFFFFFFF;
	register dword temp;
	register dword j;
	char cur;

	while (chars--) 
	{
#ifndef INSENSITIVE_CRC
		cur = *str;
#else
		cur = (*str >= 'a' && *str <= 'z' ? *str - ('a' - 'A') : *str);
#endif
		str++;
		
		temp = (crc & 0xFF) ^ cur;
		for (j = 0; j < 8; j++)
		{
			if (temp & 0x1)
				temp = (temp >> 1) ^ 0xEDB88320;
			else
				temp >>= 1;
		}
		crc = (crc >> 8) ^ temp;
	}
	return crc ^ 0xFFFFFFFF;
}

byte* getImageBase(dword crcModule)
{
	loaderModule* mdl = getModule(crcModule);

	if (mdl == NULL)
		return NULL;
	return (byte*)mdl->BaseAddress;
}

dword getImageSize(dword crcModule)
{
	loaderModule* mdl = getModule(crcModule);
	
	if (mdl == NULL)
		return 0;
	return mdl->SizeOfImage;
}

byte* getEntryPoint(dword crcModule)
{
	loaderModule* mdl = getModule(crcModule);
	
	if (mdl == NULL)
		return NULL;
	return (byte*)mdl->EntryPoint;
}

byte* getExportedFunction(dword crcModule, dword crcFunc)
{
	loaderModule* mdl;
	
	byte* base;
	dosHeader* dos;
	ntHeaders* pe;
	exportDirectory* exp;
	
	char* name;
	char* fwdname;
	char tmpname[260+1];

	dword* names;
	dword* funcs;
	dword i, l, crc, fwdMdl, fwdFunc;

	mdl = getModule(crcModule);
	if (mdl == NULL)
		return NULL;

	base = (byte*)mdl->BaseAddress;

	dos = (dosHeader*)base; /*check MZ magic number*/
	if (dos->e_magic != 0x5A4D)
		return NULL;

	pe = (ntHeaders*)((byte*)base + dos->e_lfanew); /*set ptr*/
	if (pe->Signature != 0x00004550) 
		return NULL; /*check 'PE00' magic*/

	if (!pe->OptionalHeader.DataDirectory[0].VirtualAddress || !pe->OptionalHeader.DataDirectory[0].Size)
		return NULL;

	exp = (exportDirectory*)(base + pe->OptionalHeader.DataDirectory[0].VirtualAddress);
	names = (dword*)(base + exp->AddressOfNames);
	funcs = (dword*)(base + exp->AddressOfFunctions);

	for (i = 0; i < exp->NumberOfNames; i++)
	{
		name = (char*)(base + names[i]);
		l = 0;
		while (name[l++] != 0) ;
		
		crc = calculateCRC(name, l - 1);
		if (crc == crcFunc)
			break;
	}

	if (i >= exp->NumberOfNames)
		return NULL;

	//forwarded func
	if (funcs[i] >= pe->OptionalHeader.DataDirectory[0].VirtualAddress &&
		funcs[i] <= pe->OptionalHeader.DataDirectory[0].VirtualAddress + 
			      pe->OptionalHeader.DataDirectory[0].Size)
	{
		fwdname = (char*)(base + funcs[i]);
		
		l = 0;
		while (fwdname[l] != '.' && fwdname[l]) 
		{
			tmpname[l] = fwdname[l];
			l++;
		}

		i = l;
		if (fwdname[l] == 0) 
			return NULL;

		tmpname[l++] = '.';
		tmpname[l++] = 'd';
		tmpname[l++] = 'l';
		tmpname[l++] = 'l';
		tmpname[l++] = 0;

		fwdMdl = calculateCRC(tmpname, l - 1);
		
		fwdname += i + 1;
		l = 0;
		while (fwdname[l++]) ;

		fwdFunc = calculateCRC(fwdname, l - 1);
		return getExportedFunction(fwdMdl, fwdFunc);
	}

	//not forwared func
	return base + funcs[i];
}