/**********************************************************************************
						Windows PE Disassembler\Assembler

	- implements Operating System Disassembler\Assembler for Windows
	  Portable Executable format.
**********************************************************************************/

#ifndef PE_H_

/************************** common declares ***************************/
#define PE_H_

#include "engine.h"

#define pe_align(x, y) (((x)+(y)-1)&(~((y)-1)))

/*
---------------------------------------------------------------------------------------
									dos + pe headers + sections headers
---------------------------------------------------------------------------------------
*/

typedef struct dosHeader_s {			// DOS .EXE header
    word   e_magic;                     // Magic number
    word   e_cblp;                      // Bytes on last page of file
    word   e_cp;                        // Pages in file
    word   e_crlc;                      // Relocations
    word   e_cparhdr;                   // Size of header in paragraphs
    word   e_minalloc;                  // Minimum extra paragraphs needed
    word   e_maxalloc;                  // Maximum extra paragraphs needed
    word   e_ss;                        // Initial (relative) SS value
    word   e_sp;                        // Initial SP value
    word   e_csum;                      // Checksum
    word   e_ip;                        // Initial IP value
    word   e_cs;                        // Initial (relative) CS value
    word   e_lfarlc;                    // File address of relocation table
    word   e_ovno;                      // Overlay number
    word   e_res[4];                    // Reserved words
    word   e_oemid;                     // OEM identifier (for e_oeminfo)
    word   e_oeminfo;                   // OEM information; e_oemid specific
    word   e_res2[10];                  // Reserved words
    long   e_lfanew;                    // File address of new exe header
} dosHeader;

typedef struct fileHeader_s {
    word    Machine;
    word    NumberOfSections;
    dword   TimeDateStamp;
    dword   PointerToSymbolTable;
    dword   NumberOfSymbols;
    word    SizeOfOptionalHeader;
    word    Characteristics;
} fileHeader;

typedef struct dataDirectory_s {
    dword   VirtualAddress;
    dword   Size;
} dataDirectory;

#define NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct optionalHeader_s {
    //
    // Standard fields.
    //

    word    Magic;
    byte    MajorLinkerVersion;
    byte    MinorLinkerVersion;
    dword   SizeOfCode;
    dword   SizeOfInitializedData;
    dword   SizeOfUninitializedData;
    dword   AddressOfEntryPoint;
    dword   BaseOfCode;
    dword   BaseOfData;

    //
    // NT additional fields.
    //

    dword   ImageBase;
    dword   SectionAlignment;
    dword   FileAlignment;
    word    MajorOperatingSystemVersion;
    word    MinorOperatingSystemVersion;
    word    MajorImageVersion;
    word    MinorImageVersion;
    word    MajorSubsystemVersion;
    word    MinorSubsystemVersion;
    dword   Win32VersionValue;
    dword   SizeOfImage;
    dword   SizeOfHeaders;
    dword   CheckSum;
    word    Subsystem;
    word    DllCharacteristics;
    dword   SizeOfStackReserve;
    dword   SizeOfStackCommit;
    dword   SizeOfHeapReserve;
    dword   SizeOfHeapCommit;
    dword   LoaderFlags;
    dword   NumberOfRvaAndSizes;
    dataDirectory DataDirectory[NUMBEROF_DIRECTORY_ENTRIES];
} optionalHeader;

typedef struct ntHeaders_s {
    dword Signature;
    fileHeader FileHeader;
    optionalHeader OptionalHeader;
} ntHeaders;

#define SIZEOF_SHORT_NAME              8

typedef struct sectionHeader_s {
    byte    Name[SIZEOF_SHORT_NAME];
    union {
            dword   PhysicalAddress;
            dword   VirtualSize;
    } Misc;
    dword   VirtualAddress;
    dword   SizeOfRawData;
    dword   PointerToRawData;
    dword   PointerToRelocations;
    dword   PointerToLinenumbers;
    word    NumberOfRelocations;
    word    NumberOfLinenumbers;
    dword   Characteristics;
} sectionHeader;


/*
---------------------------------------------------------------------------------------
									data directories
---------------------------------------------------------------------------------------
*/

//0: Export
typedef struct exportDirectory_s {
    dword   Characteristics;
    dword   TimeDateStamp;
    word    MajorVersion;
    word    MinorVersion;
    dword   Name;
    dword   Base;
    dword   NumberOfFunctions;
    dword   NumberOfNames;
    dword   AddressOfFunctions;     // RVA from base of image
    dword   AddressOfNames;         // RVA from base of image
    dword   AddressOfNameOrdinals;  // RVA from base of image
} exportDirectory;

//1, 13: Import
typedef struct importDescriptor_s {
    union {
        dword   Characteristics;            // 0 for terminating null import descriptor
        dword   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    };
    dword   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    dword   ForwarderChain;                 // -1 if no forwarders
    dword   Name;
    dword   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} importDescriptor;

typedef struct thunkData_s {
    union {
        dword ForwarderString;      // Pbyte 
        dword Function;             // Pdword
        dword Ordinal;
        dword AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
} thunkData;

typedef struct importByName_s {
    word    Hint;
    byte    Name[1];
} importByName;

//2: Resource
typedef struct resourceDirectory_s {
    dword   Characteristics;
    dword   TimeDateStamp;
    word    MajorVersion;
    word    MinorVersion;
    word    NumberOfNamedEntries;
    word    NumberOfIdEntries;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} resourceDirectory;

typedef struct resourceDirectoryEntry_s {
    union {
        struct {
            dword NameOffset:31;
            dword NameIsString:1;
        };
        dword   Name;
        word    Id;
    };
    union {
        dword   OffsetToData;
        struct {
            dword   OffsetToDirectory:31;
            dword   DataIsDirectory:1; //if points to dirEntry
        };
    };
} resourceDirectoryEntry;

typedef struct reourceDataEntry_s {
    dword   OffsetToData;
    dword   Size;
    dword   CodePage;
    dword   Reserved;
} resourceDataEntry;

//3: Exceptions?, 4: Security?

//5: Base reloc
typedef struct baseRelocation_s {
    dword   VirtualAddress; //RVA
    dword   SizeOfBlock;    //number of offsets
//  word    TypeOffset[1];
} baseRelocation;

//6: Debug
typedef struct debugDirectory_s {
    dword   Characteristics;
    dword   TimeDateStamp;
    word    MajorVersion;
    word    MinorVersion;
    dword   Type;
    dword   SizeOfData;
    dword   AddressOfRawData;	//RVA
    dword   PointerToRawData;	//RVA
} debugDirectory;

//7: Architecture?, 8: GlobalPtr?

typedef struct tlsDirectory_s {
    dword   StartAddressOfRawData;
    dword   EndAddressOfRawData;
    dword   AddressOfIndex;             // Pdword
    dword   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    dword   SizeOfZeroFill;
    dword   Characteristics;
} tlsDirectory;

//10: LoadConfig(no rvas)

//11: Bound import
typedef struct boundImportDescriptor_s {
    dword   TimeDateStamp;
    word    OffsetModuleName;
    word    NumberOfModuleForwarderRefs;
} boundImportDescriptor;

//12: IAT(=1), 13:delay import(=1), 14: Com descriptor?

ntHeaders* peHeader(byte* base);

#endif