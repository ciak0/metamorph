/*
						Operating System Disassembler\Assembler v 2.0

	- uses Single Instruction Disassembler\Assembler.
	- uses Operating System implementations.
*/

#ifndef ENGINE_H_

#define ENGINE_H_

//configuration: options
//#define ENG_NOVIRTUAL	//disable virtual data : everything will be reassembled phisically

//generic constants
#define ENG_MAXXREFS		2
#define ENG_MAXINSTRLEN		32
#define ENG_INVALIDRVA		0xFFFFFFFF
#define ENG_INVALIDOFF		ENG_INVALIDRVA

//errors and warnings
#define ENG_WARNOK		1
#define ENG_WARNNOSIZE	2
#define ENG_WARNNOREF	3

#define ENG_ERRNONE		0

#define ENG_ERRPARS		-1
#define ENG_ERRMEM		-2
#define ENG_ERRASM		-3
#define ENG_ERRMAP		-4

//generic macros
#define isError(err) ((err) < ENG_ERRNONE)
#define isWarning(err) ((err) > ENG_ERRNONE)

#define isVA(address, map) ((address) >= (map)->virtualAddress && \
							 (address) < (map)->virtualAddress + (map)->imageSize)

#define getOffset(ptr, base) ((int)((byte*)ptr - (byte*)base))

//generic types
#ifndef NULL
	#define NULL (void*)0
#endif

#ifndef BASIC_TYPES
    #define BASIC_TYPES
    typedef unsigned long dword;
    typedef unsigned short word;
    typedef unsigned char byte;
	typedef int cbool;
	typedef long sdword;
#endif

/*
imageEntity represents a single entity into image that can be:
data, code, fixed structure:
can contains a copy of his data (byte array)
and can group consecutive amounts of data
*/

//type of entity infos
#define IE_DATA		0x00000000
#define IE_CODE		0x00000001
#define IE_UNKNOWN	0x00000002

//disassembling\assembling infos
#define IE_MAIN		0x00000010 //reached by ep control flow
#define IE_LABEL	0x00000020 //it has ref by other instruction\data through instruction
#define IE_REFDATA	0x00000040 //referenced data
#define IE_ELABING	0x00000080 //bytes will be merged on success

//operating system infos
#define IE_OSREAD	0x00000100
#define IE_OSWRITE	0x00000200
#define IE_OSEXEC	0x00000400
#define IE_OSEP		0x00000800
#define IE_OSPHYS	0x00001000 //physical entities on disk
#define IE_OSDATA	0x00002000
#define IE_OSREFED	0x00004000

//additional infos
#define IE_BREAK	0x40000000 //with code: entity breaks control flow
#define IE_OWNDATA	0x80000000 //entity has own alloced data, so it must be freed

//masks
#define IE_OSMASK		(IE_OSREAD|IE_OSWRITE|IE_OSEXEC|IE_OSPHYS|IE_OSDATA)

//those are flags that user can manipulate on entities (when adding new one)
#define IE_USERMASK		(IE_CODE|IE_OSMASK|IE_OSEP)

typedef struct imageEntity_s{ //image entity: 28bytes + (8bytes * MAX_XREFS)
	dword flags;
	dword length;
	
	byte* data; //pointer to data, it can be from input buffer or realloced
	struct imageEntity_s *next; //used for modifications, not inside disasm

	struct imageXRef_s* xrefs[ENG_MAXXREFS]; //xrefs per instruction/data (if any)

	//from here user additional data
	dword injflags;
	struct imageEntity_s* remote;
} imageEntity;


/*
imageXRef represents a single xref from an entity to another,
it can be of different sizes, can be a physical offset, and can
involve different x86 operands.
*/

/*
flags depending on source type:
data
{
	REL: relative from image base
	!REL: it is a virtual address (!PHYSIC)
	PHYSIC: it is ALWAYS relative from base address (REL implicit)
	SRCBASE: used with rel or physic set that base it is source rva\address

	JUMP, SIB, MEMORY, USER+: nonsense
}
code
{
	OS: nonsense
	REL: it is relative from instruction pointer
	!REL: it is a virtual address/constant
	PHYSIC: nonsense
	SRCBASE: implicit with REL -> never checked
}
*/

//xref types
#define XRF_BYTE		0x00000001 //1byte size (if both of those are 0 then its dword)
#define XRF_WORD		0x00000002 //word size
#define XRF_REL			0x00000004 //relative (if not flagged then it's absolute)
#define XRF_OS			0x00000008 //it is an operating system structure xref

#define XRF_PHYSIC		0x00000010 //it is a physical offset
#define XRF_USEDELTA	0x00000020 //it uses deltas (for source, dest)
#define XRF_SRCBASE		0x00000040 //base is not image base but source (+rel\physic)

#define XRF_USERVA		0x00000080 //use rva instead of pointer

#define XRF_JUMP		0x00000100 //jump reference (it is part of jmp instruction)
#define XRF_SIB			0x00000200 //rva is in sib
#define XRF_MEMORY		0x00000400 //reference is in memory operand

#define XRF_POINTER		0x00000800 //used with immediates: immediate is moved to memory (can be used as ptr)

#define XRF_USER		0x00001000 //user defined flags

typedef struct imageXRef_s //image xref: 16bytes
{
	dword type;
	sdword srcdelta;
	sdword dstdelta;
	
	union
	{
		imageEntity* target;
		dword rva;
	} ;
} imageXRef;

/*
heapManager is a two functions structure
for malloc and free
*/
typedef void* (*MALLOC_FUNC)(unsigned int);
typedef void (*FREE_FUNC)(void*);

typedef struct heapManager_s
{
	MALLOC_FUNC malloc;
	FREE_FUNC free;
} heapManager;

/*
imageMap represents a whole executable with its infos,
and disassembled entities.
*/

//imageMap flags: management flags that represents status of imageMap.
#define IM_ISLINKED	0x00000001
#define IM_READONLY	0x00000002	//read only map cant me touched in any way
#define IM_COPYDATA	0x00000004	//copy data and dont use main pointer after disasm succeeded

typedef struct imageMap_s //imageMap represents an entire image
{
	heapManager* heapAgent;

	dword virtualAddress;
	dword imageSize;
	dword flags;
	byte* data; //complete va-aligned executable (read only)
	imageEntity** entities;
} imageMap;


/*
public fuctions
*/

//utilities:
void zeroStruct(void* ptr, dword size);
void copyStruct(void* dst, void* src, dword size);

imageEntity* rvaToEntity(imageMap* map, dword rva, dword* rem);
dword entityToRVA(imageMap* map, imageEntity* entity);

imageEntity* offsetToEntity(imageMap* map, dword offset, dword* rem);
dword entityToOffset(imageMap* map, imageEntity* entity);

//disassembling procedure:
int disassemblePE(imageMap* map);

//mutation procedure:
int deleteEntity(imageMap* map, imageEntity* entity);
imageEntity* addEntity(imageMap* map, imageEntity* prev, byte* data, dword length, dword flags);
int resizeEntity(imageMap* map, imageEntity* entity, dword size);
int addXRef(imageMap* map, imageEntity* entity, imageXRef xref);
int rwData(imageMap* map, cbool bWrite, imageEntity* base, dword off, dword size, byte* buff);

//assembling procedure:
int assemblePE(imageMap* map);

//management:
void resetImageMap(imageMap* map);

#endif