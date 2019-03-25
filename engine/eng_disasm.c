
#include "eng_base.h"

//operating system
#include "eng_pe.h"

//architecure disassembler
#include "eng_x86.h"

//forward declares
#define FB_1STPASS	0x01	//1st pass: main branch from ep
#define FB_2NDPASS	0x10	//2nd pass: refed entities

int followBranch(imageMap* map, imageEntity* entity, dword flags);


/**********************************************************************************
createOsXRef:
	add xref for source rva and specified target, and merge immediatly
	entities for the source (cause i'm sure of its size).

	in: map, source rva, xref target and flags
	out: err code
***********************************************************************************/
int createOsXRef(imageMap* map, dword srcrva, imageXRef xref)
{
	register imageEntity *src, *dst;
	register dword length;
	register int err;

	//register xref
	src = map->entities[srcrva];
	err = registerXRef(map, src, xref);
	if (isError(err))
		return err;

	//merge source bytes immediatly
	length = sizeof(dword);
	if (xref.type & XRF_WORD)
		length = sizeof(word);
	if (xref.type & XRF_BYTE)
		length = sizeof(byte);

	src = createImageEntity(map, srcrva, length, 0);
	if (src == NULL)
		return ENG_ERRMAP;

	//save dest flag
	if (xref.type & XRF_USERVA)
		dst = map->entities[xref.rva];
	else
		dst = xref.target;

	dst->flags |= IE_OSREFED;
	return err;
}

/**********************************************************************************
disasembleData:
	disassemble data entity refed by code, following possible flows
	or refing other data.

	in: map, entity, type of xref used
	out: err code
***********************************************************************************/
int disassembleData(imageMap* map, imageEntity* entity, dword xreft)
{
	register int err;
	register dword rva;
	register dword destva;
	register imageEntity* target;
	register cbool addxref;

	register dword arrayc;

	imageXRef xref;

	rva = getOffset(entity->data, map->data);
	
	xref.srcdelta = xref.dstdelta = 0;
	xref.type = xref.rva = 0;

	addxref = 1;

	//only physical entities can have xrefs, do not pass two times same entity
	if ((entity->flags & IE_ELABING) || 
		(entity->flags & (IE_OSPHYS|IE_UNKNOWN)) != (IE_OSPHYS|IE_UNKNOWN))
	{
		return ENG_WARNOK;
	}

	//check i have space for reading dword
	if (rva > map->imageSize - sizeof(dword))
	{
		//error: jump with data must be dword sized
		if (xreft & XRF_JUMP)
			return ENG_ERRMAP;

		return ENG_WARNNOSIZE;
	}
	
	//i cant merge entity in one (just emulated here)
	if (!createImageEntity(map, rva, sizeof(dword), 1))
		return ENG_ERRMAP;

	//tag each byte as going to be merged and set that we are currently following its flow
	tagEntities(map, rva, sizeof(dword), IE_ELABING, 0);

	destva = *((dword*)entity->data);
	arrayc = 0;

	//if im referenced with a sib or i am zero -> try find jump table/array of ptr
	if (!destva || (xreft & XRF_SIB))
	{
		//try backward array
		if (rva > sizeof(dword))
		{
			target = map->entities[rva - sizeof(dword)];
			if (target &&  //it is still unknown readable, physical data
				(target->flags & (IE_UNKNOWN|IE_OSREAD|IE_OSPHYS)) == (IE_UNKNOWN|IE_OSREAD|IE_OSPHYS))
			{
				err = disassembleData(map, target, xreft);
				if (isError(err))
				{
					untagEntities(map, rva, sizeof(dword), IE_ELABING);
					return err;
				}
				else if (err == ENG_ERRNONE)
					arrayc++;
			}
		}

		//then forward array
		if (rva < map->imageSize - sizeof(dword))
		{
			target = map->entities[rva + sizeof(dword)];
			if (target &&  //it is still unknown readable, physical data
				(target->flags & (IE_UNKNOWN|IE_OSREAD|IE_OSPHYS)) == (IE_UNKNOWN|IE_OSREAD|IE_OSPHYS))
			{
				err = disassembleData(map, target, xreft);
				if (isError(err))
				{
					untagEntities(map, rva, sizeof(dword), IE_ELABING);
					return err;
				}
				else if (err == ENG_ERRNONE)
					arrayc++;
			}
		}
	}
	
	//check im a valid virtual address
	if (!isVA(destva, map))
	{
		untagEntities(map, rva, sizeof(dword), IE_ELABING);

		if ((xreft & XRF_JUMP) && !arrayc) //invalid jump by data (sib also)
			return ENG_ERRMAP;

		if (arrayc) //i am array element
		{
			if (!createImageEntity(map, rva, sizeof(dword), 0))
				return ENG_ERRMAP; //fatal error: some subcall overwrote myself

			return ENG_ERRNONE;
		}
		
		return ENG_WARNNOREF;
	}
	
	//here i'm a valid va: check im pointing to right things
	target = map->entities[destva - map->virtualAddress];

	//im used in a jump instruction, i must point to executable entities!
	if (xreft & XRF_JUMP)
	{
		if (!target || //im pointing mid of a known entity
			(target->flags & (IE_OSEXEC|IE_OSPHYS)) != (IE_OSEXEC|IE_OSPHYS) || //not an executable entity
			(!(target->flags & IE_UNKNOWN) && //if im pointing to a known non code entity: wrong jump
			!(target->flags & IE_CODE))
			)
		{
			untagEntities(map, rva, sizeof(dword), IE_ELABING);
			return ENG_ERRMAP;
		}

		//unknown target, try disassemble whole branch, on error quit
		if (target->flags & IE_UNKNOWN)
		{
			err = followBranch(map, target, 0);
			if (isError(err))
			{
				untagEntities(map, rva, sizeof(dword), IE_ELABING);
				return err;
			}

			target->flags |= IE_CODE|IE_LABEL;
		}
	}
	else if (target) //try understand what the hell i am pointing to
	{
		//if i points to executable section try disassemble branch, on error ignore
		if ((target->flags & (IE_OSEXEC|IE_OSPHYS)) == (IE_OSEXEC|IE_OSPHYS))
		{
			err = followBranch(map, target, 0);
			if (!isError(err))
				target->flags |= IE_CODE|IE_LABEL;
			else
				addxref = 0;
		}
		else
		{
			err = disassembleData(map, target, 0); //disassemble pointed data
			if (isError(err))
				addxref = 0; //data was wrong: do not add xref
		}
	}
	else
	{
		untagEntities(map, rva, sizeof(dword), IE_ELABING);
		return ENG_WARNNOREF; //i point mid of entity
	}

	//register xref if it has to
	if (addxref)
	{
		xref.type = XRF_USERVA;
		xref.rva = destva - map->virtualAddress;
		err = registerXRef(map, entity, xref);
		if (isError(err))
		{
			untagEntities(map, rva, sizeof(dword), IE_ELABING);
			return err;
		}
	}

	//finally we can merge bytes to data
	untagEntities(map, rva, sizeof(dword), IE_ELABING);

	if (!createImageEntity(map, rva, sizeof(dword), 0))
		return ENG_ERRMAP; //fatal error: some subcall overwrote myself

	return ENG_ERRNONE;
}

/**********************************************************************************
followBranch:
	follow control flow branch from given entity, trying disassemble everything
	needed, on whatever error branch will not be validated.

	in: map, entity, disassembling mode (1stpass: without heuristic)
	out: err code
***********************************************************************************/
int followBranch(imageMap* map, imageEntity* entity, dword mode)
{
	register int err, count, i;
	register dword rva, len;
	register imageEntity* next;

	register dword flags;

	x86instr code;
	imageXRef targets[ENG_MAXXREFS];

	rva = getOffset(entity->data, map->data);
	flags = 0;

	//choose flags depending on mode
	if (mode & FB_1STPASS)
		flags = IE_MAIN;

	if ((entity->flags & IE_ELABING))
		return ENG_WARNOK; //already elabing

	//known entity and not 2nd pass
	if (!(entity->flags & IE_UNKNOWN) && !(mode & FB_2NDPASS))
		return ENG_WARNOK;

	//on disasm error return
	len = disassembleBinary(entity->data, &code);
	if (!len)
		return ENG_ERRASM;

	//if current entity is unknown
	if (entity->flags & IE_UNKNOWN)
	{
		//suspicious instruction and not in reached flow return
		if (isSuspicious(&code) && !(flags & IE_MAIN))
			return ENG_ERRASM;

		//fatal error: map overflow
		if (rva + code.len > map->imageSize)
			return ENG_ERRASM;

		//i cant merge entity in one (just emulated here)
		if (!createImageEntity(map, rva, len, 1))
			return ENG_ERRMAP;

		//tag each byte as going to be merged and set that we are currently following its flow
		tagEntities(map, rva, len, IE_ELABING, 0);

		//if instruction its not a break and not at the end of image
		if (!isBreak(&code) && rva + code.len < map->imageSize)
		{
			//try follow instruction branch if unknown
			next = map->entities[rva + code.len];
			if (next->flags & IE_UNKNOWN)
			{
				err = followBranch(map, next, mode);
				if (isError(err)) //on error invalidate current instruction and whole branch
				{
					untagEntities(map, rva, len, IE_ELABING);
					return err;
				}

				next->flags |= IE_CODE|flags;
			}
		}
	}
	else
		entity->flags |= IE_ELABING; //just save flag

	//get instruction possible targets: immediates\offsets\addresses will be returned
	count = getTargets(rva, map->virtualAddress, &code, targets, ENG_MAXXREFS);
	for (i = 0; i < count; i++)
	{
		if (targets[i].rva > map->imageSize)
		{
			if (targets[i].type & XRF_JUMP)
			{
				untagEntities(map, rva, len, IE_ELABING);
				return ENG_ERRASM; //jump target: should be at least included in image
			}
			else
				continue; //immediates, offsets: dont give a damn
		}

		next = map->entities[targets[i].rva];
		
		//direct jump\call\jcc: follow new branch 
		//(only if current entity is unknown: 1st pass or 2nd pass and not already elabed)
		if ((entity->flags & IE_UNKNOWN) && 
			(targets[i].type & XRF_JUMP) && 
			!(targets[i].type & (XRF_MEMORY|XRF_SIB)))
		{
			if (!next || //jump mid of known entity, must be executable and physic
				(next->flags & (IE_OSEXEC|IE_OSPHYS)) != (IE_OSEXEC|IE_OSPHYS))
			{
				untagEntities(map, rva, len, IE_ELABING);
				return ENG_ERRASM;
			}
			
			//if it is unknown data\code
			if (next->flags & IE_UNKNOWN)
			{
				err = followBranch(map, next, mode);
				if (isError(err))
				{
					untagEntities(map, rva, len, IE_ELABING);
					return err;
				}
			}

			//here we have validated all branches from current xref: we can set flags and add xrefs
			next->flags |= IE_CODE|IE_LABEL|flags;
		}
		else if (targets[i].type & XRF_MEMORY)
		{
			//entity is known, im not an indirect jump and its not 2nd pass -> leave it after
			if (!(entity->flags & IE_UNKNOWN) && !(targets[i].type & XRF_JUMP) &&
				!(mode & FB_2NDPASS))
			{
				continue; 
			}

			if (!next) //memory points mid of known entity: wrong address
			{
				untagEntities(map, rva, len, IE_ELABING);
				return ENG_ERRMAP;
			}

			//disassemble data and follow branches if necessary
			err = disassembleData(map, next, targets[i].type);
			if (isError(err))
			{
				if (err == ENG_ERRMEM)
				{
					untagEntities(map, rva, len, IE_ELABING);
					return err; //on memory error end everything
				}

				continue; //if couldnt resolve branches do not care
			}

			next->flags |= IE_REFDATA; //set flag
		}
		else if ((mode & FB_2NDPASS) && next)
		{
			//try understand role of immediate (it can be a ptr to func)
			if ((next->flags & (IE_UNKNOWN|IE_OSEXEC|IE_OSPHYS)) == 
				(IE_UNKNOWN|IE_OSEXEC|IE_OSPHYS)) //must be unknown exec physic
			{
				err = followBranch(map, next, mode);
				if (!isError(err)) //add flags to entity: code, label
					next->flags |= IE_CODE|IE_LABEL;
			}

			//it can also be a ptr to data (if not already tagged as code)
			if (!(next->flags & IE_CODE) &&
				(next->flags & (IE_OSREAD|IE_OSPHYS)) == (IE_OSREAD|IE_OSPHYS)) //must be readable physic
			{
				//if already found no problem, we must register xref btw
				err = disassembleData(map, next, targets[i].type);
				if (!isError(err))
					next->flags |= IE_REFDATA; //set flag
			}

			//we register xref anytime,
			//this way we could patch constants that are similar to rvas
			//but it's necessary cause we dont know if its used as address
			//or data (maybe we could do some heuristic in next versions)

			//if (!(next->flags & IE_CODE) && (targets[i].type & XRF_POINTER))
			next->flags |= IE_REFDATA; //if immediate is used with memory could be pointer
		}

		//if analysis found some flag on target: register xref
		if (next->flags & (IE_LABEL|IE_REFDATA))
		{
			err = registerXRef(map, entity, targets[i]);
			if (isError(err))
				return err;
		}
	}

	if (entity->flags & IE_UNKNOWN)
	{
		//finally we can merge bytes to instruction
		untagEntities(map, rva, len, IE_ELABING);
		
		if (isBreak(&code)) //add other infos
			entity->flags |= IE_BREAK;

		if (!createImageEntity(map, rva, len, 0))
			return ENG_ERRMAP; //fatal error: some subcall overwrote myself
	}
	else
		entity->flags &= ~IE_ELABING;

	return ENG_ERRNONE;
}

/**********************************************************************************
disassembleRefCode:
	2nd analysis on map: try to follow possible branches from already validated
	entry point control flow.

	in: map
	out: err code
***********************************************************************************/
int disassembleRefCode(imageMap* map)
{
	register imageEntity* ent;
	register dword rva;
	register int err;

	rva = 0;

	//for each already disassembled instruction
	//follow possible refrerenced branches
	while (rva != map->imageSize)
	{
		ent = map->entities[rva];

		//follow branches for current instruction 
		//(2nd pass mode analyzes only references on known entities)
		if (ent->flags & IE_MAIN)
		{
			err = followBranch(map, ent, FB_2NDPASS);
			if (isError(err))
				return err; //maybe we could ignore this...
		}

		rva += ent->length;
	}

	return ENG_ERRNONE;
}

/**********************************************************************************
disassembleCode:
	disassemble all code and data with given maop and entry point.

	in: map, entry point rva
	out: err code
***********************************************************************************/
int disassembleCode(imageMap* map, dword ep)
{
	register imageEntity* entity;
	register int err;
	
	//get entity point
	entity = map->entities[ep];

	//check it's into executable section
	if (!(entity->flags & IE_OSEXEC))
		return ENG_ERRMAP;

	//set flags
	entity->flags |= IE_OSEP;
	
	//1st pass: follow entry point flow and resolve everything
	err = followBranch(map, entity, FB_1STPASS);
	if (isError(err))
		return err;

	entity->flags |= IE_CODE|IE_LABEL|IE_MAIN;
	
	//2nd pass: we must be sure that entry point flow its already
	//perfectly done, try with referenced data and possible instructions
	err = disassembleRefCode(map);
	return err;
}

/*
------------------------------------------------------------------------------------
							specific disasmer functions
------------------------------------------------------------------------------------
*/

/**********************************************************************************
peHeader:
	get pe header from base.

	in: base
	out: pe header
***********************************************************************************/
ntHeaders* peHeader(byte* base)
{
	register dosHeader* dos; 
	register ntHeaders* nt;

	if (!base) 
		return NULL;

	dos = (dosHeader*)base; //check MZ magic number
	if (dos->e_magic != 0x5A4D) 
		return NULL;

	nt = (ntHeaders*)((byte*)base + dos->e_lfanew); //set ptr
	if (nt->Signature != 0x00004550) 
		return NULL; //check 'PE00' magic

	return nt;
}

/**********************************************************************************
offsetToRVA:
	transform offset to rva with given pe header.

	in: pe header, offset
	out: rva
***********************************************************************************/
dword offsetToRVA(ntHeaders* pe, dword offset)
{
	register sectionHeader* sh;
	register dword i, ret;
	
	if (offset < pe->OptionalHeader.SizeOfHeaders)
		return offset;

	for (i = 0; i < pe->FileHeader.NumberOfSections; i++)
	{
		sh = (sectionHeader*)(pe + 1);
		sh += i;

		if (offset >= sh->PointerToRawData && 
			offset < sh->PointerToRawData + sh->SizeOfRawData)
		{
			ret = offset - sh->PointerToRawData;
			ret += sh->VirtualAddress;
			return ret;
		}
	}

	return ENG_INVALIDRVA;
}

/**********************************************************************************
registerResourcedDir:
	recursively register xrefs for pe resource directories.

	in: map, root directory, current directory
	out: err code
***********************************************************************************/
int registerResourceDir(imageMap* map, resourceDirectory* root, resourceDirectory* dir)
{
	register dword i;
	register int ret;
	register resourceDirectoryEntry* rde;
	register resourceDataEntry* rdd;

	imageXRef xref;

	xref.dstdelta = xref.srcdelta = 0;

	rde = (resourceDirectoryEntry*)(dir + 1);
	for (i = 0; i < (dword)(dir->NumberOfIdEntries + dir->NumberOfNamedEntries); i++)
	{
		if (rde->DataIsDirectory)
		{
			//we don't register relative offsets cause
			ret = registerResourceDir(map, root, (resourceDirectory*)((byte*)root + rde->OffsetToDirectory));
			if (isError(ret))
				return ret;
		}
		else
		{
			rdd = (resourceDataEntry*)((byte*)root + rde->OffsetToData);

			//OffsetToData is an rva
			xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
			xref.rva = rdd->OffsetToData;
			ret = createOsXRef(map, getOffset(&rdd->OffsetToData, map->data), xref);
			if (isError(ret))
				return ret;
		}

		rde++;
	}

	return ret;
}

/*
	EXPORT: contains RVAs to exported funcs
	IMPORT: contains importDescriptors and thunks to imported dll & APIs
	RESOURCE: contains resources entity with some RVAs
	EXCEPTION: not supported (who knows?)
	SECURITY: not supported (who knows?)
	BASERELOC: contains array of basereloc structures with RVAs
	DEBUG: contains debug descriptor with RVAs
	ARCHITECTURE: not supported (who knows?)
	GLOBALPTR: maybe contains some RVAs... not supported (who knows?)
	TLS: contains thread infos with RVAs and offsets!
	LOAD_CONFIG: contains some load infos without RVAs
	BOUND_IMPORT: contains array of boundImportDescriptor with RVAs
	IAT: just ptr to APIs descripted by IMPORT
	DELAY_IMPORT: contains same structure as IMPORT
	COM_DESCRIPTOR: not supported (who knows?)
*/
/**********************************************************************************
prepareDataDirectory:
	prepare pe data directory registering all xrefs and tagging all entities.

	in: map, pe header, number of directory
	out: err code
***********************************************************************************/
int prepareDataDirectory(imageMap* map, ntHeaders* nt, int dir)
{
	register int ret;
	register dword i;
	register dataDirectory* dd;

	//export
	register exportDirectory* exp;
	register dword *names, *funcs;

	//import, delay import
	register importDescriptor* dll;
	register thunkData* thunk;

	//resource
	register resourceDirectory* rsr;

	//debug
	register debugDirectory* dbg;

	//tls
	register tlsDirectory* tls;
	
	//bound import
	register boundImportDescriptor* bound;

	imageXRef xref;

	//tag datadir as data
	dd = &nt->OptionalHeader.DataDirectory[dir];
	tagEntities(map, dd->VirtualAddress, dd->Size, IE_OSDATA|IE_OSPHYS, 1);
	
	xref.dstdelta = xref.srcdelta = 0;

	//save datadir xref
	xref.type = XRF_USERVA|XRF_OS|XRF_REL;
	xref.rva = dd->VirtualAddress;
	ret = createOsXRef(map, getOffset(&dd->VirtualAddress, map->data), xref);
	if (isError(ret))
		return ret;

	//export directory
	if (dir == 0)
	{
		exp = (exportDirectory*)(map->data + dd->VirtualAddress);
		
		//register xrefs for structure
		xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
		xref.rva = exp->AddressOfFunctions;
		ret = createOsXRef(map, getOffset(&exp->AddressOfFunctions, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
		xref.rva = exp->AddressOfNameOrdinals;
		ret = createOsXRef(map, getOffset(&exp->AddressOfNameOrdinals, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
		xref.rva = exp->AddressOfNames;
		ret = createOsXRef(map, getOffset(&exp->AddressOfNames, map->data), xref);
		if (isError(ret))
			return ret;

		//then for each name
		names = (dword*)(map->data + exp->AddressOfNames);
		for (i = 0; i < exp->NumberOfNames; i++)
		{
			xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
			xref.rva = *names;
			ret = createOsXRef(map, getOffset(names, map->data), xref);
			if (isError(ret))
				return ret;
			names++;
		}

		//and each func
		funcs = (dword*)(map->data + exp->AddressOfFunctions);
		for (i = 0; i < exp->NumberOfNames; i++)
		{
			xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
			xref.rva = *funcs;
			ret = createOsXRef(map, getOffset(funcs, map->data), xref);
			if (isError(ret))
				return ret;
			funcs++;
		}

		return ENG_ERRNONE;
	}

	//import, delay import
	if (dir == 1 || dir == 13)
	{
		dll = (importDescriptor*)(map->data + dd->VirtualAddress);
		
		while (dll->Name)
		{
			xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
			xref.rva = dll->Name;
			ret = createOsXRef(map, getOffset(&dll->Name, map->data), xref);
			if (isError(ret))
				return ret;

			if (dll->FirstThunk)
			{
				xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
				xref.rva = dll->FirstThunk;
				ret = createOsXRef(map, getOffset(&dll->FirstThunk, map->data), xref);
				if (isError(ret))
					return ret;
			}

			if (dll->OriginalFirstThunk)
			{
				xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
				xref.rva = dll->OriginalFirstThunk;
				ret = createOsXRef(map, getOffset(&dll->OriginalFirstThunk, map->data), xref);
				if (isError(ret))
					return ret;

				thunk = (thunkData*)(map->data + dll->OriginalFirstThunk);
			}
			else
				thunk = (thunkData*)(map->data + dll->FirstThunk);

			while (thunk->u1.AddressOfData)
			{
				xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
				xref.rva = thunk->u1.AddressOfData;
				ret = createOsXRef(map, getOffset(&thunk->u1.AddressOfData, map->data), xref);
				if (isError(ret))
					return ret;
				thunk++;
			}

			dll++;
		}

		return ENG_ERRNONE;
	}

	//resource
	if (dir == 2)
	{
		rsr = (resourceDirectory*)(map->data + dd->VirtualAddress);
		return registerResourceDir(map, rsr, rsr);
	}

	//exceptions: not supported
	if (dir == 3)
		return ENG_ERRPARS;

	//security: nop
	if (dir == 4)
		return ENG_ERRNONE;

	//basereloc
	//unpatchable: rvas can be patched but offsets are offsets to dwords in the code...
	//so reference is completely wrong and unpatchable because we dont know wich mutations
	//could be done on the instruction (also those refs are already patched by me).
	if (dir == 5)
		return ENG_ERRPARS;

	//debug
	if (dir == 6) 
	{
		dbg = (debugDirectory*)(map->data + dd->VirtualAddress);
		
		for (i = 0; i < dd->Size / sizeof(debugDirectory); i++)
		{
			xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
			xref.rva = dbg->AddressOfRawData;
			ret = createOsXRef(map, getOffset(&dbg->AddressOfRawData, map->data), xref);
			if (isError(ret))
				return ret;

			xref.type = XRF_USERVA|XRF_OS|XRF_PHYSIC; 
			xref.rva = dbg->AddressOfRawData; //entry is mapped at rva
			ret = createOsXRef(map, getOffset(&dbg->PointerToRawData, map->data), xref);
			if (isError(ret))
				return ret;

			dbg++;
		}

		return ENG_ERRNONE;
	}

	//architecture: nop
	if (dir == 7)
		return ENG_ERRNONE;

	//global ptr: nop
	if (dir == 8)
		return ENG_ERRNONE;

	//tls
	if (dir == 9)
	{
		tls = (tlsDirectory*)(map->data + dd->VirtualAddress);

		//register xrefs for members: all are VAs
		xref.type = XRF_USERVA|XRF_OS;
		xref.rva = tls->AddressOfCallBacks - nt->OptionalHeader.ImageBase;
		ret = createOsXRef(map, getOffset(&tls->AddressOfCallBacks, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS;
		xref.rva = tls->AddressOfIndex - nt->OptionalHeader.ImageBase;
		ret = createOsXRef(map, getOffset(&tls->AddressOfIndex, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS;
		xref.rva = tls->EndAddressOfRawData - nt->OptionalHeader.ImageBase;
		ret = createOsXRef(map, getOffset(&tls->EndAddressOfRawData, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS;
		xref.rva = tls->StartAddressOfRawData - nt->OptionalHeader.ImageBase;
		ret = createOsXRef(map, getOffset(&tls->StartAddressOfRawData, map->data), xref);
		if (isError(ret))
			return ret;

		//for each function register xref
		funcs = (dword*)(map->data + tls->AddressOfCallBacks - nt->OptionalHeader.ImageBase);
		while (*funcs)
		{
			xref.type = XRF_USERVA|XRF_OS;
			xref.rva = *funcs - nt->OptionalHeader.ImageBase;
			ret = createOsXRef(map, getOffset(funcs, map->data), xref);
			if (isError(ret))
				return ret;

			funcs++;
		}

		return ENG_ERRNONE;
	}

	//load config: nop
	if (dir == 10)
		return ENG_ERRNONE;

	//bound import
	if (dir == 11)
	{
		bound = (boundImportDescriptor*)(map->data + dd->VirtualAddress);
		
		while (bound->TimeDateStamp)
		{
			//bound import offset module name is physical offset
			//from base of bound structure, it is also word sized
			xref.type = XRF_USERVA|XRF_OS|XRF_PHYSIC|XRF_SRCBASE|XRF_USEDELTA|XRF_WORD; 
			xref.srcdelta = -getOffset(&bound->OffsetModuleName, bound);
			xref.rva = getOffset(bound, map->data) + bound->OffsetModuleName;
			xref.rva = offsetToRVA(nt, xref.rva); //calculate rva from offset

			ret = createOsXRef(map, getOffset(&bound->OffsetModuleName, map->data), xref);
			if (isError(ret))
				return ret;
			bound++;
		}

		return ENG_ERRNONE;
	}

	//iat: nop
	if (dir == 12)
		return ENG_ERRNONE;

	//com descriptor: unsupported (.net exes)
	if (dir == 14)
		return ENG_ERRPARS;

	//should never be here
	return ENG_ERRPARS;
}

/**********************************************************************************
prepareMap:
	prepare map for a pe file.

	in: map, pe header
	out: err code
***********************************************************************************/
int prepareMap(imageMap* map, ntHeaders* nt)
{
	register int ret;
	register dword i, flags;
	register sectionHeader* sh;

	imageXRef xref;

	ret = ENG_ERRNONE;
	xref.srcdelta = xref.dstdelta = 0;
	
	//tag headers as os data block
	tagEntities(map, 0, nt->OptionalHeader.SizeOfHeaders, IE_OSDATA|IE_OSPHYS, 1);

	//register xref for entity point field
	xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
	xref.rva = nt->OptionalHeader.AddressOfEntryPoint;
	ret = createOsXRef(map, getOffset(&nt->OptionalHeader.AddressOfEntryPoint, map->data), xref);
	if (isError(ret))
		return ret;

	//for each section header tag section blocks
	for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		sh = (sectionHeader*)(nt + 1);
		sh += i;

		//check empty section headers
		if (!sh->PointerToRawData || !sh->VirtualAddress || !sh->SizeOfRawData)
			continue;

		//register xrefs for section
		xref.type = XRF_USERVA|XRF_OS|XRF_PHYSIC; 
		xref.rva = sh->VirtualAddress; //right entry is mapped at rva
		ret = createOsXRef(map, getOffset(&sh->PointerToRawData, map->data), xref);
		if (isError(ret))
			return ret;

		xref.type = XRF_USERVA|XRF_OS|XRF_REL; 
		xref.rva = sh->VirtualAddress;
		ret = createOsXRef(map, getOffset(&sh->VirtualAddress, map->data), xref);
		if (isError(ret))
			return ret;

		//tag data as physic and right attributes
		flags = IE_OSPHYS;
		if (sh->Characteristics & 0x20000000) //IMAGE_SCN_MEM_EXECUTE
			flags |= IE_OSEXEC;
		if (sh->Characteristics & 0x40000000) //IMAGE_SCN_MEM_READ
			flags |= IE_OSREAD;
		if (sh->Characteristics & 0x80000000) //IMAGE_SCN_MEM_WRITE
			flags |= IE_OSWRITE;

		//do not use known cause we dont know exactly what it is inside each section
		//code section could have also data as you well know
		tagEntities(map, sh->VirtualAddress, sh->SizeOfRawData, flags, 0);
	}

	/*for each directory entity add xref and tag target*/
	for (i = 0; i < NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		if (!nt->OptionalHeader.DataDirectory[i].VirtualAddress ||
			!nt->OptionalHeader.DataDirectory[i].Size)
		{
			continue;
		}

		ret = prepareDataDirectory(map, nt, i);
		if (isError(ret))
			return ret;
	}

	return ret;
}

/**********************************************************************************
disassemblePE:
	public function for disassembling a complete portable executable file.

	in: map
	out: err code
***********************************************************************************/
int disassemblePE(imageMap* map)
{
	register ntHeaders* nt;
	register int err;

	if (!map ||!map->data)
		return ENG_ERRPARS;

	nt = peHeader(map->data);
	if (nt == NULL)
		return ENG_ERRPARS;

	//initialize map
	err = initImageMap(map, nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage);
	if (isError(err))
		return err;
	
	//prepare image
	err = prepareMap(map, nt);
	if (isError(err))
		return err;

	//disassemble all code
	err = disassembleCode(map, nt->OptionalHeader.AddressOfEntryPoint);
	if (isError(err))
		resetImageMap(map);
	else
		err = compressImageMap(map);

	return err;
}

