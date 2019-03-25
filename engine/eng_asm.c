
#include "eng_base.h"

//operating system
#include "eng_pe.h"

//to be implemented for os
int alignSections(imageMap* );
int patchHeaders(imageMap* );

//architecure disassembler
#include "eng_x86.h"


/**********************************************************************************
patchXRefs:
	patch all xrefs for specified entity.

	in: image map, entity, rva for current entity, physic offset for current entity
	out: err code (warn ok if something changed)
***********************************************************************************/
int patchXRefs(imageMap* map, imageEntity* entity, dword rva, dword offset)
{
	register dword i, len, old, value;
	register int c;

	x86instr code;
	byte buff[ENG_MAXINSTRLEN];
	imageXRef xrefs[ENG_MAXXREFS];

	c = 0;
	for (i = 0; i < ENG_MAXXREFS; i++)
	{
		if (entity->xrefs[i])
		{
			xrefs[i] = *entity->xrefs[i];
			if (!(xrefs[i].type & XRF_USERVA))
			{
				//if it is a physic xref calculate offset instead of rva
				if (xrefs[i].type & XRF_PHYSIC)
					xrefs[i].rva = entityToOffset(map, xrefs[i].target);
				else
					xrefs[i].rva = entityToRVA(map, xrefs[i].target);

				xrefs[i].type |= XRF_USERVA;
			}
			c++;
		}
	}

	//no xrefs? quit
	if (!c)
		return ENG_ERRNONE;

	//entity is code, disassemble it, patch refs and reassemble it
	if (entity->flags & IE_CODE)
	{
		if (!disassembleBinary(entity->data, &code))
			return ENG_ERRASM;

		c = setTargets(rva, map->virtualAddress, &code, xrefs, c);
		if (c) //targets have changed
		{
			//reassemble instruction and copy new data
			len = assembleInstruction(&code, buff, ENG_MAXINSTRLEN);
			
			if (!(entity->flags & IE_OWNDATA) || len > entity->length)
			{
				if (entity->flags & IE_OWNDATA)
					map->heapAgent->free(entity->data);

				entity->data = map->heapAgent->malloc(len);
				if (!entity->data)
					return ENG_ERRMEM;

				entity->length = len;
				entity->flags |= IE_OWNDATA;
			}

			copyStruct(entity->data, buff, len);
			return ENG_WARNOK;
		}
	}
	else //entity is data
	{
		if (c != 1) //wtf? usually data has 1 ref max
			return ENG_ERRMAP;

		//check xref size: check appropriate length for data
		if (xrefs[0].type & XRF_BYTE)
		{
			if (entity->length < sizeof(byte))
				return ENG_ERRMAP;
			old = *entity->data;
		}
		else if (xrefs[0].type & XRF_WORD)
		{
			if (entity->length < sizeof(word))
				return ENG_ERRMAP;
			old = *((word*)entity->data);
		}
		else
		{
			if (entity->length < sizeof(dword))
				return ENG_ERRMAP;
			old = *((dword*)entity->data);
		}

		//xref uses delta: refresh rvas\offsets
		if (xrefs[0].type & XRF_USEDELTA)
		{
			rva += xrefs[0].srcdelta;
			offset += xrefs[0].srcdelta;
			xrefs[0].rva += xrefs[0].dstdelta;
		}

		//calculate new value depending if its relative\physic 
		//(data relative is meant relative from base address)
		if (xrefs[0].type & (XRF_REL|XRF_PHYSIC))
		{
			if (xrefs[0].type & XRF_SRCBASE)
			{
				if (xrefs[0].type & XRF_PHYSIC)
					value = xrefs[0].rva - offset;
				else
					value = xrefs[0].rva - rva;
			}
			else
				value = xrefs[0].rva;
		}
		else
			value = map->virtualAddress + xrefs[0].rva; //it is abs va
		
		//value changed: refresh data
		if (old != value)
		{
			if (xrefs[0].type & XRF_BYTE)
				*entity->data = (byte)value;
			else if (xrefs[0].type & XRF_WORD)
				*((word*)entity->data) = (word)value;
			else
				*((dword*)entity->data) = value;

			return ENG_WARNOK;
		}
	}

	return ENG_ERRNONE;
}

/**********************************************************************************
assembleCode:
	assemble all code.

	in: image map
	out: err code
***********************************************************************************/
int assembleCode(imageMap* map)
{
	register imageEntity* entity;
	register int err;
	register dword rva, offset, oldlen;
	register cbool patched;
	
	while(1) //until nothing changed
	{
		rva = offset = 0;
		patched = 0;
		entity = *map->entities;
		
		while (entity)
		{
			oldlen = entity->length;

			err = patchXRefs(map, entity, rva, offset); //patch xrefs (if any)
			if (isError(err))
				return err;

			if (oldlen != entity->length)
				patched = 1; //entity changed length: add pass

			rva += entity->length;

			if (entity->flags & IE_OSPHYS)
				offset += entity->length;

			entity = entity->next;
		}

		if (!patched) //everything patched
		{
			err = alignSections(map); //fix alignment etc
			patched = (err != ENG_ERRNONE);
		}

		if (isError(err))
			return err; //on error exit

		if (!patched)
			break; //nothing else to patch
	}

	map->imageSize = rva; //refresh total image size
	
	err = patchHeaders(map);
	if (isError(err))
		return err;

	return ENG_ERRNONE; //map is completely fixed and reassembled
}

/*
------------------------------------------------------------------------------------
						specific assembler functions
------------------------------------------------------------------------------------
*/

/**********************************************************************************
alignSections:
	align pe sections.

	in: map
	out: err code
***********************************************************************************/
int alignSections(imageMap* map)
{
	dosHeader dos;
	ntHeaders pe;
	sectionHeader cur;
	dword off;

	register byte* data;
	register imageEntity *first, *last, *ent, *lp;
	register dword i, phys, virt,
					psize, vsize,
					prevrva;
	register int err;

	//read dos & nt headers
	err = rwData(map, 0, *map->entities, 0, sizeof(dosHeader), (byte*)&dos);
	if (isError(err))
		return err;

	err = rwData(map, 0, *map->entities, dos.e_lfanew, sizeof(ntHeaders), (byte*)&pe);
	if (isError(err))
		return err;

	prevrva = pe.OptionalHeader.SizeOfHeaders;

	//for each section header
	for (i = 0; i < pe.FileHeader.NumberOfSections; i++)
	{
		off = dos.e_lfanew + sizeof(ntHeaders) + (sizeof(sectionHeader) * i);
		
		err = rwData(map, 0, *map->entities, off, sizeof(sectionHeader), (byte*)&cur);
		if (isError(err))
			return err;

		//get first and last entities of previous section
		first = rvaToEntity(map, prevrva, NULL);
		if (!first)
			return ENG_ERRMAP;

		last = rvaToEntity(map, cur.VirtualAddress - 1, NULL);
		if (!last)
			return ENG_ERRMAP;

		//if ptr not aligned to file: we must increase size
		if (cur.PointerToRawData & (pe.OptionalHeader.FileAlignment-1))
		{
			//calculate new address aligned to pe
			phys = pe_align(cur.PointerToRawData, pe.OptionalHeader.FileAlignment);
			
			//for each virtual entity in the previous section
			//set em physical and recalculate cur addresses
			ent = first; 
			lp = last;

			do
			{
				//on virtual entity try to set it physical if needed
				if (!(ent->flags & IE_OSPHYS))
				{
					if (cur.PointerToRawData + ent->length > phys)
						break; //if size exceed quit

					//else set it physic and refresh addresses
					ent->flags |= IE_OSPHYS;
					cur.PointerToRawData += ent->length;
				}
				else
					lp = ent; //save last physical entity

				ent = ent->next;
			} while (ent != last);
			
			//ok, recalculate how much i need for phys & virtual entities
			psize = phys - cur.PointerToRawData;
			
			//allocate data for new entity
			data = map->heapAgent->malloc(psize);
			if (!data)
				return ENG_ERRMEM;

			//add it to map
			ent = addEntity(map, lp, data, psize, IE_OSPHYS);
			
			map->heapAgent->free(data);
			if (!ent)
				return ENG_ERRMAP;

			return ENG_WARNOK;
			//changed++;
		}

		//virtual address not aligned to pe
		if (cur.VirtualAddress & (pe.OptionalHeader.SectionAlignment - 1))
		{
			virt = pe_align(cur.VirtualAddress, pe.OptionalHeader.SectionAlignment);
			vsize = (virt - cur.VirtualAddress);

			//refresh last entity
			last = rvaToEntity(map, cur.VirtualAddress - 1, NULL);
			if (!last)
				return ENG_ERRMAP;

			//allocate data for entity
			data = map->heapAgent->malloc(vsize);
			if (!data)
				return ENG_ERRMEM;

			//add virtual entity to map
			ent = addEntity(map, last, data, vsize, 0);
			
			map->heapAgent->free(data);
			if (!ent)
				return ENG_ERRMAP;

			return ENG_WARNOK;
		}

		prevrva = cur.VirtualAddress;
	}

	//errnone: nothing changed
	return ENG_ERRNONE;
}

/**********************************************************************************
patchHeaders:
	patch pe headers with new infos.

	in: map
	out: err code
***********************************************************************************/
int patchHeaders(imageMap* map)
{
	dosHeader dos;
	ntHeaders pe;
	sectionHeader cur, prev;

	register dword i, off;
	register int err;

	err = rwData(map, 0, *map->entities, 0, sizeof(dosHeader), (byte*)&dos);
	if (isError(err)) 
		return err;

	err = rwData(map, 0, *map->entities, dos.e_lfanew, sizeof(ntHeaders), (byte*)&pe);
	if (isError(err))
		return err;

	//for each section
	for (i = 0; i < pe.FileHeader.NumberOfSections; i++)
	{
		off = dos.e_lfanew + sizeof(ntHeaders) + (sizeof(sectionHeader) * i);
		
		err = rwData(map, 0, *map->entities, off, sizeof(sectionHeader), (byte*)&cur);
		if (isError(err))
			return err;

		//refresh pe header size of headers or previous section header
		if (!i)
			pe.OptionalHeader.SizeOfHeaders = cur.PointerToRawData;
		else
		{
			prev.SizeOfRawData = cur.PointerToRawData - prev.PointerToRawData;
			prev.Misc.VirtualSize = cur.VirtualAddress - prev.VirtualAddress;

			//write previous section header
			err = rwData(map, 1, *map->entities, off - sizeof(sectionHeader), sizeof(sectionHeader), (byte*)&prev);
			if (isError(err))
				return err;
		}

		prev = cur;
	}

	//refresh imagebase and size
	pe.OptionalHeader.ImageBase = map->virtualAddress;
	pe.OptionalHeader.SizeOfImage = map->imageSize;
	pe.OptionalHeader.CheckSum = 0;
	//todo: patch checksum and other unused things

	err = rwData(map, 1, *map->entities, dos.e_lfanew, sizeof(ntHeaders), (byte*)&pe);
	if (isError(err))
		return err;
	
	return ENG_ERRNONE;
}

/**********************************************************************************
assemblePE:
	public function for assembling a complete pe.

	in: map
	out: err code
***********************************************************************************/
int assemblePE(imageMap* map)
{
	//check map before
	if (!map || !map->entities || !(map->flags & IM_ISLINKED) || 
		(map->flags & IM_READONLY))
	{
		return ENG_ERRPARS;
	}

	//assemble all code
	return assembleCode(map);
}
