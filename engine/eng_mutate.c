
#include "eng_base.h"

/**********************************************************************************
removeAllXRefs:
	remove all xrefs for specified entity.

	in: map, entity
	out: void
***********************************************************************************/
void removeAllXRefs(imageMap* map, imageEntity* entity)
{
	register imageEntity* cur;
	register dword i, xrefs;

	cur = *map->entities;
	while (cur) //for each entity
	{
		xrefs = 0; //for each xref count and find target
		for (i = 0; i < ENG_MAXXREFS; i++)
		{
			if (!cur->xrefs[i]) 
				continue;

			xrefs++; //target found: remove xref and dec count
			if (cur->xrefs[i]->target == entity)
			{
				map->heapAgent->free(cur->xrefs[i]);
				cur->xrefs[i] = NULL;
				xrefs--;
			}
		}

		cur = cur->next;
	}
}

/*
------------------------------------------------------------------------------------
								public functions
------------------------------------------------------------------------------------
*/

/**********************************************************************************
deleteEntity:
	public function for deleting an entity.

	in: map, entity
	out: err code
***********************************************************************************/
int deleteEntity(imageMap* map, imageEntity* entity)
{
	register imageEntity *prev, *cur;

	//check pars: must be disasmed map and no virtual entity
	if (!map || !entity || !map->entities || 
		!(map->flags & IM_ISLINKED) ||
		(entity->flags & IE_OSPHYS))
	{
		return ENG_ERRPARS;
	}

	prev = NULL;
	cur = *map->entities;
	
	while (cur && cur != entity)
	{
		prev = cur; //find previous entity in list
		cur = cur->next;
	}
	
	if (!cur) //not found
		return ENG_ERRMAP;

	if (prev) //unlink entity
		prev->next = cur->next;
	else
		*map->entities = cur->next;

	//remove all xrefs for entity and destroy mem
	removeAllXRefs(map, cur);

	destroyImageEntity(cur, map->heapAgent);
	return ENG_ERRNONE;
}

/**********************************************************************************
addEntity:
	public function for adding data/code into image linkin it correctly and setting
	initial infos.

	in: map, previous entity, data, data length, flags
	out: ptr
***********************************************************************************/
imageEntity* addEntity(imageMap* map, imageEntity* prev, byte* data, dword length, 
					   dword flags)
{
	register imageEntity* ret;

	//check pars: no readonly map, check flags
	if (!map || !data || !length || !map->entities ||
		!(map->flags & IM_ISLINKED) || (map->flags & IM_READONLY) ||
		(flags & ~IE_USERMASK))
	{	
		return NULL;
	}

	//physic entities must be always contiguos
	if ((flags & IE_OSPHYS) && prev && !(prev->flags & IE_OSPHYS))
		return NULL;

	//create new entity
	ret = map->heapAgent->malloc(sizeof(imageEntity));
	if (!ret)
		return NULL;

	zeroStruct(ret, sizeof(imageEntity));
	
	//always copy data internally
	ret->data = (byte*)map->heapAgent->malloc(length);
	if (!ret->data)
	{
		map->heapAgent->free(ret);
		return NULL;
	}

	//set infos
	ret->flags = flags|IE_OWNDATA;
	copyStruct(ret->data, data, length);
	ret->length = length;
	
	if (prev)
	{
		ret->next = prev->next;
		prev->next = ret;
	}
	else
	{
		prev->next = *map->entities;
		*map->entities = ret;
	}

	return ret;
}

/**********************************************************************************
resizeEntity:
	resize entity and data if necessary.

	in: map, entity, new size
	out: err code
***********************************************************************************/
int resizeEntity(imageMap* map, imageEntity* entity, dword size)
{
	register byte* data;

	//check pars: linked and no read only
	if (!map || !entity || !size || !map->entities ||
		!(map->flags & IM_ISLINKED) || (map->flags & IM_READONLY))
	{
		return ENG_ERRPARS;
	}
	
	if (size == entity->length)
		return ENG_WARNOK;

	//if size < length and entity doesnt have own data just set length
	if (size < entity->length && !(entity->flags & IE_OWNDATA))
		entity->length = size;
	else
	{
		//otherwise create new buffer and copy old one
		data = map->heapAgent->malloc(size);
		if (!data)
			return ENG_ERRMEM;

		copyStruct(data, entity->data, entity->length);
		if (entity->flags & IE_OWNDATA)
			map->heapAgent->free(entity->data);

		entity->data = data;
		entity->flags |= IE_OWNDATA;
	}

	return ENG_ERRNONE;
}

/**********************************************************************************
addXRef:
	add specified xref to entity.

	in: map, entity, xref
	out: err code
***********************************************************************************/
int addXRef(imageMap* map, imageEntity* entity, imageXRef xref)
{
	//check pars: linked and no read only, xref must use pointer
	if (!map || !entity || !map->entities ||
		!(map->flags & IM_ISLINKED) || (map->flags & IM_READONLY) ||
		(xref.type & XRF_USERVA))
	{
		return ENG_ERRPARS;
	}

	return registerXRef(map, entity, xref);
}

/**********************************************************************************
rwData:
	read\write data from\to entities.

	in: map, write or read, base entity, offset, size, buffer
	out: err code
***********************************************************************************/
int rwData(imageMap* map, cbool bWrite, imageEntity* base, dword off, 
		   dword size, byte* buff)
{
	register imageEntity* cur;
	register dword coff, i;
	register sdword mod;
	register byte *source, *dest;

	//check pars: linked and no read only, xref must use pointer
	if (!map || !base || !size || !map->entities ||
		!(map->flags & IM_ISLINKED) || (map->flags & IM_READONLY))
	{
		return ENG_ERRPARS;
	}

	cur = base;
	coff = 0;
	while (cur && size)
	{
		if (off >= coff && off < coff + cur->length)
			mod = off - coff; //calculate starting offset
		else
			mod = 0;

		//if data it is inside current entity
		if (coff + mod >= off)
		{
			//set source and dest pointers
			source = (bWrite ? buff : cur->data + mod);
			dest = (bWrite ? cur->data + mod : buff);
			
			for (i = mod; i < cur->length; i++)
			{
				//no remaining bytes
				if (!size) 
					break;
				
				//copy bytes and decrease count
				*dest++ = *source++;
				size--;
				buff++;
			}
		}

		//move to next entity
		coff += cur->length;
		cur = cur->next;
	}

	if (size) //went outside map
		return ENG_ERRPARS;

	return ENG_ERRNONE;
}
