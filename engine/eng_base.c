
#include "eng_base.h"

/**********************************************************************************
newImageEntity:
	creates a new image entity in specified map at specified offset and length.

	in: map, offset, length
	out: imageEntity ptr
***********************************************************************************/
imageEntity* newImageEntity(imageMap* map, dword offset, dword length)
{
	register imageEntity *ret;
	register dword i;

	//check length and offset
	if (!length)
		return NULL;

	if (offset + length > map->imageSize)
		return NULL;

	//allocate new structure
	ret = (imageEntity*)map->heapAgent->malloc(sizeof(imageEntity));
	if (!ret)
		return NULL;

	//set initial values
	zeroStruct(ret, sizeof(imageEntity));
	ret->flags = IE_UNKNOWN;
	ret->data = map->data + offset;
	ret->length = length;

	//map it on the ptrs map
	for (i = 0; i < length; i++)
		map->entities[offset + i] = ret;
	return ret;
}

/**********************************************************************************
destroyImageEntity:
	destroy an imageEntity structure freeing all data (if any).

	in: entity, heap
	out: void
***********************************************************************************/
void destroyImageEntity(imageEntity* entity, heapManager* heap)
{
	register dword i;

	if (entity->data && (entity->flags & IE_OWNDATA))
		heap->free(entity->data);

	for (i = 0; i < ENG_MAXXREFS; i++)
	{
		if (entity->xrefs[i]) 
			heap->free(entity->xrefs[i]);
		
		entity->xrefs[i] = NULL;
	}

	heap->free(entity);
}

/**********************************************************************************
createImageEntity:
	create an image entity at offset with specified length merging sub entities
	if necessary and possible, emulate bool only emulate operation returning
	NULL on error or 1st byte pointer on success.

	in: map, offset, length, heap
	out: imageEntity ptr
***********************************************************************************/
imageEntity* createImageEntity(imageMap* map, dword offset, dword length, cbool emulate)
{
	register imageEntity *next, *ret;
	register dword i, flags, noflags;

	//always we will not merge code, labels, ref data, next to be merged
	noflags = IE_MAIN|IE_CODE|IE_LABEL|IE_REFDATA|IE_ELABING;
	flags = 0;
	
	i = 0;
	for (i = 0; i < length; i++)
	{
		next = map->entities[offset + i];
		
		if (!next) //im trying to merge already merged entities
			return NULL;

		if (i)
		{
			if ((next->flags & flags) != flags || (next->flags & noflags))
				return NULL; //every entity must have flags and no flags
		}
		
		//calculate new flags: we must not change sections, os types
		flags = (next->flags & IE_OSMASK);
	}

	//ok it was just a check
	if (emulate)
		return map->entities[offset];
	
	//we have more entities, but they can all be merged
	ret = NULL;
	for (i = 0; i < length; i++)
	{
		if (!ret)
			ret = map->entities[offset + i];
		else if (map->entities[offset + i] != ret)
			destroyImageEntity(map->entities[offset + i], map->heapAgent);

		map->entities[offset + i] = NULL; //remove entity ptr for midbytes
	}

	map->entities[offset] = ret; //set entity ptr to first byte

	ret->flags &= ~IE_UNKNOWN; //remove unknown
	ret->data = map->data + offset;
	ret->length = length;
	return ret;
}

/**********************************************************************************
hasXRefs:
	return count of xrefs for current entity.

	in: entity
	out: num of xrefs
***********************************************************************************/
dword hasXRefs(imageEntity* ent)
{
	register dword i, ret;

	ret = 0;
	for (i = 0; i < ENG_MAXXREFS; i++)
		if (ent->xrefs[i]) ret++;
	
	return ret;
}

/**********************************************************************************
tagEntities:
	tag entities from specified rva to specified length with flags 
	removing IE_UNKNOWN if specified: entities are part of os image structure.

	in: map, rva, len, flags, known bool
	out: void
***********************************************************************************/
void tagEntities(imageMap* map, dword rva, dword length, dword flags, cbool known)
{
	register dword i;
	for (i = rva; i < rva + length; i++)
	{
		map->entities[i]->flags |= flags;
		if (known)
			map->entities[i]->flags &= ~IE_UNKNOWN;
	}
}

/**********************************************************************************
untagEntities:
	untag entities from specified rva to specified length removing specified flags.

	in: map, rva, len, flags
	out: void
***********************************************************************************/
void untagEntities(imageMap* map, dword rva, dword length, dword flags)
{
	register dword i;
	for (i = rva; i < rva + length; i++)
		map->entities[i]->flags &= ~flags;
}

/**********************************************************************************
newImageXRef:
	create new XRef that points to target.

	in: heap manager
	out: imageXRef ptr
***********************************************************************************/
imageXRef* newImageXRef(heapManager* heap)
{
	register imageXRef* ret;
	
	ret = (imageXRef*)heap->malloc(sizeof(imageXRef));
	if (!ret)
		return NULL;

	ret->srcdelta = ret->dstdelta = ret->type = 0;
	ret->target = NULL;
	return ret;
}

/**********************************************************************************
initImageMap:
	initialize an empty image map.

	in: map, data, image virtual address, image size, heap
	out: err code
***********************************************************************************/
int initImageMap(imageMap* map, dword va, dword size)
{
	register dword i;

	map->virtualAddress = va;
	map->imageSize = size;

	//allocate map of ptrs
	map->entities = (imageEntity**)map->heapAgent->malloc(sizeof(imageEntity*) * size);
	if (!map->entities)
		return ENG_ERRMEM;

	//for each entity pointer create a 1 byte element (we must do this since we 
	//need each byte have its own infos for xrefs etc)
	for (i = 0; i < map->imageSize; i++)
		map->entities[i] = newImageEntity(map, i, 1);
	
	return ENG_ERRNONE;
}

/**********************************************************************************
registerXRef:
	register an xref into map from given source, destination, type.
	
	in: map, src, xref struct
	out: err code
***********************************************************************************/
int registerXRef(imageMap* map, imageEntity* src, imageXRef xref)
{
	register dword i, free;
	register imageXRef *ret;
	
	free = ENG_MAXXREFS;
	ret = NULL;

	for (i = 0; i < ENG_MAXXREFS; i++)
	{
		if (!src->xrefs[i])
		{
			if (free == ENG_MAXXREFS)
				free = i;
			continue;
		}

		if (src->xrefs[i]->target == xref.target)
			return ENG_WARNOK; //found
	}

	//no more room for other xrefs
	if (free == ENG_MAXXREFS)
		return ENG_ERRMEM;

	//new xref dynamically allocated
	ret = newImageXRef(map->heapAgent);
	if (!ret)
		return ENG_ERRMEM;

	//save xref into source and copy infos
	//src->flags |= IE_HASXREFS;
	src->xrefs[free] = ret;
	*ret = xref;

	/*if (xref.type & XRF_USERVA)
		map->entities[xref.rva]->flags |= IE_ISTARGET;
	else
		xref.target->flags |= IE_ISTARGET;*/
	return ENG_ERRNONE;
}

/**********************************************************************************
compressImageMap:
	compress an imageMap to a linked list form.

	in: map
	out: err code
***********************************************************************************/
int compressImageMap(imageMap* map)
{
	register imageEntity *entity; 
	register int start, end;
	register dword i, j, flags;
	register byte* data;

	register imageEntity* dst;

	//check map before
	if (!map->imageSize || !map->entities || !map->data)
		return ENG_ERRPARS;

	if (map->flags & IM_ISLINKED)
		return ENG_WARNOK;
	
	//merge all unknown data into blocks (if any)
	start = -1; end = -1; 
	i = flags = 0; 
	
	while (i < map->imageSize)
	{
		entity = map->entities[i];
		
		//set end offset if start already set
		if (start != -1 && 
			(hasXRefs(entity) != 0 ||
			(entity->flags & (IE_LABEL|IE_REFDATA|IE_CODE|IE_OSREFED)) ||
			(entity->flags & IE_OSMASK) != flags))
		{
			end = i;
		}
		
		if (end != -1 && start != -1) //try merging blocks
		{
			if (end > start + 1) //do not merge same byte
				createImageEntity(map, start, end - start, 0);
			start = end = -1;
		}

		//set start: try to merge also data without refs
		if (start == -1 && 
			!hasXRefs(entity) &&
			!(entity->flags & (IE_LABEL|IE_CODE)) &&
			entity->length == 1)
		{
			start = i;
			flags = (entity->flags & IE_OSMASK);
		}
		
		i += entity->length;
	}

	//remaining block opened: set end offset
	if (start)
	{
		end = map->imageSize;
		createImageEntity(map, start, end - start, 0);
	}

	i = 0; //for each block: finalize map
	while (i < map->imageSize)
	{
		entity = map->entities[i];
		entity->flags &= ~IE_UNKNOWN; //delete unknown

#ifdef ENG_NOVIRTUAL
		entity->flags |= IE_OSPHYS; //disable virtual entities
#endif

		//consolidate xrefs using pointers
		for (j = 0; j < ENG_MAXXREFS; j++)
		{
			if (!entity->xrefs[j])
				continue;

			dst = map->entities[entity->xrefs[j]->rva];
			if (!dst)
			{
				map->heapAgent->free(entity->xrefs[j]);
				entity->xrefs[j] = NULL;
			}
			else
			{
				entity->xrefs[j]->type &= ~XRF_USERVA;
				entity->xrefs[j]->target = dst;
			}
		}


		//allocate data
		if (map->flags & IM_COPYDATA)
		{
			data = (byte*)map->heapAgent->malloc(entity->length);
			if (!data) 
				return ENG_ERRMEM; 

			copyStruct(data, map->data + i, entity->length);
			entity->data = data; //copy it into entity
			entity->flags |= IE_OWNDATA; //set flags
		}

		//link entities to each other
		if (i + entity->length < map->imageSize)
			entity->next = map->entities[i + entity->length];
		else
			entity->next = NULL;

		i += entity->length;
	}

	//save first entity pointer
	entity = *map->entities;

	map->heapAgent->free(map->entities); //delete entities array

	//create new array of 1 pointer
	map->entities = map->heapAgent->malloc(sizeof(imageEntity**));
	if (!map->entities)
		return ENG_ERRMEM;

	*map->entities = entity; //link first entity and set flags
	map->flags |= IM_ISLINKED;
	return ENG_ERRNONE;
}

/*
------------------------------------------------------------------------------------
								public useful functions:
------------------------------------------------------------------------------------
*/

/**********************************************************************************
zeroStruct:
	reset to zero a mem structure.

	in: void*, size
	out: void
***********************************************************************************/
void zeroStruct(void* ptr, dword size)
{
	register dword i;
	register byte* b = (byte*)ptr;

	for (i = 0; i < size; i++)
		*b++ = 0;
}

/**********************************************************************************
copyStruct:
	copy a mem structure to another one.

	in: void*, void*, size
	out: void
***********************************************************************************/
void copyStruct(void* dst, void* src, dword size)
{
	register dword i;
	register byte *d = (byte*)dst, *s = (byte*)src;

	for (i = 0; i < size; i++)
		*d++ = *s++;
}

/**********************************************************************************
resetImageMap:
	reset all infos of an image map freein all data.

	in: map
	out: void
***********************************************************************************/
void resetImageMap(imageMap* map)
{
	register imageEntity *entity, *prev;
	register dword i;

	i = 0;
	entity = *map->entities;
	while (entity) //for each entity destroy it
	{
		prev = entity;

		if (map->flags & IM_ISLINKED)
			entity = entity->next; //linked map: already disasmed
		else
			entity = map->entities[i + entity->length]; //temporary map
		
		i += prev->length;
		destroyImageEntity(prev, map->heapAgent);
	}

	if (map->entities) //free array
		map->heapAgent->free(map->entities);

	//reset infos
	map->virtualAddress = map->imageSize = 
		map->flags = 0;
	map->entities = NULL;
	map->data = NULL;
}

/**********************************************************************************
rvaToEntity:
	from given map and rva returns entity if found and remaining offset 
	from entity base.

	in: map, rva, (out)remaining
	out: entity
***********************************************************************************/
imageEntity* rvaToEntity(imageMap* map, dword rva, dword* rem)
{
	register imageEntity* cur;
	register dword base;

	if (!map || !map->entities ||
		!(map->flags & IM_ISLINKED))
	{
		return NULL;
	}

	base = 0;
	cur = *map->entities;
	while (cur && base < rva)
	{
		if (rva >= base && rva < base + cur->length)
			break;

		base += cur->length;
		cur = cur->next;
	}

	if (base > rva)
		return NULL;
	
	if (rem)
		*rem = rva - base;

	return cur;
}

/**********************************************************************************
entityToRVA:
	from given map and entity returns rva 
	(if invalid entity returns ENG_INVALIDRVA).

	in: map, entity
	out: rva
***********************************************************************************/
dword entityToRVA(imageMap* map, imageEntity* entity)
{
	register imageEntity* cur;
	register dword rva;

	if (!map || !entity || !map->entities ||
		!(map->flags & IM_ISLINKED))
	{
		return ENG_INVALIDRVA;
	}

	rva = 0;
	cur = *map->entities;
	while (cur)
	{
		if (cur == entity)
			break;
		rva += cur->length;
		cur = cur->next;
	}

	if (!cur)
		return ENG_INVALIDRVA;
	return rva;
}

/**********************************************************************************
offsetToEntity:
	from given map and offset returns entity if found and remaining offset 
	from entity base.

	in: map, offset, (out)remaining
	out: entity
***********************************************************************************/
imageEntity* offsetToEntity(imageMap* map, dword offset, dword* rem)
{
	register imageEntity* cur;
	register dword base;

	if (!map || !map->entities ||
		!(map->flags & IM_ISLINKED))
	{
		return NULL;
	}

	base = 0;
	cur = *map->entities;
	while (cur && base < offset)
	{
		if (offset >= base && offset < base + cur->length)
			break;

		if (cur->flags & IE_OSPHYS)
			base += cur->length;

		cur = cur->next;
	}

	if (base > offset)
		return NULL;
	
	if (rem)
		*rem = offset - base;

	return cur;
}

/**********************************************************************************
entityToOffset:
	from given map and entity returns offset 
	(if invalid entity returns ENG_INVALIDOFF).

	in: map, entity
	out: rva
***********************************************************************************/
dword entityToOffset(imageMap* map, imageEntity* entity)
{
	register imageEntity* cur;
	register dword off;

	if (!map || !entity || !map->entities ||
		!(map->flags & IM_ISLINKED))
	{
		return ENG_INVALIDOFF;
	}

	off = 0;
	cur = *map->entities;
	while (cur)
	{
		if (cur == entity)
			break;
		
		if (cur->flags & IE_OSPHYS)
			off += cur->length;

		cur = cur->next;
	}

	if (!cur)
		return ENG_INVALIDOFF;

	return off;
}
