
#ifndef ENGINE_BASE_H_

#define ENGINE_BASE_H_

#include "engine.h"

//private functions
int initImageMap(imageMap* map, dword va, dword size);

imageEntity* createImageEntity(imageMap* map, dword offset, dword length, cbool emulate);
void destroyImageEntity(imageEntity* entity, heapManager* heap);

void tagEntities(imageMap* map, dword rva, dword length, dword flags, cbool known);
void untagEntities(imageMap* map, dword rva, dword length, dword remflags);

dword hasXRefs(imageEntity* ent);

int registerXRef(imageMap* map, imageEntity* src, imageXRef xref);

void resetImageMap(imageMap* map);

int compressImageMap(imageMap* map);

#endif