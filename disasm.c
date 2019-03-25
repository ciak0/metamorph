/**********************************************************************************
					Single Instruction Disassembler\Assembler

	- uses Architecture implementations.
**********************************************************************************/

#include "disasm.h"

/**********************************************************************************
readBitsStream:
	read specified bits stream from base, return bits in low positions.

	in: base, bitsStream
	out: dword value
***********************************************************************************/
dword readBitsStream(dword* base, bitsStream* bs)
{
	register dword ret, value, mask, i;
	register word disp;

	ret = 0; disp = bs->disp;

	if (bs->disp + bs->len >= 32)
	{
		disp = bs->disp - ((bs->disp >> 3) << 3);
		base = (dword*)((byte*)base + (bs->disp >> 3));
	}

	value = endian(*base);
	for (i = 0; i < bs->len; i++) /*for each bit*/
	{
		mask = value & (0x01 << (31 - disp - i)); /*read bit from value*/
		ret |= mask; /*set it big-endian*/
	}
	return ret >> (32 - disp - bs->len); /*shift to low positions*/
}

/**********************************************************************************
writeBitsStream:
	puts in buffer bits specified by bitsStream.

	in: bitsStream, output buff
	out: void (+buff)
***********************************************************************************/
void writeBitsStream(bitsStream* bs, byte* buff)
{
	register dword byteoff, bitoff, i, mask;
	register byte *out;
	
	bitoff = bs->disp % 8;
	byteoff = bs->disp >> 3;
	out = buff + byteoff; /*shift base with offset*/

	for (i = 0; i < bs->len; i++) /*for each bit of stream*/
	{
		if (bitoff == 8){ out++; bitoff = 0; } /*if bit offset reached max -> next byte*/

		/*read the i-bit from the bit stream value*/
		mask = bs->value & (0x01 << (bs->len-1-i));
		mask >>= bs->len-1-i; /*set it to lowest bit*/

		*out |= (((byte)mask) << (7-bitoff)); /*set buffer bit*/
		bitoff++; /*increase bit offset*/
	}
}

/**********************************************************************************
binInstrLen:
	get binary instruction length (last bitsField displacement + length).

	in: binInstruction
	out: length in bits
***********************************************************************************/
dword binInstrLen(binInstruction* bin)
{
	dword i, len;

	if (!bin)
		return 0;

	len = 0;
	for (i = 0; i < MAX_BFS_COUNT; i++)
	{
		if (!bin->fields[i].type)
			break;
		len += bin->fields[i].stream.len;
	}
	return len;
}

/**********************************************************************************
resetBinInstruction:
	reset to empty binInstruction.

	in: binInstruction
	out: void
***********************************************************************************/
void resetBinInstruction(binInstruction* binstr)
{
	dword i;

	if (!binstr) 
		return;
	
	binstr->id = ID_NONE;
	binstr->type = FAMILY_NONE;
	binstr->flags = BIF_NONE;
	for (i = 0; i < MAX_BFS_COUNT; i++)
	{
		binstr->fields[i].flags = BFF_NONE;
		binstr->fields[i].type = BFT_NONE;
		binstr->fields[i].stream.disp = binstr->fields[i].stream.len = 0;
		binstr->fields[i].stream.value = 0;
	}
}

/**********************************************************************************
isConditional:
	check if an instruction is a conditional jump

	in: asmInstruction
	out: cbool
***********************************************************************************/
cbool isConditional(asmInstruction* jmp)
{
	register dword i, j;

	if (jmp->type != FAMILY_FLOW) 
		return 1;
	if (!(jmp->flags & AIF_FLOWABS)) 
		return 1;

	for (i = 0; i < OPERANDS_COUNT; i++)
	{
		if (!jmp->ops[i])
			continue;
		for (j = 0; j < jmp->ops[i]->fieldsCount; j++)
		{
			if (jmp->ops[i]->fields[j].type == AFT_COND) 
				return 1;
		}
	}

	return 0;
}

/**********************************************************************************
addField:
	add dynamic asmField to asmOperand.

	in: asmOperand, heap manager
	out: last field added
***********************************************************************************/
asmField* addField(asmOperand* operand, heapManager* heap)
{
	asmField *last, *src, *out;
	dword i;

	if (!operand || !heap)
		return NULL;
	if (!heap->malloc || !heap->free) 
		return NULL;

	src = operand->fields; /*save ptr, alloc new array*/
	out = (asmField*)heap->malloc(sizeof(asmField) * (operand->fieldsCount + 1));
	if (!out) 
		return NULL;

	operand->fields = out; /*save ptr to operand*/
	if (src)
	{
		last = src;
		for (i = 0; i < operand->fieldsCount; i++) /*copy old array*/
		{
			out->type = src->type;
			out->value = src->value;
			src++; out++;
		}
		heap->free(last); /*free old array*/
	}

	operand->fieldsCount++; /*increase count and reset values*/
	out->type = 0;
	out->value = 0;
	return out;
}

/**********************************************************************************
addOperand:
	add dynamic asmOperand to instruction.

	in: asmInstruction, heap manager
	out: last operand added
***********************************************************************************/
asmOperand* addOperand(asmInstruction* ainstr, heapManager* heap)
{
	asmOperand** out; 
	dword i;

	if (!ainstr || !heap) 
		return NULL;
	if (!heap->malloc || !heap->free) 
		return NULL;

	out = NULL;
	for (i = 0; i < OPERANDS_COUNT; i++)
	{
		if (ainstr->ops[i]) 
			continue;
		out = &ainstr->ops[i];
		break;
	}

	if (!out)
		return NULL;

	*out = (asmOperand*)heap->malloc(sizeof(asmOperand));
	if (!(*out)) 
		return NULL;

	(*out)->fieldsCount = 0;
	(*out)->fields = NULL;
	(*out)->flags = 0;
	return (*out);
}

/**********************************************************************************
resetAsmInstruction:
	reset to empty asmInstruction using heapManager.

	in: asmInstruction, heapManager
	out: void
***********************************************************************************/
void resetAsmInstruction(asmInstruction* ainstr, heapManager* heap)
{
	register dword i;

	if (!ainstr || !heap)
		return;
	if (!heap->free) 
		return;

	ainstr->id = ID_NONE;
	ainstr->length = 0;
	ainstr->flags = AIF_NONE;
	ainstr->type = FAMILY_NONE;

	for (i = 0; i < OPERANDS_COUNT; i++)
	{
		if (ainstr->ops[i])
		{
			if (ainstr->ops[i]->fields)
				heap->free(ainstr->ops[i]->fields);
			heap->free(ainstr->ops[i]);
		}
		ainstr->ops[i] = NULL;
	}
}


/**********************************************************************************
nextSet:
	move to next instruction depending on set type (compressed or not).

	in: instruction set ptr, current bin instruction
	out: bin instruction ptr
***********************************************************************************/
binInstruction* nextSet(iSet* set, binInstruction* cur)
{
	register bitsField* field;

	if (set->type & ISET_COMPRESSED)
	{
		field = cur->fields;
		while (field->type)
			field++;
		return (binInstruction*)(&(field->flags));
	}
	
	return (cur + 1);
}

/**********************************************************************************
disassembleBinary:
	disassemble a binary string into an assembly instruction using specified
	instruction set.

	in: instruction set ptr, binary ptr, (out)assembly instruction
	out: dword (err code), assembly instruction
***********************************************************************************/
dword disassembleBinary(iSet* set, byte* ptr, heapManager* heap, asmInstruction* out_asm)
{
	register dword prefixes, prefLen;
	register word disp;
	register byte* opcode;

	register bitsField *field, *dynField; /*fields*/
	register binInstruction *curBin, *lastBin;
	
	register cbool bDump;
	register asmOperand** out_op;
	register asmField* out_field;

	bitsStream rdr; 
	binInstruction dynBin;
	word flags;
	cbool bPhys;

	/*check input errors*/
	if (!set || !heap || !ptr || !out_asm)
		return DISASM_ERRPARS;
	if (!heap->malloc || !heap->free) 
		return DISASM_ERRPARS;
	if (!set->disasmFilter || !set->disasmFields || !set->disasmLength ||
		!set->disasmPrefix || !set->bftTOaft || !set->id || !set->set)
	{
			return DISASM_ERRPARS;
	}

	opcode = ptr; 
	prefixes = prefLen = 0;
	field = NULL;
	lastBin = NULL;
	curBin = set->set;

	resetAsmInstruction(out_asm, heap); /*reset output*/
	resetBinInstruction(&dynBin); /*reset dyn instr*/
	
	while (curBin->id) /*for each instruction model into set*/
	{
		field = curBin->fields;
		disp = 0;
		while (field->type) /*for each constant bits field, check it*/
		{
			if (field->type == BFT_CONST)
			{
				rdr.disp = disp;
				rdr.len = field->stream.len;
				rdr.value = field->stream.value;

				if (readBitsStream((dword*)opcode, &rdr) != field->stream.value)
					goto nextL;
			}
			disp += field->stream.len;
			field++;
		}

		/*bit pattern matches instruction model*/

		if (curBin->flags & BIF_PREFIX) /*prefix instruction*/
		{
			prefLen = set->disasmPrefix(curBin, out_asm); /*call specific arch function*/
			if (!prefLen) 
				return DISASM_ERRSET; /*error*/
			
			opcode += prefLen; /*set opcode ptr*/
			curBin = set->set; /*perform new full search into set*/
			prefixes++;
			continue;
		}

		if (lastBin) 
			return DISASM_ERRPLUSINSTR; /*no prefix, instr already found!*/
		
		lastBin = curBin; /*save main instruction model*/

nextL:
		curBin = nextSet(set, curBin); /*next*/
	}
	
	if (!lastBin)
		return DISASM_ERRNOINSTR; /*instruction not found into set*/
	
	dynBin.id = lastBin->id; /*copy instr infos to dynamic one*/
	dynBin.type = lastBin->type;
	dynBin.flags = lastBin->flags;
	disp = 0;

	field = lastBin->fields;
	dynField = dynBin.fields;

	while (field->type) /*for each field into instr*/
	{
		bPhys = 1;
		dynField->type = field->type; /*copy infos to dynamic one*/
		dynField->flags = field->flags;
		dynField->stream.disp = disp;

		if (field->flags & BFF_VARLEN) /*field has variable length, call arch*/
		{
			dynField->stream.len = set->disasmLength(&dynBin, out_asm, dynField);
			if (!dynField->stream.len) 
				return DISASM_ERRSET; /*internal error*/
		}
		else
			dynField->stream.len = field->stream.len; /*copy length*/

		if (dynField->stream.len) /*read binary value using bitsStream*/
			dynField->stream.value = readBitsStream((dword*)opcode, &dynField->stream);
		else
			dynField->stream.value = field->stream.value; /*implicits*/

		if (dynField->flags & BFF_CONST) /*const field? check values*/
		{
			if (dynField->stream.value != field->stream.value) 
				return DISASM_ERRSET;
		}

		if (dynField->flags & BFF_DUMP) /*field can be dumped*/
		{
			flags = 0;
			bDump = set->disasmFilter(&dynBin, dynField, &flags, &bPhys);

			if (bDump) /*field has to be dumped*/
			{
				if (!(dynField->flags & (BFF_OP1|BFF_OP2|BFF_OP3)))
					return DISASM_ERRSET; /*none operand selected*/

				if (dynField->flags & BFF_OP1)
					out_op = &out_asm->ops[0];
				else if (dynField->flags & BFF_OP2)
					out_op = &out_asm->ops[1];
				else if (dynField->flags & BFF_OP3)
					out_op = &out_asm->ops[2];
				
				if (!(*out_op)) /*operand not found, allocate*/
				{
					*out_op = heap->malloc(sizeof(asmOperand));
					if (!(*out_op)) 
						return DISASM_ERRMEM;
					
					/*reset fields*/
					(*out_op)->fieldsCount = 0;
					(*out_op)->fields = NULL;
					(*out_op)->flags = 0;
				}

				(*out_op)->flags |= flags; /*add arch operand flags*/
				
				out_field = addField(*out_op, heap); /*add field to operand*/
				if (!out_field)
					return DISASM_ERRMEM; /*mem error*/
				
				out_field->type = set->bftTOaft(dynField); /*convert infos*/
				out_field->value = dynField->stream.value; /*set value*/
			}	
		}
		
		if (bPhys)
		{
			dynField->flags |= BFF_SET;
			disp += dynField->stream.len; /*increase displacement by length*/
		}
		field++; dynField++; /*next field*/
	}
	
	if (disp % 8 != 0) 
		return DISASM_ERRSET; /*byte misaligned, internal error*/

	set->disasmFields(&dynBin, out_asm); /*set eventual flags to instruction*/
	
	out_asm->id = dynBin.id; /*save output infos and return*/
	out_asm->type = dynBin.type;
	out_asm->length = prefLen + (disp >> 3);
	
	if (dynBin.flags & BIF_LENONLY)
		out_asm->flags |= AIF_LENONLY;
	if (dynBin.flags & BIF_FLOWABS)
		out_asm->flags |= AIF_FLOWABS;
	if (dynBin.flags & BIF_RARE)
		return DISASM_WARNRARE;
	return DISASM_ERRNONE;
}

/**********************************************************************************
assembleModel:
	assemble an assembly instruction into it's binary form using 
	specified instruction set and specified binary model.

	in: assembly instruction, instruction set ptr, model, (out)binary instruction
	out: cbool (1:compatible model, 0:err)
***********************************************************************************/
cbool assembleModel(asmInstruction* assembly, iSet* set, binInstruction* model,
					dword asmFlags, binInstruction* out_bin)
{
	register dword i, j, c;
	register word disp;

	c = set->asmPrefixes(assembly, out_bin->fields); /*assemble prefixes into bits*/
	for (i = 0; i < MAX_BFS_COUNT; i++) /*for each output field*/
	{
		if (i < c)
			out_bin->fields[i].flags |= BFF_SET; /*prefixes always included*/
		else
		{
			out_bin->fields[i].type = out_bin->fields[i].flags = 0; /*reset infos*/
			out_bin->fields[i].stream.disp = out_bin->fields[i].stream.len = 0;
			out_bin->fields[i].stream.value = 0;
		}
	}

	out_bin->id = model->id; /*copy model infos*/
	out_bin->type = model->type;
	out_bin->flags = model->flags;
	
	j = 0;
	for (i = c; i < MAX_BFS_COUNT; i++) /*copy fields from prefixes to end*/
	{
		if (!model->fields[j].type) 
			break; /*exit on last model field*/

		out_bin->fields[i].type = model->fields[j].type;
		out_bin->fields[i].flags = model->fields[j].flags;
		out_bin->fields[i].stream.len = model->fields[j].stream.len;
		out_bin->fields[i].stream.value = model->fields[j].stream.value;
		j++;
	}

	for (i = 0; i < OPERANDS_COUNT; i++) /*for each assembly operand*/
	{
		if (!assembly->ops[i]) 
			continue; /*if it's not present pass it*/
		if (!assembly->ops[i]->fieldsCount || !assembly->ops[i]->fields)
			continue;

		/*convert operand*/
		if (!set->asmConverter(out_bin, assembly, asmFlags, assembly->ops[i]))
			return 0; /*error, unconvertible*/
	}

	disp = 0;
	for (i = 0; i < MAX_BFS_COUNT; i++) /*delete unused fields*/
	{
		if (out_bin->fields[i].type == BFT_CONST)
			out_bin->fields[i].flags |= BFF_SET;
		if (!(out_bin->fields[i].flags & BFF_SET))
			out_bin->fields[i].stream.len = 0;

		disp += out_bin->fields[i].stream.len;
	}

	return (disp % 8) == 0;
}

/**********************************************************************************
assembleInstruction:
	assemble an assembly instruction into it's binary form using 
	specified instruction set.

	in: instruction set ptr, assembly instruction, asm flags, (out)binary ptr, out size
	out: dword (length of written bytes), binary string (if ptr given)
***********************************************************************************/
dword assembleInstruction(iSet* set, asmInstruction* assembly, dword flags,
						  byte* out_ptr, dword size)
{
	register dword i, len, founds;
	register dword minLen, minIndex, maxLen, maxIndex;
	register word disp;
	register binInstruction *scanBin;

	binInstruction outBin[MAX_BIN_COUNT];
	
	if (!set || !assembly) 
		return 0; /*check errors*/
	if (!set->asmPrefixes || !set->asmConverter || !set->set) 
		return 0;
	
	scanBin = set->set;
	len = founds = 0;
	while (scanBin->id) /*scan set in search of id*/
	{
		if (scanBin->id == assembly->id) /*same id, try assemble with model*/
		{
			if (assembleModel(assembly, set, scanBin, flags, &outBin[founds]))
			{
				founds++; /*save output*/
				if (founds == MAX_BIN_COUNT) 
					break;
			}
		}
		
		scanBin = nextSet(set, scanBin); /*next*/
	}

	if (!founds) 
		return 0; /*not found*/

	minLen = 0xFFFFFFFF; maxLen = 0;
	minIndex = maxIndex = founds;

	if (flags) /*assembly flags enabled*/
	{
		for (i = 0; i < founds; i++)
		{
			len = binInstrLen(&outBin[i]); /*get instruction length*/
			len >>= 3;
			
			if (len < minLen){ minLen = len; minIndex = i; } /*save min,max*/
			if (len > maxLen){ maxLen = len; maxIndex = i; }

			if ((flags & ASM_RARE) && (outBin->flags & BIF_RARE))
				break; /*rare flag, found*/
		}

		if (flags & ASM_SHORTEST) 
			i = minIndex; /*get min\max if enabled*/
		
		if (flags & ASM_LONGEST) 
			i = maxIndex;

		if (i == founds)
			return 0; /*can't choose instruction*/

		scanBin = &outBin[i];
	}
	else
		scanBin = &outBin[0]; /*get 1st one*/

	len = binInstrLen(scanBin); /*get length*/
	len >>= 3;

	if (!out_ptr) /*output ptr not given, just return length*/
		return len;
	if (len > size) /*output size too small*/
		return len;

	for (i = 0; i < len; i++) /*reset buffer*/
		out_ptr[i] = 0;

	disp = 0;
	for (i = 0; i < MAX_BFS_COUNT; i++) /*for each field*/
	{
		scanBin->fields[i].stream.disp = disp; /*calculate disp*/
		writeBitsStream(&scanBin->fields[i].stream, out_ptr); /*write stream*/
		disp += scanBin->fields[i].stream.len; /*increase disp*/
	}

	return len;
}

/**********************************************************************************
compressSet:
	compress instruction set removing all unused informations.

	in: instruction set ptr, (out)destination buffer, max size of buffer
	out: dword (length of written bytes into buffer)
***********************************************************************************/
dword compressSet(iSet* set, byte* out_buffer, dword size)
{
	register binInstruction *cur, *dst;
	register bitsField *cf, *df;
	register dword count;

	if (!set)
		return 0;
	if (!set->set)
		return 0;
	if (set->type & ISET_COMPRESSED)
		return 0;

	count = 0;
	cur = set->set;
	dst = (binInstruction*)out_buffer;

	while (cur->id)
	{
		if (dst && !(count + sizeof(dword) > size))
		{
			dst->id = cur->id;
			dst->type = cur->type;
			dst->flags = cur->flags;
		}
		count += sizeof(dword); /*id+type+flags*/

		cf = cur->fields;
		if (dst) 
			df = dst->fields;
		else
			df = NULL;

		while (cf->type)
		{
			if (df && !(count + sizeof(bitsField) > size))
			{
				df->type = cf->type;
				df->flags = cf->flags;
				df->stream = cf->stream;
				df++;
			}

			count += sizeof(bitsField);
			cf++;
		}

		/*null terminator field*/
		if (df && !(count + sizeof(word) > size))
			df->type = 0;
		count += sizeof(word);

		if (dst)
			dst = (binInstruction*)(&(df->flags));
		cur++;
	}

	/*null terminator*/
	if (dst && !(count + sizeof(byte) > size))
		dst->id = 0;
	count += sizeof(byte);

	return count;
}