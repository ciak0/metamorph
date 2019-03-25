/**********************************************************************************
					Single Instruction Disassembler\Assembler

	- uses Architecture implementations.
**********************************************************************************/

#ifndef DISASM_H_

/************************** common declares ***************************/
#define DISASM_H_

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


/**********************************************************************/

/************************* common macro declares **********************/

#define ALIGN_TO_BYTE(bits)	((bits) >> 3 & 0xf ? (bits) : ((bits) + 8) & ~7)

#define endian(dw) (((dw)>>24)&0x000000FF) | \
					(((dw)>>8)&0x0000FF00) | \
					(((dw)<<8)&0x00FF0000) | \
					(((dw)<<24)&0xFF000000)

/**********************************************************************/

/************************* constant declares **************************/

/*binary*/
#define MAX_BFS_COUNT	12
#define MAX_BIN_COUNT	4

/*errors*/
#define DISASM_ERRNONE		0
#define DISASM_ERRPARS		1 /*wrong params*/
#define DISASM_ERRNOINSTR	2 /*instruction not found*/
#define DISASM_ERRPLUSINSTR	3 /*more decoding for binary*/
#define DISASM_ERRSET		4 /*internal instruction set error*/
#define DISASM_ERRCODE		5 /*bad opcode\prefixes sequence*/
#define DISASM_ERRMEM		6 /*no more memory*/

#define DISASM_WARNRARE		7 /*warning: rare instruction*/

/*flags*/
#define ASM_NONE			0x00
#define ASM_SHORTEST		0x01
#define ASM_LONGEST			0x02
#define ASM_RARE			0x04

/*instruction sets arch dependents*/
#define ISET_NONE	0x00

/*instruction operands*/
#define OPERANDS_COUNT	3

/*instructuons ids: arch dependents*/
#define ID_NONE			0x00
#define ID_ARCHS		0x01

/*instructions families*/
#define FAMILY_NONE		0x00
#define FAMILY_MATH		0x01
#define FAMILY_LOGIC	0x02
#define FAMILY_MOVE		0x03
#define FAMILY_STACK	0x04
#define FAMILY_FLOW		0x05
#define FAMILY_BITS		0x06
#define FAMILY_TEST		0x07
#define FAMILY_NOP		0x08
#define FAMILY_INT		0x09

/**********************************************************************/

/************************* struct declares ****************************/

/*** bitsStream (size: 8) ***/
typedef struct bitsStream_s{
	word disp; word len;
	dword value;
} bitsStream;

/*** bitsField (size:4+8) ***/
typedef struct bitsField_s{
	word type; word flags;
	bitsStream stream;
} bitsField;

typedef cbool (*BF_COMPARE_FUNC)(bitsField*, bitsField*);

/*type values:*/
#define BFT_NONE	0x0000
#define BFT_CONST	0x0001 /*constant field (opcode)*/
#define BFT_ARCHS	0x0002 /*arch dependent values*/
/*other values are archs dependent*/

/*flags:*/
#define BFF_NONE	0x0000
#define BFF_DUMP	0x0001 /*dump content to output*/
#define BFF_DYN		0x0002 /*dynamic field*/
#define BFF_OP1		0x0004
#define BFF_OP2		0x0008
#define BFF_OP3		0x0010
#define BFF_CONST	0x0020 /*field must have specified constant value*/
#define BFF_VARLEN	0x0040 /*field has variable length, must use arch rules*/
#define BFF_SET		0x0080 /*field value already set (useful in assembly)*/
#define BFF_ARCHS	0x0100 /*arch dependent values*/
/*other values are archs dependent*/

/*** binary instruction (size:4+[12*MAX_BFS_COUNT]) ***/
typedef struct binaryInstruction_s{
	byte id; byte type;
	word flags;
	bitsField fields[MAX_BFS_COUNT];
} binInstruction;

/*id: arch dependents*/
/*types: family*/

/*flags*/
#define BIF_NONE		0x0000
#define BIF_LENONLY		0x0001
#define BIF_PREFIX		0x0002
#define BIF_RARE		0x0004
#define BIF_FLOWABS		0x0008
#define BIF_ARCHS		0x0010
/*others are arch dependent*/

/*** assembly field (size:8) ***/
typedef struct assemblyField_s{
	dword type;
	dword value;
} asmField;

/*type values*/
#define AFT_NONE	0x00000000
#define AFT_COND	0x00000001
#define AFT_REG		0x00000002
#define AFT_IMM		0x00000003
#define AFT_ADDR	0x00000004
#define AFT_OFFSET	0x00000005
#define AFT_ARCH	0x00000100
/*others are arch dependent*/

/*** assembly operand (size:12) ***/
typedef struct assemblyOperand_s{
	dword flags;
	dword fieldsCount;
	asmField* fields;
} asmOperand;

/*flag values*/
#define AOF_NONE	0x00000000
#define AOF_MEMORY	0x00000001 /*mem operand address*/
#define AOF_SIGNED	0x00000002 /*signed immediate*/
#define AOF_SOURCE	0x00000004
#define AOF_DEST	0x00000008

/*** assembly instruction (size:8+[4*OPERANDS_COUNT]) ***/
typedef struct assemblyInstruction_s{
	byte id; byte type;
	word flags;
	dword length;
	asmOperand* ops[OPERANDS_COUNT];
} asmInstruction;

/*id: same as binInstruction*/
/*type: same as binInstruction*/

/*flags*/
#define AIF_NONE	0x0000
#define AIF_LENONLY	0x0001
#define AIF_FLOWABS	0x0002
#define AIF_ARCHS	0x0010
/*others are arch dependent*/

/*** instruction set (used for disassembly\assembly) ***/
typedef dword (*DISPREFIX_FUNC)(binInstruction*, asmInstruction*);
typedef void (*DISFIELDS_FUNC)(binInstruction*, asmInstruction*);
typedef cbool (*DISFILTER_FUNC)(binInstruction*, bitsField*, word*, cbool*);
typedef word (*DISLEN_FUNC)(binInstruction*, asmInstruction*, bitsField*);

typedef dword (*ASMPREF_FUNC) (asmInstruction*, bitsField*);
typedef dword (*ASMCONV_FUNC)(binInstruction*, asmInstruction*, dword, asmOperand*);

typedef dword (*BFTTOAFT_FUNC)(bitsField*);

#define ISET_COMPRESSED		0x01

typedef struct instructionSet_s{
	word id; word type;

	DISPREFIX_FUNC disasmPrefix;
	DISFIELDS_FUNC disasmFields;
	DISFILTER_FUNC disasmFilter;
	DISLEN_FUNC	disasmLength;

	BFTTOAFT_FUNC bftTOaft; /*translator: bitsField type to asmField type*/

	ASMPREF_FUNC asmPrefixes;
	ASMCONV_FUNC asmConverter;
	
	binInstruction* set;
} iSet;

/*** o\s heap manager ***/
typedef void* (*MALLOC_FUNC)(unsigned int);
typedef void (*FREE_FUNC)(void*);

typedef struct heapManager_s{
	MALLOC_FUNC malloc;
	FREE_FUNC free;
} heapManager;

/**********************************************************************/

void resetAsmInstruction(asmInstruction* ainstr, heapManager* heap);

asmOperand* addOperand(asmInstruction* ainstr, heapManager* heap);
asmField* addField(asmOperand* operand, heapManager* heap);

cbool isConditional(asmInstruction* jmp);

dword disassembleBinary(iSet* set, byte* ptr, heapManager* heap, asmInstruction* out_asm);
dword assembleInstruction(iSet* set, asmInstruction* assembly, dword flags, byte* out_ptr, dword size);

/*24-04-09: added compressed set type and routines*/
dword compressSet(iSet* set, byte* out_buffer, dword size);

#endif
