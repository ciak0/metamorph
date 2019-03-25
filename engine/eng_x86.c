
#include "eng_x86.h"
#include "eng_x86tbl.c"

#define XDE32_DEFAULT_ADDR      32      //16 or 32, changed by 0x67 prefix
#define XDE32_DEFAULT_DATA      32      //16 or 32, changed by 0x66 prefix

dword reg2xset(int reg_sz, dword reg)
{
	if (reg_sz == 1)
		return reg == 0 ? XSET_AL :
				reg == 1 ? XSET_CL :
				reg == 2 ? XSET_DL :
				reg == 3 ? XSET_BL :
				reg == 4 ? XSET_AH :
				reg == 5 ? XSET_CH :
				reg == 6 ? XSET_DH :
						  XSET_BH;
	else if (reg_sz == 2)
		return reg == 0 ? (XSET_AX|XSET_AL|XSET_AH) :
				reg == 1 ? (XSET_CX|XSET_CL|XSET_CH) :
				reg == 2 ? (XSET_DX|XSET_DL|XSET_DH) :
				reg == 3 ? (XSET_BX|XSET_BL|XSET_BH) :
				reg == 4 ? XSET_SP :
				reg == 5 ? XSET_BP :
				reg == 6 ? XSET_SI :
						  XSET_DI;
	else
		return reg == 0 ? (XSET_EAX|XSET_AX|XSET_AL|XSET_AH) :
				reg == 1 ? (XSET_ECX|XSET_CX|XSET_CL|XSET_CH) :
				reg == 2 ? (XSET_EDX|XSET_DX|XSET_DL|XSET_DH) :
				reg == 3 ? (XSET_EBX|XSET_BX|XSET_BL|XSET_BH) :
				reg == 4 ? (XSET_ESP|XSET_SP) :
				reg == 5 ? (XSET_EBP|XSET_BP) :
				reg == 6 ? (XSET_ESI|XSET_SI) :
						  (XSET_EDI|XSET_DI);
}

dword disassembleBinary(byte *buff, x86instr *out)
{
	register byte c, *p;
	register dword flag, a, d, i, xset;
	register dword mod, reg, rm, index, base;

	p = buff;

	for (i = 0; i < sizeof(x86instr); i++)
	  ((byte*)out)[i] = 0;

	out->defdata = XDE32_DEFAULT_ADDR/8;
	out->defaddr = XDE32_DEFAULT_DATA/8;

	flag = 0;

	if (*(unsigned short*)p == 0x0000)
		flag |= C_BAD;
	if (*(unsigned short*)p == 0xFFFF)
		flag |= C_BAD;

	while(1)
	{
		c = *p++;

		//size prefixes
		if (c == 0x66)
		{
			if (out->p_66 != 0) 
				flag |= C_BAD; //twice 

			out->p_66 = 0x66;
			out->defdata = (XDE32_DEFAULT_DATA^32^16) / 8;
			continue;
		}

		if (c == 0x67)
		{
			if (out->p_67 != 0) 
				flag |= C_BAD; //twice 

			out->p_67 = 0x67;
			out->defaddr = (XDE32_DEFAULT_ADDR^32^16)/8;
			continue;
		}

		//segments
		if ((c == 0x26) || (c == 0x2E) || (c == 0x36) || (c == 0x3E) ||
			(c == 0x64) || (c == 0x65))
		{
			if (out->p_seg != 0) 
				flag |= C_BAD; //twice 
			out->p_seg = c;
			continue;
		}

		//rep
		if ((c == 0xF2) || (c == 0xF3))
		{
			if (out->p_rep != 0)
				flag |= C_BAD; //twice 
			out->p_rep = c;
			continue;
		}

		//lock
		if (c == 0xF0)
		{
			if (out->p_lock != 0)
				flag |= C_BAD; //twice 
			out->p_lock = c;
			continue;
		}

		break;

	} //do while prefix found 

	//rep uses implicit ecx
	if (out->p_rep)
	{
		xset = XSET_FL | (out->defdata == 2 ? XSET_CX : XSET_ECX);
		out->src_set |= xset;
		out->dst_set |= xset;
	}

	//instruction flags by buff 
	flag |= x86_table[TBL_NORMAL + c];

	if (flag == C_ERROR)
		return 0;

	out->opcode = c;

	//0F two byte opcodes
	if (c == 0x0F)
	{
		c = *p++;

		//2nd buff 
		flag |= x86_table[TBL_0F + c]; //from the 2nd half of the table 

		if (flag == C_ERROR)
			return 0;

		out->opcode2 = c;

		//0F-prefixed "special" opcodes 
		if ( (c == 0xB2) || (c == 0xB4) || (c == 0xB5) || //lss/lfs/lgs reg,r/m 
			 (c == 0xA1) || (c == 0xA9) )                 //pop fs, gs 
		{
			out->dst_set |= XSET_OTHER;
		}

		if ((c == 0xA0) || (c == 0xA8))  //push fs, gs 
			out->src_set |= XSET_OTHER;

		if (c == 0xA2) //cpuid 
		{
			out->src_set |= XSET_EAX;
			out->dst_set |= XSET_EAX|XSET_EBX|XSET_ECX|XSET_EDX;
		}

		if ((c == 0xA5) || (c == 0xAD))   //shld/shrd r/m, reg, CL 
			out->src_set |= XSET_CL;
	}
	else
	{
		//"special" opcodes

		if ((c == 0xA4) || (c == 0xA5) || //movsb, movsd 
			(c == 0xA6) || (c == 0xA7))   //cmpsb, cmpsd 
		{
			//66 or 67 ? 
			xset = out->defaddr == 2 ? (XSET_SI | XSET_DI) : (XSET_ESI | XSET_EDI);
			out->src_set |= xset;
			out->dst_set |= xset;
		}

		if ((c == 0xAC) || (c == 0xAD)) //lodsb, lodsd 
		{
			xset = out->defaddr == 2 ? XSET_SI : XSET_ESI;
			out->src_set |= xset;
			out->dst_set |= xset;
		}

		if ((c == 0xAA) || (c == 0xAB) || //stosb, stosd 
			(c == 0xAE) || (c == 0xAF))   //scasb, scasd 
		{
			xset = out->defaddr == 2 ? XSET_DI : XSET_EDI;
			out->src_set |= xset;
			out->dst_set |= xset;
		}

		if ((c == 0x6C) || (c == 0x6D)) //insb, insd 
		{
			//66/67 ? 
			xset = XSET_DEV | (out->defaddr == 2 ? XSET_DI : XSET_EDI);
			out->src_set |= xset | XSET_DX;
			out->dst_set |= xset;
		}
		if ((c == 0x6E) || (c == 0x6F)) //outsb, outsd 
		{
			xset = XSET_DEV | (out->defaddr == 2 ? XSET_SI : XSET_ESI);
			out->src_set |= xset | XSET_DX;
			out->dst_set |= xset;
		}

		if (c == 0x9E) //sahf 
			out->src_set |= XSET_AH;
		if (c == 0x9F) //lahf 
			out->dst_set |= XSET_AH;

		if (c == 0x98) //cbw, cwde 
		{
			out->src_set |= out->defdata == 2 ? XSET_AL : XSET_AX;
			out->dst_set |= out->defdata == 2 ? XSET_AX : XSET_EAX;
		}
		if (c == 0x99) //cwd, cdq 
		{
			out->src_set |= out->defdata == 2 ? XSET_AX : XSET_EAX;
			out->dst_set |= out->defdata == 2 ? XSET_DX : XSET_EDX;
		}

		if ((c == 0x37) || (c == 0x3F)) //aaa, aas 
		{
			out->src_set |= XSET_AH;
			out->dst_set |= XSET_AH;
		}

		if ((c == 0xD4) || (c == 0xD5)) //aam xx, aad xx 
		{
			out->src_set |= c == 0xD4 ? XSET_AL : XSET_AX;
			out->dst_set |= XSET_AX;
		}

		if (c == 0x60) //pusha 
			out->src_set |= out->defdata == 2 ? XSET_ALL16 : XSET_ALL32;
		if (c == 0x61) //popa 
			out->dst_set |= out->defdata == 2 ? XSET_ALL16 : XSET_ALL32;

		if ((c == 0xE4) || (c == 0xE5) || //in al|(e)ax, NN 
			(c == 0xE6) || (c == 0xE7))   //out NN, al|(e)ax 
		{
			//66,67 ? 
			out->src_set |= XSET_DEV;
			out->dst_set |= XSET_DEV;
		}

		if ((c == 0xEC) || (c == 0xED)) //in al|(e)ax, dx 
		{
			//66,67 ? 
			out->src_set |= XSET_DEV | XSET_DX;
			out->dst_set |= XSET_DEV;
		}
		if ((c == 0xEE) || (c == 0xEF)) //out dx, al|(e)ax 
		{
			//66,67 ? 
			out->src_set |= XSET_DEV;
			out->dst_set |= XSET_DEV | XSET_DX;
		}

		//push es, cs, ss, ds 
		if ((c == 0x06) || (c == 0x0E) || (c == 0x16) || (c == 0x1E))
			out->src_set |= XSET_OTHER;

		if ((c == 0x07) || (c == 0x17) || (c == 0x1F) ||  //pop es, ss, ds 
			(c == 0xC4) || (c == 0xC5)) //les/lds reg, r/m 
		{
			out->dst_set |= XSET_OTHER;
		}

		if (c == 0xD7) //xlat 
			out->src_set |= out->defaddr == 2 ? XSET_BX : XSET_EBX;

		if ((c == 0xC8) || (c == 0xC9)) //enter xxxx, yy || leave 
		{
			xset = out->defaddr == 2 ? (XSET_SP | XSET_BP) : (XSET_ESP | XSET_EBP);
			out->src_set |= xset;
			out->dst_set |= xset;
		}

		if (c == 0x8C)  //mov [r/m]:16, sreg 
			out->src_set |= XSET_OTHER;
		if (c == 0x8E)  //mov sreg, [r/m]:16 
			out->dst_set |= XSET_OTHER;
	}

	//mod rm parse
	if (flag & C_MODRM)
	{
		c = *p++;

		out->modrm = c;

		mod = c & 0xC0;
		reg = (c & 0x38) >> 3; //reg or ttt 
		rm  = c & 0x07;

		c = out->opcode;

		//shift 
		if ((c == 0xC0) || (c == 0xC1) || ((c >= 0xD0) && (c <= 0xD3)))
		{
			//ttt: 0=rol 1=ror 2=rcl 3=rcr 4=shl 5=shr 6=sal 7=sar
			if ((reg == 2) || (reg == 3)) //rcl, rcr -- uses CF 
				out->src_set |= XSET_FL;
			if ((c == 0xD2) || (c == 0xD3))
				out->src_set |= XSET_CL;
		}

		if ((c == 0xC6) || (c == 0xC7) || (c == 0x8F)) //mov [r/m], imm8/16/32, pop [r/m] 
			if (reg != 0) flag |= C_BAD; //ttt=000, other illegal

		if ((c >= 0x80) && (c <= 0x83))
			flag |= x86_table[TBL_80_83 + reg];

		if (c == 0xBA)
			if (reg >= 5) //bts/btr/btc [r/m], imm8 
				flag |= C_DST_RM;

		if (c == 0xF6)
			flag |= x86_table[TBL_F6 + reg];
		if (c == 0xF7)
			flag |= x86_table[TBL_F7 + reg];
		if (c == 0xFE)
			flag |= x86_table[TBL_FE + reg];
		if (c == 0xFF) 
			flag |= x86_table[TBL_FF + reg];

		if ((c == 0xF6) || (c == 0xF7))
		{
			if ((reg == 4) || (reg == 5)) //mul/imul r/m 
			{
				if (c == 0xF6)
				{
					out->src_set |= XSET_AL;
					out->dst_set |= XSET_AX;
				}
				else if (out->defaddr == 2)
				{
					out->src_set |= XSET_AX;
					out->dst_set |= XSET_DX | XSET_AX;
				}
				else
				{
					out->src_set |= XSET_EAX;
					out->dst_set |= XSET_EDX | XSET_EAX;
				}
			}

			if ((reg == 6) || (reg == 7)) //div/idiv r/m 
			{
				if (c == 0xF6)
				{
					out->src_set |= XSET_AX;
					out->dst_set |= XSET_AX;
				}
				else if (out->defaddr == 2)
				{
					out->src_set |= XSET_DX | XSET_AX;
					out->dst_set |= XSET_DX | XSET_AX;
				}
				else
				{
					out->src_set |= XSET_EDX | XSET_EAX;
					out->dst_set |= XSET_EDX | XSET_EAX;
				}
			}
		}
		//F6, F7

		if (flag == C_ERROR)
			return 0;

		xset = reg2xset(flag & C_OPSZ8 ? 1 : out->defdata, reg);
		if (flag & C_SRC_REG) 
			out->src_set |= xset;
		if (flag & C_DST_REG) 
			out->dst_set |= xset;

		if (mod == 0xC0)
		{
			xset = reg2xset(flag & C_OPSZ8 ? 1 : out->defdata, rm);
			//defaddr (0x67) prefix --> ??? 
			if (flag & C_DST_RM)
				out->dst_set |= xset;

			if ( (out->opcode == 0x0F) &&
			   ( (out->opcode2 == 0xB6) ||  //movzx, movsx 
				 (out->opcode2 == 0xB7) ||
				 (out->opcode2 == 0xBE) ||
				 (out->opcode2 == 0xBF) ) )
			{
				 xset = reg2xset(out->defdata == 4 ? 2 : 1, rm);
			}

			if (flag & C_SRC_RM)
				out->src_set |= xset;
		}
		else
		{
			if (out->opcode != 0x8D) //LEA: doesnt access memory contents 
			{
				out->src_set |= XSET_OTHER;  //since we have sreg:[xxx] 
				if (flag & C_SRC_RM)
					out->src_set |= XSET_MEM;
			}

			if (flag & C_DST_RM)
				out->dst_set |= XSET_MEM;

			//32-bit MODR/M 
			if (out->defaddr == 4)
			{	
				if (mod == 0x40)
					flag |= C_ADDR1;
				else if (mod == 0x80)
					flag |= C_ADDR4;

				//SIB
				if (rm == 4)
				{
					flag |= C_SIB;
					c = *p++;
					out->sib = c;

					//scale = c & 0xC0;
					index = (c & 0x38) >> 3;
					base = c & 0x07;

					if (base == 5)
					{
						xset = (mod == 0 ? 0 : XSET_EBP) | reg2xset(4, index);
						if (mod == 0) 
							flag |= C_ADDR4;
						if (flag & C_SRC_RM)
							out->src_set |= xset;
						if (flag & C_DST_RM)
							out->src_set |= xset;
					}
					else
					{
						xset = reg2xset(4, base);
						if (flag & C_SRC_RM)
							out->src_set |= xset;
						if (flag & C_DST_RM)
							out->src_set |= xset;

						if (index != 0x05)
						{
						  xset = reg2xset(4, index);
						  if (flag & C_SRC_RM)
							  out->src_set |= xset;
						  if (flag & C_DST_RM) 
							  out->src_set |= xset;
						}
					}
				}
				else
				{
					//no sib, just modr/m 32 
					if ((mod == 0x00) && (rm == 0x05))
						flag |= C_ADDR4;
					else
					{
						xset = reg2xset(4, rm);
						if (flag & C_SRC_RM) 
							out->src_set |= xset;
						if (flag & C_DST_RM) 
							out->src_set |= xset;
					}
				}
			}
			else
			{
				//16-bit MODR/M 

				if (mod == 0x40)
					flag |= C_ADDR1;
				else if (mod == 0x80)
					flag |= C_ADDR2;
				else //mod == 0x00 
				{
					if (rm == 0x06)
						flag |= C_ADDR2;
				}

				if ((mod != 0x00) || (rm != 0x06))
				{
					xset = rm == 0 ? (XSET_BX | XSET_SI) :
						 rm == 1 ? (XSET_BX | XSET_DI) :
						 rm == 2 ? (XSET_BP | XSET_SI) :
						 rm == 3 ? (XSET_BP | XSET_DI) :
						 rm == 4 ? XSET_SI :
						 rm == 5 ? XSET_DI :
						 rm == 6 ? XSET_BP :
								   XSET_BX;
					if (flag & C_SRC_RM)
						out->src_set |= xset;
					if (flag & C_DST_RM) 
						out->src_set |= xset;
				}
			}
		}
	} //C_MODRM 
	else
	{
		//its not modr/m, check for mem ref 
		if (flag & C_SRC_RM) 
			out->src_set |= XSET_MEM;
		if (flag & C_DST_RM) 
			out->dst_set |= XSET_MEM;
	}

	if (flag & C_UNDEF)
	{
		out->src_set = XSET_UNDEF;
		out->dst_set = XSET_UNDEF;
	}

	//implicit r0
	xset = reg2xset(out->defdata, c & 0x07);
	if (flag & C_SRC_R0)
		out->src_set |= xset;
	if (flag & C_DST_R0) 
		out->dst_set |= xset;

	//has fl
	if (flag & C_SRC_FL)
		out->src_set |= XSET_FL;
	if (flag & C_DST_FL)
		out->dst_set |= XSET_FL;

	xset = out->defaddr == 2 ? XSET_SP : XSET_ESP; //incorrect, need stk seg sz
	if (flag & C_PUSH)
	{
		out->src_set |= xset;                              //+
		out->dst_set |= xset | XSET_MEM;
	}
	if (flag & C_POP)
	{
		out->src_set |= xset | XSET_MEM;                   //+
		out->dst_set |= xset;
	}

	xset = flag & C_OPSZ8 ? XSET_AL : out->defdata == 2 ? XSET_AX : XSET_EAX;
	if (flag & C_SRC_ACC)
		out->src_set |= xset;
	if (flag & C_DST_ACC)
		out->dst_set |= xset;

	a =  flag & (C_ADDR1 | C_ADDR2 | C_ADDR4);
	d = (flag & (C_DATA1 | C_DATA2 | C_DATA4)) >> 8;

	if (flag & C_ADDR67)
		a += out->defaddr;
	if (flag & C_DATA66) 
		d += out->defdata;

	for(i=0; i<a; i++)
		out->addr_b[i] = *p++;

	for(i=0; i<d; i++)
		out->data_b[i] = *p++;

	out->flag = flag;
	out->addrsize = a;
	out->datasize = d;
	out->len = p - buff;

	return out->len;
}

dword assembleInstruction(x86instr* dis, byte* out, dword size)
{
	byte* p;
	dword i;
	dword ret;

	p = out;
	ret = 0;
	
	if (dis->p_seg)
	{
		if (p && ret < size)
			*p++ = dis->p_seg;
		ret++;
	}
	if (dis->p_lock)
	{
		if (p && ret < size)
			*p++ = dis->p_lock;
		ret++;
	}
	if (dis->p_rep)
	{
		if (p && ret < size)
			*p++ = dis->p_rep;
		ret++;
	}
	if (dis->p_67)
	{
		if (p && ret < size)
			*p++ = dis->p_67;
		ret++;
	}
	if (dis->p_66)
	{
		if (p && ret < size)
			*p++ = dis->p_66;
		ret++;
	}
	
	*p++ = dis->opcode;
	ret++;

	if (dis->opcode == 0x0F)
	{
		if (p && ret < size)
			*p++ = dis->opcode2;
		ret++;
	}
	if (dis->flag & C_MODRM)
	{
		if (p && ret < size)
			*p++ = dis->modrm;
		ret++;
	}
	if (dis->flag & C_SIB)
	{
		if (p && ret < size)
			*p++ = dis->sib;
		ret++;
	}
	for(i = 0; i < dis->addrsize; i++)
	{
		if (p && ret < size)
			*p++ = dis->addr_b[i];
		ret++;
	}
	for(i = 0; i < dis->datasize; i++)
	{
		if (p && ret < size)
			*p++ = dis->data_b[i];
		ret++;
	}

	return ret;
}

int getTargets(dword rva, dword ib, x86instr* code, imageXRef* out, dword size)
{
	register int ret;
	register sdword rel;
	
	imageXRef value;

	value.dstdelta = value.srcdelta = 0;
	value.rva = 0;

	ret = 0;
	if (code->addrsize)
	{
		value.type = XRF_USERVA|XRF_USEADDR;
		value.rva = -1;

		if ((code->flag & C_REL) || //rel (call/jcc/jmp)
			(code->flag & C_CMD_CALL) || //call commands
			((code->flag & C_STOP) && //jumps excluding rets
			  code->opcode != 0xC2 && code->opcode != 0xC3 &&
			  code->opcode != 0xCA && code->opcode != 0xCB &&
			  code->opcode != 0xCF))
		{
			value.type |= XRF_JUMP;
		}
		
		if (code->sib)
			value.type |= XRF_SIB;
		else
			value.type |= XRF_MEMORY;

		rel = (sdword)code->addr_d;
		if (code->addrsize == sizeof(word))
		{
			rel = (short)code->addr_d;
			value.type |= XRF_WORD;	
		}
		else if (code->addrsize == sizeof(byte))
		{
			rel = (char)code->addr_d;
			value.type |= XRF_BYTE;
		}
		
		if (code->addr_d > ib)
			value.rva = code->addr_d - ib;
		
		if (value.rva != -1)
		{
			if (ret != size && out)
				*out++ = value;
			ret++;
		}
	}
	if (code->datasize)
	{
		value.type = XRF_USERVA|XRF_USEDATA;
		value.rva = -1;
		
		if ((code->flag & C_REL) || //rel (call/jcc/jmp)
			(code->flag & C_CMD_CALL) || //call commands
			((code->flag & C_STOP) && //jumps excluding rets
			  code->opcode != 0xC2 && code->opcode != 0xC3 &&
			  code->opcode != 0xCA && code->opcode != 0xCB &&
			  code->opcode != 0xCF))
		{
			value.type |= XRF_JUMP;
		}

		rel = (sdword)code->data_d;
		if (code->datasize == sizeof(word))
		{
			rel = (short)code->data_d;
			value.type |= XRF_WORD;	
		}
		else if (code->datasize == sizeof(byte))
		{
			rel = (char)code->data_d;
			value.type |= XRF_BYTE;
		}
		
		if (value.type & XRF_JUMP)
			value.type |= XRF_REL;
		else if (code->dst_set & XSET_MEM)
			value.type |= XRF_POINTER; //immediate used with memory: can be pointer

		if (value.type & XRF_REL)
			value.rva = rva + code->len + rel;
		else if (code->data_d > ib)
			value.rva = code->data_d - ib;
		
		if (value.rva != -1)
		{
			if (ret != size && out)
				*out++ = value;
			ret++;
		}
	}

	return ret;
}

int setTargets(dword rva, dword ib, x86instr* out, imageXRef* xrefs, dword size)
{
	register imageXRef* cur;
	register dword i, j, ret;
	register sdword old;

	register cbool extend;
	
	sdword val;

	extend = 0;
	ret = 0;
	cur = xrefs;
	for (i = 0; i < size; i++)
	{
		if (!(cur->type & XRF_USERVA))
			return -1;

		if (cur->type & XRF_REL)
			val = (sdword)cur->rva - (sdword)(rva + out->len);
		else
			val = ib + cur->rva;

		if (cur->type & XRF_USEADDR)
		{
			if (out->addrsize == sizeof(byte))
				old = (char)out->addr_d;
			else if (out->addrsize == sizeof(word))
				old = (short)out->addr_d;
			else
				old = (sdword)out->addr_d;

			if (old != val)
			{
				//extend addr size if overflowed
				if (out->addrsize == sizeof(byte) && val != (char)val)
				{
					extend = 1;
					out->addrsize = sizeof(dword);
				}

				for (j = 0; j < out->addrsize; j++)
					out->addr_b[j] = ((byte*)&val)[j];
				ret++;
			}
		}
		else if (cur->type & XRF_USEDATA)
		{
			if (out->datasize == sizeof(byte))
				old = (char)out->data_d;
			else if (out->datasize == sizeof(word))
				old = (short)out->data_d;
			else
				old = (sdword)out->data_d;

			if (old != val)
			{
				//extend data size if overflowed
				if (out->datasize == sizeof(byte) && val != (char)val)
				{
					extend = 1;
					out->datasize = sizeof(dword);
				}

				for (j = 0; j < out->datasize; j++)
					out->data_b[j] = ((byte*)&val)[j];
				ret++;
			}
		}
		else
			return -1;

		cur++;
	}

	if (extend)
	{
		if (out->opcode == 0xEB)
			out->opcode = 0xE9; //jmp short to near
		else if ((out->opcode & 0xF0) == 0x70) //jxx short to near
		{
			out->opcode2 = out->opcode ^ 0x70 ^ 0x80;
			out->opcode = 0x0F;
		}
	}

	return ret;
}
