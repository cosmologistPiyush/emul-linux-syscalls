/*	$NetBSD: elf_machdep.h,v 1.2 2001/01/18 23:50:50 bjh21 Exp $	*/

#define ELF32_MACHDEP_ENDIANNESS	ELFDATA2LSB

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_ARM_RELEXEC		0x00000001
#define EF_ARM_HASENTRY		0x00000002
#define EF_ARM_INTERWORK	0x00000004 /* GNU binutils 000413 */
#define EF_ARM_SYMSARESORTED	0x00000004 /* ARM ELF A08 */
#define EF_ARM_APCS_26		0x00000008 /* GNU binutils 000413 */
#define EF_ARM_DYNSYMSUSESEGIDX	0x00000008 /* ARM ELF B01 */
#define EF_ARM_APCS_FLOAT	0x00000010 /* GNU binutils 000413 */
#define EF_ARM_MAPSYMSFIRST	0x00000010 /* ARM ELF B01 */
#define EF_ARM_PIC		0x00000020
#define EF_ARM_ALIGN8		0x00000040 /* 8-bit structure alignment.  */
#define EF_ARM_NEW_ABI		0x00000080
#define EF_ARM_OLD_ABI		0x00000100
#define EF_ARM_SOFT_FLOAT	0x00000200
#define EF_ARM_EABIMASK		0xff000000

#define	ELF32_MACHDEP_ID_CASES						\
		case EM_ARM:						\
			break;

#define ARCH_ELFSIZE		32	/* MD native binary size */

/* Processor specific relocation types */

#define R_ARM_NONE		0
#define R_ARM_PC24		1
#define R_ARM_ABS32		2
#define R_ARM_REL32		3
#define R_ARM_PC13		4
#define R_ARM_ABS16		5
#define R_ARM_ABS12		6
#define R_ARM_THM_ABS5		7
#define R_ARM_ABS8		8
#define R_ARM_SBREL32		9
#define R_ARM_THM_PC22		10
#define R_ARM_THM_PC8		11
#define R_ARM_AMP_VCALL9	12
#define R_ARM_SWI24		13
#define R_ARM_THM_SWI8		14
#define R_ARM_XPC25		15
#define R_ARM_THM_XPC22		16

/* 17-31 are reserved for ARM Linux. */
#define R_ARM_COPY		20
#define R_ARM_GLOB_DAT		21
#define	R_ARM_JUMP_SLOT		22
#define R_ARM_RELATIVE		23
#define	R_ARM_GOTOFF		24
#define R_ARM_GOTPC		25
#define R_ARM_GOT32		26
#define R_ARM_PLT32		27

#define R_ARM_ALU_PCREL_7_0	32
#define R_ARM_ALU_PCREL_15_8	33
#define R_ARM_ALU_PCREL_23_15	34
#define R_ARM_ALU_SBREL_11_0	35
#define R_ARM_ALU_SBREL_19_12	36
#define R_ARM_ALU_SBREL_27_20	37

/* 96-111 are reserved to G++. */
#define R_ARM_GNU_VTENTRY	100
#define R_ARM_GNU_VTINHERIT	101
#define R_ARM_THM_PC11		102
#define R_ARM_THM_PC9		103

/* 112-127 are reserved for private experiments. */

#define R_ARM_RXPC25		249
#define R_ARM_RSBREL32		250
#define R_ARM_THM_RPC22		251
#define R_ARM_RREL32		252
#define R_ARM_RABS32		253
#define R_ARM_RPC24		254
#define R_ARM_RBASE		255

#define R_TYPE(name)		__CONCAT(R_ARM_,name)

/* Processor specific program header flags */
#define PF_ARM_SB		0x10000000
#define PF_ARM_PI		0x20000000
#define PF_ARM_ENTRY		0x80000000

/* Processor specific section header flags */
#define SHF_ENTRYSECT		0x10000000
#define SHF_COMDEF		0x80000000
