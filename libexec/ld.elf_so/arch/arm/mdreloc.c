/*	$NetBSD: mdreloc.c,v 1.20 2002/10/03 20:39:22 mycroft Exp $	*/

#include <sys/types.h>
#include <sys/stat.h>

#include "debug.h"
#include "rtld.h"

void _rtld_bind_start(void);
void _rtld_relocate_nonplt_self(Elf_Dyn *, Elf_Addr);
caddr_t _rtld_bind __P((const Obj_Entry *, Elf_Word));

void
_rtld_setup_pltgot(const Obj_Entry *obj)
{
	obj->pltgot[1] = (Elf_Addr) obj;
	obj->pltgot[2] = (Elf_Addr) &_rtld_bind_start;
}

void
_rtld_relocate_nonplt_self(dynp, relocbase)
	Elf_Dyn *dynp;
	Elf_Addr relocbase;
{
	const Elf_Rel *rel = 0, *rellim;
	Elf_Addr relsz = 0;
	Elf_Addr *where;

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_REL:
			rel = (const Elf_Rel *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_RELSZ:
			relsz = dynp->d_un.d_val;
			break;
		}
	}
	rellim = (const Elf_Rel *)((caddr_t)rel + relsz);
	for (; rel < rellim; rel++) {
		where = (Elf_Addr *)(relocbase + rel->r_offset);
		*where += (Elf_Addr)relocbase;
	}
}

/*
 * It is possible for the compiler to emit relocations for unaligned data.
 * We handle this situation with these inlines.
 */
#define	RELOC_ALIGNED_P(x) \
	(((uintptr_t)(x) & (sizeof(void *) - 1)) == 0)

static __inline Elf_Addr
load_ptr(void *where)
{
	Elf_Addr res;

	memcpy(&res, where, sizeof(res));

	return (res);
}

static __inline void
store_ptr(void *where, Elf_Addr val)
{

	memcpy(where, &val, sizeof(val));
}

int
_rtld_relocate_nonplt_objects(obj)
	const Obj_Entry *obj;
{
	const Elf_Rel *rel;

	for (rel = obj->rel; rel < obj->rellim; rel++) {
		Elf_Addr        *where;
		const Elf_Sym   *def;
		const Obj_Entry *defobj;
		Elf_Addr         tmp;
		unsigned long	 symnum;

		where = (Elf_Addr *)(obj->relocbase + rel->r_offset);
		symnum = ELF_R_SYM(rel->r_info);

		switch (ELF_R_TYPE(rel->r_info)) {
		case R_TYPE(NONE):
			break;

#if 1 /* XXX should not occur */
		case R_TYPE(PC24): {	/* word32 S - P + A */
			Elf32_Sword addend;

			/*
			 * Extract addend and sign-extend if needed.
			 */
			addend = *where;
			if (addend & 0x00800000)
				addend |= 0xff000000;

			def = _rtld_find_symdef(symnum, obj, &defobj, false);
			if (def == NULL)
				return -1;
			tmp = (Elf_Addr)obj->relocbase + def->st_value
			    - (Elf_Addr)where + (addend << 2);
			if ((tmp & 0xfe000000) != 0xfe000000 &&
			    (tmp & 0xfe000000) != 0) {
				_rtld_error(
				"%s: R_ARM_PC24 relocation @ %p to %s failed "
				"(displacement %ld (%#lx) out of range)",
				    obj->path, where,
				    obj->strtab + obj->symtab[symnum].st_name,
				    (long) tmp, (long) tmp);
				return -1;
			}
			tmp >>= 2;
			*where = (*where & 0xff000000) | (tmp & 0x00ffffff);
			rdbg(("PC24 %s in %s --> %p @ %p in %s",
			    obj->strtab + obj->symtab[symnum].st_name,
			    obj->path, (void *)*where, where, defobj->path));
			break;
		}
#endif

		case R_TYPE(ABS32):	/* word32 B + S + A */
		case R_TYPE(GLOB_DAT):	/* word32 B + S */
			def = _rtld_find_symdef(symnum, obj, &defobj, false);
			if (def == NULL)
				return -1;
			if (__predict_true(RELOC_ALIGNED_P(where))) {
				tmp = *where + (Elf_Addr)defobj->relocbase +
				    def->st_value;
				*where = tmp;
			} else {
				tmp = load_ptr(where) +
				    (Elf_Addr)defobj->relocbase +
				    def->st_value;
				store_ptr(where, tmp);
			}
			rdbg(("ABS32/GLOB_DAT %s in %s --> %p @ %p in %s",
			    obj->strtab + obj->symtab[symnum].st_name,
			    obj->path, (void *)tmp, where, defobj->path));
			break;

		case R_TYPE(RELATIVE):	/* word32 B + A */
			if (__predict_true(RELOC_ALIGNED_P(where))) {
				tmp = *where + (Elf_Addr)obj->relocbase;
				*where = tmp;
			} else {
				tmp = load_ptr(where) +
				    (Elf_Addr)obj->relocbase;
				store_ptr(where, tmp);
			}
			rdbg(("RELATIVE in %s --> %p", obj->path,
			    (void *)tmp));
			break;

		case R_TYPE(COPY):
			/*
			 * These are deferred until all other relocations have
			 * been done.  All we do here is make sure that the
			 * COPY relocation is not in a shared library.  They
			 * are allowed only in executable files.
			 */
			if (obj->isdynamic) {
				_rtld_error(
			"%s: Unexpected R_COPY relocation in shared library",
				    obj->path);
				return -1;
			}
			rdbg(("COPY (avoid in main)"));
			break;

		default:
			rdbg(("sym = %lu, type = %lu, offset = %p, "
			    "contents = %p, symbol = %s",
			    symnum, (u_long)ELF_R_TYPE(rel->r_info),
			    (void *)rel->r_offset, (void *)load_ptr(where),
			    obj->strtab + obj->symtab[symnum].st_name));
			_rtld_error("%s: Unsupported relocation type %ld "
			    "in non-PLT relocations\n",
			    obj->path, (u_long) ELF_R_TYPE(rel->r_info));
			return -1;
		}
	}
	return 0;
}

int
_rtld_relocate_plt_lazy(obj)
	const Obj_Entry *obj;
{
	const Elf_Rel *rel;

	if (!obj->relocbase)
		return 0;

	for (rel = obj->pltrel; rel < obj->pltrellim; rel++) {
		Elf_Addr *where = (Elf_Addr *)(obj->relocbase + rel->r_offset);

		assert(ELF_R_TYPE(rel->r_info) == R_TYPE(JUMP_SLOT));

		/* Just relocate the GOT slots pointing into the PLT */
		*where += (Elf_Addr)obj->relocbase;
		rdbg(("fixup !main in %s --> %p", obj->path, (void *)*where));
	}

	return 0;
}

caddr_t
_rtld_bind(obj, reloff)
	const Obj_Entry *obj;
	Elf_Word reloff;
{
	const Elf_Rel *rel = (const Elf_Rel *)((caddr_t)obj->pltrel + reloff);
	Elf_Addr *where = (Elf_Addr *)(obj->relocbase + rel->r_offset);
	Elf_Addr new_value;
	const Elf_Sym  *def;
	const Obj_Entry *defobj;

	assert(ELF_R_TYPE(rel->r_info) == R_TYPE(JUMP_SLOT));

	def = _rtld_find_symdef(ELF_R_SYM(rel->r_info), obj, &defobj, true);
	if (def == NULL)
		_rtld_die();

	new_value = (Elf_Addr)(defobj->relocbase + def->st_value);
	rdbg(("bind now/fixup in %s --> old=%p new=%p",
	    defobj->strtab + def->st_name, (void *)*where, (void *)new_value));
	if (*where != new_value)
		*where = new_value;

	return (caddr_t)new_value;
}
