/*	$NetBSD: mdreloc.c,v 1.6 2002/09/05 15:38:33 mycroft Exp $	*/

/*
 * Copyright (c) 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Frank van der Linden for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed for the NetBSD Project by
 *      Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 1996 John D. Polstra.
 * Copyright 1996 Matt Thomas <matt@3am-software.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by John Polstra.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

#include "debug.h"
#include "rtld.h"

extern Elf64_Addr _GLOBAL_OFFSET_TABLE_[];

int
_rtld_relocate_nonplt_object(Obj_Entry *obj, const Elf_Rela *rela, bool dodebug)
{
	Elf64_Addr *where64;
	Elf32_Addr *where32;
	const Elf_Sym *def;
	const Obj_Entry *defobj;
	Elf64_Addr tmp64;
	Elf32_Addr tmp32;

	where64 = (Elf64_Addr *)(obj->relocbase + rela->r_offset);
	where32 = (Elf32_Addr *)where64;

	switch (ELF_R_TYPE(rela->r_info)) {

	case R_TYPE(NONE):
		break;

	case R_TYPE(32):	/* word32 S + A, truncate */
	case R_TYPE(32S):	/* word32 S + A, signed truncate */
	case R_TYPE(GOT32):	/* word32 G + A (XXX can we see these?) */
		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, false);
		if (def == NULL)
			return -1;
		tmp32 = (Elf32_Addr)(u_long)(defobj->relocbase + def->st_value +
		    rela->r_addend);

		if (*where32 != tmp32)
			*where32 = tmp32;
		rdbg(dodebug, ("32/32S %s in %s --> %p in %s",
		    defobj->strtab + def->st_name, obj->path,
		    (void *)(unsigned long)*where32, defobj->path));
		break;
	case R_TYPE(64):	/* word64 S + A */
		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, false);
		if (def == NULL)
			return -1;

		tmp64 = (Elf64_Addr)(defobj->relocbase + def->st_value +
		    rela->r_addend);

		if (*where64 != tmp64)
			*where64 = tmp64;
		rdbg(dodebug, ("64 %s in %s --> %p in %s",
		    defobj->strtab + def->st_name, obj->path,
		    (void *)*where64, defobj->path));
		break;
	case R_TYPE(PC32):	/* word32 S + A - P */
		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, false);
		if (def == NULL)
			return -1;
		tmp32 = (Elf32_Addr)(u_long)(defobj->relocbase + def->st_value +
		    rela->r_addend - (Elf64_Addr)where64);
		if (*where32 != tmp32)
			*where32 = tmp32;
		rdbg(dodebug, ("PC32 %s in %s --> %p in %s",
		    defobj->strtab + def->st_name, obj->path,
		    (void *)(unsigned long)*where32, defobj->path));
		break;
	case R_TYPE(GLOB_DAT):	/* word64 S */
		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, false);
		if (def == NULL)
			return -1;

		tmp64 = (Elf64_Addr)(defobj->relocbase + def->st_value);

		if (*where64 != tmp64)
			*where64 = tmp64;
		rdbg(dodebug, ("64 %s in %s --> %p in %s",
		    defobj->strtab + def->st_name, obj->path,
		    (void *)*where64, defobj->path));
		break;
	case R_TYPE(RELATIVE):  /* word64 B + A */
		tmp64 = (Elf64_Addr)(obj->relocbase + rela->r_addend);
		if (*where64 != tmp64) 
			*where64 = tmp64; 
		rdbg(dodebug, ("RELATIVE in %s --> %p", obj->path,
		    (void *)*where64)); 
                break;

	case R_TYPE(COPY):
		rdbg(dodebug, ("COPY"));
		break;

	default:
		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, true);
		rdbg(dodebug, ("sym = %lu, type = %lu, offset = %p, "
		    "addend = %p, contents = %p, symbol = %s",
		    (u_long)ELF_R_SYM(rela->r_info),
		    (u_long)ELF_R_TYPE(rela->r_info),
		    (void *)rela->r_offset, (void *)rela->r_addend,
		    (void *)*where64,
		    def ? defobj->strtab + def->st_name : "??"));
		_rtld_error("%s: Unsupported relocation type %ld "
		    "in non-PLT relocations\n",
		    obj->path, (u_long) ELF_R_TYPE(rela->r_info));
		return -1;
	}
	return 0;
}



int
_rtld_relocate_plt_object(Obj_Entry *obj, const Elf_Rela *rela, caddr_t *addrp,
			  bool bind_now, bool dodebug)
{
	Elf_Addr *where = (Elf_Addr *)(obj->relocbase + rela->r_offset);
	Elf_Addr new_value;

	/* Fully resolve procedure addresses now */

	if (bind_now || obj->pltgot == NULL) {
		const Elf_Sym  *def;
		const Obj_Entry *defobj;

		assert(ELF_R_TYPE(rela->r_info) == R_TYPE(JUMP_SLOT));

		def = _rtld_find_symdef(_rtld_objlist, rela->r_info, NULL, obj,
		    &defobj, true);
		if (def == NULL)
			return -1;

		new_value = (Elf_Addr)
		    (defobj->relocbase + def->st_value + rela->r_addend);
		rdbg(dodebug, ("bind now %d/fixup in %s --> old=%p new=%p",
		    (int)bind_now,
		    defobj->strtab + def->st_name,
		    (void *)*where, (void *)new_value));
	} else {
		if (!obj->mainprog) {
			/* Just relocate the GOT slots pointing into the PLT */
			new_value = *where + (Elf_Addr) obj->relocbase;
			rdbg(dodebug, ("fixup !main in %s --> %p", obj->path,
			    (void *)(unsigned long)*where));
		} else {
			return 0;
		}
	}
	/*
         * Since this page is probably copy-on-write, let's not write
         * it unless we really really have to.
         */
	if (*where != new_value)
		*where = new_value;
	if (addrp != NULL)
		*addrp = *(caddr_t *)(obj->relocbase + rela->r_offset) -
		    rela->r_addend;
	return 0;
}

void
_rtld_setup_pltgot(const Obj_Entry *obj)
{
	obj->pltgot[1] = (Elf_Addr) obj;
	obj->pltgot[2] = (Elf_Addr) &_rtld_bind_start;
}
