/*	$NetBSD: mach_vm.c,v 1.20 2002/12/15 00:40:25 manu Exp $ */

/*-
 * Copyright (c) 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: mach_vm.c,v 1.20 2002/12/15 00:40:25 manu Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/exec.h>
#include <sys/syscallargs.h>

#include <uvm/uvm_prot.h>
#include <uvm/uvm_map.h>

/* Too much debug output from here, but we might need it later...  */
#undef DEBUG_MACH
 
#include <compat/mach/mach_types.h>
#include <compat/mach/mach_message.h>
#include <compat/mach/mach_clock.h> 
#include <compat/mach/mach_vm.h> 
#include <compat/mach/mach_errno.h> 
#include <compat/mach/mach_syscallargs.h>

int
mach_vm_map(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_map_request_t req;
	mach_vm_map_reply_t rep;
	struct sys_mmap_args cup;
	vaddr_t addr;
	int error, flags;
	void *ret;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	DPRINTF(("mach_vm_map(addr = %p, size = 0x%08x, obj = 0x%x, "
	    "mask = 0x%08x, flags = 0x%x, offset = 0x%08llx, "
	    "copy = %d, cur_prot = 0x%x, max_prot = 0x%x, inh = 0x%x);\n",
	    (void *)req.req_address, req.req_size, req.req_object.name,
	    req.req_mask, req.req_flags, (off_t)req.req_offset, req.req_copy,
	    req.req_cur_protection, req.req_max_protection, 
	    req.req_inherance));

#if 1
	/* XXX Darwin fails on mapping a page at address 0 */
	if (req.req_address == 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, ENOMEM, maxlen, dst);
#endif

	bzero(&rep, sizeof(rep));

	req.req_size = round_page(req.req_size);

	/* Where Mach uses 0x00ff, we use 0x0100 */
	if ((req.req_mask & (req.req_mask + 1)) || (req.req_mask == 0))
		req.req_mask = 0;
	else
		req.req_mask += 1;

	if (req.req_flags & MACH_VM_FLAGS_ANYWHERE) {
		SCARG(&cup, flags) = MAP_ANON;
		flags = 0;
	} else {
		SCARG(&cup, flags) = MAP_ANON | MAP_FIXED;
		flags = MAP_FIXED;
	}

	/* 
	 * Use uvm_map_findspace to find a place which conforms to the 
	 * requested alignement.
	 */
	vm_map_lock(&p->p_vmspace->vm_map);
	ret = uvm_map_findspace(&p->p_vmspace->vm_map,
	    trunc_page(req.req_address), req.req_size, &addr, 
	    NULL, 0, req.req_mask, flags); 
	vm_map_unlock(&p->p_vmspace->vm_map);

	if (ret == NULL)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, ENOMEM, maxlen, dst);

	switch(req.req_inherance) {
	case MACH_VM_INHERIT_SHARE:
		SCARG(&cup, flags) |= MAP_INHERIT;
		break;
	case MACH_VM_INHERIT_COPY:
		SCARG(&cup, flags) |= MAP_COPY;
		break;
	case MACH_VM_INHERIT_NONE:
		break;
	case MACH_VM_INHERIT_DONATE_COPY:
	default:
		uprintf("mach_vm_map: unsupported inherance flag %d\n",
		    req.req_inherance);
		break;
	}

	SCARG(&cup, addr) = (void *)addr;
	SCARG(&cup, len) = req.req_size;
	SCARG(&cup, prot) = req.req_cur_protection;
	SCARG(&cup, fd) = -1;		/* XXX For now, no object mapping */
	SCARG(&cup, pos) = req.req_offset;
	
	if ((error = sys_mmap(p, &cup, &rep.rep_retval)) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);

	rep.rep_msgh.msgh_bits = 
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}

int
mach_vm_allocate(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_allocate_request_t req;
	mach_vm_allocate_reply_t rep;
	struct sys_mmap_args cup;
	vaddr_t addr;
	size_t size;
	int error;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	addr = req.req_address;
	size = req.req_size;

	DPRINTF(("mach_vm_allocate(addr = %p, size = 0x%08x);\n", 
	    (void *)addr, size));

	size = round_page(size);
	if (req.req_flags & MACH_VM_FLAGS_ANYWHERE)
		addr = vm_map_min(&p->p_vmspace->vm_map);
	else
		addr = trunc_page(addr);

	if (((addr + size) > vm_map_max(&p->p_vmspace->vm_map)) ||
	    ((addr + size) <= addr))
		addr = vm_map_min(&p->p_vmspace->vm_map);

	bzero(&rep, sizeof(rep));
	if (size == 0)
		goto out;

	SCARG(&cup, addr) = (caddr_t)addr;
	SCARG(&cup, len) = size;
	SCARG(&cup, prot) = PROT_READ | PROT_WRITE;
	SCARG(&cup, flags) = MAP_ANON;
	if ((req.req_flags & MACH_VM_FLAGS_ANYWHERE) == 0)
		SCARG(&cup, flags) |= MAP_FIXED;
	SCARG(&cup, fd) = -1;
	SCARG(&cup, pos) = 0;

	if ((error = sys_mmap(p, &cup, &rep.rep_address)) != 0) 
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);
	DPRINTF(("vm_allocate: success at %p\n", (void *)rep.rep_address));

out:
	rep.rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}

int
mach_vm_deallocate(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_deallocate_request_t req;
	mach_vm_deallocate_reply_t rep;
	struct sys_munmap_args cup;
	int error;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	DPRINTF(("mach_vm_deallocate(addr = %p, size = 0x%08x);\n",
	    (void *)req.req_address, req.req_size));

	bzero(&rep, sizeof(rep));

	SCARG(&cup, addr) = (caddr_t)req.req_address;
	SCARG(&cup, len) = req.req_size;

	if ((error = sys_munmap(p, &cup, &rep.rep_retval)) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);

	rep.rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}

int
mach_vm_wire(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_wire_request_t req;
	mach_vm_wire_reply_t rep;
	register_t retval;
	int error;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	DPRINTF(("mach_vm_wire(addr = %p, size = 0x%08x, prot = 0x%x);\n",
	    (void *)req.req_address, req.req_size, req.req_access));

	bzero(&rep, sizeof(rep));

	if ((req.req_access & ~VM_PROT_ALL) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, EINVAL, maxlen, dst);

	/* 
	 * Mach maitains a count of how many times a page is wired
	 * and unwire it once the count is zero. We cannot do that yet.
	 */
	if (req.req_access == 0) {
		struct sys_munlock_args cup;

		SCARG(&cup, addr) = (void *)req.req_address;
		SCARG(&cup, len) = req.req_size;
		error = sys_munlock(p, &cup, &retval);
	} else {
		struct sys_mlock_args cup;

		SCARG(&cup, addr) = (void *)req.req_address;
		SCARG(&cup, len) = req.req_size;
		error = sys_mlock(p, &cup, &retval);
	}
	if (error != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);
		
	if ((error = uvm_map_protect(&p->p_vmspace->vm_map, req.req_address, 
	    req.req_address + req.req_size, req.req_access, 0)) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);

	rep.rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}

int
mach_vm_protect(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_protect_request_t req;
	mach_vm_protect_reply_t rep;
	struct sys_mprotect_args cup;
	register_t retval;
	int error;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	SCARG(&cup, addr) = (void *)req.req_addr;
	SCARG(&cup, len) = req.req_size;
	SCARG(&cup, prot) = req.req_prot;

	if ((error = sys_mprotect(p, &cup, &retval)) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);

	bzero(&rep, sizeof(rep));

	rep.rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}

/* XXX The findspace argument is not handled correctly */
int
mach_sys_map_fd(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct mach_sys_map_fd_args /* {
		syscallarg(int) fd;
		syscallarg(mach_vm_offset_t) offset;
		syscallarg(mach_vm_offset_t *) va;
		syscallarg(mach_boolean_t) findspace;
		syscallarg(mach_vm_size_t) size;
	} */ *uap = v;
	struct file *fp; 
	struct filedesc *fdp;
	struct vnode *vp;
	struct exec_vmcmd evc;
	struct vm_map_entry *ret;
	void *va;
	int error;

	if ((error = copyin(SCARG(uap, va), (void *)&va, sizeof(va))) != 0)
		return error;

	fdp = p->p_fd;
	fp = fd_getfile(fdp, SCARG(uap, fd));
	if (fp == NULL)
		return EBADF;

	FILE_USE(fp);
	vp = (struct vnode *)fp->f_data;
	vref(vp);

	DPRINTF(("vm_map_fd: addr = %p len = 0x%08x\n", va, SCARG(uap, size)));
	bzero(&evc, sizeof(evc));
	evc.ev_addr = (u_long)va;
	evc.ev_len = SCARG(uap, size);
	evc.ev_prot = VM_PROT_ALL;
	evc.ev_flags = 0;
	evc.ev_proc = vmcmd_map_readvn;
	evc.ev_offset = SCARG(uap, offset);
	evc.ev_vp = vp;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	if ((error = (*evc.ev_proc)(p, &evc)) != 0) {
		VOP_UNLOCK(vp, 0);

		DPRINTF(("mach_sys_map_fd: mapping at %p failed\n", va));

		if (SCARG(uap, findspace) == 0)
			goto bad2;

		vm_map_lock(&p->p_vmspace->vm_map);
		if ((ret = uvm_map_findspace(&p->p_vmspace->vm_map,
		    vm_map_min(&p->p_vmspace->vm_map), evc.ev_len, 
		    (vaddr_t *)&evc.ev_addr, NULL, 0, PAGE_SIZE, 0)) == NULL) {
			vm_map_unlock(&p->p_vmspace->vm_map);
			goto bad2;
		}
		vm_map_unlock(&p->p_vmspace->vm_map);

		va = (void *)evc.ev_addr;

		bzero(&evc, sizeof(evc));
		evc.ev_addr = (u_long)va;
		evc.ev_len = SCARG(uap, size);
		evc.ev_prot = VM_PROT_ALL;
		evc.ev_flags = 0;
		evc.ev_proc = vmcmd_map_readvn;
		evc.ev_offset = SCARG(uap, offset);
		evc.ev_vp = vp;

		DPRINTF(("mach_sys_map_fd: trying at %p\n", va));
		vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
		if ((error = (*evc.ev_proc)(p, &evc)) != 0)
			goto bad1;
	}

	vput(vp);
	FILE_UNUSE(fp, p);
	DPRINTF(("mach_sya_map_fd: mapping at %p\n", (void *)evc.ev_addr));

	va = (mach_vm_offset_t *)evc.ev_addr;

	if ((error = copyout((void *)&va, SCARG(uap, va), sizeof(va))) != 0)
		return error;
	
	return 0;

bad1:
	VOP_UNLOCK(vp, 0);
bad2:	
	vrele(vp);
	FILE_UNUSE(fp, p);
	DPRINTF(("mach_sys_map_fd: mapping at %p failed, error = %d\n", 
	    (void *)evc.ev_addr, error));
	return error;
}
 
int
mach_vm_inherit(p, msgh, maxlen, dst)
	struct proc *p;
	mach_msg_header_t *msgh;
	size_t maxlen;
	mach_msg_header_t *dst;
{
	mach_vm_inherit_request_t req;
	mach_vm_inherit_reply_t rep;
	struct sys_minherit_args cup;
	register_t retval;
	int error;

	if ((error = copyin(msgh, &req, sizeof(req))) != 0)
		return error;

	bzero(&rep, sizeof(rep));

	SCARG(&cup, addr) = (void *)req.req_addr;
	SCARG(&cup, len) = req.req_size;
	/* Flags map well between Mach and NetBSD, just a 8 bit shift */
	SCARG(&cup, inherit) = req.req_inh << 8;

	if ((error = sys_minherit(p, &cup, &retval)) != 0)
		return MACH_MSG_ERROR(p, msgh, &req, &rep, error, maxlen, dst);
	
	rep.rep_msgh.msgh_bits =
	    MACH_MSGH_REPLY_LOCAL_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE);
	rep.rep_msgh.msgh_size = sizeof(rep) - sizeof(rep.rep_trailer);
	rep.rep_msgh.msgh_local_port = req.req_msgh.msgh_local_port;
	rep.rep_msgh.msgh_id = req.req_msgh.msgh_id + 100;
	rep.rep_trailer.msgh_trailer_size = 8;

	return MACH_MSG_RETURN(p, &rep, msgh, sizeof(rep), maxlen, dst);
}
