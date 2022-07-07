/*-
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 * Copyright (c) 1994 John S. Dyson
 * All rights reserved.
 * Copyright (c) 1994 David Greenman
 * All rights reserved.
 * Copyright (c) 2003 Peter Wemm
 * All rights reserved.
 * Copyright (c) 2005-2010 Alan L. Cox <alc@cs.rice.edu>
 * All rights reserved.
 * Copyright (c) 2014 Andrew Turner
 * All rights reserved.
 * Copyright (c) 2014-2016 The FreeBSD Foundation
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
 *
 * This software was developed by Andrew Turner under sponsorship from
 * the FreeBSD Foundation.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from:	@(#)pmap.c	7.7 (Berkeley)	5/12/91
 */
/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Jake Burkholder,
 * Safeport Network Services, and Network Associates Laboratories, the
 * Security Research Division of Network Associates, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the DARPA
 * CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 *	Manages physical address maps.
 *
 *	Since the information managed by this module is
 *	also stored by the logical address mapping module,
 *	this module may throw away valid virtual-to-physical
 *	mappings at almost any time.  However, invalidations
 *	of virtual-to-physical mappings must be done as
 *	requested.
 *
 *	In order to cope with hardware architectures which
 *	make virtual-to-physical map invalidates expensive,
 *	this module may delay invalidate or reduced protection
 *	operations until such time as they are actually
 *	necessary.  This module is given full information as
 *	to which processors are currently using which maps,
 *	and to when physical maps must be made correct.
 */

#include "opt_vm.h"

#include <sys/param.h>
#include <sys/bitstring.h>
#include <sys/bus.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/msgbuf.h>
#include <sys/mutex.h>
#include <sys/physmem.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sbuf.h>
#include <sys/sx.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/_unrhdr.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/vm_radix.h>
#include <vm/vm_reserv.h>
#include <vm/vm_dumpset.h>
#include <vm/uma.h>

#include <machine/machdep.h>
#include <machine/md_var.h>
#include <machine/pcb.h>

#define	PMAP_ASSERT_STAGE1(pmap)	MPASS((pmap)->pm_stage == PM_STAGE1)
#define	PMAP_ASSERT_STAGE2(pmap)	MPASS((pmap)->pm_stage == PM_STAGE2)

#define	NL0PG		(PAGE_SIZE/(sizeof (pd_entry_t)))
#define	NL1PG		(PAGE_SIZE/(sizeof (pd_entry_t)))
#define	NL2PG		(PAGE_SIZE/(sizeof (pd_entry_t)))
#define	NL3PG		(PAGE_SIZE/(sizeof (pt_entry_t)))

#define	NUL0E		L0_ENTRIES
#define	NUL1E		(NUL0E * NL1PG)
#define	NUL2E		(NUL1E * NL2PG)

#if !defined(DIAGNOSTIC)
#ifdef __GNUC_GNU_INLINE__
#define PMAP_INLINE	__attribute__((__gnu_inline__)) inline
#else
#define PMAP_INLINE	extern inline
#endif
#else
#define PMAP_INLINE
#endif

#ifdef PV_STATS
#define PV_STAT(x)	do { x ; } while (0)
#else
#define PV_STAT(x)	do { } while (0)
#endif

#define	pmap_l0_pindex(v)	(NUL2E + NUL1E + ((v) >> L0_SHIFT))
#define	pmap_l1_pindex(v)	(NUL2E + ((v) >> L1_SHIFT))
#define	pmap_l2_pindex(v)	((v) >> L2_SHIFT)

static struct md_page *
pa_to_pvh(vm_paddr_t pa)
{
	struct vm_phys_seg *seg;
	int segind;

	for (segind = 0; segind < vm_phys_nsegs; segind++) {
		seg = &vm_phys_segs[segind];
		if (pa >= seg->start && pa < seg->end)
			return ((struct md_page *)seg->md_first +
			    pmap_l2_pindex(pa) - pmap_l2_pindex(seg->start));
	}
	panic("pa 0x%jx not within vm_phys_segs", (uintmax_t)pa);
}

static struct md_page *
page_to_pvh(vm_page_t m)
{
	struct vm_phys_seg *seg;

	seg = &vm_phys_segs[m->segind];
	return ((struct md_page *)seg->md_first +
	    pmap_l2_pindex(VM_PAGE_TO_PHYS(m)) - pmap_l2_pindex(seg->start));
}

#define	NPV_LIST_LOCKS	MAXCPU

#define	PHYS_TO_PV_LIST_LOCK(pa)	\
			(&pv_list_locks[pa_index(pa) % NPV_LIST_LOCKS])

#define	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa)	do {	\
	struct rwlock **_lockp = (lockp);		\
	struct rwlock *_new_lock;			\
							\
	_new_lock = PHYS_TO_PV_LIST_LOCK(pa);		\
	if (_new_lock != *_lockp) {			\
		if (*_lockp != NULL)			\
			rw_wunlock(*_lockp);		\
		*_lockp = _new_lock;			\
		rw_wlock(*_lockp);			\
	}						\
} while (0)

#define	CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m)	\
			CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, VM_PAGE_TO_PHYS(m))

#define	RELEASE_PV_LIST_LOCK(lockp)		do {	\
	struct rwlock **_lockp = (lockp);		\
							\
	if (*_lockp != NULL) {				\
		rw_wunlock(*_lockp);			\
		*_lockp = NULL;				\
	}						\
} while (0)

#define	VM_PAGE_TO_PV_LIST_LOCK(m)	\
			PHYS_TO_PV_LIST_LOCK(VM_PAGE_TO_PHYS(m))

/*
 * The presence of this flag indicates that the mapping is writeable.
 * If the ATTR_S1_AP_RO bit is also set, then the mapping is clean, otherwise
 * it is dirty.  This flag may only be set on managed mappings.
 *
 * The DBM bit is reserved on ARMv8.0 but it seems we can safely treat it
 * as a software managed bit.
 */
#define	ATTR_SW_DBM	ATTR_DBM

struct pmap kernel_pmap_store;

/* Used for mapping ACPI memory before VM is initialized */
#define	PMAP_PREINIT_MAPPING_COUNT	32
#define	PMAP_PREINIT_MAPPING_SIZE	(PMAP_PREINIT_MAPPING_COUNT * L2_SIZE)
static vm_offset_t preinit_map_va;	/* Start VA of pre-init mapping space */
static int vm_initialized = 0;		/* No need to use pre-init maps when set */

/*
 * Reserve a few L2 blocks starting from 'preinit_map_va' pointer.
 * Always map entire L2 block for simplicity.
 * VA of L2 block = preinit_map_va + i * L2_SIZE
 */
static struct pmap_preinit_mapping {
	vm_paddr_t	pa;
	vm_offset_t	va;
	vm_size_t	size;
} pmap_preinit_mapping[PMAP_PREINIT_MAPPING_COUNT];

vm_offset_t virtual_avail;	/* VA of first avail page (after kernel bss) */
vm_offset_t virtual_end;	/* VA of last avail page (end of kernel AS) */
vm_offset_t kernel_vm_end = 0;

/*
 * Data for the pv entry allocation mechanism.
 */
static TAILQ_HEAD(pch, pv_chunk) pv_chunks = TAILQ_HEAD_INITIALIZER(pv_chunks);
static struct mtx pv_chunks_mutex;
static struct rwlock pv_list_locks[NPV_LIST_LOCKS];
static struct md_page *pv_table;
static struct md_page pv_dummy;

vm_paddr_t dmap_phys_base;	/* The start of the dmap region */
vm_paddr_t dmap_phys_max;	/* The limit of the dmap region */
vm_offset_t dmap_max_addr;	/* The virtual address limit of the dmap */

/* This code assumes all L1 DMAP entries will be used */
CTASSERT((DMAP_MIN_ADDRESS  & ~L0_OFFSET) == DMAP_MIN_ADDRESS);
CTASSERT((DMAP_MAX_ADDRESS  & ~L0_OFFSET) == DMAP_MAX_ADDRESS);

#define	DMAP_TABLES	((DMAP_MAX_ADDRESS - DMAP_MIN_ADDRESS) >> L0_SHIFT)
extern pt_entry_t pagetable_dmap[];

#define	PHYSMAP_SIZE	(2 * (VM_PHYSSEG_MAX - 1))
static vm_paddr_t physmap[PHYSMAP_SIZE];
static u_int physmap_idx;

static SYSCTL_NODE(_vm, OID_AUTO, pmap, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "VM/pmap parameters");

/*
 * This ASID allocator uses a bit vector ("asid_set") to remember which ASIDs
 * that it has currently allocated to a pmap, a cursor ("asid_next") to
 * optimize its search for a free ASID in the bit vector, and an epoch number
 * ("asid_epoch") to indicate when it has reclaimed all previously allocated
 * ASIDs that are not currently active on a processor.
 *
 * The current epoch number is always in the range [0, INT_MAX).  Negative
 * numbers and INT_MAX are reserved for special cases that are described
 * below.
 */
struct asid_set {
	int asid_bits;
	bitstr_t *asid_set;
	int asid_set_size;
	int asid_next;
	int asid_epoch;
	struct mtx asid_set_mutex;
};

static struct asid_set asids;
static struct asid_set vmids;

static SYSCTL_NODE(_vm_pmap, OID_AUTO, asid, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "ASID allocator");
SYSCTL_INT(_vm_pmap_asid, OID_AUTO, bits, CTLFLAG_RD, &asids.asid_bits, 0,
    "The number of bits in an ASID");
SYSCTL_INT(_vm_pmap_asid, OID_AUTO, next, CTLFLAG_RD, &asids.asid_next, 0,
    "The last allocated ASID plus one");
SYSCTL_INT(_vm_pmap_asid, OID_AUTO, epoch, CTLFLAG_RD, &asids.asid_epoch, 0,
    "The current epoch number");

static SYSCTL_NODE(_vm_pmap, OID_AUTO, vmid, CTLFLAG_RD, 0, "VMID allocator");
SYSCTL_INT(_vm_pmap_vmid, OID_AUTO, bits, CTLFLAG_RD, &vmids.asid_bits, 0,
    "The number of bits in an VMID");
SYSCTL_INT(_vm_pmap_vmid, OID_AUTO, next, CTLFLAG_RD, &vmids.asid_next, 0,
    "The last allocated VMID plus one");
SYSCTL_INT(_vm_pmap_vmid, OID_AUTO, epoch, CTLFLAG_RD, &vmids.asid_epoch, 0,
    "The current epoch number");

void (*pmap_clean_stage2_tlbi)(void);
void (*pmap_invalidate_vpipt_icache)(void);

/*
 * A pmap's cookie encodes an ASID and epoch number.  Cookies for reserved
 * ASIDs have a negative epoch number, specifically, INT_MIN.  Cookies for
 * dynamically allocated ASIDs have a non-negative epoch number.
 *
 * An invalid ASID is represented by -1.
 *
 * There are two special-case cookie values: (1) COOKIE_FROM(-1, INT_MIN),
 * which indicates that an ASID should never be allocated to the pmap, and
 * (2) COOKIE_FROM(-1, INT_MAX), which indicates that an ASID should be
 * allocated when the pmap is next activated.
 */
#define	COOKIE_FROM(asid, epoch)	((long)((u_int)(asid) |	\
					    ((u_long)(epoch) << 32)))
#define	COOKIE_TO_ASID(cookie)		((int)(cookie))
#define	COOKIE_TO_EPOCH(cookie)		((int)((u_long)(cookie) >> 32))

static int superpages_enabled = 1;
SYSCTL_INT(_vm_pmap, OID_AUTO, superpages_enabled,
    CTLFLAG_RDTUN | CTLFLAG_NOFETCH, &superpages_enabled, 0,
    "Are large page mappings enabled?");

/*
 * Internal flags for pmap_enter()'s helper functions.
 */
#define	PMAP_ENTER_NORECLAIM	0x1000000	/* Don't reclaim PV entries. */
#define	PMAP_ENTER_NOREPLACE	0x2000000	/* Don't replace mappings. */

static void	free_pv_chunk(struct pv_chunk *pc);
static void	free_pv_entry(pmap_t pmap, pv_entry_t pv);
static pv_entry_t get_pv_entry(pmap_t pmap, struct rwlock **lockp);
static vm_page_t reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp);
static void	pmap_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va);
static pv_entry_t pmap_pvh_remove(struct md_page *pvh, pmap_t pmap,
		    vm_offset_t va);

static void pmap_abort_ptp(pmap_t pmap, vm_offset_t va, vm_page_t mpte);
static bool pmap_activate_int(pmap_t pmap);
static void pmap_alloc_asid(pmap_t pmap);
static int pmap_change_attr_locked(vm_offset_t va, vm_size_t size, int mode);
static pt_entry_t *pmap_demote_l1(pmap_t pmap, pt_entry_t *l1, vm_offset_t va);
static pt_entry_t *pmap_demote_l2_locked(pmap_t pmap, pt_entry_t *l2,
    vm_offset_t va, struct rwlock **lockp);
static pt_entry_t *pmap_demote_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t va);
static vm_page_t pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va,
    vm_page_t m, vm_prot_t prot, vm_page_t mpte, struct rwlock **lockp);
static int pmap_enter_l2(pmap_t pmap, vm_offset_t va, pd_entry_t new_l2,
    u_int flags, vm_page_t m, struct rwlock **lockp);
static int pmap_remove_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t sva,
    pd_entry_t l1e, struct spglist *free, struct rwlock **lockp);
static int pmap_remove_l3(pmap_t pmap, pt_entry_t *l3, vm_offset_t sva,
    pd_entry_t l2e, struct spglist *free, struct rwlock **lockp);
static void pmap_reset_asid_set(pmap_t pmap);
static boolean_t pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va,
    vm_page_t m, struct rwlock **lockp);

static vm_page_t _pmap_alloc_l3(pmap_t pmap, vm_pindex_t ptepindex,
		struct rwlock **lockp);

static void _pmap_unwire_l3(pmap_t pmap, vm_offset_t va, vm_page_t m,
    struct spglist *free);
static int pmap_unuse_pt(pmap_t, vm_offset_t, pd_entry_t, struct spglist *);
static __inline vm_page_t pmap_remove_pt_page(pmap_t pmap, vm_offset_t va);

/*
 * These load the old table data and store the new value.
 * They need to be atomic as the System MMU may write to the table at
 * the same time as the CPU.
 */
#define	pmap_clear(table)		atomic_store_64(table, 0)
#define	pmap_clear_bits(table, bits)	atomic_clear_64(table, bits)
#define	pmap_load(table)		(*table)
#define	pmap_load_clear(table)		atomic_swap_64(table, 0)
#define	pmap_load_store(table, entry)	atomic_swap_64(table, entry)
#define	pmap_set_bits(table, bits)	atomic_set_64(table, bits)
#define	pmap_store(table, entry)	atomic_store_64(table, entry)

/********************/
/* Inline functions */
/********************/

static __inline void
pagecopy(void *s, void *d)
{

	memcpy(d, s, PAGE_SIZE);
}

static __inline pd_entry_t *
pmap_l0(pmap_t pmap, vm_offset_t va)
{

	return (&pmap->pm_l0[pmap_l0_index(va)]);
}

static __inline pd_entry_t *
pmap_l0_to_l1(pd_entry_t *l0, vm_offset_t va)
{
	pd_entry_t *l1;

	l1 = (pd_entry_t *)PHYS_TO_DMAP(pmap_load(l0) & ~ATTR_MASK);
	return (&l1[pmap_l1_index(va)]);
}

static __inline pd_entry_t *
pmap_l1(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l0;

	l0 = pmap_l0(pmap, va);
	if ((pmap_load(l0) & ATTR_DESCR_MASK) != L0_TABLE)
		return (NULL);

	return (pmap_l0_to_l1(l0, va));
}

static __inline pd_entry_t *
pmap_l1_to_l2(pd_entry_t *l1p, vm_offset_t va)
{
	pd_entry_t l1, *l2p;

	l1 = pmap_load(l1p);

	/*
	 * The valid bit may be clear if pmap_update_entry() is concurrently
	 * modifying the entry, so for KVA only the entry type may be checked.
	 */
	KASSERT(va >= VM_MAX_USER_ADDRESS || (l1 & ATTR_DESCR_VALID) != 0,
	    ("%s: L1 entry %#lx for %#lx is invalid", __func__, l1, va));
	KASSERT((l1 & ATTR_DESCR_TYPE_MASK) == ATTR_DESCR_TYPE_TABLE,
	    ("%s: L1 entry %#lx for %#lx is a leaf", __func__, l1, va));
	l2p = (pd_entry_t *)PHYS_TO_DMAP(l1 & ~ATTR_MASK);
	return (&l2p[pmap_l2_index(va)]);
}

static __inline pd_entry_t *
pmap_l2(pmap_t pmap, vm_offset_t va)
{
	pd_entry_t *l1;

	l1 = pmap_l1(pmap, va);
	if ((pmap_load(l1) & ATTR_DESCR_MASK) != L1_TABLE)
		return (NULL);

	return (pmap_l1_to_l2(l1, va));
}

static __inline pt_entry_t *
pmap_l2_to_l3(pd_entry_t *l2p, vm_offset_t va)
{
	pd_entry_t l2;
	pt_entry_t *l3p;

	l2 = pmap_load(l2p);

	/*
	 * The valid bit may be clear if pmap_update_entry() is concurrently
	 * modifying the entry, so for KVA only the entry type may be checked.
	 */
	KASSERT(va >= VM_MAX_USER_ADDRESS || (l2 & ATTR_DESCR_VALID) != 0,
	    ("%s: L2 entry %#lx for %#lx is invalid", __func__, l2, va));
	KASSERT((l2 & ATTR_DESCR_TYPE_MASK) == ATTR_DESCR_TYPE_TABLE,
	    ("%s: L2 entry %#lx for %#lx is a leaf", __func__, l2, va));
	l3p = (pt_entry_t *)PHYS_TO_DMAP(l2 & ~ATTR_MASK);
	return (&l3p[pmap_l3_index(va)]);
}

/*
 * Returns the lowest valid pde for a given virtual address.
 * The next level may or may not point to a valid page or block.
 */
static __inline pd_entry_t *
pmap_pde(pmap_t pmap, vm_offset_t va, int *level)
{
	pd_entry_t *l0, *l1, *l2, desc;

	l0 = pmap_l0(pmap, va);
	desc = pmap_load(l0) & ATTR_DESCR_MASK;
	if (desc != L0_TABLE) {
		*level = -1;
		return (NULL);
	}

	l1 = pmap_l0_to_l1(l0, va);
	desc = pmap_load(l1) & ATTR_DESCR_MASK;
	if (desc != L1_TABLE) {
		*level = 0;
		return (l0);
	}

	l2 = pmap_l1_to_l2(l1, va);
	desc = pmap_load(l2) & ATTR_DESCR_MASK;
	if (desc != L2_TABLE) {
		*level = 1;
		return (l1);
	}

	*level = 2;
	return (l2);
}

/*
 * Returns the lowest valid pte block or table entry for a given virtual
 * address. If there are no valid entries return NULL and set the level to
 * the first invalid level.
 */
static __inline pt_entry_t *
pmap_pte(pmap_t pmap, vm_offset_t va, int *level)
{
	pd_entry_t *l1, *l2, desc;
	pt_entry_t *l3;

	l1 = pmap_l1(pmap, va);
	if (l1 == NULL) {
		*level = 0;
		return (NULL);
	}
	desc = pmap_load(l1) & ATTR_DESCR_MASK;
	if (desc == L1_BLOCK) {
		*level = 1;
		return (l1);
	}

	if (desc != L1_TABLE) {
		*level = 1;
		return (NULL);
	}

	l2 = pmap_l1_to_l2(l1, va);
	desc = pmap_load(l2) & ATTR_DESCR_MASK;
	if (desc == L2_BLOCK) {
		*level = 2;
		return (l2);
	}

	if (desc != L2_TABLE) {
		*level = 2;
		return (NULL);
	}

	*level = 3;
	l3 = pmap_l2_to_l3(l2, va);
	if ((pmap_load(l3) & ATTR_DESCR_MASK) != L3_PAGE)
		return (NULL);

	return (l3);
}

bool
pmap_ps_enabled(pmap_t pmap __unused)
{

	return (superpages_enabled != 0);
}

bool
pmap_get_tables(pmap_t pmap, vm_offset_t va, pd_entry_t **l0, pd_entry_t **l1,
    pd_entry_t **l2, pt_entry_t **l3)
{
	pd_entry_t *l0p, *l1p, *l2p;

	if (pmap->pm_l0 == NULL)
		return (false);

	l0p = pmap_l0(pmap, va);
	*l0 = l0p;

	if ((pmap_load(l0p) & ATTR_DESCR_MASK) != L0_TABLE)
		return (false);

	l1p = pmap_l0_to_l1(l0p, va);
	*l1 = l1p;

	if ((pmap_load(l1p) & ATTR_DESCR_MASK) == L1_BLOCK) {
		*l2 = NULL;
		*l3 = NULL;
		return (true);
	}

	if ((pmap_load(l1p) & ATTR_DESCR_MASK) != L1_TABLE)
		return (false);

	l2p = pmap_l1_to_l2(l1p, va);
	*l2 = l2p;

	if ((pmap_load(l2p) & ATTR_DESCR_MASK) == L2_BLOCK) {
		*l3 = NULL;
		return (true);
	}

	if ((pmap_load(l2p) & ATTR_DESCR_MASK) != L2_TABLE)
		return (false);

	*l3 = pmap_l2_to_l3(l2p, va);

	return (true);
}

static __inline int
pmap_l3_valid(pt_entry_t l3)
{

	return ((l3 & ATTR_DESCR_MASK) == L3_PAGE);
}

CTASSERT(L1_BLOCK == L2_BLOCK);

static pt_entry_t
pmap_pte_memattr(pmap_t pmap, vm_memattr_t memattr)
{
	pt_entry_t val;

	if (pmap->pm_stage == PM_STAGE1) {
		val = ATTR_S1_IDX(memattr);
		if (memattr == VM_MEMATTR_DEVICE)
			val |= ATTR_S1_XN;
		return (val);
	}

	val = 0;

	switch (memattr) {
	case VM_MEMATTR_DEVICE:
		return (ATTR_S2_MEMATTR(ATTR_S2_MEMATTR_DEVICE_nGnRnE) |
		    ATTR_S2_XN(ATTR_S2_XN_ALL));
	case VM_MEMATTR_UNCACHEABLE:
		return (ATTR_S2_MEMATTR(ATTR_S2_MEMATTR_NC));
	case VM_MEMATTR_WRITE_BACK:
		return (ATTR_S2_MEMATTR(ATTR_S2_MEMATTR_WB));
	case VM_MEMATTR_WRITE_THROUGH:
		return (ATTR_S2_MEMATTR(ATTR_S2_MEMATTR_WT));
	default:
		panic("%s: invalid memory attribute %x", __func__, memattr);
	}
}

static pt_entry_t
pmap_pte_prot(pmap_t pmap, vm_prot_t prot)
{
	pt_entry_t val;

	val = 0;
	if (pmap->pm_stage == PM_STAGE1) {
		if ((prot & VM_PROT_EXECUTE) == 0)
			val |= ATTR_S1_XN;
		if ((prot & VM_PROT_WRITE) == 0)
			val |= ATTR_S1_AP(ATTR_S1_AP_RO);
	} else {
		if ((prot & VM_PROT_WRITE) != 0)
			val |= ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE);
		if ((prot & VM_PROT_READ) != 0)
			val |= ATTR_S2_S2AP(ATTR_S2_S2AP_READ);
		if ((prot & VM_PROT_EXECUTE) == 0)
			val |= ATTR_S2_XN(ATTR_S2_XN_ALL);
	}

	return (val);
}

/*
 * Checks if the PTE is dirty.
 */
static inline int
pmap_pte_dirty(pmap_t pmap, pt_entry_t pte)
{

	KASSERT((pte & ATTR_SW_MANAGED) != 0, ("pte %#lx is unmanaged", pte));

	if (pmap->pm_stage == PM_STAGE1) {
		KASSERT((pte & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) != 0,
		    ("pte %#lx is writeable and missing ATTR_SW_DBM", pte));

		return ((pte & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) ==
		    (ATTR_S1_AP(ATTR_S1_AP_RW) | ATTR_SW_DBM));
	}

	return ((pte & ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE)) ==
	    ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE));
}

static __inline void
pmap_resident_count_inc(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	pmap->pm_stats.resident_count += count;
}

static __inline void
pmap_resident_count_dec(pmap_t pmap, int count)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(pmap->pm_stats.resident_count >= count,
	    ("pmap %p resident count underflow %ld %d", pmap,
	    pmap->pm_stats.resident_count, count));
	pmap->pm_stats.resident_count -= count;
}

static pt_entry_t *
pmap_early_page_idx(vm_offset_t l1pt, vm_offset_t va, u_int *l1_slot,
    u_int *l2_slot)
{
	pt_entry_t *l2;
	pd_entry_t *l1;

	l1 = (pd_entry_t *)l1pt;
	*l1_slot = (va >> L1_SHIFT) & Ln_ADDR_MASK;

	/* Check locore has used a table L1 map */
	KASSERT((l1[*l1_slot] & ATTR_DESCR_MASK) == L1_TABLE,
	   ("Invalid bootstrap L1 table"));
	/* Find the address of the L2 table */
	l2 = (pt_entry_t *)init_pt_va;
	*l2_slot = pmap_l2_index(va);

	return (l2);
}

static vm_paddr_t
pmap_early_vtophys(vm_offset_t l1pt, vm_offset_t va)
{
	u_int l1_slot, l2_slot;
	pt_entry_t *l2;

	l2 = pmap_early_page_idx(l1pt, va, &l1_slot, &l2_slot);

	return ((l2[l2_slot] & ~ATTR_MASK) + (va & L2_OFFSET));
}

static vm_offset_t
pmap_bootstrap_dmap(vm_offset_t kern_l1, vm_paddr_t min_pa,
    vm_offset_t freemempos)
{
	pt_entry_t *l2;
	vm_offset_t va;
	vm_paddr_t l2_pa, pa;
	u_int l1_slot, l2_slot, prev_l1_slot;
	int i;

	dmap_phys_base = min_pa & ~L1_OFFSET;
	dmap_phys_max = 0;
	dmap_max_addr = 0;
	l2 = NULL;
	prev_l1_slot = -1;

#define	DMAP_TABLES	((DMAP_MAX_ADDRESS - DMAP_MIN_ADDRESS) >> L0_SHIFT)
	memset(pagetable_dmap, 0, PAGE_SIZE * DMAP_TABLES);

	for (i = 0; i < (physmap_idx * 2); i += 2) {
		pa = physmap[i] & ~L2_OFFSET;
		va = pa - dmap_phys_base + DMAP_MIN_ADDRESS;

		/* Create L2 mappings at the start of the region */
		if ((pa & L1_OFFSET) != 0) {
			l1_slot = ((va - DMAP_MIN_ADDRESS) >> L1_SHIFT);
			if (l1_slot != prev_l1_slot) {
				prev_l1_slot = l1_slot;
				l2 = (pt_entry_t *)freemempos;
				l2_pa = pmap_early_vtophys(kern_l1,
				    (vm_offset_t)l2);
				freemempos += PAGE_SIZE;

				pmap_store(&pagetable_dmap[l1_slot],
				    (l2_pa & ~Ln_TABLE_MASK) | L1_TABLE);

				memset(l2, 0, PAGE_SIZE);
			}
			KASSERT(l2 != NULL,
			    ("pmap_bootstrap_dmap: NULL l2 map"));
			for (; va < DMAP_MAX_ADDRESS && pa < physmap[i + 1];
			    pa += L2_SIZE, va += L2_SIZE) {
				/*
				 * We are on a boundary, stop to
				 * create a level 1 block
				 */
				if ((pa & L1_OFFSET) == 0)
					break;

				l2_slot = pmap_l2_index(va);
				KASSERT(l2_slot != 0, ("..."));
				pmap_store(&l2[l2_slot],
				    (pa & ~L2_OFFSET) | ATTR_DEFAULT |
				    ATTR_S1_XN |
				    ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK) |
				    L2_BLOCK);
			}
			KASSERT(va == (pa - dmap_phys_base + DMAP_MIN_ADDRESS),
			    ("..."));
		}

		for (; va < DMAP_MAX_ADDRESS && pa < physmap[i + 1] &&
		    (physmap[i + 1] - pa) >= L1_SIZE;
		    pa += L1_SIZE, va += L1_SIZE) {
			l1_slot = ((va - DMAP_MIN_ADDRESS) >> L1_SHIFT);
			pmap_store(&pagetable_dmap[l1_slot],
			    (pa & ~L1_OFFSET) | ATTR_DEFAULT | ATTR_S1_XN |
			    ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK) | L1_BLOCK);
		}

		/* Create L2 mappings at the end of the region */
		if (pa < physmap[i + 1]) {
			l1_slot = ((va - DMAP_MIN_ADDRESS) >> L1_SHIFT);
			if (l1_slot != prev_l1_slot) {
				prev_l1_slot = l1_slot;
				l2 = (pt_entry_t *)freemempos;
				l2_pa = pmap_early_vtophys(kern_l1,
				    (vm_offset_t)l2);
				freemempos += PAGE_SIZE;

				pmap_store(&pagetable_dmap[l1_slot],
				    (l2_pa & ~Ln_TABLE_MASK) | L1_TABLE);

				memset(l2, 0, PAGE_SIZE);
			}
			KASSERT(l2 != NULL,
			    ("pmap_bootstrap_dmap: NULL l2 map"));
			for (; va < DMAP_MAX_ADDRESS && pa < physmap[i + 1];
			    pa += L2_SIZE, va += L2_SIZE) {
				l2_slot = pmap_l2_index(va);
				pmap_store(&l2[l2_slot],
				    (pa & ~L2_OFFSET) | ATTR_DEFAULT |
				    ATTR_S1_XN |
				    ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK) |
				    L2_BLOCK);
			}
		}

		if (pa > dmap_phys_max) {
			dmap_phys_max = pa;
			dmap_max_addr = va;
		}
	}

	cpu_tlb_flushID();

	return (freemempos);
}

static vm_offset_t
pmap_bootstrap_l2(vm_offset_t l1pt, vm_offset_t va, vm_offset_t l2_start)
{
	vm_offset_t l2pt;
	vm_paddr_t pa;
	pd_entry_t *l1;
	u_int l1_slot;

	KASSERT((va & L1_OFFSET) == 0, ("Invalid virtual address"));

	l1 = (pd_entry_t *)l1pt;
	l1_slot = pmap_l1_index(va);
	l2pt = l2_start;

	for (; va < VM_MAX_KERNEL_ADDRESS; l1_slot++, va += L1_SIZE) {
		KASSERT(l1_slot < Ln_ENTRIES, ("Invalid L1 index"));

		pa = pmap_early_vtophys(l1pt, l2pt);
		pmap_store(&l1[l1_slot],
		    (pa & ~Ln_TABLE_MASK) | L1_TABLE);
		l2pt += PAGE_SIZE;
	}

	/* Clean the L2 page table */
	memset((void *)l2_start, 0, l2pt - l2_start);

	return l2pt;
}

static vm_offset_t
pmap_bootstrap_l3(vm_offset_t l1pt, vm_offset_t va, vm_offset_t l3_start)
{
	vm_offset_t l3pt;
	vm_paddr_t pa;
	pd_entry_t *l2;
	u_int l2_slot;

	KASSERT((va & L2_OFFSET) == 0, ("Invalid virtual address"));

	l2 = pmap_l2(kernel_pmap, va);
	l2 = (pd_entry_t *)rounddown2((uintptr_t)l2, PAGE_SIZE);
	l2_slot = pmap_l2_index(va);
	l3pt = l3_start;

	for (; va < VM_MAX_KERNEL_ADDRESS; l2_slot++, va += L2_SIZE) {
		KASSERT(l2_slot < Ln_ENTRIES, ("Invalid L2 index"));

		pa = pmap_early_vtophys(l1pt, l3pt);
		pmap_store(&l2[l2_slot],
		    (pa & ~Ln_TABLE_MASK) | ATTR_S1_UXN | L2_TABLE);
		l3pt += PAGE_SIZE;
	}

	/* Clean the L2 page table */
	memset((void *)l3_start, 0, l3pt - l3_start);

	return l3pt;
}

/*
 *	Bootstrap the system enough to run with virtual memory.
 */
void
pmap_bootstrap(vm_offset_t l0pt, vm_offset_t l1pt, vm_paddr_t kernstart,
    vm_size_t kernlen)
{
	vm_offset_t freemempos;
	vm_offset_t dpcpu, msgbufpv;
	vm_paddr_t start_pa, pa, min_pa;
	uint64_t kern_delta;
	int i;

	/* Verify that the ASID is set through TTBR0. */
	KASSERT((READ_SPECIALREG(tcr_el1) & TCR_A1) == 0,
	    ("pmap_bootstrap: TCR_EL1.A1 != 0"));

	kern_delta = KERNBASE - kernstart;

	printf("pmap_bootstrap %lx %lx %lx\n", l1pt, kernstart, kernlen);
	printf("%lx\n", l1pt);
	printf("%lx\n", (KERNBASE >> L1_SHIFT) & Ln_ADDR_MASK);

	/* Set this early so we can use the pagetable walking functions */
	kernel_pmap_store.pm_l0 = (pd_entry_t *)l0pt;
	PMAP_LOCK_INIT(kernel_pmap);
	kernel_pmap->pm_l0_paddr = l0pt - kern_delta;
	kernel_pmap->pm_cookie = COOKIE_FROM(-1, INT_MIN);
	kernel_pmap->pm_stage = PM_STAGE1;
	kernel_pmap->pm_levels = 4;
	kernel_pmap->pm_ttbr = kernel_pmap->pm_l0_paddr;
	kernel_pmap->pm_asid_set = &asids;

	/* Assume the address we were loaded to is a valid physical address */
	min_pa = KERNBASE - kern_delta;

	physmap_idx = physmem_avail(physmap, nitems(physmap));
	physmap_idx /= 2;

	/*
	 * Find the minimum physical address. physmap is sorted,
	 * but may contain empty ranges.
	 */
	for (i = 0; i < physmap_idx * 2; i += 2) {
		if (physmap[i] == physmap[i + 1])
			continue;
		if (physmap[i] <= min_pa)
			min_pa = physmap[i];
	}

	freemempos = KERNBASE + kernlen;
	freemempos = roundup2(freemempos, PAGE_SIZE);

	/* Create a direct map region early so we can use it for pa -> va */
	freemempos = pmap_bootstrap_dmap(l1pt, min_pa, freemempos);

	start_pa = pa = KERNBASE - kern_delta;

	/*
	 * Create the l2 tables up to VM_MAX_KERNEL_ADDRESS.  We assume that the
	 * loader allocated the first and only l2 page table page used to map
	 * the kernel, preloaded files and module metadata.
	 */
	freemempos = pmap_bootstrap_l2(l1pt, KERNBASE + L1_SIZE, freemempos);
	/* And the l3 tables for the early devmap */
	freemempos = pmap_bootstrap_l3(l1pt,
	    VM_MAX_KERNEL_ADDRESS - (PMAP_MAPDEV_EARLY_SIZE), freemempos);

	cpu_tlb_flushID();

#define alloc_pages(var, np)						\
	(var) = freemempos;						\
	freemempos += (np * PAGE_SIZE);					\
	memset((char *)(var), 0, ((np) * PAGE_SIZE));

	/* Allocate dynamic per-cpu area. */
	alloc_pages(dpcpu, DPCPU_SIZE / PAGE_SIZE);
	dpcpu_init((void *)dpcpu, 0);

	/* Allocate memory for the msgbuf, e.g. for /sbin/dmesg */
	alloc_pages(msgbufpv, round_page(msgbufsize) / PAGE_SIZE);
	msgbufp = (void *)msgbufpv;

	/* Reserve some VA space for early BIOS/ACPI mapping */
	preinit_map_va = roundup2(freemempos, L2_SIZE);

	virtual_avail = preinit_map_va + PMAP_PREINIT_MAPPING_SIZE;
	virtual_avail = roundup2(virtual_avail, L1_SIZE);
	virtual_end = VM_MAX_KERNEL_ADDRESS - (PMAP_MAPDEV_EARLY_SIZE);
	kernel_vm_end = virtual_avail;

	pa = pmap_early_vtophys(l1pt, freemempos);

	physmem_exclude_region(start_pa, pa - start_pa, EXFLAG_NOALLOC);

	cpu_tlb_flushID();
}

/*
 *	Initialize a vm_page's machine-dependent fields.
 */
void
pmap_page_init(vm_page_t m)
{

	TAILQ_INIT(&m->md.pv_list);
	m->md.pv_memattr = VM_MEMATTR_WRITE_BACK;
}

static void
pmap_init_asids(struct asid_set *set, int bits)
{
	int i;

	set->asid_bits = bits;

	/*
	 * We may be too early in the overall initialization process to use
	 * bit_alloc().
	 */
	set->asid_set_size = 1 << set->asid_bits;
	set->asid_set = (bitstr_t *)kmem_malloc(bitstr_size(set->asid_set_size),
	    M_WAITOK | M_ZERO);
	for (i = 0; i < ASID_FIRST_AVAILABLE; i++)
		bit_set(set->asid_set, i);
	set->asid_next = ASID_FIRST_AVAILABLE;
	mtx_init(&set->asid_set_mutex, "asid set", NULL, MTX_SPIN);
}

/*
 *	Initialize the pmap module.
 *	Called by vm_init, to initialize any structures that the pmap
 *	system needs to map virtual memory.
 */
void
pmap_init(void)
{
	struct vm_phys_seg *seg, *next_seg;
	struct md_page *pvh;
	vm_size_t s;
	uint64_t mmfr1;
	int i, pv_npg, vmid_bits;

	/*
	 * Are large page mappings enabled?
	 */
	TUNABLE_INT_FETCH("vm.pmap.superpages_enabled", &superpages_enabled);
	if (superpages_enabled) {
		KASSERT(MAXPAGESIZES > 1 && pagesizes[1] == 0,
		    ("pmap_init: can't assign to pagesizes[1]"));
		pagesizes[1] = L2_SIZE;
		KASSERT(MAXPAGESIZES > 2 && pagesizes[2] == 0,
		    ("pmap_init: can't assign to pagesizes[2]"));
		pagesizes[2] = L1_SIZE;
	}

	/*
	 * Initialize the ASID allocator.
	 */
	pmap_init_asids(&asids,
	    (READ_SPECIALREG(tcr_el1) & TCR_ASID_16) != 0 ? 16 : 8);

	if (has_hyp()) {
		mmfr1 = READ_SPECIALREG(id_aa64mmfr1_el1);
		vmid_bits = 8;

		if (ID_AA64MMFR1_VMIDBits_VAL(mmfr1) ==
		    ID_AA64MMFR1_VMIDBits_16)
			vmid_bits = 16;
		pmap_init_asids(&vmids, vmid_bits);
	}

	/*
	 * Initialize the pv chunk list mutex.
	 */
	mtx_init(&pv_chunks_mutex, "pmap pv chunk list", NULL, MTX_DEF);

	/*
	 * Initialize the pool of pv list locks.
	 */
	for (i = 0; i < NPV_LIST_LOCKS; i++)
		rw_init(&pv_list_locks[i], "pmap pv list");

	/*
	 * Calculate the size of the pv head table for superpages.
	 */
	pv_npg = 0;
	for (i = 0; i < vm_phys_nsegs; i++) {
		seg = &vm_phys_segs[i];
		pv_npg += pmap_l2_pindex(roundup2(seg->end, L2_SIZE)) -
		    pmap_l2_pindex(seg->start);
	}

	/*
	 * Allocate memory for the pv head table for superpages.
	 */
	s = (vm_size_t)(pv_npg * sizeof(struct md_page));
	s = round_page(s);
	pv_table = (struct md_page *)kmem_malloc(s, M_WAITOK | M_ZERO);
	for (i = 0; i < pv_npg; i++)
		TAILQ_INIT(&pv_table[i].pv_list);
	TAILQ_INIT(&pv_dummy.pv_list);

	/*
	 * Set pointers from vm_phys_segs to pv_table.
	 */
	for (i = 0, pvh = pv_table; i < vm_phys_nsegs; i++) {
		seg = &vm_phys_segs[i];
		seg->md_first = pvh;
		pvh += pmap_l2_pindex(roundup2(seg->end, L2_SIZE)) -
		    pmap_l2_pindex(seg->start);

		/*
		 * If there is a following segment, and the final
		 * superpage of this segment and the initial superpage
		 * of the next segment are the same then adjust the
		 * pv_table entry for that next segment down by one so
		 * that the pv_table entries will be shared.
		 */
		if (i + 1 < vm_phys_nsegs) {
			next_seg = &vm_phys_segs[i + 1];
			if (pmap_l2_pindex(roundup2(seg->end, L2_SIZE)) - 1 ==
			    pmap_l2_pindex(next_seg->start)) {
				pvh--;
			}
		}
	}

	vm_initialized = 1;
}

static SYSCTL_NODE(_vm_pmap, OID_AUTO, l2, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "2MB page mapping counters");

static u_long pmap_l2_demotions;
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, demotions, CTLFLAG_RD,
    &pmap_l2_demotions, 0, "2MB page demotions");

static u_long pmap_l2_mappings;
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, mappings, CTLFLAG_RD,
    &pmap_l2_mappings, 0, "2MB page mappings");

static u_long pmap_l2_p_failures;
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, p_failures, CTLFLAG_RD,
    &pmap_l2_p_failures, 0, "2MB page promotion failures");

static u_long pmap_l2_promotions;
SYSCTL_ULONG(_vm_pmap_l2, OID_AUTO, promotions, CTLFLAG_RD,
    &pmap_l2_promotions, 0, "2MB page promotions");

/*
 * Invalidate a single TLB entry.
 */
static __inline void
pmap_invalidate_page(pmap_t pmap, vm_offset_t va)
{
	uint64_t r;

	PMAP_ASSERT_STAGE1(pmap);

	dsb(ishst);
	if (pmap == kernel_pmap) {
		r = atop(va);
		__asm __volatile("tlbi vaae1is, %0" : : "r" (r));
	} else {
		r = ASID_TO_OPERAND(COOKIE_TO_ASID(pmap->pm_cookie)) | atop(va);
		__asm __volatile("tlbi vae1is, %0" : : "r" (r));
	}
	dsb(ish);
	isb();
}

static __inline void
pmap_invalidate_range(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	uint64_t end, r, start;

	PMAP_ASSERT_STAGE1(pmap);

	dsb(ishst);
	if (pmap == kernel_pmap) {
		start = atop(sva);
		end = atop(eva);
		for (r = start; r < end; r++)
			__asm __volatile("tlbi vaae1is, %0" : : "r" (r));
	} else {
		start = end = ASID_TO_OPERAND(COOKIE_TO_ASID(pmap->pm_cookie));
		start |= atop(sva);
		end |= atop(eva);
		for (r = start; r < end; r++)
			__asm __volatile("tlbi vae1is, %0" : : "r" (r));
	}
	dsb(ish);
	isb();
}

static __inline void
pmap_invalidate_all(pmap_t pmap)
{
	uint64_t r;

	PMAP_ASSERT_STAGE1(pmap);

	dsb(ishst);
	if (pmap == kernel_pmap) {
		__asm __volatile("tlbi vmalle1is");
	} else {
		r = ASID_TO_OPERAND(COOKIE_TO_ASID(pmap->pm_cookie));
		__asm __volatile("tlbi aside1is, %0" : : "r" (r));
	}
	dsb(ish);
	isb();
}

/*
 *	Routine:	pmap_extract
 *	Function:
 *		Extract the physical page address associated
 *		with the given map/virtual_address pair.
 */
vm_paddr_t
pmap_extract(pmap_t pmap, vm_offset_t va)
{
	pt_entry_t *pte, tpte;
	vm_paddr_t pa;
	int lvl;

	pa = 0;
	PMAP_LOCK(pmap);
	/*
	 * Find the block or page map for this virtual address. pmap_pte
	 * will return either a valid block/page entry, or NULL.
	 */
	pte = pmap_pte(pmap, va, &lvl);
	if (pte != NULL) {
		tpte = pmap_load(pte);
		pa = tpte & ~ATTR_MASK;
		switch(lvl) {
		case 1:
			KASSERT((tpte & ATTR_DESCR_MASK) == L1_BLOCK,
			    ("pmap_extract: Invalid L1 pte found: %lx",
			    tpte & ATTR_DESCR_MASK));
			pa |= (va & L1_OFFSET);
			break;
		case 2:
			KASSERT((tpte & ATTR_DESCR_MASK) == L2_BLOCK,
			    ("pmap_extract: Invalid L2 pte found: %lx",
			    tpte & ATTR_DESCR_MASK));
			pa |= (va & L2_OFFSET);
			break;
		case 3:
			KASSERT((tpte & ATTR_DESCR_MASK) == L3_PAGE,
			    ("pmap_extract: Invalid L3 pte found: %lx",
			    tpte & ATTR_DESCR_MASK));
			pa |= (va & L3_OFFSET);
			break;
		}
	}
	PMAP_UNLOCK(pmap);
	return (pa);
}

/*
 *	Routine:	pmap_extract_and_hold
 *	Function:
 *		Atomically extract and hold the physical page
 *		with the given pmap and virtual address pair
 *		if that mapping permits the given protection.
 */
vm_page_t
pmap_extract_and_hold(pmap_t pmap, vm_offset_t va, vm_prot_t prot)
{
	pt_entry_t *pte, tpte;
	vm_offset_t off;
	vm_page_t m;
	int lvl;
	bool use;

	m = NULL;
	PMAP_LOCK(pmap);
	pte = pmap_pte(pmap, va, &lvl);
	if (pte != NULL) {
		tpte = pmap_load(pte);

		KASSERT(lvl > 0 && lvl <= 3,
		    ("pmap_extract_and_hold: Invalid level %d", lvl));
		CTASSERT(L1_BLOCK == L2_BLOCK);
		KASSERT((lvl == 3 && (tpte & ATTR_DESCR_MASK) == L3_PAGE) ||
		    (lvl < 3 && (tpte & ATTR_DESCR_MASK) == L1_BLOCK),
		    ("pmap_extract_and_hold: Invalid pte at L%d: %lx", lvl,
		     tpte & ATTR_DESCR_MASK));

		use = false;
		if ((prot & VM_PROT_WRITE) == 0)
			use = true;
		else if (pmap->pm_stage == PM_STAGE1 &&
		    (tpte & ATTR_S1_AP_RW_BIT) == ATTR_S1_AP(ATTR_S1_AP_RW))
			use = true;
		else if (pmap->pm_stage == PM_STAGE2 &&
		    ((tpte & ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE)) ==
		     ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE)))
			use = true;

		if (use) {
			switch (lvl) {
			case 1:
				off = va & L1_OFFSET;
				break;
			case 2:
				off = va & L2_OFFSET;
				break;
			case 3:
			default:
				off = 0;
			}
			m = PHYS_TO_VM_PAGE((tpte & ~ATTR_MASK) | off);
			if (m != NULL && !vm_page_wire_mapped(m))
				m = NULL;
		}
	}
	PMAP_UNLOCK(pmap);
	return (m);
}

/*
 * Walks the page tables to translate a kernel virtual address to a
 * physical address. Returns true if the kva is valid and stores the
 * physical address in pa if it is not NULL.
 */
bool
pmap_klookup(vm_offset_t va, vm_paddr_t *pa)
{
	pt_entry_t *pte, tpte;
	register_t intr;
	uint64_t par;

	/*
	 * Disable interrupts so we don't get interrupted between asking
	 * for address translation, and getting the result back.
	 */
	intr = intr_disable();
	par = arm64_address_translate_s1e1r(va);
	intr_restore(intr);

	if (PAR_SUCCESS(par)) {
		if (pa != NULL)
			*pa = (par & PAR_PA_MASK) | (va & PAR_LOW_MASK);
		return (true);
	}

	/*
	 * Fall back to walking the page table. The address translation
	 * instruction may fail when the page is in a break-before-make
	 * sequence. As we only clear the valid bit in said sequence we
	 * can walk the page table to find the physical address.
	 */

	pte = pmap_l1(kernel_pmap, va);
	if (pte == NULL)
		return (false);

	/*
	 * A concurrent pmap_update_entry() will clear the entry's valid bit
	 * but leave the rest of the entry unchanged.  Therefore, we treat a
	 * non-zero entry as being valid, and we ignore the valid bit when
	 * determining whether the entry maps a block, page, or table.
	 */
	tpte = pmap_load(pte);
	if (tpte == 0)
		return (false);
	if ((tpte & ATTR_DESCR_TYPE_MASK) == ATTR_DESCR_TYPE_BLOCK) {
		if (pa != NULL)
			*pa = (tpte & ~ATTR_MASK) | (va & L1_OFFSET);
		return (true);
	}
	pte = pmap_l1_to_l2(&tpte, va);
	tpte = pmap_load(pte);
	if (tpte == 0)
		return (false);
	if ((tpte & ATTR_DESCR_TYPE_MASK) == ATTR_DESCR_TYPE_BLOCK) {
		if (pa != NULL)
			*pa = (tpte & ~ATTR_MASK) | (va & L2_OFFSET);
		return (true);
	}
	pte = pmap_l2_to_l3(&tpte, va);
	tpte = pmap_load(pte);
	if (tpte == 0)
		return (false);
	if (pa != NULL)
		*pa = (tpte & ~ATTR_MASK) | (va & L3_OFFSET);
	return (true);
}

vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	vm_paddr_t pa;

	if (va >= DMAP_MIN_ADDRESS && va < DMAP_MAX_ADDRESS)
		return (DMAP_TO_PHYS(va));

	if (pmap_klookup(va, &pa) == false)
		return (0);
	return (pa);
}

/***************************************************
 * Low level mapping routines.....
 ***************************************************/

void
pmap_kenter(vm_offset_t sva, vm_size_t size, vm_paddr_t pa, int mode)
{
	pd_entry_t *pde;
	pt_entry_t *pte, attr;
	vm_offset_t va;
	int lvl;

	KASSERT((pa & L3_OFFSET) == 0,
	   ("pmap_kenter: Invalid physical address"));
	KASSERT((sva & L3_OFFSET) == 0,
	   ("pmap_kenter: Invalid virtual address"));
	KASSERT((size & PAGE_MASK) == 0,
	    ("pmap_kenter: Mapping is not page-sized"));

	attr = ATTR_DEFAULT | ATTR_S1_AP(ATTR_S1_AP_RW) | ATTR_S1_XN |
	    ATTR_S1_IDX(mode) | L3_PAGE;
	va = sva;
	while (size != 0) {
		pde = pmap_pde(kernel_pmap, va, &lvl);
		KASSERT(pde != NULL,
		    ("pmap_kenter: Invalid page entry, va: 0x%lx", va));
		KASSERT(lvl == 2, ("pmap_kenter: Invalid level %d", lvl));

		pte = pmap_l2_to_l3(pde, va);
		pmap_load_store(pte, (pa & ~L3_OFFSET) | attr);

		va += PAGE_SIZE;
		pa += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

void
pmap_kenter_device(vm_offset_t sva, vm_size_t size, vm_paddr_t pa)
{

	pmap_kenter(sva, size, pa, VM_MEMATTR_DEVICE);
}

/*
 * Remove a page from the kernel pagetables.
 */
PMAP_INLINE void
pmap_kremove(vm_offset_t va)
{
	pt_entry_t *pte;
	int lvl;

	pte = pmap_pte(kernel_pmap, va, &lvl);
	KASSERT(pte != NULL, ("pmap_kremove: Invalid address"));
	KASSERT(lvl == 3, ("pmap_kremove: Invalid pte level %d", lvl));

	pmap_clear(pte);
	pmap_invalidate_page(kernel_pmap, va);
}

void
pmap_kremove_device(vm_offset_t sva, vm_size_t size)
{
	pt_entry_t *pte;
	vm_offset_t va;
	int lvl;

	KASSERT((sva & L3_OFFSET) == 0,
	   ("pmap_kremove_device: Invalid virtual address"));
	KASSERT((size & PAGE_MASK) == 0,
	    ("pmap_kremove_device: Mapping is not page-sized"));

	va = sva;
	while (size != 0) {
		pte = pmap_pte(kernel_pmap, va, &lvl);
		KASSERT(pte != NULL, ("Invalid page table, va: 0x%lx", va));
		KASSERT(lvl == 3,
		    ("Invalid device pagetable level: %d != 3", lvl));
		pmap_clear(pte);

		va += PAGE_SIZE;
		size -= PAGE_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

/*
 *	Used to map a range of physical addresses into kernel
 *	virtual address space.
 *
 *	The value passed in '*virt' is a suggested virtual address for
 *	the mapping. Architectures which can support a direct-mapped
 *	physical to virtual region can return the appropriate address
 *	within that region, leaving '*virt' unchanged. Other
 *	architectures should map the pages starting at '*virt' and
 *	update '*virt' with the first usable address after the mapped
 *	region.
 */
vm_offset_t
pmap_map(vm_offset_t *virt, vm_paddr_t start, vm_paddr_t end, int prot)
{
	return PHYS_TO_DMAP(start);
}

/*
 * Add a list of wired pages to the kva
 * this routine is only used for temporary
 * kernel mappings that do not need to have
 * page modification or references recorded.
 * Note that old mappings are simply written
 * over.  The page *must* be wired.
 * Note: SMP coherent.  Uses a ranged shootdown IPI.
 */
void
pmap_qenter(vm_offset_t sva, vm_page_t *ma, int count)
{
	pd_entry_t *pde;
	pt_entry_t *pte, pa;
	vm_offset_t va;
	vm_page_t m;
	int i, lvl;

	va = sva;
	for (i = 0; i < count; i++) {
		pde = pmap_pde(kernel_pmap, va, &lvl);
		KASSERT(pde != NULL,
		    ("pmap_qenter: Invalid page entry, va: 0x%lx", va));
		KASSERT(lvl == 2,
		    ("pmap_qenter: Invalid level %d", lvl));

		m = ma[i];
		pa = VM_PAGE_TO_PHYS(m) | ATTR_DEFAULT |
		    ATTR_S1_AP(ATTR_S1_AP_RW) | ATTR_S1_XN |
		    ATTR_S1_IDX(m->md.pv_memattr) | L3_PAGE;
		pte = pmap_l2_to_l3(pde, va);
		pmap_load_store(pte, pa);

		va += L3_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

/*
 * This routine tears out page mappings from the
 * kernel -- it is meant only for temporary mappings.
 */
void
pmap_qremove(vm_offset_t sva, int count)
{
	pt_entry_t *pte;
	vm_offset_t va;
	int lvl;

	KASSERT(sva >= VM_MIN_KERNEL_ADDRESS, ("usermode va %lx", sva));

	va = sva;
	while (count-- > 0) {
		pte = pmap_pte(kernel_pmap, va, &lvl);
		KASSERT(lvl == 3,
		    ("Invalid device pagetable level: %d != 3", lvl));
		if (pte != NULL) {
			pmap_clear(pte);
		}

		va += PAGE_SIZE;
	}
	pmap_invalidate_range(kernel_pmap, sva, va);
}

/***************************************************
 * Page table page management routines.....
 ***************************************************/
/*
 * Schedule the specified unused page table page to be freed.  Specifically,
 * add the page to the specified list of pages that will be released to the
 * physical memory manager after the TLB has been updated.
 */
static __inline void
pmap_add_delayed_free_list(vm_page_t m, struct spglist *free,
    boolean_t set_PG_ZERO)
{

	if (set_PG_ZERO)
		m->flags |= PG_ZERO;
	else
		m->flags &= ~PG_ZERO;
	SLIST_INSERT_HEAD(free, m, plinks.s.ss);
}

/*
 * Decrements a page table page's reference count, which is used to record the
 * number of valid page table entries within the page.  If the reference count
 * drops to zero, then the page table page is unmapped.  Returns TRUE if the
 * page table page was unmapped and FALSE otherwise.
 */
static inline boolean_t
pmap_unwire_l3(pmap_t pmap, vm_offset_t va, vm_page_t m, struct spglist *free)
{

	--m->ref_count;
	if (m->ref_count == 0) {
		_pmap_unwire_l3(pmap, va, m, free);
		return (TRUE);
	} else
		return (FALSE);
}

static void
_pmap_unwire_l3(pmap_t pmap, vm_offset_t va, vm_page_t m, struct spglist *free)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	/*
	 * unmap the page table page
	 */
	if (m->pindex >= (NUL2E + NUL1E)) {
		/* l1 page */
		pd_entry_t *l0;

		l0 = pmap_l0(pmap, va);
		pmap_clear(l0);
	} else if (m->pindex >= NUL2E) {
		/* l2 page */
		pd_entry_t *l1;

		l1 = pmap_l1(pmap, va);
		pmap_clear(l1);
	} else {
		/* l3 page */
		pd_entry_t *l2;

		l2 = pmap_l2(pmap, va);
		pmap_clear(l2);
	}
	pmap_resident_count_dec(pmap, 1);
	if (m->pindex < NUL2E) {
		/* We just released an l3, unhold the matching l2 */
		pd_entry_t *l1, tl1;
		vm_page_t l2pg;

		l1 = pmap_l1(pmap, va);
		tl1 = pmap_load(l1);
		l2pg = PHYS_TO_VM_PAGE(tl1 & ~ATTR_MASK);
		pmap_unwire_l3(pmap, va, l2pg, free);
	} else if (m->pindex < (NUL2E + NUL1E)) {
		/* We just released an l2, unhold the matching l1 */
		pd_entry_t *l0, tl0;
		vm_page_t l1pg;

		l0 = pmap_l0(pmap, va);
		tl0 = pmap_load(l0);
		l1pg = PHYS_TO_VM_PAGE(tl0 & ~ATTR_MASK);
		pmap_unwire_l3(pmap, va, l1pg, free);
	}
	pmap_invalidate_page(pmap, va);

	/*
	 * Put page on a list so that it is released after
	 * *ALL* TLB shootdown is done
	 */
	pmap_add_delayed_free_list(m, free, TRUE);
}

/*
 * After removing a page table entry, this routine is used to
 * conditionally free the page, and manage the reference count.
 */
static int
pmap_unuse_pt(pmap_t pmap, vm_offset_t va, pd_entry_t ptepde,
    struct spglist *free)
{
	vm_page_t mpte;

	if (va >= VM_MAXUSER_ADDRESS)
		return (0);
	KASSERT(ptepde != 0, ("pmap_unuse_pt: ptepde != 0"));
	mpte = PHYS_TO_VM_PAGE(ptepde & ~ATTR_MASK);
	return (pmap_unwire_l3(pmap, va, mpte, free));
}

/*
 * Release a page table page reference after a failed attempt to create a
 * mapping.
 */
static void
pmap_abort_ptp(pmap_t pmap, vm_offset_t va, vm_page_t mpte)
{
	struct spglist free;

	SLIST_INIT(&free);
	if (pmap_unwire_l3(pmap, va, mpte, &free)) {
		/*
		 * Although "va" was never mapped, the TLB could nonetheless
		 * have intermediate entries that refer to the freed page
		 * table pages.  Invalidate those entries.
		 *
		 * XXX redundant invalidation (See _pmap_unwire_l3().)
		 */
		pmap_invalidate_page(pmap, va);
		vm_page_free_pages_toq(&free, true);
	}
}

void
pmap_pinit0(pmap_t pmap)
{

	PMAP_LOCK_INIT(pmap);
	bzero(&pmap->pm_stats, sizeof(pmap->pm_stats));
	pmap->pm_l0_paddr = READ_SPECIALREG(ttbr0_el1);
	pmap->pm_l0 = (pd_entry_t *)PHYS_TO_DMAP(pmap->pm_l0_paddr);
	pmap->pm_root.rt_root = 0;
	pmap->pm_cookie = COOKIE_FROM(ASID_RESERVED_FOR_PID_0, INT_MIN);
	pmap->pm_stage = PM_STAGE1;
	pmap->pm_levels = 4;
	pmap->pm_ttbr = pmap->pm_l0_paddr;
	pmap->pm_asid_set = &asids;

	PCPU_SET(curpmap, pmap);
}

int
pmap_pinit_stage(pmap_t pmap, enum pmap_stage stage, int levels)
{
	vm_page_t m;

	/*
	 * allocate the l0 page
	 */
	while ((m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL |
	    VM_ALLOC_NOOBJ | VM_ALLOC_WIRED | VM_ALLOC_ZERO)) == NULL)
		vm_wait(NULL);

	pmap->pm_l0_paddr = VM_PAGE_TO_PHYS(m);
	pmap->pm_l0 = (pd_entry_t *)PHYS_TO_DMAP(pmap->pm_l0_paddr);

	if ((m->flags & PG_ZERO) == 0)
		pagezero(pmap->pm_l0);

	pmap->pm_root.rt_root = 0;
	bzero(&pmap->pm_stats, sizeof(pmap->pm_stats));
	pmap->pm_cookie = COOKIE_FROM(-1, INT_MAX);

	MPASS(levels == 3 || levels == 4);
	pmap->pm_levels = levels;
	pmap->pm_stage = stage;
	switch (stage) {
	case PM_STAGE1:
		pmap->pm_asid_set = &asids;
		break;
	case PM_STAGE2:
		pmap->pm_asid_set = &vmids;
		break;
	default:
		panic("%s: Invalid pmap type %d", __func__, stage);
		break;
	}

	/* XXX Temporarily disable deferred ASID allocation. */
	pmap_alloc_asid(pmap);

	/*
	 * Allocate the level 1 entry to use as the root. This will increase
	 * the refcount on the level 1 page so it won't be removed until
	 * pmap_release() is called.
	 */
	if (pmap->pm_levels == 3) {
		PMAP_LOCK(pmap);
		m = _pmap_alloc_l3(pmap, NUL2E + NUL1E, NULL);
		PMAP_UNLOCK(pmap);
	}
	pmap->pm_ttbr = VM_PAGE_TO_PHYS(m);

	return (1);
}

int
pmap_pinit(pmap_t pmap)
{

	return (pmap_pinit_stage(pmap, PM_STAGE1, 4));
}

/*
 * This routine is called if the desired page table page does not exist.
 *
 * If page table page allocation fails, this routine may sleep before
 * returning NULL.  It sleeps only if a lock pointer was given.
 *
 * Note: If a page allocation fails at page table level two or three,
 * one or two pages may be held during the wait, only to be released
 * afterwards.  This conservative approach is easily argued to avoid
 * race conditions.
 */
static vm_page_t
_pmap_alloc_l3(pmap_t pmap, vm_pindex_t ptepindex, struct rwlock **lockp)
{
	vm_page_t m, l1pg, l2pg;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	/*
	 * Allocate a page table page.
	 */
	if ((m = vm_page_alloc(NULL, ptepindex, VM_ALLOC_NOOBJ |
	    VM_ALLOC_WIRED | VM_ALLOC_ZERO)) == NULL) {
		if (lockp != NULL) {
			RELEASE_PV_LIST_LOCK(lockp);
			PMAP_UNLOCK(pmap);
			vm_wait(NULL);
			PMAP_LOCK(pmap);
		}

		/*
		 * Indicate the need to retry.  While waiting, the page table
		 * page may have been allocated.
		 */
		return (NULL);
	}
	if ((m->flags & PG_ZERO) == 0)
		pmap_zero_page(m);

	/*
	 * Because of AArch64's weak memory consistency model, we must have a
	 * barrier here to ensure that the stores for zeroing "m", whether by
	 * pmap_zero_page() or an earlier function, are visible before adding
	 * "m" to the page table.  Otherwise, a page table walk by another
	 * processor's MMU could see the mapping to "m" and a stale, non-zero
	 * PTE within "m".
	 */
	dmb(ishst);

	/*
	 * Map the pagetable page into the process address space, if
	 * it isn't already there.
	 */

	if (ptepindex >= (NUL2E + NUL1E)) {
		pd_entry_t *l0;
		vm_pindex_t l0index;

		l0index = ptepindex - (NUL2E + NUL1E);
		l0 = &pmap->pm_l0[l0index];
		pmap_store(l0, VM_PAGE_TO_PHYS(m) | L0_TABLE);
	} else if (ptepindex >= NUL2E) {
		vm_pindex_t l0index, l1index;
		pd_entry_t *l0, *l1;
		pd_entry_t tl0;

		l1index = ptepindex - NUL2E;
		l0index = l1index >> L0_ENTRIES_SHIFT;

		l0 = &pmap->pm_l0[l0index];
		tl0 = pmap_load(l0);
		if (tl0 == 0) {
			/* recurse for allocating page dir */
			if (_pmap_alloc_l3(pmap, NUL2E + NUL1E + l0index,
			    lockp) == NULL) {
				vm_page_unwire_noq(m);
				vm_page_free_zero(m);
				return (NULL);
			}
		} else {
			l1pg = PHYS_TO_VM_PAGE(tl0 & ~ATTR_MASK);
			l1pg->ref_count++;
		}

		l1 = (pd_entry_t *)PHYS_TO_DMAP(pmap_load(l0) & ~ATTR_MASK);
		l1 = &l1[ptepindex & Ln_ADDR_MASK];
		pmap_store(l1, VM_PAGE_TO_PHYS(m) | L1_TABLE);
	} else {
		vm_pindex_t l0index, l1index;
		pd_entry_t *l0, *l1, *l2;
		pd_entry_t tl0, tl1;

		l1index = ptepindex >> Ln_ENTRIES_SHIFT;
		l0index = l1index >> L0_ENTRIES_SHIFT;

		l0 = &pmap->pm_l0[l0index];
		tl0 = pmap_load(l0);
		if (tl0 == 0) {
			/* recurse for allocating page dir */
			if (_pmap_alloc_l3(pmap, NUL2E + l1index,
			    lockp) == NULL) {
				vm_page_unwire_noq(m);
				vm_page_free_zero(m);
				return (NULL);
			}
			tl0 = pmap_load(l0);
			l1 = (pd_entry_t *)PHYS_TO_DMAP(tl0 & ~ATTR_MASK);
			l1 = &l1[l1index & Ln_ADDR_MASK];
		} else {
			l1 = (pd_entry_t *)PHYS_TO_DMAP(tl0 & ~ATTR_MASK);
			l1 = &l1[l1index & Ln_ADDR_MASK];
			tl1 = pmap_load(l1);
			if (tl1 == 0) {
				/* recurse for allocating page dir */
				if (_pmap_alloc_l3(pmap, NUL2E + l1index,
				    lockp) == NULL) {
					vm_page_unwire_noq(m);
					vm_page_free_zero(m);
					return (NULL);
				}
			} else {
				l2pg = PHYS_TO_VM_PAGE(tl1 & ~ATTR_MASK);
				l2pg->ref_count++;
			}
		}

		l2 = (pd_entry_t *)PHYS_TO_DMAP(pmap_load(l1) & ~ATTR_MASK);
		l2 = &l2[ptepindex & Ln_ADDR_MASK];
		pmap_store(l2, VM_PAGE_TO_PHYS(m) | L2_TABLE);
	}

	pmap_resident_count_inc(pmap, 1);

	return (m);
}

static pd_entry_t *
pmap_alloc_l2(pmap_t pmap, vm_offset_t va, vm_page_t *l2pgp,
    struct rwlock **lockp)
{
	pd_entry_t *l1, *l2;
	vm_page_t l2pg;
	vm_pindex_t l2pindex;

retry:
	l1 = pmap_l1(pmap, va);
	if (l1 != NULL && (pmap_load(l1) & ATTR_DESCR_MASK) == L1_TABLE) {
		l2 = pmap_l1_to_l2(l1, va);
		if (va < VM_MAXUSER_ADDRESS) {
			/* Add a reference to the L2 page. */
			l2pg = PHYS_TO_VM_PAGE(pmap_load(l1) & ~ATTR_MASK);
			l2pg->ref_count++;
		} else
			l2pg = NULL;
	} else if (va < VM_MAXUSER_ADDRESS) {
		/* Allocate a L2 page. */
		l2pindex = pmap_l2_pindex(va) >> Ln_ENTRIES_SHIFT;
		l2pg = _pmap_alloc_l3(pmap, NUL2E + l2pindex, lockp);
		if (l2pg == NULL) {
			if (lockp != NULL)
				goto retry;
			else
				return (NULL);
		}
		l2 = (pd_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(l2pg));
		l2 = &l2[pmap_l2_index(va)];
	} else
		panic("pmap_alloc_l2: missing page table page for va %#lx",
		    va);
	*l2pgp = l2pg;
	return (l2);
}

static vm_page_t
pmap_alloc_l3(pmap_t pmap, vm_offset_t va, struct rwlock **lockp)
{
	vm_pindex_t ptepindex;
	pd_entry_t *pde, tpde;
#ifdef INVARIANTS
	pt_entry_t *pte;
#endif
	vm_page_t m;
	int lvl;

	/*
	 * Calculate pagetable page index
	 */
	ptepindex = pmap_l2_pindex(va);
retry:
	/*
	 * Get the page directory entry
	 */
	pde = pmap_pde(pmap, va, &lvl);

	/*
	 * If the page table page is mapped, we just increment the hold count,
	 * and activate it. If we get a level 2 pde it will point to a level 3
	 * table.
	 */
	switch (lvl) {
	case -1:
		break;
	case 0:
#ifdef INVARIANTS
		pte = pmap_l0_to_l1(pde, va);
		KASSERT(pmap_load(pte) == 0,
		    ("pmap_alloc_l3: TODO: l0 superpages"));
#endif
		break;
	case 1:
#ifdef INVARIANTS
		pte = pmap_l1_to_l2(pde, va);
		KASSERT(pmap_load(pte) == 0,
		    ("pmap_alloc_l3: TODO: l1 superpages"));
#endif
		break;
	case 2:
		tpde = pmap_load(pde);
		if (tpde != 0) {
			m = PHYS_TO_VM_PAGE(tpde & ~ATTR_MASK);
			m->ref_count++;
			return (m);
		}
		break;
	default:
		panic("pmap_alloc_l3: Invalid level %d", lvl);
	}

	/*
	 * Here if the pte page isn't mapped, or if it has been deallocated.
	 */
	m = _pmap_alloc_l3(pmap, ptepindex, lockp);
	if (m == NULL && lockp != NULL)
		goto retry;

	return (m);
}

/***************************************************
 * Pmap allocation/deallocation routines.
 ***************************************************/

/*
 * Release any resources held by the given physical map.
 * Called when a pmap initialized by pmap_pinit is being released.
 * Should only be called if the map contains no valid mappings.
 */
void
pmap_release(pmap_t pmap)
{
	boolean_t rv;
	struct spglist free;
	struct asid_set *set;
	vm_page_t m;
	int asid;

	if (pmap->pm_levels != 4) {
		PMAP_ASSERT_STAGE2(pmap);
		KASSERT(pmap->pm_stats.resident_count == 1,
		    ("pmap_release: pmap resident count %ld != 0",
		    pmap->pm_stats.resident_count));
		KASSERT((pmap->pm_l0[0] & ATTR_DESCR_VALID) == ATTR_DESCR_VALID,
		    ("pmap_release: Invalid l0 entry: %lx", pmap->pm_l0[0]));

		SLIST_INIT(&free);
		m = PHYS_TO_VM_PAGE(pmap->pm_ttbr);
		PMAP_LOCK(pmap);
		rv = pmap_unwire_l3(pmap, 0, m, &free);
		PMAP_UNLOCK(pmap);
		MPASS(rv == TRUE);
		vm_page_free_pages_toq(&free, true);
	}

	KASSERT(pmap->pm_stats.resident_count == 0,
	    ("pmap_release: pmap resident count %ld != 0",
	    pmap->pm_stats.resident_count));
	KASSERT(vm_radix_is_empty(&pmap->pm_root),
	    ("pmap_release: pmap has reserved page table page(s)"));

	set = pmap->pm_asid_set;
	KASSERT(set != NULL, ("%s: NULL asid set", __func__));

	/*
	 * Allow the ASID to be reused. In stage 2 VMIDs we don't invalidate
	 * the entries when removing them so rely on a later tlb invalidation.
	 * this will happen when updating the VMID generation. Because of this
	 * we don't reuse VMIDs within a generation.
	 */
	if (pmap->pm_stage == PM_STAGE1) {
		mtx_lock_spin(&set->asid_set_mutex);
		if (COOKIE_TO_EPOCH(pmap->pm_cookie) == set->asid_epoch) {
			asid = COOKIE_TO_ASID(pmap->pm_cookie);
			KASSERT(asid >= ASID_FIRST_AVAILABLE &&
			    asid < set->asid_set_size,
			    ("pmap_release: pmap cookie has out-of-range asid"));
			bit_clear(set->asid_set, asid);
		}
		mtx_unlock_spin(&set->asid_set_mutex);
	}

	m = PHYS_TO_VM_PAGE(pmap->pm_l0_paddr);
	vm_page_unwire_noq(m);
	vm_page_free_zero(m);
}

static int
kvm_size(SYSCTL_HANDLER_ARGS)
{
	unsigned long ksize = VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS;

	return sysctl_handle_long(oidp, &ksize, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_size, CTLTYPE_LONG | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, kvm_size, "LU",
    "Size of KVM");

static int
kvm_free(SYSCTL_HANDLER_ARGS)
{
	unsigned long kfree = VM_MAX_KERNEL_ADDRESS - kernel_vm_end;

	return sysctl_handle_long(oidp, &kfree, 0, req);
}
SYSCTL_PROC(_vm, OID_AUTO, kvm_free, CTLTYPE_LONG | CTLFLAG_RD | CTLFLAG_MPSAFE,
    0, 0, kvm_free, "LU",
    "Amount of KVM free");

/*
 * grow the number of kernel page table entries, if needed
 */
void
pmap_growkernel(vm_offset_t addr)
{
	vm_paddr_t paddr;
	vm_page_t nkpg;
	pd_entry_t *l0, *l1, *l2;

	mtx_assert(&kernel_map->system_mtx, MA_OWNED);

	addr = roundup2(addr, L2_SIZE);
	if (addr - 1 >= vm_map_max(kernel_map))
		addr = vm_map_max(kernel_map);
	while (kernel_vm_end < addr) {
		l0 = pmap_l0(kernel_pmap, kernel_vm_end);
		KASSERT(pmap_load(l0) != 0,
		    ("pmap_growkernel: No level 0 kernel entry"));

		l1 = pmap_l0_to_l1(l0, kernel_vm_end);
		if (pmap_load(l1) == 0) {
			/* We need a new PDP entry */
			nkpg = vm_page_alloc(NULL, kernel_vm_end >> L1_SHIFT,
			    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ |
			    VM_ALLOC_WIRED | VM_ALLOC_ZERO);
			if (nkpg == NULL)
				panic("pmap_growkernel: no memory to grow kernel");
			if ((nkpg->flags & PG_ZERO) == 0)
				pmap_zero_page(nkpg);
			/* See the dmb() in _pmap_alloc_l3(). */
			dmb(ishst);
			paddr = VM_PAGE_TO_PHYS(nkpg);
			pmap_store(l1, paddr | L1_TABLE);
			continue; /* try again */
		}
		l2 = pmap_l1_to_l2(l1, kernel_vm_end);
		if (pmap_load(l2) != 0) {
			kernel_vm_end = (kernel_vm_end + L2_SIZE) & ~L2_OFFSET;
			if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
				kernel_vm_end = vm_map_max(kernel_map);
				break;
			}
			continue;
		}

		nkpg = vm_page_alloc(NULL, kernel_vm_end >> L2_SHIFT,
		    VM_ALLOC_INTERRUPT | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED |
		    VM_ALLOC_ZERO);
		if (nkpg == NULL)
			panic("pmap_growkernel: no memory to grow kernel");
		if ((nkpg->flags & PG_ZERO) == 0)
			pmap_zero_page(nkpg);
		/* See the dmb() in _pmap_alloc_l3(). */
		dmb(ishst);
		paddr = VM_PAGE_TO_PHYS(nkpg);
		pmap_store(l2, paddr | L2_TABLE);

		kernel_vm_end = (kernel_vm_end + L2_SIZE) & ~L2_OFFSET;
		if (kernel_vm_end - 1 >= vm_map_max(kernel_map)) {
			kernel_vm_end = vm_map_max(kernel_map);
			break;
		}
	}
}

/***************************************************
 * page management routines.
 ***************************************************/

CTASSERT(sizeof(struct pv_chunk) == PAGE_SIZE);
CTASSERT(_NPCM == 3);
CTASSERT(_NPCPV == 168);

static __inline struct pv_chunk *
pv_to_chunk(pv_entry_t pv)
{

	return ((struct pv_chunk *)((uintptr_t)pv & ~(uintptr_t)PAGE_MASK));
}

#define PV_PMAP(pv) (pv_to_chunk(pv)->pc_pmap)

#define	PC_FREE0	0xfffffffffffffffful
#define	PC_FREE1	0xfffffffffffffffful
#define	PC_FREE2	0x000000fffffffffful

static const uint64_t pc_freemask[_NPCM] = { PC_FREE0, PC_FREE1, PC_FREE2 };

#if 0
#ifdef PV_STATS
static int pc_chunk_count, pc_chunk_allocs, pc_chunk_frees, pc_chunk_tryfail;

SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_count, CTLFLAG_RD, &pc_chunk_count, 0,
	"Current number of pv entry chunks");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_allocs, CTLFLAG_RD, &pc_chunk_allocs, 0,
	"Current number of pv entry chunks allocated");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_frees, CTLFLAG_RD, &pc_chunk_frees, 0,
	"Current number of pv entry chunks frees");
SYSCTL_INT(_vm_pmap, OID_AUTO, pc_chunk_tryfail, CTLFLAG_RD, &pc_chunk_tryfail, 0,
	"Number of times tried to get a chunk page but failed.");

static long pv_entry_frees, pv_entry_allocs, pv_entry_count;
static int pv_entry_spare;

SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_frees, CTLFLAG_RD, &pv_entry_frees, 0,
	"Current number of pv entry frees");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_allocs, CTLFLAG_RD, &pv_entry_allocs, 0,
	"Current number of pv entry allocs");
SYSCTL_LONG(_vm_pmap, OID_AUTO, pv_entry_count, CTLFLAG_RD, &pv_entry_count, 0,
	"Current number of pv entries");
SYSCTL_INT(_vm_pmap, OID_AUTO, pv_entry_spare, CTLFLAG_RD, &pv_entry_spare, 0,
	"Current number of spare pv entries");
#endif
#endif /* 0 */

/*
 * We are in a serious low memory condition.  Resort to
 * drastic measures to free some pages so we can allocate
 * another pv entry chunk.
 *
 * Returns NULL if PV entries were reclaimed from the specified pmap.
 *
 * We do not, however, unmap 2mpages because subsequent accesses will
 * allocate per-page pv entries until repromotion occurs, thereby
 * exacerbating the shortage of free pv entries.
 */
static vm_page_t
reclaim_pv_chunk(pmap_t locked_pmap, struct rwlock **lockp)
{
	struct pv_chunk *pc, *pc_marker, *pc_marker_end;
	struct pv_chunk_header pc_marker_b, pc_marker_end_b;
	struct md_page *pvh;
	pd_entry_t *pde;
	pmap_t next_pmap, pmap;
	pt_entry_t *pte, tpte;
	pv_entry_t pv;
	vm_offset_t va;
	vm_page_t m, m_pc;
	struct spglist free;
	uint64_t inuse;
	int bit, field, freed, lvl;
	static int active_reclaims = 0;

	PMAP_LOCK_ASSERT(locked_pmap, MA_OWNED);
	KASSERT(lockp != NULL, ("reclaim_pv_chunk: lockp is NULL"));

	pmap = NULL;
	m_pc = NULL;
	SLIST_INIT(&free);
	bzero(&pc_marker_b, sizeof(pc_marker_b));
	bzero(&pc_marker_end_b, sizeof(pc_marker_end_b));
	pc_marker = (struct pv_chunk *)&pc_marker_b;
	pc_marker_end = (struct pv_chunk *)&pc_marker_end_b;

	mtx_lock(&pv_chunks_mutex);
	active_reclaims++;
	TAILQ_INSERT_HEAD(&pv_chunks, pc_marker, pc_lru);
	TAILQ_INSERT_TAIL(&pv_chunks, pc_marker_end, pc_lru);
	while ((pc = TAILQ_NEXT(pc_marker, pc_lru)) != pc_marker_end &&
	    SLIST_EMPTY(&free)) {
		next_pmap = pc->pc_pmap;
		if (next_pmap == NULL) {
			/*
			 * The next chunk is a marker.  However, it is
			 * not our marker, so active_reclaims must be
			 * > 1.  Consequently, the next_chunk code
			 * will not rotate the pv_chunks list.
			 */
			goto next_chunk;
		}
		mtx_unlock(&pv_chunks_mutex);

		/*
		 * A pv_chunk can only be removed from the pc_lru list
		 * when both pv_chunks_mutex is owned and the
		 * corresponding pmap is locked.
		 */
		if (pmap != next_pmap) {
			if (pmap != NULL && pmap != locked_pmap)
				PMAP_UNLOCK(pmap);
			pmap = next_pmap;
			/* Avoid deadlock and lock recursion. */
			if (pmap > locked_pmap) {
				RELEASE_PV_LIST_LOCK(lockp);
				PMAP_LOCK(pmap);
				mtx_lock(&pv_chunks_mutex);
				continue;
			} else if (pmap != locked_pmap) {
				if (PMAP_TRYLOCK(pmap)) {
					mtx_lock(&pv_chunks_mutex);
					continue;
				} else {
					pmap = NULL; /* pmap is not locked */
					mtx_lock(&pv_chunks_mutex);
					pc = TAILQ_NEXT(pc_marker, pc_lru);
					if (pc == NULL ||
					    pc->pc_pmap != next_pmap)
						continue;
					goto next_chunk;
				}
			}
		}

		/*
		 * Destroy every non-wired, 4 KB page mapping in the chunk.
		 */
		freed = 0;
		for (field = 0; field < _NPCM; field++) {
			for (inuse = ~pc->pc_map[field] & pc_freemask[field];
			    inuse != 0; inuse &= ~(1UL << bit)) {
				bit = ffsl(inuse) - 1;
				pv = &pc->pc_pventry[field * 64 + bit];
				va = pv->pv_va;
				pde = pmap_pde(pmap, va, &lvl);
				if (lvl != 2)
					continue;
				pte = pmap_l2_to_l3(pde, va);
				tpte = pmap_load(pte);
				if ((tpte & ATTR_SW_WIRED) != 0)
					continue;
				tpte = pmap_load_clear(pte);
				m = PHYS_TO_VM_PAGE(tpte & ~ATTR_MASK);
				if (pmap_pte_dirty(pmap, tpte))
					vm_page_dirty(m);
				if ((tpte & ATTR_AF) != 0) {
					pmap_invalidate_page(pmap, va);
					vm_page_aflag_set(m, PGA_REFERENCED);
				}
				CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
				TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
				m->md.pv_gen++;
				if (TAILQ_EMPTY(&m->md.pv_list) &&
				    (m->flags & PG_FICTITIOUS) == 0) {
					pvh = page_to_pvh(m);
					if (TAILQ_EMPTY(&pvh->pv_list)) {
						vm_page_aflag_clear(m,
						    PGA_WRITEABLE);
					}
				}
				pc->pc_map[field] |= 1UL << bit;
				pmap_unuse_pt(pmap, va, pmap_load(pde), &free);
				freed++;
			}
		}
		if (freed == 0) {
			mtx_lock(&pv_chunks_mutex);
			goto next_chunk;
		}
		/* Every freed mapping is for a 4 KB page. */
		pmap_resident_count_dec(pmap, freed);
		PV_STAT(atomic_add_long(&pv_entry_frees, freed));
		PV_STAT(atomic_add_int(&pv_entry_spare, freed));
		PV_STAT(atomic_subtract_long(&pv_entry_count, freed));
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		if (pc->pc_map[0] == PC_FREE0 && pc->pc_map[1] == PC_FREE1 &&
		    pc->pc_map[2] == PC_FREE2) {
			PV_STAT(atomic_subtract_int(&pv_entry_spare, _NPCPV));
			PV_STAT(atomic_subtract_int(&pc_chunk_count, 1));
			PV_STAT(atomic_add_int(&pc_chunk_frees, 1));
			/* Entire chunk is free; return it. */
			m_pc = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pc));
			dump_drop_page(m_pc->phys_addr);
			mtx_lock(&pv_chunks_mutex);
			TAILQ_REMOVE(&pv_chunks, pc, pc_lru);
			break;
		}
		TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		mtx_lock(&pv_chunks_mutex);
		/* One freed pv entry in locked_pmap is sufficient. */
		if (pmap == locked_pmap)
			break;

next_chunk:
		TAILQ_REMOVE(&pv_chunks, pc_marker, pc_lru);
		TAILQ_INSERT_AFTER(&pv_chunks, pc, pc_marker, pc_lru);
		if (active_reclaims == 1 && pmap != NULL) {
			/*
			 * Rotate the pv chunks list so that we do not
			 * scan the same pv chunks that could not be
			 * freed (because they contained a wired
			 * and/or superpage mapping) on every
			 * invocation of reclaim_pv_chunk().
			 */
			while ((pc = TAILQ_FIRST(&pv_chunks)) != pc_marker) {
				MPASS(pc->pc_pmap != NULL);
				TAILQ_REMOVE(&pv_chunks, pc, pc_lru);
				TAILQ_INSERT_TAIL(&pv_chunks, pc, pc_lru);
			}
		}
	}
	TAILQ_REMOVE(&pv_chunks, pc_marker, pc_lru);
	TAILQ_REMOVE(&pv_chunks, pc_marker_end, pc_lru);
	active_reclaims--;
	mtx_unlock(&pv_chunks_mutex);
	if (pmap != NULL && pmap != locked_pmap)
		PMAP_UNLOCK(pmap);
	if (m_pc == NULL && !SLIST_EMPTY(&free)) {
		m_pc = SLIST_FIRST(&free);
		SLIST_REMOVE_HEAD(&free, plinks.s.ss);
		/* Recycle a freed page table page. */
		m_pc->ref_count = 1;
	}
	vm_page_free_pages_toq(&free, true);
	return (m_pc);
}

/*
 * free the pv_entry back to the free list
 */
static void
free_pv_entry(pmap_t pmap, pv_entry_t pv)
{
	struct pv_chunk *pc;
	int idx, field, bit;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_frees, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, 1));
	PV_STAT(atomic_subtract_long(&pv_entry_count, 1));
	pc = pv_to_chunk(pv);
	idx = pv - &pc->pc_pventry[0];
	field = idx / 64;
	bit = idx % 64;
	pc->pc_map[field] |= 1ul << bit;
	if (pc->pc_map[0] != PC_FREE0 || pc->pc_map[1] != PC_FREE1 ||
	    pc->pc_map[2] != PC_FREE2) {
		/* 98% of the time, pc is already at the head of the list. */
		if (__predict_false(pc != TAILQ_FIRST(&pmap->pm_pvchunk))) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
			TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		}
		return;
	}
	TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
	free_pv_chunk(pc);
}

static void
free_pv_chunk(struct pv_chunk *pc)
{
	vm_page_t m;

	mtx_lock(&pv_chunks_mutex);
 	TAILQ_REMOVE(&pv_chunks, pc, pc_lru);
	mtx_unlock(&pv_chunks_mutex);
	PV_STAT(atomic_subtract_int(&pv_entry_spare, _NPCPV));
	PV_STAT(atomic_subtract_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_frees, 1));
	/* entire chunk is free, return it */
	m = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t)pc));
	dump_drop_page(m->phys_addr);
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

/*
 * Returns a new PV entry, allocating a new PV chunk from the system when
 * needed.  If this PV chunk allocation fails and a PV list lock pointer was
 * given, a PV chunk is reclaimed from an arbitrary pmap.  Otherwise, NULL is
 * returned.
 *
 * The given PV list lock may be released.
 */
static pv_entry_t
get_pv_entry(pmap_t pmap, struct rwlock **lockp)
{
	int bit, field;
	pv_entry_t pv;
	struct pv_chunk *pc;
	vm_page_t m;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PV_STAT(atomic_add_long(&pv_entry_allocs, 1));
retry:
	pc = TAILQ_FIRST(&pmap->pm_pvchunk);
	if (pc != NULL) {
		for (field = 0; field < _NPCM; field++) {
			if (pc->pc_map[field]) {
				bit = ffsl(pc->pc_map[field]) - 1;
				break;
			}
		}
		if (field < _NPCM) {
			pv = &pc->pc_pventry[field * 64 + bit];
			pc->pc_map[field] &= ~(1ul << bit);
			/* If this was the last item, move it to tail */
			if (pc->pc_map[0] == 0 && pc->pc_map[1] == 0 &&
			    pc->pc_map[2] == 0) {
				TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
				TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc,
				    pc_list);
			}
			PV_STAT(atomic_add_long(&pv_entry_count, 1));
			PV_STAT(atomic_subtract_int(&pv_entry_spare, 1));
			return (pv);
		}
	}
	/* No free items, allocate another chunk */
	m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ |
	    VM_ALLOC_WIRED);
	if (m == NULL) {
		if (lockp == NULL) {
			PV_STAT(pc_chunk_tryfail++);
			return (NULL);
		}
		m = reclaim_pv_chunk(pmap, lockp);
		if (m == NULL)
			goto retry;
	}
	PV_STAT(atomic_add_int(&pc_chunk_count, 1));
	PV_STAT(atomic_add_int(&pc_chunk_allocs, 1));
	dump_add_page(m->phys_addr);
	pc = (void *)PHYS_TO_DMAP(m->phys_addr);
	pc->pc_pmap = pmap;
	pc->pc_map[0] = PC_FREE0 & ~1ul;	/* preallocated bit 0 */
	pc->pc_map[1] = PC_FREE1;
	pc->pc_map[2] = PC_FREE2;
	mtx_lock(&pv_chunks_mutex);
	TAILQ_INSERT_TAIL(&pv_chunks, pc, pc_lru);
	mtx_unlock(&pv_chunks_mutex);
	pv = &pc->pc_pventry[0];
	TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
	PV_STAT(atomic_add_long(&pv_entry_count, 1));
	PV_STAT(atomic_add_int(&pv_entry_spare, _NPCPV - 1));
	return (pv);
}

/*
 * Ensure that the number of spare PV entries in the specified pmap meets or
 * exceeds the given count, "needed".
 *
 * The given PV list lock may be released.
 */
static void
reserve_pv_entries(pmap_t pmap, int needed, struct rwlock **lockp)
{
	struct pch new_tail;
	struct pv_chunk *pc;
	vm_page_t m;
	int avail, free;
	bool reclaimed;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(lockp != NULL, ("reserve_pv_entries: lockp is NULL"));

	/*
	 * Newly allocated PV chunks must be stored in a private list until
	 * the required number of PV chunks have been allocated.  Otherwise,
	 * reclaim_pv_chunk() could recycle one of these chunks.  In
	 * contrast, these chunks must be added to the pmap upon allocation.
	 */
	TAILQ_INIT(&new_tail);
retry:
	avail = 0;
	TAILQ_FOREACH(pc, &pmap->pm_pvchunk, pc_list) {
		bit_count((bitstr_t *)pc->pc_map, 0,
		    sizeof(pc->pc_map) * NBBY, &free);
		if (free == 0)
			break;
		avail += free;
		if (avail >= needed)
			break;
	}
	for (reclaimed = false; avail < needed; avail += _NPCPV) {
		m = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ |
		    VM_ALLOC_WIRED);
		if (m == NULL) {
			m = reclaim_pv_chunk(pmap, lockp);
			if (m == NULL)
				goto retry;
			reclaimed = true;
		}
		PV_STAT(atomic_add_int(&pc_chunk_count, 1));
		PV_STAT(atomic_add_int(&pc_chunk_allocs, 1));
		dump_add_page(m->phys_addr);
		pc = (void *)PHYS_TO_DMAP(m->phys_addr);
		pc->pc_pmap = pmap;
		pc->pc_map[0] = PC_FREE0;
		pc->pc_map[1] = PC_FREE1;
		pc->pc_map[2] = PC_FREE2;
		TAILQ_INSERT_HEAD(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&new_tail, pc, pc_lru);
		PV_STAT(atomic_add_int(&pv_entry_spare, _NPCPV));

		/*
		 * The reclaim might have freed a chunk from the current pmap.
		 * If that chunk contained available entries, we need to
		 * re-count the number of available entries.
		 */
		if (reclaimed)
			goto retry;
	}
	if (!TAILQ_EMPTY(&new_tail)) {
		mtx_lock(&pv_chunks_mutex);
		TAILQ_CONCAT(&pv_chunks, &new_tail, pc_lru);
		mtx_unlock(&pv_chunks_mutex);
	}
}

/*
 * First find and then remove the pv entry for the specified pmap and virtual
 * address from the specified pv list.  Returns the pv entry if found and NULL
 * otherwise.  This operation can be performed on pv lists for either 4KB or
 * 2MB page mappings.
 */
static __inline pv_entry_t
pmap_pvh_remove(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
		if (pmap == PV_PMAP(pv) && va == pv->pv_va) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
			break;
		}
	}
	return (pv);
}

/*
 * After demotion from a 2MB page mapping to 512 4KB page mappings,
 * destroy the pv entry for the 2MB page mapping and reinstantiate the pv
 * entries for each of the 4KB page mappings.
 */
static void
pmap_pv_demote_l2(pmap_t pmap, vm_offset_t va, vm_paddr_t pa,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	struct pv_chunk *pc;
	pv_entry_t pv;
	vm_offset_t va_last;
	vm_page_t m;
	int bit, field;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((va & L2_OFFSET) == 0,
	    ("pmap_pv_demote_l2: va is not 2mpage aligned"));
	KASSERT((pa & L2_OFFSET) == 0,
	    ("pmap_pv_demote_l2: pa is not 2mpage aligned"));
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	/*
	 * Transfer the 2mpage's pv entry for this mapping to the first
	 * page's pv list.  Once this transfer begins, the pv list lock
	 * must not be released until the last pv entry is reinstantiated.
	 */
	pvh = pa_to_pvh(pa);
	pv = pmap_pvh_remove(pvh, pmap, va);
	KASSERT(pv != NULL, ("pmap_pv_demote_l2: pv not found"));
	m = PHYS_TO_VM_PAGE(pa);
	TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
	m->md.pv_gen++;
	/* Instantiate the remaining Ln_ENTRIES - 1 pv entries. */
	PV_STAT(atomic_add_long(&pv_entry_allocs, Ln_ENTRIES - 1));
	va_last = va + L2_SIZE - PAGE_SIZE;
	for (;;) {
		pc = TAILQ_FIRST(&pmap->pm_pvchunk);
		KASSERT(pc->pc_map[0] != 0 || pc->pc_map[1] != 0 ||
		    pc->pc_map[2] != 0, ("pmap_pv_demote_l2: missing spare"));
		for (field = 0; field < _NPCM; field++) {
			while (pc->pc_map[field]) {
				bit = ffsl(pc->pc_map[field]) - 1;
				pc->pc_map[field] &= ~(1ul << bit);
				pv = &pc->pc_pventry[field * 64 + bit];
				va += PAGE_SIZE;
				pv->pv_va = va;
				m++;
				KASSERT((m->oflags & VPO_UNMANAGED) == 0,
			    ("pmap_pv_demote_l2: page %p is not managed", m));
				TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
				m->md.pv_gen++;
				if (va == va_last)
					goto out;
			}
		}
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_list);
	}
out:
	if (pc->pc_map[0] == 0 && pc->pc_map[1] == 0 && pc->pc_map[2] == 0) {
		TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
		TAILQ_INSERT_TAIL(&pmap->pm_pvchunk, pc, pc_list);
	}
	PV_STAT(atomic_add_long(&pv_entry_count, Ln_ENTRIES - 1));
	PV_STAT(atomic_subtract_int(&pv_entry_spare, Ln_ENTRIES - 1));
}

/*
 * First find and then destroy the pv entry for the specified pmap and virtual
 * address.  This operation can be performed on pv lists for either 4KB or 2MB
 * page mappings.
 */
static void
pmap_pvh_free(struct md_page *pvh, pmap_t pmap, vm_offset_t va)
{
	pv_entry_t pv;

	pv = pmap_pvh_remove(pvh, pmap, va);
	KASSERT(pv != NULL, ("pmap_pvh_free: pv not found"));
	free_pv_entry(pmap, pv);
}

/*
 * Conditionally create the PV entry for a 4KB page mapping if the required
 * memory can be allocated without resorting to reclamation.
 */
static boolean_t
pmap_try_insert_pv_entry(pmap_t pmap, vm_offset_t va, vm_page_t m,
    struct rwlock **lockp)
{
	pv_entry_t pv;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	/* Pass NULL instead of the lock pointer to disable reclamation. */
	if ((pv = get_pv_entry(pmap, NULL)) != NULL) {
		pv->pv_va = va;
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		return (TRUE);
	} else
		return (FALSE);
}

/*
 * Create the PV entry for a 2MB page mapping.  Always returns true unless the
 * flag PMAP_ENTER_NORECLAIM is specified.  If that flag is specified, returns
 * false if the PV entry cannot be allocated without resorting to reclamation.
 */
static bool
pmap_pv_insert_l2(pmap_t pmap, vm_offset_t va, pd_entry_t l2e, u_int flags,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_paddr_t pa;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	/* Pass NULL instead of the lock pointer to disable reclamation. */
	if ((pv = get_pv_entry(pmap, (flags & PMAP_ENTER_NORECLAIM) != 0 ?
	    NULL : lockp)) == NULL)
		return (false);
	pv->pv_va = va;
	pa = l2e & ~ATTR_MASK;
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;
	return (true);
}

static void
pmap_remove_kernel_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t va)
{
	pt_entry_t newl2, oldl2;
	vm_page_t ml3;
	vm_paddr_t ml3pa;

	KASSERT(!VIRT_IN_DMAP(va), ("removing direct mapping of %#lx", va));
	KASSERT(pmap == kernel_pmap, ("pmap %p is not kernel_pmap", pmap));
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	ml3 = pmap_remove_pt_page(pmap, va);
	if (ml3 == NULL)
		panic("pmap_remove_kernel_l2: Missing pt page");

	ml3pa = VM_PAGE_TO_PHYS(ml3);
	newl2 = ml3pa | L2_TABLE;

	/*
	 * If this page table page was unmapped by a promotion, then it
	 * contains valid mappings.  Zero it to invalidate those mappings.
	 */
	if (ml3->valid != 0)
		pagezero((void *)PHYS_TO_DMAP(ml3pa));

	/*
	 * Demote the mapping.  The caller must have already invalidated the
	 * mapping (i.e., the "break" in break-before-make).
	 */
	oldl2 = pmap_load_store(l2, newl2);
	KASSERT(oldl2 == 0, ("%s: found existing mapping at %p: %#lx",
	    __func__, l2, oldl2));
}

/*
 * pmap_remove_l2: Do the things to unmap a level 2 superpage.
 */
static int
pmap_remove_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t sva,
    pd_entry_t l1e, struct spglist *free, struct rwlock **lockp)
{
	struct md_page *pvh;
	pt_entry_t old_l2;
	vm_offset_t eva, va;
	vm_page_t m, ml3;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT((sva & L2_OFFSET) == 0, ("pmap_remove_l2: sva is not aligned"));
	old_l2 = pmap_load_clear(l2);
	KASSERT((old_l2 & ATTR_DESCR_MASK) == L2_BLOCK,
	    ("pmap_remove_l2: L2e %lx is not a block mapping", old_l2));

	/*
	 * Since a promotion must break the 4KB page mappings before making
	 * the 2MB page mapping, a pmap_invalidate_page() suffices.
	 */
	pmap_invalidate_page(pmap, sva);

	if (old_l2 & ATTR_SW_WIRED)
		pmap->pm_stats.wired_count -= L2_SIZE / PAGE_SIZE;
	pmap_resident_count_dec(pmap, L2_SIZE / PAGE_SIZE);
	if (old_l2 & ATTR_SW_MANAGED) {
		CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, old_l2 & ~ATTR_MASK);
		pvh = pa_to_pvh(old_l2 & ~ATTR_MASK);
		pmap_pvh_free(pvh, pmap, sva);
		eva = sva + L2_SIZE;
		for (va = sva, m = PHYS_TO_VM_PAGE(old_l2 & ~ATTR_MASK);
		    va < eva; va += PAGE_SIZE, m++) {
			if (pmap_pte_dirty(pmap, old_l2))
				vm_page_dirty(m);
			if (old_l2 & ATTR_AF)
				vm_page_aflag_set(m, PGA_REFERENCED);
			if (TAILQ_EMPTY(&m->md.pv_list) &&
			    TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
	}
	if (pmap == kernel_pmap) {
		pmap_remove_kernel_l2(pmap, l2, sva);
	} else {
		ml3 = pmap_remove_pt_page(pmap, sva);
		if (ml3 != NULL) {
			KASSERT(ml3->valid == VM_PAGE_BITS_ALL,
			    ("pmap_remove_l2: l3 page not promoted"));
			pmap_resident_count_dec(pmap, 1);
			KASSERT(ml3->ref_count == NL3PG,
			    ("pmap_remove_l2: l3 page ref count error"));
			ml3->ref_count = 0;
			pmap_add_delayed_free_list(ml3, free, FALSE);
		}
	}
	return (pmap_unuse_pt(pmap, sva, l1e, free));
}

/*
 * pmap_remove_l3: do the things to unmap a page in a process
 */
static int
pmap_remove_l3(pmap_t pmap, pt_entry_t *l3, vm_offset_t va,
    pd_entry_t l2e, struct spglist *free, struct rwlock **lockp)
{
	struct md_page *pvh;
	pt_entry_t old_l3;
	vm_page_t m;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	old_l3 = pmap_load_clear(l3);
	pmap_invalidate_page(pmap, va);
	if (old_l3 & ATTR_SW_WIRED)
		pmap->pm_stats.wired_count -= 1;
	pmap_resident_count_dec(pmap, 1);
	if (old_l3 & ATTR_SW_MANAGED) {
		m = PHYS_TO_VM_PAGE(old_l3 & ~ATTR_MASK);
		if (pmap_pte_dirty(pmap, old_l3))
			vm_page_dirty(m);
		if (old_l3 & ATTR_AF)
			vm_page_aflag_set(m, PGA_REFERENCED);
		CHANGE_PV_LIST_LOCK_TO_VM_PAGE(lockp, m);
		pmap_pvh_free(&m->md, pmap, va);
		if (TAILQ_EMPTY(&m->md.pv_list) &&
		    (m->flags & PG_FICTITIOUS) == 0) {
			pvh = page_to_pvh(m);
			if (TAILQ_EMPTY(&pvh->pv_list))
				vm_page_aflag_clear(m, PGA_WRITEABLE);
		}
	}
	return (pmap_unuse_pt(pmap, va, l2e, free));
}

/*
 * Remove the specified range of addresses from the L3 page table that is
 * identified by the given L2 entry.
 */
static void
pmap_remove_l3_range(pmap_t pmap, pd_entry_t l2e, vm_offset_t sva,
    vm_offset_t eva, struct spglist *free, struct rwlock **lockp)
{
	struct md_page *pvh;
	struct rwlock *new_lock;
	pt_entry_t *l3, old_l3;
	vm_offset_t va;
	vm_page_t l3pg, m;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(rounddown2(sva, L2_SIZE) + L2_SIZE == roundup2(eva, L2_SIZE),
	    ("pmap_remove_l3_range: range crosses an L3 page table boundary"));
	l3pg = sva < VM_MAXUSER_ADDRESS ? PHYS_TO_VM_PAGE(l2e & ~ATTR_MASK) :
	    NULL;
	va = eva;
	for (l3 = pmap_l2_to_l3(&l2e, sva); sva != eva; l3++, sva += L3_SIZE) {
		if (!pmap_l3_valid(pmap_load(l3))) {
			if (va != eva) {
				pmap_invalidate_range(pmap, va, sva);
				va = eva;
			}
			continue;
		}
		old_l3 = pmap_load_clear(l3);
		if ((old_l3 & ATTR_SW_WIRED) != 0)
			pmap->pm_stats.wired_count--;
		pmap_resident_count_dec(pmap, 1);
		if ((old_l3 & ATTR_SW_MANAGED) != 0) {
			m = PHYS_TO_VM_PAGE(old_l3 & ~ATTR_MASK);
			if (pmap_pte_dirty(pmap, old_l3))
				vm_page_dirty(m);
			if ((old_l3 & ATTR_AF) != 0)
				vm_page_aflag_set(m, PGA_REFERENCED);
			new_lock = PHYS_TO_PV_LIST_LOCK(VM_PAGE_TO_PHYS(m));
			if (new_lock != *lockp) {
				if (*lockp != NULL) {
					/*
					 * Pending TLB invalidations must be
					 * performed before the PV list lock is
					 * released.  Otherwise, a concurrent
					 * pmap_remove_all() on a physical page
					 * could return while a stale TLB entry
					 * still provides access to that page.
					 */
					if (va != eva) {
						pmap_invalidate_range(pmap, va,
						    sva);
						va = eva;
					}
					rw_wunlock(*lockp);
				}
				*lockp = new_lock;
				rw_wlock(*lockp);
			}
			pmap_pvh_free(&m->md, pmap, sva);
			if (TAILQ_EMPTY(&m->md.pv_list) &&
			    (m->flags & PG_FICTITIOUS) == 0) {
				pvh = page_to_pvh(m);
				if (TAILQ_EMPTY(&pvh->pv_list))
					vm_page_aflag_clear(m, PGA_WRITEABLE);
			}
		}
		if (va == eva)
			va = sva;
		if (l3pg != NULL && pmap_unwire_l3(pmap, sva, l3pg, free)) {
			sva += L3_SIZE;
			break;
		}
	}
	if (va != eva)
		pmap_invalidate_range(pmap, va, sva);
}

/*
 *	Remove the given range of addresses from the specified map.
 *
 *	It is assumed that the start and end are properly
 *	rounded to the page size.
 */
void
pmap_remove(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	struct rwlock *lock;
	vm_offset_t va_next;
	pd_entry_t *l0, *l1, *l2;
	pt_entry_t l3_paddr;
	struct spglist free;

	/*
	 * Perform an unsynchronized read.  This is, however, safe.
	 */
	if (pmap->pm_stats.resident_count == 0)
		return;

	SLIST_INIT(&free);

	PMAP_LOCK(pmap);

	lock = NULL;
	for (; sva < eva; sva = va_next) {
		if (pmap->pm_stats.resident_count == 0)
			break;

		l0 = pmap_l0(pmap, sva);
		if (pmap_load(l0) == 0) {
			va_next = (sva + L0_SIZE) & ~L0_OFFSET;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		va_next = (sva + L1_SIZE) & ~L1_OFFSET;
		if (va_next < sva)
			va_next = eva;
		l1 = pmap_l0_to_l1(l0, sva);
		if (pmap_load(l1) == 0)
			continue;
		if ((pmap_load(l1) & ATTR_DESCR_MASK) == L1_BLOCK) {
			KASSERT(va_next <= eva,
			    ("partial update of non-transparent 1G page "
			    "l1 %#lx sva %#lx eva %#lx va_next %#lx",
			    pmap_load(l1), sva, eva, va_next));
			MPASS(pmap != kernel_pmap);
			MPASS((pmap_load(l1) & ATTR_SW_MANAGED) == 0);
			pmap_clear(l1);
			pmap_invalidate_page(pmap, sva);
			pmap_resident_count_dec(pmap, L1_SIZE / PAGE_SIZE);
			pmap_unuse_pt(pmap, sva, pmap_load(l0), &free);
			continue;
		}

		/*
		 * Calculate index for next page table.
		 */
		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;

		l2 = pmap_l1_to_l2(l1, sva);
		if (l2 == NULL)
			continue;

		l3_paddr = pmap_load(l2);

		if ((l3_paddr & ATTR_DESCR_MASK) == L2_BLOCK) {
			if (sva + L2_SIZE == va_next && eva >= va_next) {
				pmap_remove_l2(pmap, l2, sva, pmap_load(l1),
				    &free, &lock);
				continue;
			} else if (pmap_demote_l2_locked(pmap, l2, sva,
			    &lock) == NULL)
				continue;
			l3_paddr = pmap_load(l2);
		}

		/*
		 * Weed out invalid mappings.
		 */
		if ((l3_paddr & ATTR_DESCR_MASK) != L2_TABLE)
			continue;

		/*
		 * Limit our scan to either the end of the va represented
		 * by the current page table page, or to the end of the
		 * range being removed.
		 */
		if (va_next > eva)
			va_next = eva;

		pmap_remove_l3_range(pmap, l3_paddr, sva, va_next, &free,
		    &lock);
	}
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
	vm_page_free_pages_toq(&free, true);
}

/*
 *	Routine:	pmap_remove_all
 *	Function:
 *		Removes this physical page from
 *		all physical maps in which it resides.
 *		Reflects back modify bits to the pager.
 *
 *	Notes:
 *		Original versions of this routine were very
 *		inefficient because they iteratively called
 *		pmap_remove (slow...)
 */

void
pmap_remove_all(vm_page_t m)
{
	struct md_page *pvh;
	pv_entry_t pv;
	pmap_t pmap;
	struct rwlock *lock;
	pd_entry_t *pde, tpde;
	pt_entry_t *pte, tpte;
	vm_offset_t va;
	struct spglist free;
	int lvl, pvh_gen, md_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_remove_all: page %p is not managed", m));
	SLIST_INIT(&free);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy : page_to_pvh(m);
retry:
	rw_wlock(lock);
	while ((pv = TAILQ_FIRST(&pvh->pv_list)) != NULL) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				rw_wunlock(lock);
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		va = pv->pv_va;
		pte = pmap_pte(pmap, va, &lvl);
		KASSERT(pte != NULL,
		    ("pmap_remove_all: no page table entry found"));
		KASSERT(lvl == 2,
		    ("pmap_remove_all: invalid pte level %d", lvl));

		pmap_demote_l2_locked(pmap, pte, va, &lock);
		PMAP_UNLOCK(pmap);
	}
	while ((pv = TAILQ_FIRST(&m->md.pv_list)) != NULL) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				rw_wunlock(lock);
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		pmap_resident_count_dec(pmap, 1);

		pde = pmap_pde(pmap, pv->pv_va, &lvl);
		KASSERT(pde != NULL,
		    ("pmap_remove_all: no page directory entry found"));
		KASSERT(lvl == 2,
		    ("pmap_remove_all: invalid pde level %d", lvl));
		tpde = pmap_load(pde);

		pte = pmap_l2_to_l3(pde, pv->pv_va);
		tpte = pmap_load_clear(pte);
		if (tpte & ATTR_SW_WIRED)
			pmap->pm_stats.wired_count--;
		if ((tpte & ATTR_AF) != 0) {
			pmap_invalidate_page(pmap, pv->pv_va);
			vm_page_aflag_set(m, PGA_REFERENCED);
		}

		/*
		 * Update the vm_page_t clean and reference bits.
		 */
		if (pmap_pte_dirty(pmap, tpte))
			vm_page_dirty(m);
		pmap_unuse_pt(pmap, pv->pv_va, tpde, &free);
		TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		free_pv_entry(pmap, pv);
		PMAP_UNLOCK(pmap);
	}
	vm_page_aflag_clear(m, PGA_WRITEABLE);
	rw_wunlock(lock);
	vm_page_free_pages_toq(&free, true);
}

/*
 * pmap_protect_l2: do the things to protect a 2MB page in a pmap
 */
static void
pmap_protect_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t sva, pt_entry_t mask,
    pt_entry_t nbits)
{
	pd_entry_t old_l2;
	vm_page_t m, mt;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PMAP_ASSERT_STAGE1(pmap);
	KASSERT((sva & L2_OFFSET) == 0,
	    ("pmap_protect_l2: sva is not 2mpage aligned"));
	old_l2 = pmap_load(l2);
	KASSERT((old_l2 & ATTR_DESCR_MASK) == L2_BLOCK,
	    ("pmap_protect_l2: L2e %lx is not a block mapping", old_l2));

	/*
	 * Return if the L2 entry already has the desired access restrictions
	 * in place.
	 */
retry:
	if ((old_l2 & mask) == nbits)
		return;

	/*
	 * When a dirty read/write superpage mapping is write protected,
	 * update the dirty field of each of the superpage's constituent 4KB
	 * pages.
	 */
	if ((old_l2 & ATTR_SW_MANAGED) != 0 &&
	    (nbits & ATTR_S1_AP(ATTR_S1_AP_RO)) != 0 &&
	    pmap_pte_dirty(pmap, old_l2)) {
		m = PHYS_TO_VM_PAGE(old_l2 & ~ATTR_MASK);
		for (mt = m; mt < &m[L2_SIZE / PAGE_SIZE]; mt++)
			vm_page_dirty(mt);
	}

	if (!atomic_fcmpset_64(l2, &old_l2, (old_l2 & ~mask) | nbits))
		goto retry;

	/*
	 * Since a promotion must break the 4KB page mappings before making
	 * the 2MB page mapping, a pmap_invalidate_page() suffices.
	 */
	pmap_invalidate_page(pmap, sva);
}

/*
 *	Set the physical protection on the
 *	specified range of this map as requested.
 */
void
pmap_protect(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, vm_prot_t prot)
{
	vm_offset_t va, va_next;
	pd_entry_t *l0, *l1, *l2;
	pt_entry_t *l3p, l3, mask, nbits;

	PMAP_ASSERT_STAGE1(pmap);
	KASSERT((prot & ~VM_PROT_ALL) == 0, ("invalid prot %x", prot));
	if (prot == VM_PROT_NONE) {
		pmap_remove(pmap, sva, eva);
		return;
	}

	mask = nbits = 0;
	if ((prot & VM_PROT_WRITE) == 0) {
		mask |= ATTR_S1_AP_RW_BIT | ATTR_SW_DBM;
		nbits |= ATTR_S1_AP(ATTR_S1_AP_RO);
	}
	if ((prot & VM_PROT_EXECUTE) == 0) {
		mask |= ATTR_S1_XN;
		nbits |= ATTR_S1_XN;
	}
	if (mask == 0)
		return;

	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		l0 = pmap_l0(pmap, sva);
		if (pmap_load(l0) == 0) {
			va_next = (sva + L0_SIZE) & ~L0_OFFSET;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		va_next = (sva + L1_SIZE) & ~L1_OFFSET;
		if (va_next < sva)
			va_next = eva;
		l1 = pmap_l0_to_l1(l0, sva);
		if (pmap_load(l1) == 0)
			continue;
		if ((pmap_load(l1) & ATTR_DESCR_MASK) == L1_BLOCK) {
			KASSERT(va_next <= eva,
			    ("partial update of non-transparent 1G page "
			    "l1 %#lx sva %#lx eva %#lx va_next %#lx",
			    pmap_load(l1), sva, eva, va_next));
			MPASS((pmap_load(l1) & ATTR_SW_MANAGED) == 0);
			if ((pmap_load(l1) & mask) != nbits) {
				pmap_store(l1, (pmap_load(l1) & ~mask) | nbits);
				pmap_invalidate_page(pmap, sva);
			}
			continue;
		}

		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;

		l2 = pmap_l1_to_l2(l1, sva);
		if (pmap_load(l2) == 0)
			continue;

		if ((pmap_load(l2) & ATTR_DESCR_MASK) == L2_BLOCK) {
			if (sva + L2_SIZE == va_next && eva >= va_next) {
				pmap_protect_l2(pmap, l2, sva, mask, nbits);
				continue;
			} else if (pmap_demote_l2(pmap, l2, sva) == NULL)
				continue;
		}
		KASSERT((pmap_load(l2) & ATTR_DESCR_MASK) == L2_TABLE,
		    ("pmap_protect: Invalid L2 entry after demotion"));

		if (va_next > eva)
			va_next = eva;

		va = va_next;
		for (l3p = pmap_l2_to_l3(l2, sva); sva != va_next; l3p++,
		    sva += L3_SIZE) {
			l3 = pmap_load(l3p);
retry:
			/*
			 * Go to the next L3 entry if the current one is
			 * invalid or already has the desired access
			 * restrictions in place.  (The latter case occurs
			 * frequently.  For example, in a "buildworld"
			 * workload, almost 1 out of 4 L3 entries already
			 * have the desired restrictions.)
			 */
			if (!pmap_l3_valid(l3) || (l3 & mask) == nbits) {
				if (va != va_next) {
					pmap_invalidate_range(pmap, va, sva);
					va = va_next;
				}
				continue;
			}

			/*
			 * When a dirty read/write mapping is write protected,
			 * update the page's dirty field.
			 */
			if ((l3 & ATTR_SW_MANAGED) != 0 &&
			    (nbits & ATTR_S1_AP(ATTR_S1_AP_RO)) != 0 &&
			    pmap_pte_dirty(pmap, l3))
				vm_page_dirty(PHYS_TO_VM_PAGE(l3 & ~ATTR_MASK));

			if (!atomic_fcmpset_64(l3p, &l3, (l3 & ~mask) | nbits))
				goto retry;
			if (va == va_next)
				va = sva;
		}
		if (va != va_next)
			pmap_invalidate_range(pmap, va, sva);
	}
	PMAP_UNLOCK(pmap);
}

/*
 * Inserts the specified page table page into the specified pmap's collection
 * of idle page table pages.  Each of a pmap's page table pages is responsible
 * for mapping a distinct range of virtual addresses.  The pmap's collection is
 * ordered by this virtual address range.
 *
 * If "promoted" is false, then the page table page "mpte" must be zero filled.
 */
static __inline int
pmap_insert_pt_page(pmap_t pmap, vm_page_t mpte, bool promoted)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	mpte->valid = promoted ? VM_PAGE_BITS_ALL : 0;
	return (vm_radix_insert(&pmap->pm_root, mpte));
}

/*
 * Removes the page table page mapping the specified virtual address from the
 * specified pmap's collection of idle page table pages, and returns it.
 * Otherwise, returns NULL if there is no page table page corresponding to the
 * specified virtual address.
 */
static __inline vm_page_t
pmap_remove_pt_page(pmap_t pmap, vm_offset_t va)
{

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	return (vm_radix_remove(&pmap->pm_root, pmap_l2_pindex(va)));
}

/*
 * Performs a break-before-make update of a pmap entry. This is needed when
 * either promoting or demoting pages to ensure the TLB doesn't get into an
 * inconsistent state.
 */
static void
pmap_update_entry(pmap_t pmap, pd_entry_t *pte, pd_entry_t newpte,
    vm_offset_t va, vm_size_t size)
{
	register_t intr;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	/*
	 * Ensure we don't get switched out with the page table in an
	 * inconsistent state. We also need to ensure no interrupts fire
	 * as they may make use of an address we are about to invalidate.
	 */
	intr = intr_disable();

	/*
	 * Clear the old mapping's valid bit, but leave the rest of the entry
	 * unchanged, so that a lockless, concurrent pmap_kextract() can still
	 * lookup the physical address.
	 */
	pmap_clear_bits(pte, ATTR_DESCR_VALID);
	pmap_invalidate_range(pmap, va, va + size);

	/* Create the new mapping */
	pmap_store(pte, newpte);
	dsb(ishst);

	intr_restore(intr);
}

#if VM_NRESERVLEVEL > 0
/*
 * After promotion from 512 4KB page mappings to a single 2MB page mapping,
 * replace the many pv entries for the 4KB page mappings by a single pv entry
 * for the 2MB page mapping.
 */
static void
pmap_pv_promote_l2(pmap_t pmap, vm_offset_t va, vm_paddr_t pa,
    struct rwlock **lockp)
{
	struct md_page *pvh;
	pv_entry_t pv;
	vm_offset_t va_last;
	vm_page_t m;

	KASSERT((pa & L2_OFFSET) == 0,
	    ("pmap_pv_promote_l2: pa is not 2mpage aligned"));
	CHANGE_PV_LIST_LOCK_TO_PHYS(lockp, pa);

	/*
	 * Transfer the first page's pv entry for this mapping to the 2mpage's
	 * pv list.  Aside from avoiding the cost of a call to get_pv_entry(),
	 * a transfer avoids the possibility that get_pv_entry() calls
	 * reclaim_pv_chunk() and that reclaim_pv_chunk() removes one of the
	 * mappings that is being promoted.
	 */
	m = PHYS_TO_VM_PAGE(pa);
	va = va & ~L2_OFFSET;
	pv = pmap_pvh_remove(&m->md, pmap, va);
	KASSERT(pv != NULL, ("pmap_pv_promote_l2: pv not found"));
	pvh = pa_to_pvh(pa);
	TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
	pvh->pv_gen++;
	/* Free the remaining NPTEPG - 1 pv entries. */
	va_last = va + L2_SIZE - PAGE_SIZE;
	do {
		m++;
		va += PAGE_SIZE;
		pmap_pvh_free(&m->md, pmap, va);
	} while (va < va_last);
}

/*
 * Tries to promote the 512, contiguous 4KB page mappings that are within a
 * single level 2 table entry to a single 2MB page mapping.  For promotion
 * to occur, two conditions must be met: (1) the 4KB page mappings must map
 * aligned, contiguous physical memory and (2) the 4KB page mappings must have
 * identical characteristics.
 */
static void
pmap_promote_l2(pmap_t pmap, pd_entry_t *l2, vm_offset_t va,
    struct rwlock **lockp)
{
	pt_entry_t *firstl3, *l3, newl2, oldl3, pa;
	vm_page_t mpte;
	vm_offset_t sva;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PMAP_ASSERT_STAGE1(pmap);

	sva = va & ~L2_OFFSET;
	firstl3 = pmap_l2_to_l3(l2, sva);
	newl2 = pmap_load(firstl3);

setl2:
	if (((newl2 & (~ATTR_MASK | ATTR_AF)) & L2_OFFSET) != ATTR_AF) {
		atomic_add_long(&pmap_l2_p_failures, 1);
		CTR2(KTR_PMAP, "pmap_promote_l2: failure for va %#lx"
		    " in pmap %p", va, pmap);
		return;
	}

	if ((newl2 & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) ==
	    (ATTR_S1_AP(ATTR_S1_AP_RO) | ATTR_SW_DBM)) {
		if (!atomic_fcmpset_64(l2, &newl2, newl2 & ~ATTR_SW_DBM))
			goto setl2;
		newl2 &= ~ATTR_SW_DBM;
	}

	pa = newl2 + L2_SIZE - PAGE_SIZE;
	for (l3 = firstl3 + NL3PG - 1; l3 > firstl3; l3--) {
		oldl3 = pmap_load(l3);
setl3:
		if ((oldl3 & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) ==
		    (ATTR_S1_AP(ATTR_S1_AP_RO) | ATTR_SW_DBM)) {
			if (!atomic_fcmpset_64(l3, &oldl3, oldl3 &
			    ~ATTR_SW_DBM))
				goto setl3;
			oldl3 &= ~ATTR_SW_DBM;
		}
		if (oldl3 != pa) {
			atomic_add_long(&pmap_l2_p_failures, 1);
			CTR2(KTR_PMAP, "pmap_promote_l2: failure for va %#lx"
			    " in pmap %p", va, pmap);
			return;
		}
		pa -= PAGE_SIZE;
	}

	/*
	 * Save the page table page in its current state until the L2
	 * mapping the superpage is demoted by pmap_demote_l2() or
	 * destroyed by pmap_remove_l3().
	 */
	mpte = PHYS_TO_VM_PAGE(pmap_load(l2) & ~ATTR_MASK);
	KASSERT(mpte >= vm_page_array &&
	    mpte < &vm_page_array[vm_page_array_size],
	    ("pmap_promote_l2: page table page is out of range"));
	KASSERT(mpte->pindex == pmap_l2_pindex(va),
	    ("pmap_promote_l2: page table page's pindex is wrong"));
	if (pmap_insert_pt_page(pmap, mpte, true)) {
		atomic_add_long(&pmap_l2_p_failures, 1);
		CTR2(KTR_PMAP,
		    "pmap_promote_l2: failure for va %#lx in pmap %p", va,
		    pmap);
		return;
	}

	if ((newl2 & ATTR_SW_MANAGED) != 0)
		pmap_pv_promote_l2(pmap, va, newl2 & ~ATTR_MASK, lockp);

	newl2 &= ~ATTR_DESCR_MASK;
	newl2 |= L2_BLOCK;

	pmap_update_entry(pmap, l2, newl2, sva, L2_SIZE);

	atomic_add_long(&pmap_l2_promotions, 1);
	CTR2(KTR_PMAP, "pmap_promote_l2: success for va %#lx in pmap %p", va,
		    pmap);
}
#endif /* VM_NRESERVLEVEL > 0 */

static int
pmap_enter_largepage(pmap_t pmap, vm_offset_t va, pt_entry_t newpte, int flags,
    int psind)
{
	pd_entry_t *l0p, *l1p, *l2p, origpte;
	vm_page_t mp;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	KASSERT(psind > 0 && psind < MAXPAGESIZES,
	    ("psind %d unexpected", psind));
	KASSERT(((newpte & ~ATTR_MASK) & (pagesizes[psind] - 1)) == 0,
	    ("unaligned phys address %#lx newpte %#lx psind %d",
	    (newpte & ~ATTR_MASK), newpte, psind));

restart:
	if (psind == 2) {
		l0p = pmap_l0(pmap, va);
		if ((pmap_load(l0p) & ATTR_DESCR_VALID) == 0) {
			mp = _pmap_alloc_l3(pmap, pmap_l0_pindex(va), NULL);
			if (mp == NULL) {
				if ((flags & PMAP_ENTER_NOSLEEP) != 0)
					return (KERN_RESOURCE_SHORTAGE);
				PMAP_UNLOCK(pmap);
				vm_wait(NULL);
				PMAP_LOCK(pmap);
				goto restart;
			}
			l1p = pmap_l0_to_l1(l0p, va);
			KASSERT(l1p != NULL, ("va %#lx lost l1 entry", va));
			origpte = pmap_load(l1p);
		} else {
			l1p = pmap_l0_to_l1(l0p, va);
			KASSERT(l1p != NULL, ("va %#lx lost l1 entry", va));
			origpte = pmap_load(l1p);
			if ((origpte & ATTR_DESCR_VALID) == 0) {
				mp = PHYS_TO_VM_PAGE(pmap_load(l0p) &
				    ~ATTR_MASK);
				mp->ref_count++;
			}
		}
		KASSERT((origpte & ATTR_DESCR_VALID) == 0 ||
		    ((origpte & ATTR_DESCR_MASK) == L1_BLOCK &&
		     (origpte & ~ATTR_MASK) == (newpte & ~ATTR_MASK)),
		    ("va %#lx changing 1G phys page l1 %#lx newpte %#lx",
		    va, origpte, newpte));
		pmap_store(l1p, newpte);
	} else /* (psind == 1) */ {
		l2p = pmap_l2(pmap, va);
		if (l2p == NULL) {
			mp = _pmap_alloc_l3(pmap, pmap_l1_pindex(va), NULL);
			if (mp == NULL) {
				if ((flags & PMAP_ENTER_NOSLEEP) != 0)
					return (KERN_RESOURCE_SHORTAGE);
				PMAP_UNLOCK(pmap);
				vm_wait(NULL);
				PMAP_LOCK(pmap);
				goto restart;
			}
			l2p = (pd_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mp));
			l2p = &l2p[pmap_l2_index(va)];
			origpte = pmap_load(l2p);
		} else {
			l1p = pmap_l1(pmap, va);
			origpte = pmap_load(l2p);
			if ((origpte & ATTR_DESCR_VALID) == 0) {
				mp = PHYS_TO_VM_PAGE(pmap_load(l1p) &
				    ~ATTR_MASK);
				mp->ref_count++;
			}
		}
		KASSERT((origpte & ATTR_DESCR_VALID) == 0 ||
		    ((origpte & ATTR_DESCR_MASK) == L2_BLOCK &&
		     (origpte & ~ATTR_MASK) == (newpte & ~ATTR_MASK)),
		    ("va %#lx changing 2M phys page l2 %#lx newpte %#lx",
		    va, origpte, newpte));
		pmap_store(l2p, newpte);
	}
	dsb(ishst);

	if ((origpte & ATTR_DESCR_VALID) == 0)
		pmap_resident_count_inc(pmap, pagesizes[psind] / PAGE_SIZE);
	if ((newpte & ATTR_SW_WIRED) != 0 && (origpte & ATTR_SW_WIRED) == 0)
		pmap->pm_stats.wired_count += pagesizes[psind] / PAGE_SIZE;
	else if ((newpte & ATTR_SW_WIRED) == 0 &&
	    (origpte & ATTR_SW_WIRED) != 0)
		pmap->pm_stats.wired_count -= pagesizes[psind] / PAGE_SIZE;

	return (KERN_SUCCESS);
}

/*
 * Add a single SMMU entry. This function does not sleep.
 */
int
pmap_senter(pmap_t pmap, vm_offset_t va, vm_paddr_t pa,
    vm_prot_t prot, u_int flags)
{
	pd_entry_t *pde;
	pt_entry_t new_l3, orig_l3;
	pt_entry_t *l3;
	vm_page_t mpte;
	int lvl;
	int rv;

	PMAP_ASSERT_STAGE1(pmap);
	KASSERT(va < VM_MAXUSER_ADDRESS, ("wrong address space"));

	va = trunc_page(va);
	new_l3 = (pt_entry_t)(pa | ATTR_DEFAULT |
	    ATTR_S1_IDX(VM_MEMATTR_DEVICE) | L3_PAGE);
	if ((prot & VM_PROT_WRITE) == 0)
		new_l3 |= ATTR_S1_AP(ATTR_S1_AP_RO);
	new_l3 |= ATTR_S1_XN; /* Execute never. */
	new_l3 |= ATTR_S1_AP(ATTR_S1_AP_USER);
	new_l3 |= ATTR_S1_nG; /* Non global. */

	CTR2(KTR_PMAP, "pmap_senter: %.16lx -> %.16lx", va, pa);

	PMAP_LOCK(pmap);

	/*
	 * In the case that a page table page is not
	 * resident, we are creating it here.
	 */
retry:
	pde = pmap_pde(pmap, va, &lvl);
	if (pde != NULL && lvl == 2) {
		l3 = pmap_l2_to_l3(pde, va);
	} else {
		mpte = _pmap_alloc_l3(pmap, pmap_l2_pindex(va), NULL);
		if (mpte == NULL) {
			CTR0(KTR_PMAP, "pmap_enter: mpte == NULL");
			rv = KERN_RESOURCE_SHORTAGE;
			goto out;
		}
		goto retry;
	}

	orig_l3 = pmap_load(l3);
	KASSERT(!pmap_l3_valid(orig_l3), ("l3 is valid"));

	/* New mapping */
	pmap_store(l3, new_l3);
	pmap_resident_count_inc(pmap, 1);
	dsb(ishst);

	rv = KERN_SUCCESS;
out:
	PMAP_UNLOCK(pmap);

	return (rv);
}

/*
 * Remove a single SMMU entry.
 */
int
pmap_sremove(pmap_t pmap, vm_offset_t va)
{
	pt_entry_t *pte;
	int lvl;
	int rc;

	PMAP_LOCK(pmap);

	pte = pmap_pte(pmap, va, &lvl);
	KASSERT(lvl == 3,
	    ("Invalid SMMU pagetable level: %d != 3", lvl));

	if (pte != NULL) {
		pmap_resident_count_dec(pmap, 1);
		pmap_clear(pte);
		rc = KERN_SUCCESS;
	} else
		rc = KERN_FAILURE;

	PMAP_UNLOCK(pmap);

	return (rc);
}

/*
 * Remove all the allocated L1, L2 pages from SMMU pmap.
 * All the L3 entires must be cleared in advance, otherwise
 * this function panics.
 */
void
pmap_sremove_pages(pmap_t pmap)
{
	pd_entry_t l0e, *l1, l1e, *l2, l2e;
	pt_entry_t *l3, l3e;
	vm_page_t m, m0, m1;
	vm_offset_t sva;
	vm_paddr_t pa;
	vm_paddr_t pa0;
	vm_paddr_t pa1;
	int i, j, k, l;

	PMAP_LOCK(pmap);

	for (sva = VM_MINUSER_ADDRESS, i = pmap_l0_index(sva);
	    (i < Ln_ENTRIES && sva < VM_MAXUSER_ADDRESS); i++) {
		l0e = pmap->pm_l0[i];
		if ((l0e & ATTR_DESCR_VALID) == 0) {
			sva += L0_SIZE;
			continue;
		}
		pa0 = l0e & ~ATTR_MASK;
		m0 = PHYS_TO_VM_PAGE(pa0);
		l1 = (pd_entry_t *)PHYS_TO_DMAP(pa0);

		for (j = pmap_l1_index(sva); j < Ln_ENTRIES; j++) {
			l1e = l1[j];
			if ((l1e & ATTR_DESCR_VALID) == 0) {
				sva += L1_SIZE;
				continue;
			}
			if ((l1e & ATTR_DESCR_MASK) == L1_BLOCK) {
				sva += L1_SIZE;
				continue;
			}
			pa1 = l1e & ~ATTR_MASK;
			m1 = PHYS_TO_VM_PAGE(pa1);
			l2 = (pd_entry_t *)PHYS_TO_DMAP(pa1);

			for (k = pmap_l2_index(sva); k < Ln_ENTRIES; k++) {
				l2e = l2[k];
				if ((l2e & ATTR_DESCR_VALID) == 0) {
					sva += L2_SIZE;
					continue;
				}
				pa = l2e & ~ATTR_MASK;
				m = PHYS_TO_VM_PAGE(pa);
				l3 = (pt_entry_t *)PHYS_TO_DMAP(pa);

				for (l = pmap_l3_index(sva); l < Ln_ENTRIES;
				    l++, sva += L3_SIZE) {
					l3e = l3[l];
					if ((l3e & ATTR_DESCR_VALID) == 0)
						continue;
					panic("%s: l3e found for va %jx\n",
					    __func__, sva);
				}

				vm_page_unwire_noq(m1);
				vm_page_unwire_noq(m);
				pmap_resident_count_dec(pmap, 1);
				vm_page_free(m);
				pmap_clear(&l2[k]);
			}

			vm_page_unwire_noq(m0);
			pmap_resident_count_dec(pmap, 1);
			vm_page_free(m1);
			pmap_clear(&l1[j]);
		}

		pmap_resident_count_dec(pmap, 1);
		vm_page_free(m0);
		pmap_clear(&pmap->pm_l0[i]);
	}

	KASSERT(pmap->pm_stats.resident_count == 0,
	    ("Invalid resident count %jd", pmap->pm_stats.resident_count));

	PMAP_UNLOCK(pmap);
}

/*
 *	Insert the given physical page (p) at
 *	the specified virtual address (v) in the
 *	target physical map with the protection requested.
 *
 *	If specified, the page will be wired down, meaning
 *	that the related pte can not be reclaimed.
 *
 *	NB:  This is the only routine which MAY NOT lazy-evaluate
 *	or lose information.  That is, this routine must actually
 *	insert this page into the given map NOW.
 */
int
pmap_enter(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
    u_int flags, int8_t psind)
{
	struct rwlock *lock;
	pd_entry_t *pde;
	pt_entry_t new_l3, orig_l3;
	pt_entry_t *l2, *l3;
	pv_entry_t pv;
	vm_paddr_t opa, pa;
	vm_page_t mpte, om;
	boolean_t nosleep;
	int lvl, rv;

	va = trunc_page(va);
	if ((m->oflags & VPO_UNMANAGED) == 0)
		VM_PAGE_OBJECT_BUSY_ASSERT(m);
	pa = VM_PAGE_TO_PHYS(m);
	new_l3 = (pt_entry_t)(pa | ATTR_DEFAULT | L3_PAGE);
	new_l3 |= pmap_pte_memattr(pmap, m->md.pv_memattr);
	new_l3 |= pmap_pte_prot(pmap, prot);

	if ((flags & PMAP_ENTER_WIRED) != 0)
		new_l3 |= ATTR_SW_WIRED;
	if (pmap->pm_stage == PM_STAGE1) {
		if (va < VM_MAXUSER_ADDRESS)
			new_l3 |= ATTR_S1_AP(ATTR_S1_AP_USER) | ATTR_S1_PXN;
		else
			new_l3 |= ATTR_S1_UXN;
		if (pmap != kernel_pmap)
			new_l3 |= ATTR_S1_nG;
	} else {
		/*
		 * Clear the access flag on executable mappings, this will be
		 * set later when the page is accessed. The fault handler is
		 * required to invalidate the I-cache.
		 *
		 * TODO: Switch to the valid flag to allow hardware management
		 * of the access flag. Much of the pmap code assumes the
		 * valid flag is set and fails to destroy the old page tables
		 * correctly if it is clear.
		 */
		if (prot & VM_PROT_EXECUTE)
			new_l3 &= ~ATTR_AF;
	}
	if ((m->oflags & VPO_UNMANAGED) == 0) {
		new_l3 |= ATTR_SW_MANAGED;
		if ((prot & VM_PROT_WRITE) != 0) {
			new_l3 |= ATTR_SW_DBM;
			if ((flags & VM_PROT_WRITE) == 0) {
				if (pmap->pm_stage == PM_STAGE1)
					new_l3 |= ATTR_S1_AP(ATTR_S1_AP_RO);
				else
					new_l3 &=
					    ~ATTR_S2_S2AP(ATTR_S2_S2AP_WRITE);
			}
		}
	}

	CTR2(KTR_PMAP, "pmap_enter: %.16lx -> %.16lx", va, pa);

	lock = NULL;
	PMAP_LOCK(pmap);
	if ((flags & PMAP_ENTER_LARGEPAGE) != 0) {
		KASSERT((m->oflags & VPO_UNMANAGED) != 0,
		    ("managed largepage va %#lx flags %#x", va, flags));
		new_l3 &= ~L3_PAGE;
		if (psind == 2)
			new_l3 |= L1_BLOCK;
		else /* (psind == 1) */
			new_l3 |= L2_BLOCK;
		rv = pmap_enter_largepage(pmap, va, new_l3, flags, psind);
		goto out;
	}
	if (psind == 1) {
		/* Assert the required virtual and physical alignment. */
		KASSERT((va & L2_OFFSET) == 0, ("pmap_enter: va unaligned"));
		KASSERT(m->psind > 0, ("pmap_enter: m->psind < psind"));
		rv = pmap_enter_l2(pmap, va, (new_l3 & ~L3_PAGE) | L2_BLOCK,
		    flags, m, &lock);
		goto out;
	}
	mpte = NULL;

	/*
	 * In the case that a page table page is not
	 * resident, we are creating it here.
	 */
retry:
	pde = pmap_pde(pmap, va, &lvl);
	if (pde != NULL && lvl == 2) {
		l3 = pmap_l2_to_l3(pde, va);
		if (va < VM_MAXUSER_ADDRESS && mpte == NULL) {
			mpte = PHYS_TO_VM_PAGE(pmap_load(pde) & ~ATTR_MASK);
			mpte->ref_count++;
		}
		goto havel3;
	} else if (pde != NULL && lvl == 1) {
		l2 = pmap_l1_to_l2(pde, va);
		if ((pmap_load(l2) & ATTR_DESCR_MASK) == L2_BLOCK &&
		    (l3 = pmap_demote_l2_locked(pmap, l2, va, &lock)) != NULL) {
			l3 = &l3[pmap_l3_index(va)];
			if (va < VM_MAXUSER_ADDRESS) {
				mpte = PHYS_TO_VM_PAGE(
				    pmap_load(l2) & ~ATTR_MASK);
				mpte->ref_count++;
			}
			goto havel3;
		}
		/* We need to allocate an L3 table. */
	}
	if (va < VM_MAXUSER_ADDRESS) {
		nosleep = (flags & PMAP_ENTER_NOSLEEP) != 0;

		/*
		 * We use _pmap_alloc_l3() instead of pmap_alloc_l3() in order
		 * to handle the possibility that a superpage mapping for "va"
		 * was created while we slept.
		 */
		mpte = _pmap_alloc_l3(pmap, pmap_l2_pindex(va),
		    nosleep ? NULL : &lock);
		if (mpte == NULL && nosleep) {
			CTR0(KTR_PMAP, "pmap_enter: mpte == NULL");
			rv = KERN_RESOURCE_SHORTAGE;
			goto out;
		}
		goto retry;
	} else
		panic("pmap_enter: missing L3 table for kernel va %#lx", va);

havel3:
	orig_l3 = pmap_load(l3);
	opa = orig_l3 & ~ATTR_MASK;
	pv = NULL;

	/*
	 * Is the specified virtual address already mapped?
	 */
	if (pmap_l3_valid(orig_l3)) {
		/*
		 * Only allow adding new entries on stage 2 tables for now.
		 * This simplifies cache invalidation as we may need to call
		 * into EL2 to perform such actions.
		 */
		PMAP_ASSERT_STAGE1(pmap);
		/*
		 * Wiring change, just update stats. We don't worry about
		 * wiring PT pages as they remain resident as long as there
		 * are valid mappings in them. Hence, if a user page is wired,
		 * the PT page will be also.
		 */
		if ((flags & PMAP_ENTER_WIRED) != 0 &&
		    (orig_l3 & ATTR_SW_WIRED) == 0)
			pmap->pm_stats.wired_count++;
		else if ((flags & PMAP_ENTER_WIRED) == 0 &&
		    (orig_l3 & ATTR_SW_WIRED) != 0)
			pmap->pm_stats.wired_count--;

		/*
		 * Remove the extra PT page reference.
		 */
		if (mpte != NULL) {
			mpte->ref_count--;
			KASSERT(mpte->ref_count > 0,
			    ("pmap_enter: missing reference to page table page,"
			     " va: 0x%lx", va));
		}

		/*
		 * Has the physical page changed?
		 */
		if (opa == pa) {
			/*
			 * No, might be a protection or wiring change.
			 */
			if ((orig_l3 & ATTR_SW_MANAGED) != 0 &&
			    (new_l3 & ATTR_SW_DBM) != 0)
				vm_page_aflag_set(m, PGA_WRITEABLE);
			goto validate;
		}

		/*
		 * The physical page has changed.  Temporarily invalidate
		 * the mapping.
		 */
		orig_l3 = pmap_load_clear(l3);
		KASSERT((orig_l3 & ~ATTR_MASK) == opa,
		    ("pmap_enter: unexpected pa update for %#lx", va));
		if ((orig_l3 & ATTR_SW_MANAGED) != 0) {
			om = PHYS_TO_VM_PAGE(opa);

			/*
			 * The pmap lock is sufficient to synchronize with
			 * concurrent calls to pmap_page_test_mappings() and
			 * pmap_ts_referenced().
			 */
			if (pmap_pte_dirty(pmap, orig_l3))
				vm_page_dirty(om);
			if ((orig_l3 & ATTR_AF) != 0) {
				pmap_invalidate_page(pmap, va);
				vm_page_aflag_set(om, PGA_REFERENCED);
			}
			CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, opa);
			pv = pmap_pvh_remove(&om->md, pmap, va);
			if ((m->oflags & VPO_UNMANAGED) != 0)
				free_pv_entry(pmap, pv);
			if ((om->a.flags & PGA_WRITEABLE) != 0 &&
			    TAILQ_EMPTY(&om->md.pv_list) &&
			    ((om->flags & PG_FICTITIOUS) != 0 ||
			    TAILQ_EMPTY(&pa_to_pvh(opa)->pv_list)))
				vm_page_aflag_clear(om, PGA_WRITEABLE);
		} else {
			KASSERT((orig_l3 & ATTR_AF) != 0,
			    ("pmap_enter: unmanaged mapping lacks ATTR_AF"));
			pmap_invalidate_page(pmap, va);
		}
		orig_l3 = 0;
	} else {
		/*
		 * Increment the counters.
		 */
		if ((new_l3 & ATTR_SW_WIRED) != 0)
			pmap->pm_stats.wired_count++;
		pmap_resident_count_inc(pmap, 1);
	}
	/*
	 * Enter on the PV list if part of our managed memory.
	 */
	if ((m->oflags & VPO_UNMANAGED) == 0) {
		if (pv == NULL) {
			pv = get_pv_entry(pmap, &lock);
			pv->pv_va = va;
		}
		CHANGE_PV_LIST_LOCK_TO_PHYS(&lock, pa);
		TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
		m->md.pv_gen++;
		if ((new_l3 & ATTR_SW_DBM) != 0)
			vm_page_aflag_set(m, PGA_WRITEABLE);
	}

validate:
	if (pmap->pm_stage == PM_STAGE1) {
		/*
		 * Sync icache if exec permission and attribute
		 * VM_MEMATTR_WRITE_BACK is set. Do it now, before the mapping
		 * is stored and made valid for hardware table walk. If done
		 * later, then other can access this page before caches are
		 * properly synced. Don't do it for kernel memory which is
		 * mapped with exec permission even if the memory isn't going
		 * to hold executable code. The only time when icache sync is
		 * needed is after kernel module is loaded and the relocation
		 * info is processed. And it's done in elf_cpu_load_file().
		*/
		if ((prot & VM_PROT_EXECUTE) &&  pmap != kernel_pmap &&
		    m->md.pv_memattr == VM_MEMATTR_WRITE_BACK &&
		    (opa != pa || (orig_l3 & ATTR_S1_XN))) {
			PMAP_ASSERT_STAGE1(pmap);
			cpu_icache_sync_range(PHYS_TO_DMAP(pa), PAGE_SIZE);
		}
	} else {
		cpu_dcache_wb_range(PHYS_TO_DMAP(pa), PAGE_SIZE);
	}

	/*
	 * Update the L3 entry
	 */
	if (pmap_l3_valid(orig_l3)) {
		PMAP_ASSERT_STAGE1(pmap);
		KASSERT(opa == pa, ("pmap_enter: invalid update"));
		if ((orig_l3 & ~ATTR_AF) != (new_l3 & ~ATTR_AF)) {
			/* same PA, different attributes */
			orig_l3 = pmap_load_store(l3, new_l3);
			pmap_invalidate_page(pmap, va);
			if ((orig_l3 & ATTR_SW_MANAGED) != 0 &&
			    pmap_pte_dirty(pmap, orig_l3))
				vm_page_dirty(m);
		} else {
			/*
			 * orig_l3 == new_l3
			 * This can happens if multiple threads simultaneously
			 * access not yet mapped page. This bad for performance
			 * since this can cause full demotion-NOP-promotion
			 * cycle.
			 * Another possible reasons are:
			 * - VM and pmap memory layout are diverged
			 * - tlb flush is missing somewhere and CPU doesn't see
			 *   actual mapping.
			 */
			CTR4(KTR_PMAP, "%s: already mapped page - "
			    "pmap %p va 0x%#lx pte 0x%lx",
			    __func__, pmap, va, new_l3);
		}
	} else {
		/* New mapping */
		pmap_store(l3, new_l3);
		dsb(ishst);
	}

#if VM_NRESERVLEVEL > 0
	/*
	 * Try to promote from level 3 pages to a level 2 superpage. This
	 * currently only works on stage 1 pmaps as pmap_promote_l2 looks at
	 * stage 1 specific fields and performs a break-before-make sequence
	 * that is incorrect a stage 2 pmap.
	 */
	if ((mpte == NULL || mpte->ref_count == NL3PG) &&
	    pmap_ps_enabled(pmap) && pmap->pm_stage == PM_STAGE1 &&
	    (m->flags & PG_FICTITIOUS) == 0 &&
	    vm_reserv_level_iffullpop(m) == 0) {
		pmap_promote_l2(pmap, pde, va, &lock);
	}
#endif

	rv = KERN_SUCCESS;
out:
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
	return (rv);
}

/*
 * Tries to create a read- and/or execute-only 2MB page mapping.  Returns true
 * if successful.  Returns false if (1) a page table page cannot be allocated
 * without sleeping, (2) a mapping already exists at the specified virtual
 * address, or (3) a PV entry cannot be allocated without reclaiming another
 * PV entry.
 */
static bool
pmap_enter_2mpage(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot,
    struct rwlock **lockp)
{
	pd_entry_t new_l2;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PMAP_ASSERT_STAGE1(pmap);

	new_l2 = (pd_entry_t)(VM_PAGE_TO_PHYS(m) | ATTR_DEFAULT |
	    ATTR_S1_IDX(m->md.pv_memattr) | ATTR_S1_AP(ATTR_S1_AP_RO) |
	    L2_BLOCK);
	if ((m->oflags & VPO_UNMANAGED) == 0) {
		new_l2 |= ATTR_SW_MANAGED;
		new_l2 &= ~ATTR_AF;
	}
	if ((prot & VM_PROT_EXECUTE) == 0 ||
	    m->md.pv_memattr == VM_MEMATTR_DEVICE)
		new_l2 |= ATTR_S1_XN;
	if (va < VM_MAXUSER_ADDRESS)
		new_l2 |= ATTR_S1_AP(ATTR_S1_AP_USER) | ATTR_S1_PXN;
	else
		new_l2 |= ATTR_S1_UXN;
	if (pmap != kernel_pmap)
		new_l2 |= ATTR_S1_nG;
	return (pmap_enter_l2(pmap, va, new_l2, PMAP_ENTER_NOSLEEP |
	    PMAP_ENTER_NOREPLACE | PMAP_ENTER_NORECLAIM, NULL, lockp) ==
	    KERN_SUCCESS);
}

/*
 * Returns true if every page table entry in the specified page table is
 * zero.
 */
static bool
pmap_every_pte_zero(vm_paddr_t pa)
{
	pt_entry_t *pt_end, *pte;

	KASSERT((pa & PAGE_MASK) == 0, ("pa is misaligned"));
	pte = (pt_entry_t *)PHYS_TO_DMAP(pa);
	for (pt_end = pte + Ln_ENTRIES; pte < pt_end; pte++) {
		if (*pte != 0)
			return (false);
	}
	return (true);
}

/*
 * Tries to create the specified 2MB page mapping.  Returns KERN_SUCCESS if
 * the mapping was created, and either KERN_FAILURE or KERN_RESOURCE_SHORTAGE
 * otherwise.  Returns KERN_FAILURE if PMAP_ENTER_NOREPLACE was specified and
 * a mapping already exists at the specified virtual address.  Returns
 * KERN_RESOURCE_SHORTAGE if PMAP_ENTER_NOSLEEP was specified and a page table
 * page allocation failed.  Returns KERN_RESOURCE_SHORTAGE if
 * PMAP_ENTER_NORECLAIM was specified and a PV entry allocation failed.
 *
 * The parameter "m" is only used when creating a managed, writeable mapping.
 */
static int
pmap_enter_l2(pmap_t pmap, vm_offset_t va, pd_entry_t new_l2, u_int flags,
    vm_page_t m, struct rwlock **lockp)
{
	struct spglist free;
	pd_entry_t *l2, old_l2;
	vm_page_t l2pg, mt;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);

	if ((l2 = pmap_alloc_l2(pmap, va, &l2pg, (flags &
	    PMAP_ENTER_NOSLEEP) != 0 ? NULL : lockp)) == NULL) {
		CTR2(KTR_PMAP, "pmap_enter_l2: failure for va %#lx in pmap %p",
		    va, pmap);
		return (KERN_RESOURCE_SHORTAGE);
	}

	/*
	 * If there are existing mappings, either abort or remove them.
	 */
	if ((old_l2 = pmap_load(l2)) != 0) {
		KASSERT(l2pg == NULL || l2pg->ref_count > 1,
		    ("pmap_enter_l2: l2pg's ref count is too low"));
		if ((flags & PMAP_ENTER_NOREPLACE) != 0 && (va <
		    VM_MAXUSER_ADDRESS || (old_l2 & ATTR_DESCR_MASK) ==
		    L2_BLOCK || !pmap_every_pte_zero(old_l2 & ~ATTR_MASK))) {
			if (l2pg != NULL)
				l2pg->ref_count--;
			CTR2(KTR_PMAP, "pmap_enter_l2: failure for va %#lx"
			    " in pmap %p", va, pmap);
			return (KERN_FAILURE);
		}
		SLIST_INIT(&free);
		if ((old_l2 & ATTR_DESCR_MASK) == L2_BLOCK)
			(void)pmap_remove_l2(pmap, l2, va,
			    pmap_load(pmap_l1(pmap, va)), &free, lockp);
		else
			pmap_remove_l3_range(pmap, old_l2, va, va + L2_SIZE,
			    &free, lockp);
		if (va < VM_MAXUSER_ADDRESS) {
			vm_page_free_pages_toq(&free, true);
			KASSERT(pmap_load(l2) == 0,
			    ("pmap_enter_l2: non-zero L2 entry %p", l2));
		} else {
			KASSERT(SLIST_EMPTY(&free),
			    ("pmap_enter_l2: freed kernel page table page"));

			/*
			 * Both pmap_remove_l2() and pmap_remove_l3_range()
			 * will leave the kernel page table page zero filled.
			 * Nonetheless, the TLB could have an intermediate
			 * entry for the kernel page table page.
			 */
			mt = PHYS_TO_VM_PAGE(pmap_load(l2) & ~ATTR_MASK);
			if (pmap_insert_pt_page(pmap, mt, false))
				panic("pmap_enter_l2: trie insert failed");
			pmap_clear(l2);
			pmap_invalidate_page(pmap, va);
		}
	}

	if ((new_l2 & ATTR_SW_MANAGED) != 0) {
		/*
		 * Abort this mapping if its PV entry could not be created.
		 */
		if (!pmap_pv_insert_l2(pmap, va, new_l2, flags, lockp)) {
			if (l2pg != NULL)
				pmap_abort_ptp(pmap, va, l2pg);
			CTR2(KTR_PMAP,
			    "pmap_enter_l2: failure for va %#lx in pmap %p",
			    va, pmap);
			return (KERN_RESOURCE_SHORTAGE);
		}
		if ((new_l2 & ATTR_SW_DBM) != 0)
			for (mt = m; mt < &m[L2_SIZE / PAGE_SIZE]; mt++)
				vm_page_aflag_set(mt, PGA_WRITEABLE);
	}

	/*
	 * Increment counters.
	 */
	if ((new_l2 & ATTR_SW_WIRED) != 0)
		pmap->pm_stats.wired_count += L2_SIZE / PAGE_SIZE;
	pmap->pm_stats.resident_count += L2_SIZE / PAGE_SIZE;

	/*
	 * Map the superpage.
	 */
	pmap_store(l2, new_l2);
	dsb(ishst);

	atomic_add_long(&pmap_l2_mappings, 1);
	CTR2(KTR_PMAP, "pmap_enter_l2: success for va %#lx in pmap %p",
	    va, pmap);

	return (KERN_SUCCESS);
}

/*
 * Maps a sequence of resident pages belonging to the same object.
 * The sequence begins with the given page m_start.  This page is
 * mapped at the given virtual address start.  Each subsequent page is
 * mapped at a virtual address that is offset from start by the same
 * amount as the page is offset from m_start within the object.  The
 * last page in the sequence is the page with the largest offset from
 * m_start that can be mapped at a virtual address less than the given
 * virtual address end.  Not every virtual page between start and end
 * is mapped; only those for which a resident page exists with the
 * corresponding offset from m_start are mapped.
 */
void
pmap_enter_object(pmap_t pmap, vm_offset_t start, vm_offset_t end,
    vm_page_t m_start, vm_prot_t prot)
{
	struct rwlock *lock;
	vm_offset_t va;
	vm_page_t m, mpte;
	vm_pindex_t diff, psize;

	VM_OBJECT_ASSERT_LOCKED(m_start->object);

	psize = atop(end - start);
	mpte = NULL;
	m = m_start;
	lock = NULL;
	PMAP_LOCK(pmap);
	while (m != NULL && (diff = m->pindex - m_start->pindex) < psize) {
		va = start + ptoa(diff);
		if ((va & L2_OFFSET) == 0 && va + L2_SIZE <= end &&
		    m->psind == 1 && pmap_ps_enabled(pmap) &&
		    pmap_enter_2mpage(pmap, va, m, prot, &lock))
			m = &m[L2_SIZE / PAGE_SIZE - 1];
		else
			mpte = pmap_enter_quick_locked(pmap, va, m, prot, mpte,
			    &lock);
		m = TAILQ_NEXT(m, listq);
	}
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
}

/*
 * this code makes some *MAJOR* assumptions:
 * 1. Current pmap & pmap exists.
 * 2. Not wired.
 * 3. Read access.
 * 4. No page table pages.
 * but is *MUCH* faster than pmap_enter...
 */

void
pmap_enter_quick(pmap_t pmap, vm_offset_t va, vm_page_t m, vm_prot_t prot)
{
	struct rwlock *lock;

	lock = NULL;
	PMAP_LOCK(pmap);
	(void)pmap_enter_quick_locked(pmap, va, m, prot, NULL, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(pmap);
}

static vm_page_t
pmap_enter_quick_locked(pmap_t pmap, vm_offset_t va, vm_page_t m,
    vm_prot_t prot, vm_page_t mpte, struct rwlock **lockp)
{
	pd_entry_t *pde;
	pt_entry_t *l2, *l3, l3_val;
	vm_paddr_t pa;
	int lvl;

	KASSERT(va < kmi.clean_sva || va >= kmi.clean_eva ||
	    (m->oflags & VPO_UNMANAGED) != 0,
	    ("pmap_enter_quick_locked: managed mapping within the clean submap"));
	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PMAP_ASSERT_STAGE1(pmap);

	CTR2(KTR_PMAP, "pmap_enter_quick_locked: %p %lx", pmap, va);
	/*
	 * In the case that a page table page is not
	 * resident, we are creating it here.
	 */
	if (va < VM_MAXUSER_ADDRESS) {
		vm_pindex_t l2pindex;

		/*
		 * Calculate pagetable page index
		 */
		l2pindex = pmap_l2_pindex(va);
		if (mpte && (mpte->pindex == l2pindex)) {
			mpte->ref_count++;
		} else {
			/*
			 * Get the l2 entry
			 */
			pde = pmap_pde(pmap, va, &lvl);

			/*
			 * If the page table page is mapped, we just increment
			 * the hold count, and activate it.  Otherwise, we
			 * attempt to allocate a page table page.  If this
			 * attempt fails, we don't retry.  Instead, we give up.
			 */
			if (lvl == 1) {
				l2 = pmap_l1_to_l2(pde, va);
				if ((pmap_load(l2) & ATTR_DESCR_MASK) ==
				    L2_BLOCK)
					return (NULL);
			}
			if (lvl == 2 && pmap_load(pde) != 0) {
				mpte =
				    PHYS_TO_VM_PAGE(pmap_load(pde) & ~ATTR_MASK);
				mpte->ref_count++;
			} else {
				/*
				 * Pass NULL instead of the PV list lock
				 * pointer, because we don't intend to sleep.
				 */
				mpte = _pmap_alloc_l3(pmap, l2pindex, NULL);
				if (mpte == NULL)
					return (mpte);
			}
		}
		l3 = (pt_entry_t *)PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mpte));
		l3 = &l3[pmap_l3_index(va)];
	} else {
		mpte = NULL;
		pde = pmap_pde(kernel_pmap, va, &lvl);
		KASSERT(pde != NULL,
		    ("pmap_enter_quick_locked: Invalid page entry, va: 0x%lx",
		     va));
		KASSERT(lvl == 2,
		    ("pmap_enter_quick_locked: Invalid level %d", lvl));
		l3 = pmap_l2_to_l3(pde, va);
	}

	/*
	 * Abort if a mapping already exists.
	 */
	if (pmap_load(l3) != 0) {
		if (mpte != NULL)
			mpte->ref_count--;
		return (NULL);
	}

	/*
	 * Enter on the PV list if part of our managed memory.
	 */
	if ((m->oflags & VPO_UNMANAGED) == 0 &&
	    !pmap_try_insert_pv_entry(pmap, va, m, lockp)) {
		if (mpte != NULL)
			pmap_abort_ptp(pmap, va, mpte);
		return (NULL);
	}

	/*
	 * Increment counters
	 */
	pmap_resident_count_inc(pmap, 1);

	pa = VM_PAGE_TO_PHYS(m);
	l3_val = pa | ATTR_DEFAULT | ATTR_S1_IDX(m->md.pv_memattr) |
	    ATTR_S1_AP(ATTR_S1_AP_RO) | L3_PAGE;
	if ((prot & VM_PROT_EXECUTE) == 0 ||
	    m->md.pv_memattr == VM_MEMATTR_DEVICE)
		l3_val |= ATTR_S1_XN;
	if (va < VM_MAXUSER_ADDRESS)
		l3_val |= ATTR_S1_AP(ATTR_S1_AP_USER) | ATTR_S1_PXN;
	else
		l3_val |= ATTR_S1_UXN;
	if (pmap != kernel_pmap)
		l3_val |= ATTR_S1_nG;

	/*
	 * Now validate mapping with RO protection
	 */
	if ((m->oflags & VPO_UNMANAGED) == 0) {
		l3_val |= ATTR_SW_MANAGED;
		l3_val &= ~ATTR_AF;
	}

	/* Sync icache before the mapping is stored to PTE */
	if ((prot & VM_PROT_EXECUTE) && pmap != kernel_pmap &&
	    m->md.pv_memattr == VM_MEMATTR_WRITE_BACK)
		cpu_icache_sync_range(PHYS_TO_DMAP(pa), PAGE_SIZE);

	pmap_store(l3, l3_val);
	dsb(ishst);

	return (mpte);
}

/*
 * This code maps large physical mmap regions into the
 * processor address space.  Note that some shortcuts
 * are taken, but the code works.
 */
void
pmap_object_init_pt(pmap_t pmap, vm_offset_t addr, vm_object_t object,
    vm_pindex_t pindex, vm_size_t size)
{

	VM_OBJECT_ASSERT_WLOCKED(object);
	KASSERT(object->type == OBJT_DEVICE || object->type == OBJT_SG,
	    ("pmap_object_init_pt: non-device object"));
}

/*
 *	Clear the wired attribute from the mappings for the specified range of
 *	addresses in the given pmap.  Every valid mapping within that range
 *	must have the wired attribute set.  In contrast, invalid mappings
 *	cannot have the wired attribute set, so they are ignored.
 *
 *	The wired attribute of the page table entry is not a hardware feature,
 *	so there is no need to invalidate any TLB entries.
 */
void
pmap_unwire(pmap_t pmap, vm_offset_t sva, vm_offset_t eva)
{
	vm_offset_t va_next;
	pd_entry_t *l0, *l1, *l2;
	pt_entry_t *l3;

	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		l0 = pmap_l0(pmap, sva);
		if (pmap_load(l0) == 0) {
			va_next = (sva + L0_SIZE) & ~L0_OFFSET;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		l1 = pmap_l0_to_l1(l0, sva);
		va_next = (sva + L1_SIZE) & ~L1_OFFSET;
		if (va_next < sva)
			va_next = eva;
		if (pmap_load(l1) == 0)
			continue;

		if ((pmap_load(l1) & ATTR_DESCR_MASK) == L1_BLOCK) {
			KASSERT(va_next <= eva,
			    ("partial update of non-transparent 1G page "
			    "l1 %#lx sva %#lx eva %#lx va_next %#lx",
			    pmap_load(l1), sva, eva, va_next));
			MPASS(pmap != kernel_pmap);
			MPASS((pmap_load(l1) & (ATTR_SW_MANAGED |
			    ATTR_SW_WIRED)) == ATTR_SW_WIRED);
			pmap_clear_bits(l1, ATTR_SW_WIRED);
			pmap->pm_stats.wired_count -= L1_SIZE / PAGE_SIZE;
			continue;
		}

		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;

		l2 = pmap_l1_to_l2(l1, sva);
		if (pmap_load(l2) == 0)
			continue;

		if ((pmap_load(l2) & ATTR_DESCR_MASK) == L2_BLOCK) {
			if ((pmap_load(l2) & ATTR_SW_WIRED) == 0)
				panic("pmap_unwire: l2 %#jx is missing "
				    "ATTR_SW_WIRED", (uintmax_t)pmap_load(l2));

			/*
			 * Are we unwiring the entire large page?  If not,
			 * demote the mapping and fall through.
			 */
			if (sva + L2_SIZE == va_next && eva >= va_next) {
				pmap_clear_bits(l2, ATTR_SW_WIRED);
				pmap->pm_stats.wired_count -= L2_SIZE /
				    PAGE_SIZE;
				continue;
			} else if (pmap_demote_l2(pmap, l2, sva) == NULL)
				panic("pmap_unwire: demotion failed");
		}
		KASSERT((pmap_load(l2) & ATTR_DESCR_MASK) == L2_TABLE,
		    ("pmap_unwire: Invalid l2 entry after demotion"));

		if (va_next > eva)
			va_next = eva;
		for (l3 = pmap_l2_to_l3(l2, sva); sva != va_next; l3++,
		    sva += L3_SIZE) {
			if (pmap_load(l3) == 0)
				continue;
			if ((pmap_load(l3) & ATTR_SW_WIRED) == 0)
				panic("pmap_unwire: l3 %#jx is missing "
				    "ATTR_SW_WIRED", (uintmax_t)pmap_load(l3));

			/*
			 * ATTR_SW_WIRED must be cleared atomically.  Although
			 * the pmap lock synchronizes access to ATTR_SW_WIRED,
			 * the System MMU may write to the entry concurrently.
			 */
			pmap_clear_bits(l3, ATTR_SW_WIRED);
			pmap->pm_stats.wired_count--;
		}
	}
	PMAP_UNLOCK(pmap);
}

/*
 *	Copy the range specified by src_addr/len
 *	from the source map to the range dst_addr/len
 *	in the destination map.
 *
 *	This routine is only advisory and need not do anything.
 *
 *	Because the executable mappings created by this routine are copied,
 *	it should not have to flush the instruction cache.
 */
void
pmap_copy(pmap_t dst_pmap, pmap_t src_pmap, vm_offset_t dst_addr, vm_size_t len,
    vm_offset_t src_addr)
{
	struct rwlock *lock;
	pd_entry_t *l0, *l1, *l2, srcptepaddr;
	pt_entry_t *dst_pte, mask, nbits, ptetemp, *src_pte;
	vm_offset_t addr, end_addr, va_next;
	vm_page_t dst_m, dstmpte, srcmpte;

	PMAP_ASSERT_STAGE1(dst_pmap);
	PMAP_ASSERT_STAGE1(src_pmap);

	if (dst_addr != src_addr)
		return;
	end_addr = src_addr + len;
	lock = NULL;
	if (dst_pmap < src_pmap) {
		PMAP_LOCK(dst_pmap);
		PMAP_LOCK(src_pmap);
	} else {
		PMAP_LOCK(src_pmap);
		PMAP_LOCK(dst_pmap);
	}
	for (addr = src_addr; addr < end_addr; addr = va_next) {
		l0 = pmap_l0(src_pmap, addr);
		if (pmap_load(l0) == 0) {
			va_next = (addr + L0_SIZE) & ~L0_OFFSET;
			if (va_next < addr)
				va_next = end_addr;
			continue;
		}

		va_next = (addr + L1_SIZE) & ~L1_OFFSET;
		if (va_next < addr)
			va_next = end_addr;
		l1 = pmap_l0_to_l1(l0, addr);
		if (pmap_load(l1) == 0)
			continue;
		if ((pmap_load(l1) & ATTR_DESCR_MASK) == L1_BLOCK) {
			KASSERT(va_next <= end_addr,
			    ("partial update of non-transparent 1G page "
			    "l1 %#lx addr %#lx end_addr %#lx va_next %#lx",
			    pmap_load(l1), addr, end_addr, va_next));
			srcptepaddr = pmap_load(l1);
			l1 = pmap_l1(dst_pmap, addr);
			if (l1 == NULL) {
				if (_pmap_alloc_l3(dst_pmap,
				    pmap_l0_pindex(addr), NULL) == NULL)
					break;
				l1 = pmap_l1(dst_pmap, addr);
			} else {
				l0 = pmap_l0(dst_pmap, addr);
				dst_m = PHYS_TO_VM_PAGE(pmap_load(l0) &
				    ~ATTR_MASK);
				dst_m->ref_count++;
			}
			KASSERT(pmap_load(l1) == 0,
			    ("1G mapping present in dst pmap "
			    "l1 %#lx addr %#lx end_addr %#lx va_next %#lx",
			    pmap_load(l1), addr, end_addr, va_next));
			pmap_store(l1, srcptepaddr & ~ATTR_SW_WIRED);
			pmap_resident_count_inc(dst_pmap, L1_SIZE / PAGE_SIZE);
			continue;
		}

		va_next = (addr + L2_SIZE) & ~L2_OFFSET;
		if (va_next < addr)
			va_next = end_addr;
		l2 = pmap_l1_to_l2(l1, addr);
		srcptepaddr = pmap_load(l2);
		if (srcptepaddr == 0)
			continue;
		if ((srcptepaddr & ATTR_DESCR_MASK) == L2_BLOCK) {
			if ((addr & L2_OFFSET) != 0 ||
			    addr + L2_SIZE > end_addr)
				continue;
			l2 = pmap_alloc_l2(dst_pmap, addr, &dst_m, NULL);
			if (l2 == NULL)
				break;
			if (pmap_load(l2) == 0 &&
			    ((srcptepaddr & ATTR_SW_MANAGED) == 0 ||
			    pmap_pv_insert_l2(dst_pmap, addr, srcptepaddr,
			    PMAP_ENTER_NORECLAIM, &lock))) {
				mask = ATTR_AF | ATTR_SW_WIRED;
				nbits = 0;
				if ((srcptepaddr & ATTR_SW_DBM) != 0)
					nbits |= ATTR_S1_AP_RW_BIT;
				pmap_store(l2, (srcptepaddr & ~mask) | nbits);
				pmap_resident_count_inc(dst_pmap, L2_SIZE /
				    PAGE_SIZE);
				atomic_add_long(&pmap_l2_mappings, 1);
			} else
				pmap_abort_ptp(dst_pmap, addr, dst_m);
			continue;
		}
		KASSERT((srcptepaddr & ATTR_DESCR_MASK) == L2_TABLE,
		    ("pmap_copy: invalid L2 entry"));
		srcptepaddr &= ~ATTR_MASK;
		srcmpte = PHYS_TO_VM_PAGE(srcptepaddr);
		KASSERT(srcmpte->ref_count > 0,
		    ("pmap_copy: source page table page is unused"));
		if (va_next > end_addr)
			va_next = end_addr;
		src_pte = (pt_entry_t *)PHYS_TO_DMAP(srcptepaddr);
		src_pte = &src_pte[pmap_l3_index(addr)];
		dstmpte = NULL;
		for (; addr < va_next; addr += PAGE_SIZE, src_pte++) {
			ptetemp = pmap_load(src_pte);

			/*
			 * We only virtual copy managed pages.
			 */
			if ((ptetemp & ATTR_SW_MANAGED) == 0)
				continue;

			if (dstmpte != NULL) {
				KASSERT(dstmpte->pindex == pmap_l2_pindex(addr),
				    ("dstmpte pindex/addr mismatch"));
				dstmpte->ref_count++;
			} else if ((dstmpte = pmap_alloc_l3(dst_pmap, addr,
			    NULL)) == NULL)
				goto out;
			dst_pte = (pt_entry_t *)
			    PHYS_TO_DMAP(VM_PAGE_TO_PHYS(dstmpte));
			dst_pte = &dst_pte[pmap_l3_index(addr)];
			if (pmap_load(dst_pte) == 0 &&
			    pmap_try_insert_pv_entry(dst_pmap, addr,
			    PHYS_TO_VM_PAGE(ptetemp & ~ATTR_MASK), &lock)) {
				/*
				 * Clear the wired, modified, and accessed
				 * (referenced) bits during the copy.
				 */
				mask = ATTR_AF | ATTR_SW_WIRED;
				nbits = 0;
				if ((ptetemp & ATTR_SW_DBM) != 0)
					nbits |= ATTR_S1_AP_RW_BIT;
				pmap_store(dst_pte, (ptetemp & ~mask) | nbits);
				pmap_resident_count_inc(dst_pmap, 1);
			} else {
				pmap_abort_ptp(dst_pmap, addr, dstmpte);
				goto out;
			}
			/* Have we copied all of the valid mappings? */
			if (dstmpte->ref_count >= srcmpte->ref_count)
				break;
		}
	}
out:
	/*
	 * XXX This barrier may not be needed because the destination pmap is
	 * not active.
	 */
	dsb(ishst);

	if (lock != NULL)
		rw_wunlock(lock);
	PMAP_UNLOCK(src_pmap);
	PMAP_UNLOCK(dst_pmap);
}

/*
 *	pmap_zero_page zeros the specified hardware page by mapping
 *	the page into KVM and using bzero to clear its contents.
 */
void
pmap_zero_page(vm_page_t m)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	pagezero((void *)va);
}

/*
 *	pmap_zero_page_area zeros the specified hardware page by mapping
 *	the page into KVM and using bzero to clear its contents.
 *
 *	off and size may not cover an area beyond a single hardware page.
 */
void
pmap_zero_page_area(vm_page_t m, int off, int size)
{
	vm_offset_t va = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));

	if (off == 0 && size == PAGE_SIZE)
		pagezero((void *)va);
	else
		bzero((char *)va + off, size);
}

/*
 *	pmap_copy_page copies the specified (machine independent)
 *	page by mapping the page into virtual memory and using
 *	bcopy to copy the page, one machine dependent page at a
 *	time.
 */
void
pmap_copy_page(vm_page_t msrc, vm_page_t mdst)
{
	vm_offset_t src = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(msrc));
	vm_offset_t dst = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(mdst));

	pagecopy((void *)src, (void *)dst);
}

int unmapped_buf_allowed = 1;

void
pmap_copy_pages(vm_page_t ma[], vm_offset_t a_offset, vm_page_t mb[],
    vm_offset_t b_offset, int xfersize)
{
	void *a_cp, *b_cp;
	vm_page_t m_a, m_b;
	vm_paddr_t p_a, p_b;
	vm_offset_t a_pg_offset, b_pg_offset;
	int cnt;

	while (xfersize > 0) {
		a_pg_offset = a_offset & PAGE_MASK;
		m_a = ma[a_offset >> PAGE_SHIFT];
		p_a = m_a->phys_addr;
		b_pg_offset = b_offset & PAGE_MASK;
		m_b = mb[b_offset >> PAGE_SHIFT];
		p_b = m_b->phys_addr;
		cnt = min(xfersize, PAGE_SIZE - a_pg_offset);
		cnt = min(cnt, PAGE_SIZE - b_pg_offset);
		if (__predict_false(!PHYS_IN_DMAP(p_a))) {
			panic("!DMAP a %lx", p_a);
		} else {
			a_cp = (char *)PHYS_TO_DMAP(p_a) + a_pg_offset;
		}
		if (__predict_false(!PHYS_IN_DMAP(p_b))) {
			panic("!DMAP b %lx", p_b);
		} else {
			b_cp = (char *)PHYS_TO_DMAP(p_b) + b_pg_offset;
		}
		bcopy(a_cp, b_cp, cnt);
		a_offset += cnt;
		b_offset += cnt;
		xfersize -= cnt;
	}
}

vm_offset_t
pmap_quick_enter_page(vm_page_t m)
{

	return (PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)));
}

void
pmap_quick_remove_page(vm_offset_t addr)
{
}

/*
 * Returns true if the pmap's pv is one of the first
 * 16 pvs linked to from this page.  This count may
 * be changed upwards or downwards in the future; it
 * is only necessary that true be returned for a small
 * subset of pmaps for proper page aging.
 */
boolean_t
pmap_page_exists_quick(pmap_t pmap, vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pv_entry_t pv;
	int loops = 0;
	boolean_t rv;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_page_exists_quick: page %p is not managed", m));
	rv = FALSE;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		if (PV_PMAP(pv) == pmap) {
			rv = TRUE;
			break;
		}
		loops++;
		if (loops >= 16)
			break;
	}
	if (!rv && loops < 16 && (m->flags & PG_FICTITIOUS) == 0) {
		pvh = page_to_pvh(m);
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			if (PV_PMAP(pv) == pmap) {
				rv = TRUE;
				break;
			}
			loops++;
			if (loops >= 16)
				break;
		}
	}
	rw_runlock(lock);
	return (rv);
}

/*
 *	pmap_page_wired_mappings:
 *
 *	Return the number of managed mappings to the given physical page
 *	that are wired.
 */
int
pmap_page_wired_mappings(vm_page_t m)
{
	struct rwlock *lock;
	struct md_page *pvh;
	pmap_t pmap;
	pt_entry_t *pte;
	pv_entry_t pv;
	int count, lvl, md_gen, pvh_gen;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (0);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:
	count = 0;
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pte = pmap_pte(pmap, pv->pv_va, &lvl);
		if (pte != NULL && (pmap_load(pte) & ATTR_SW_WIRED) != 0)
			count++;
		PMAP_UNLOCK(pmap);
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		pvh = page_to_pvh(m);
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap = PV_PMAP(pv);
			if (!PMAP_TRYLOCK(pmap)) {
				md_gen = m->md.pv_gen;
				pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen ||
				    pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			pte = pmap_pte(pmap, pv->pv_va, &lvl);
			if (pte != NULL &&
			    (pmap_load(pte) & ATTR_SW_WIRED) != 0)
				count++;
			PMAP_UNLOCK(pmap);
		}
	}
	rw_runlock(lock);
	return (count);
}

/*
 * Returns true if the given page is mapped individually or as part of
 * a 2mpage.  Otherwise, returns false.
 */
bool
pmap_page_is_mapped(vm_page_t m)
{
	struct rwlock *lock;
	bool rv;

	if ((m->oflags & VPO_UNMANAGED) != 0)
		return (false);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
	rv = !TAILQ_EMPTY(&m->md.pv_list) ||
	    ((m->flags & PG_FICTITIOUS) == 0 &&
	    !TAILQ_EMPTY(&page_to_pvh(m)->pv_list));
	rw_runlock(lock);
	return (rv);
}

/*
 * Destroy all managed, non-wired mappings in the given user-space
 * pmap.  This pmap cannot be active on any processor besides the
 * caller.
 *
 * This function cannot be applied to the kernel pmap.  Moreover, it
 * is not intended for general use.  It is only to be used during
 * process termination.  Consequently, it can be implemented in ways
 * that make it faster than pmap_remove().  First, it can more quickly
 * destroy mappings by iterating over the pmap's collection of PV
 * entries, rather than searching the page table.  Second, it doesn't
 * have to test and clear the page table entries atomically, because
 * no processor is currently accessing the user address space.  In
 * particular, a page table entry's dirty bit won't change state once
 * this function starts.
 */
void
pmap_remove_pages(pmap_t pmap)
{
	pd_entry_t *pde;
	pt_entry_t *pte, tpte;
	struct spglist free;
	vm_page_t m, ml3, mt;
	pv_entry_t pv;
	struct md_page *pvh;
	struct pv_chunk *pc, *npc;
	struct rwlock *lock;
	int64_t bit;
	uint64_t inuse, bitmask;
	int allfree, field, freed, idx, lvl;
	vm_paddr_t pa;

	lock = NULL;

	SLIST_INIT(&free);
	PMAP_LOCK(pmap);
	TAILQ_FOREACH_SAFE(pc, &pmap->pm_pvchunk, pc_list, npc) {
		allfree = 1;
		freed = 0;
		for (field = 0; field < _NPCM; field++) {
			inuse = ~pc->pc_map[field] & pc_freemask[field];
			while (inuse != 0) {
				bit = ffsl(inuse) - 1;
				bitmask = 1UL << bit;
				idx = field * 64 + bit;
				pv = &pc->pc_pventry[idx];
				inuse &= ~bitmask;

				pde = pmap_pde(pmap, pv->pv_va, &lvl);
				KASSERT(pde != NULL,
				    ("Attempting to remove an unmapped page"));

				switch(lvl) {
				case 1:
					pte = pmap_l1_to_l2(pde, pv->pv_va);
					tpte = pmap_load(pte);
					KASSERT((tpte & ATTR_DESCR_MASK) ==
					    L2_BLOCK,
					    ("Attempting to remove an invalid "
					    "block: %lx", tpte));
					break;
				case 2:
					pte = pmap_l2_to_l3(pde, pv->pv_va);
					tpte = pmap_load(pte);
					KASSERT((tpte & ATTR_DESCR_MASK) ==
					    L3_PAGE,
					    ("Attempting to remove an invalid "
					     "page: %lx", tpte));
					break;
				default:
					panic(
					    "Invalid page directory level: %d",
					    lvl);
				}

/*
 * We cannot remove wired pages from a process' mapping at this time
 */
				if (tpte & ATTR_SW_WIRED) {
					allfree = 0;
					continue;
				}

				pa = tpte & ~ATTR_MASK;

				m = PHYS_TO_VM_PAGE(pa);
				KASSERT(m->phys_addr == pa,
				    ("vm_page_t %p phys_addr mismatch %016jx %016jx",
				    m, (uintmax_t)m->phys_addr,
				    (uintmax_t)tpte));

				KASSERT((m->flags & PG_FICTITIOUS) != 0 ||
				    m < &vm_page_array[vm_page_array_size],
				    ("pmap_remove_pages: bad pte %#jx",
				    (uintmax_t)tpte));

				/*
				 * Because this pmap is not active on other
				 * processors, the dirty bit cannot have
				 * changed state since we last loaded pte.
				 */
				pmap_clear(pte);

				/*
				 * Update the vm_page_t clean/reference bits.
				 */
				if (pmap_pte_dirty(pmap, tpte)) {
					switch (lvl) {
					case 1:
						for (mt = m; mt < &m[L2_SIZE / PAGE_SIZE]; mt++)
							vm_page_dirty(mt);
						break;
					case 2:
						vm_page_dirty(m);
						break;
					}
				}

				CHANGE_PV_LIST_LOCK_TO_VM_PAGE(&lock, m);

				/* Mark free */
				pc->pc_map[field] |= bitmask;
				switch (lvl) {
				case 1:
					pmap_resident_count_dec(pmap,
					    L2_SIZE / PAGE_SIZE);
					pvh = pa_to_pvh(tpte & ~ATTR_MASK);
					TAILQ_REMOVE(&pvh->pv_list, pv,pv_next);
					pvh->pv_gen++;
					if (TAILQ_EMPTY(&pvh->pv_list)) {
						for (mt = m; mt < &m[L2_SIZE / PAGE_SIZE]; mt++)
							if ((mt->a.flags & PGA_WRITEABLE) != 0 &&
							    TAILQ_EMPTY(&mt->md.pv_list))
								vm_page_aflag_clear(mt, PGA_WRITEABLE);
					}
					ml3 = pmap_remove_pt_page(pmap,
					    pv->pv_va);
					if (ml3 != NULL) {
						KASSERT(ml3->valid == VM_PAGE_BITS_ALL,
						    ("pmap_remove_pages: l3 page not promoted"));
						pmap_resident_count_dec(pmap,1);
						KASSERT(ml3->ref_count == NL3PG,
						    ("pmap_remove_pages: l3 page ref count error"));
						ml3->ref_count = 0;
						pmap_add_delayed_free_list(ml3,
						    &free, FALSE);
					}
					break;
				case 2:
					pmap_resident_count_dec(pmap, 1);
					TAILQ_REMOVE(&m->md.pv_list, pv,
					    pv_next);
					m->md.pv_gen++;
					if ((m->a.flags & PGA_WRITEABLE) != 0 &&
					    TAILQ_EMPTY(&m->md.pv_list) &&
					    (m->flags & PG_FICTITIOUS) == 0) {
						pvh = page_to_pvh(m);
						if (TAILQ_EMPTY(&pvh->pv_list))
							vm_page_aflag_clear(m,
							    PGA_WRITEABLE);
					}
					break;
				}
				pmap_unuse_pt(pmap, pv->pv_va, pmap_load(pde),
				    &free);
				freed++;
			}
		}
		PV_STAT(atomic_add_long(&pv_entry_frees, freed));
		PV_STAT(atomic_add_int(&pv_entry_spare, freed));
		PV_STAT(atomic_subtract_long(&pv_entry_count, freed));
		if (allfree) {
			TAILQ_REMOVE(&pmap->pm_pvchunk, pc, pc_list);
			free_pv_chunk(pc);
		}
	}
	if (lock != NULL)
		rw_wunlock(lock);
	pmap_invalidate_all(pmap);
	PMAP_UNLOCK(pmap);
	vm_page_free_pages_toq(&free, true);
}

/*
 * This is used to check if a page has been accessed or modified.
 */
static boolean_t
pmap_page_test_mappings(vm_page_t m, boolean_t accessed, boolean_t modified)
{
	struct rwlock *lock;
	pv_entry_t pv;
	struct md_page *pvh;
	pt_entry_t *pte, mask, value;
	pmap_t pmap;
	int lvl, md_gen, pvh_gen;
	boolean_t rv;

	rv = FALSE;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_rlock(lock);
restart:
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			rw_runlock(lock);
			PMAP_LOCK(pmap);
			rw_rlock(lock);
			if (md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		pte = pmap_pte(pmap, pv->pv_va, &lvl);
		KASSERT(lvl == 3,
		    ("pmap_page_test_mappings: Invalid level %d", lvl));
		mask = 0;
		value = 0;
		if (modified) {
			mask |= ATTR_S1_AP_RW_BIT;
			value |= ATTR_S1_AP(ATTR_S1_AP_RW);
		}
		if (accessed) {
			mask |= ATTR_AF | ATTR_DESCR_MASK;
			value |= ATTR_AF | L3_PAGE;
		}
		rv = (pmap_load(pte) & mask) == value;
		PMAP_UNLOCK(pmap);
		if (rv)
			goto out;
	}
	if ((m->flags & PG_FICTITIOUS) == 0) {
		pvh = page_to_pvh(m);
		TAILQ_FOREACH(pv, &pvh->pv_list, pv_next) {
			pmap = PV_PMAP(pv);
			PMAP_ASSERT_STAGE1(pmap);
			if (!PMAP_TRYLOCK(pmap)) {
				md_gen = m->md.pv_gen;
				pvh_gen = pvh->pv_gen;
				rw_runlock(lock);
				PMAP_LOCK(pmap);
				rw_rlock(lock);
				if (md_gen != m->md.pv_gen ||
				    pvh_gen != pvh->pv_gen) {
					PMAP_UNLOCK(pmap);
					goto restart;
				}
			}
			pte = pmap_pte(pmap, pv->pv_va, &lvl);
			KASSERT(lvl == 2,
			    ("pmap_page_test_mappings: Invalid level %d", lvl));
			mask = 0;
			value = 0;
			if (modified) {
				mask |= ATTR_S1_AP_RW_BIT;
				value |= ATTR_S1_AP(ATTR_S1_AP_RW);
			}
			if (accessed) {
				mask |= ATTR_AF | ATTR_DESCR_MASK;
				value |= ATTR_AF | L2_BLOCK;
			}
			rv = (pmap_load(pte) & mask) == value;
			PMAP_UNLOCK(pmap);
			if (rv)
				goto out;
		}
	}
out:
	rw_runlock(lock);
	return (rv);
}

/*
 *	pmap_is_modified:
 *
 *	Return whether or not the specified physical page was modified
 *	in any physical maps.
 */
boolean_t
pmap_is_modified(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_is_modified: page %p is not managed", m));

	/*
	 * If the page is not busied then this check is racy.
	 */
	if (!pmap_page_is_write_mapped(m))
		return (FALSE);
	return (pmap_page_test_mappings(m, FALSE, TRUE));
}

/*
 *	pmap_is_prefaultable:
 *
 *	Return whether or not the specified virtual address is eligible
 *	for prefault.
 */
boolean_t
pmap_is_prefaultable(pmap_t pmap, vm_offset_t addr)
{
	pt_entry_t *pte;
	boolean_t rv;
	int lvl;

	rv = FALSE;
	PMAP_LOCK(pmap);
	pte = pmap_pte(pmap, addr, &lvl);
	if (pte != NULL && pmap_load(pte) != 0) {
		rv = TRUE;
	}
	PMAP_UNLOCK(pmap);
	return (rv);
}

/*
 *	pmap_is_referenced:
 *
 *	Return whether or not the specified physical page was referenced
 *	in any physical maps.
 */
boolean_t
pmap_is_referenced(vm_page_t m)
{

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_is_referenced: page %p is not managed", m));
	return (pmap_page_test_mappings(m, TRUE, FALSE));
}

/*
 * Clear the write and modified bits in each of the given page's mappings.
 */
void
pmap_remove_write(vm_page_t m)
{
	struct md_page *pvh;
	pmap_t pmap;
	struct rwlock *lock;
	pv_entry_t next_pv, pv;
	pt_entry_t oldpte, *pte;
	vm_offset_t va;
	int lvl, md_gen, pvh_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_remove_write: page %p is not managed", m));
	vm_page_assert_busied(m);

	if (!pmap_page_is_write_mapped(m))
		return;
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy : page_to_pvh(m);
retry_pv_loop:
	rw_wlock(lock);
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		va = pv->pv_va;
		pte = pmap_pte(pmap, pv->pv_va, &lvl);
		if ((pmap_load(pte) & ATTR_SW_DBM) != 0)
			(void)pmap_demote_l2_locked(pmap, pte, va, &lock);
		KASSERT(lock == VM_PAGE_TO_PV_LIST_LOCK(m),
		    ("inconsistent pv lock %p %p for page %p",
		    lock, VM_PAGE_TO_PV_LIST_LOCK(m), m));
		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen ||
			    md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				rw_wunlock(lock);
				goto retry_pv_loop;
			}
		}
		pte = pmap_pte(pmap, pv->pv_va, &lvl);
		oldpte = pmap_load(pte);
retry:
		if ((oldpte & ATTR_SW_DBM) != 0) {
			if (!atomic_fcmpset_long(pte, &oldpte,
			    (oldpte | ATTR_S1_AP_RW_BIT) & ~ATTR_SW_DBM))
				goto retry;
			if ((oldpte & ATTR_S1_AP_RW_BIT) ==
			    ATTR_S1_AP(ATTR_S1_AP_RW))
				vm_page_dirty(m);
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
	vm_page_aflag_clear(m, PGA_WRITEABLE);
}

/*
 *	pmap_ts_referenced:
 *
 *	Return a count of reference bits for a page, clearing those bits.
 *	It is not necessary for every reference bit to be cleared, but it
 *	is necessary that 0 only be returned when there are truly no
 *	reference bits set.
 *
 *	As an optimization, update the page's dirty field if a modified bit is
 *	found while counting reference bits.  This opportunistic update can be
 *	performed at low cost and can eliminate the need for some future calls
 *	to pmap_is_modified().  However, since this function stops after
 *	finding PMAP_TS_REFERENCED_MAX reference bits, it may not detect some
 *	dirty pages.  Those dirty pages will only be detected by a future call
 *	to pmap_is_modified().
 */
int
pmap_ts_referenced(vm_page_t m)
{
	struct md_page *pvh;
	pv_entry_t pv, pvf;
	pmap_t pmap;
	struct rwlock *lock;
	pd_entry_t *pde, tpde;
	pt_entry_t *pte, tpte;
	vm_offset_t va;
	vm_paddr_t pa;
	int cleared, lvl, md_gen, not_cleared, pvh_gen;
	struct spglist free;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_ts_referenced: page %p is not managed", m));
	SLIST_INIT(&free);
	cleared = 0;
	pa = VM_PAGE_TO_PHYS(m);
	lock = PHYS_TO_PV_LIST_LOCK(pa);
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy : page_to_pvh(m);
	rw_wlock(lock);
retry:
	not_cleared = 0;
	if ((pvf = TAILQ_FIRST(&pvh->pv_list)) == NULL)
		goto small_mappings;
	pv = pvf;
	do {
		if (pvf == NULL)
			pvf = pv;
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		va = pv->pv_va;
		pde = pmap_pde(pmap, pv->pv_va, &lvl);
		KASSERT(pde != NULL, ("pmap_ts_referenced: no l1 table found"));
		KASSERT(lvl == 1,
		    ("pmap_ts_referenced: invalid pde level %d", lvl));
		tpde = pmap_load(pde);
		KASSERT((tpde & ATTR_DESCR_MASK) == L1_TABLE,
		    ("pmap_ts_referenced: found an invalid l1 table"));
		pte = pmap_l1_to_l2(pde, pv->pv_va);
		tpte = pmap_load(pte);
		if (pmap_pte_dirty(pmap, tpte)) {
			/*
			 * Although "tpte" is mapping a 2MB page, because
			 * this function is called at a 4KB page granularity,
			 * we only update the 4KB page under test.
			 */
			vm_page_dirty(m);
		}

		if ((tpte & ATTR_AF) != 0) {
			/*
			 * Since this reference bit is shared by 512 4KB pages,
			 * it should not be cleared every time it is tested.
			 * Apply a simple "hash" function on the physical page
			 * number, the virtual superpage number, and the pmap
			 * address to select one 4KB page out of the 512 on
			 * which testing the reference bit will result in
			 * clearing that reference bit.  This function is
			 * designed to avoid the selection of the same 4KB page
			 * for every 2MB page mapping.
			 *
			 * On demotion, a mapping that hasn't been referenced
			 * is simply destroyed.  To avoid the possibility of a
			 * subsequent page fault on a demoted wired mapping,
			 * always leave its reference bit set.  Moreover,
			 * since the superpage is wired, the current state of
			 * its reference bit won't affect page replacement.
			 */
			if ((((pa >> PAGE_SHIFT) ^ (pv->pv_va >> L2_SHIFT) ^
			    (uintptr_t)pmap) & (Ln_ENTRIES - 1)) == 0 &&
			    (tpte & ATTR_SW_WIRED) == 0) {
				pmap_clear_bits(pte, ATTR_AF);
				pmap_invalidate_page(pmap, pv->pv_va);
				cleared++;
			} else
				not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		/* Rotate the PV list if it has more than one entry. */
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&pvh->pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&pvh->pv_list, pv, pv_next);
			pvh->pv_gen++;
		}
		if (cleared + not_cleared >= PMAP_TS_REFERENCED_MAX)
			goto out;
	} while ((pv = TAILQ_FIRST(&pvh->pv_list)) != pvf);
small_mappings:
	if ((pvf = TAILQ_FIRST(&m->md.pv_list)) == NULL)
		goto out;
	pv = pvf;
	do {
		if (pvf == NULL)
			pvf = pv;
		pmap = PV_PMAP(pv);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			md_gen = m->md.pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto retry;
			}
		}
		pde = pmap_pde(pmap, pv->pv_va, &lvl);
		KASSERT(pde != NULL, ("pmap_ts_referenced: no l2 table found"));
		KASSERT(lvl == 2,
		    ("pmap_ts_referenced: invalid pde level %d", lvl));
		tpde = pmap_load(pde);
		KASSERT((tpde & ATTR_DESCR_MASK) == L2_TABLE,
		    ("pmap_ts_referenced: found an invalid l2 table"));
		pte = pmap_l2_to_l3(pde, pv->pv_va);
		tpte = pmap_load(pte);
		if (pmap_pte_dirty(pmap, tpte))
			vm_page_dirty(m);
		if ((tpte & ATTR_AF) != 0) {
			if ((tpte & ATTR_SW_WIRED) == 0) {
				pmap_clear_bits(pte, ATTR_AF);
				pmap_invalidate_page(pmap, pv->pv_va);
				cleared++;
			} else
				not_cleared++;
		}
		PMAP_UNLOCK(pmap);
		/* Rotate the PV list if it has more than one entry. */
		if (pv != NULL && TAILQ_NEXT(pv, pv_next) != NULL) {
			TAILQ_REMOVE(&m->md.pv_list, pv, pv_next);
			TAILQ_INSERT_TAIL(&m->md.pv_list, pv, pv_next);
			m->md.pv_gen++;
		}
	} while ((pv = TAILQ_FIRST(&m->md.pv_list)) != pvf && cleared +
	    not_cleared < PMAP_TS_REFERENCED_MAX);
out:
	rw_wunlock(lock);
	vm_page_free_pages_toq(&free, true);
	return (cleared + not_cleared);
}

/*
 *	Apply the given advice to the specified range of addresses within the
 *	given pmap.  Depending on the advice, clear the referenced and/or
 *	modified flags in each mapping and set the mapped page's dirty field.
 */
void
pmap_advise(pmap_t pmap, vm_offset_t sva, vm_offset_t eva, int advice)
{
	struct rwlock *lock;
	vm_offset_t va, va_next;
	vm_page_t m;
	pd_entry_t *l0, *l1, *l2, oldl2;
	pt_entry_t *l3, oldl3;

	PMAP_ASSERT_STAGE1(pmap);

	if (advice != MADV_DONTNEED && advice != MADV_FREE)
		return;

	PMAP_LOCK(pmap);
	for (; sva < eva; sva = va_next) {
		l0 = pmap_l0(pmap, sva);
		if (pmap_load(l0) == 0) {
			va_next = (sva + L0_SIZE) & ~L0_OFFSET;
			if (va_next < sva)
				va_next = eva;
			continue;
		}

		va_next = (sva + L1_SIZE) & ~L1_OFFSET;
		if (va_next < sva)
			va_next = eva;
		l1 = pmap_l0_to_l1(l0, sva);
		if (pmap_load(l1) == 0)
			continue;
		if ((pmap_load(l1) & ATTR_DESCR_MASK) == L1_BLOCK) {
			KASSERT(va_next <= eva,
			    ("partial update of non-transparent 1G page "
			    "l1 %#lx sva %#lx eva %#lx va_next %#lx",
			    pmap_load(l1), sva, eva, va_next));
			continue;
		}

		va_next = (sva + L2_SIZE) & ~L2_OFFSET;
		if (va_next < sva)
			va_next = eva;
		l2 = pmap_l1_to_l2(l1, sva);
		oldl2 = pmap_load(l2);
		if (oldl2 == 0)
			continue;
		if ((oldl2 & ATTR_DESCR_MASK) == L2_BLOCK) {
			if ((oldl2 & ATTR_SW_MANAGED) == 0)
				continue;
			lock = NULL;
			if (!pmap_demote_l2_locked(pmap, l2, sva, &lock)) {
				if (lock != NULL)
					rw_wunlock(lock);

				/*
				 * The 2MB page mapping was destroyed.
				 */
				continue;
			}

			/*
			 * Unless the page mappings are wired, remove the
			 * mapping to a single page so that a subsequent
			 * access may repromote.  Choosing the last page
			 * within the address range [sva, min(va_next, eva))
			 * generally results in more repromotions.  Since the
			 * underlying page table page is fully populated, this
			 * removal never frees a page table page.
			 */
			if ((oldl2 & ATTR_SW_WIRED) == 0) {
				va = eva;
				if (va > va_next)
					va = va_next;
				va -= PAGE_SIZE;
				KASSERT(va >= sva,
				    ("pmap_advise: no address gap"));
				l3 = pmap_l2_to_l3(l2, va);
				KASSERT(pmap_load(l3) != 0,
				    ("pmap_advise: invalid PTE"));
				pmap_remove_l3(pmap, l3, va, pmap_load(l2),
				    NULL, &lock);
			}
			if (lock != NULL)
				rw_wunlock(lock);
		}
		KASSERT((pmap_load(l2) & ATTR_DESCR_MASK) == L2_TABLE,
		    ("pmap_advise: invalid L2 entry after demotion"));
		if (va_next > eva)
			va_next = eva;
		va = va_next;
		for (l3 = pmap_l2_to_l3(l2, sva); sva != va_next; l3++,
		    sva += L3_SIZE) {
			oldl3 = pmap_load(l3);
			if ((oldl3 & (ATTR_SW_MANAGED | ATTR_DESCR_MASK)) !=
			    (ATTR_SW_MANAGED | L3_PAGE))
				goto maybe_invlrng;
			else if (pmap_pte_dirty(pmap, oldl3)) {
				if (advice == MADV_DONTNEED) {
					/*
					 * Future calls to pmap_is_modified()
					 * can be avoided by making the page
					 * dirty now.
					 */
					m = PHYS_TO_VM_PAGE(oldl3 & ~ATTR_MASK);
					vm_page_dirty(m);
				}
				while (!atomic_fcmpset_long(l3, &oldl3,
				    (oldl3 & ~ATTR_AF) |
				    ATTR_S1_AP(ATTR_S1_AP_RO)))
					cpu_spinwait();
			} else if ((oldl3 & ATTR_AF) != 0)
				pmap_clear_bits(l3, ATTR_AF);
			else
				goto maybe_invlrng;
			if (va == va_next)
				va = sva;
			continue;
maybe_invlrng:
			if (va != va_next) {
				pmap_invalidate_range(pmap, va, sva);
				va = va_next;
			}
		}
		if (va != va_next)
			pmap_invalidate_range(pmap, va, sva);
	}
	PMAP_UNLOCK(pmap);
}

/*
 *	Clear the modify bits on the specified physical page.
 */
void
pmap_clear_modify(vm_page_t m)
{
	struct md_page *pvh;
	struct rwlock *lock;
	pmap_t pmap;
	pv_entry_t next_pv, pv;
	pd_entry_t *l2, oldl2;
	pt_entry_t *l3, oldl3;
	vm_offset_t va;
	int md_gen, pvh_gen;

	KASSERT((m->oflags & VPO_UNMANAGED) == 0,
	    ("pmap_clear_modify: page %p is not managed", m));
	vm_page_assert_busied(m);

	if (!pmap_page_is_write_mapped(m))
		return;
	pvh = (m->flags & PG_FICTITIOUS) != 0 ? &pv_dummy : page_to_pvh(m);
	lock = VM_PAGE_TO_PV_LIST_LOCK(m);
	rw_wlock(lock);
restart:
	TAILQ_FOREACH_SAFE(pv, &pvh->pv_list, pv_next, next_pv) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		va = pv->pv_va;
		l2 = pmap_l2(pmap, va);
		oldl2 = pmap_load(l2);
		/* If oldl2 has ATTR_SW_DBM set, then it is also dirty. */
		if ((oldl2 & ATTR_SW_DBM) != 0 &&
		    pmap_demote_l2_locked(pmap, l2, va, &lock) &&
		    (oldl2 & ATTR_SW_WIRED) == 0) {
			/*
			 * Write protect the mapping to a single page so that
			 * a subsequent write access may repromote.
			 */
			va += VM_PAGE_TO_PHYS(m) - (oldl2 & ~ATTR_MASK);
			l3 = pmap_l2_to_l3(l2, va);
			oldl3 = pmap_load(l3);
			while (!atomic_fcmpset_long(l3, &oldl3,
			    (oldl3 & ~ATTR_SW_DBM) | ATTR_S1_AP(ATTR_S1_AP_RO)))
				cpu_spinwait();
			vm_page_dirty(m);
			pmap_invalidate_page(pmap, va);
		}
		PMAP_UNLOCK(pmap);
	}
	TAILQ_FOREACH(pv, &m->md.pv_list, pv_next) {
		pmap = PV_PMAP(pv);
		PMAP_ASSERT_STAGE1(pmap);
		if (!PMAP_TRYLOCK(pmap)) {
			md_gen = m->md.pv_gen;
			pvh_gen = pvh->pv_gen;
			rw_wunlock(lock);
			PMAP_LOCK(pmap);
			rw_wlock(lock);
			if (pvh_gen != pvh->pv_gen || md_gen != m->md.pv_gen) {
				PMAP_UNLOCK(pmap);
				goto restart;
			}
		}
		l2 = pmap_l2(pmap, pv->pv_va);
		l3 = pmap_l2_to_l3(l2, pv->pv_va);
		oldl3 = pmap_load(l3);
		if (pmap_l3_valid(oldl3) &&
		    (oldl3 & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) == ATTR_SW_DBM){
			pmap_set_bits(l3, ATTR_S1_AP(ATTR_S1_AP_RO));
			pmap_invalidate_page(pmap, pv->pv_va);
		}
		PMAP_UNLOCK(pmap);
	}
	rw_wunlock(lock);
}

void *
pmap_mapbios(vm_paddr_t pa, vm_size_t size)
{
	struct pmap_preinit_mapping *ppim;
	vm_offset_t va, offset;
	pd_entry_t *pde;
	pt_entry_t *l2;
	int i, lvl, l2_blocks, free_l2_count, start_idx;

	if (!vm_initialized) {
		/*
		 * No L3 ptables so map entire L2 blocks where start VA is:
		 * 	preinit_map_va + start_idx * L2_SIZE
		 * There may be duplicate mappings (multiple VA -> same PA) but
		 * ARM64 dcache is always PIPT so that's acceptable.
		 */
		 if (size == 0)
			 return (NULL);

		 /* Calculate how many L2 blocks are needed for the mapping */
		l2_blocks = (roundup2(pa + size, L2_SIZE) -
		    rounddown2(pa, L2_SIZE)) >> L2_SHIFT;

		offset = pa & L2_OFFSET;

		if (preinit_map_va == 0)
			return (NULL);

		/* Map 2MiB L2 blocks from reserved VA space */

		free_l2_count = 0;
		start_idx = -1;
		/* Find enough free contiguous VA space */
		for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
			ppim = pmap_preinit_mapping + i;
			if (free_l2_count > 0 && ppim->pa != 0) {
				/* Not enough space here */
				free_l2_count = 0;
				start_idx = -1;
				continue;
			}

			if (ppim->pa == 0) {
				/* Free L2 block */
				if (start_idx == -1)
					start_idx = i;
				free_l2_count++;
				if (free_l2_count == l2_blocks)
					break;
			}
		}
		if (free_l2_count != l2_blocks)
			panic("%s: too many preinit mappings", __func__);

		va = preinit_map_va + (start_idx * L2_SIZE);
		for (i = start_idx; i < start_idx + l2_blocks; i++) {
			/* Mark entries as allocated */
			ppim = pmap_preinit_mapping + i;
			ppim->pa = pa;
			ppim->va = va + offset;
			ppim->size = size;
		}

		/* Map L2 blocks */
		pa = rounddown2(pa, L2_SIZE);
		for (i = 0; i < l2_blocks; i++) {
			pde = pmap_pde(kernel_pmap, va, &lvl);
			KASSERT(pde != NULL,
			    ("pmap_mapbios: Invalid page entry, va: 0x%lx",
			    va));
			KASSERT(lvl == 1,
			    ("pmap_mapbios: Invalid level %d", lvl));

			/* Insert L2_BLOCK */
			l2 = pmap_l1_to_l2(pde, va);
			pmap_load_store(l2,
			    pa | ATTR_DEFAULT | ATTR_S1_XN |
			    ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK) | L2_BLOCK);

			va += L2_SIZE;
			pa += L2_SIZE;
		}
		pmap_invalidate_all(kernel_pmap);

		va = preinit_map_va + (start_idx * L2_SIZE);

	} else {
		/* kva_alloc may be used to map the pages */
		offset = pa & PAGE_MASK;
		size = round_page(offset + size);

		va = kva_alloc(size);
		if (va == 0)
			panic("%s: Couldn't allocate KVA", __func__);

		pde = pmap_pde(kernel_pmap, va, &lvl);
		KASSERT(lvl == 2, ("pmap_mapbios: Invalid level %d", lvl));

		/* L3 table is linked */
		va = trunc_page(va);
		pa = trunc_page(pa);
		pmap_kenter(va, size, pa, memory_mapping_mode(pa));
	}

	return ((void *)(va + offset));
}

void
pmap_unmapbios(vm_offset_t va, vm_size_t size)
{
	struct pmap_preinit_mapping *ppim;
	vm_offset_t offset, tmpsize, va_trunc;
	pd_entry_t *pde;
	pt_entry_t *l2;
	int i, lvl, l2_blocks, block;
	bool preinit_map;

	l2_blocks =
	   (roundup2(va + size, L2_SIZE) - rounddown2(va, L2_SIZE)) >> L2_SHIFT;
	KASSERT(l2_blocks > 0, ("pmap_unmapbios: invalid size %lx", size));

	/* Remove preinit mapping */
	preinit_map = false;
	block = 0;
	for (i = 0; i < PMAP_PREINIT_MAPPING_COUNT; i++) {
		ppim = pmap_preinit_mapping + i;
		if (ppim->va == va) {
			KASSERT(ppim->size == size,
			    ("pmap_unmapbios: size mismatch"));
			ppim->va = 0;
			ppim->pa = 0;
			ppim->size = 0;
			preinit_map = true;
			offset = block * L2_SIZE;
			va_trunc = rounddown2(va, L2_SIZE) + offset;

			/* Remove L2_BLOCK */
			pde = pmap_pde(kernel_pmap, va_trunc, &lvl);
			KASSERT(pde != NULL,
			    ("pmap_unmapbios: Invalid page entry, va: 0x%lx",
			    va_trunc));
			l2 = pmap_l1_to_l2(pde, va_trunc);
			pmap_clear(l2);

			if (block == (l2_blocks - 1))
				break;
			block++;
		}
	}
	if (preinit_map) {
		pmap_invalidate_all(kernel_pmap);
		return;
	}

	/* Unmap the pages reserved with kva_alloc. */
	if (vm_initialized) {
		offset = va & PAGE_MASK;
		size = round_page(offset + size);
		va = trunc_page(va);

		pde = pmap_pde(kernel_pmap, va, &lvl);
		KASSERT(pde != NULL,
		    ("pmap_unmapbios: Invalid page entry, va: 0x%lx", va));
		KASSERT(lvl == 2, ("pmap_unmapbios: Invalid level %d", lvl));

		/* Unmap and invalidate the pages */
                for (tmpsize = 0; tmpsize < size; tmpsize += PAGE_SIZE)
			pmap_kremove(va + tmpsize);

		kva_free(va, size);
	}
}

/*
 * Sets the memory attribute for the specified page.
 */
void
pmap_page_set_memattr(vm_page_t m, vm_memattr_t ma)
{

	m->md.pv_memattr = ma;

	/*
	 * If "m" is a normal page, update its direct mapping.  This update
	 * can be relied upon to perform any cache operations that are
	 * required for data coherence.
	 */
	if ((m->flags & PG_FICTITIOUS) == 0 &&
	    pmap_change_attr(PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m)), PAGE_SIZE,
	    m->md.pv_memattr) != 0)
		panic("memory attribute change on the direct map failed");
}

/*
 * Changes the specified virtual address range's memory type to that given by
 * the parameter "mode".  The specified virtual address range must be
 * completely contained within either the direct map or the kernel map.  If
 * the virtual address range is contained within the kernel map, then the
 * memory type for each of the corresponding ranges of the direct map is also
 * changed.  (The corresponding ranges of the direct map are those ranges that
 * map the same physical pages as the specified virtual address range.)  These
 * changes to the direct map are necessary because Intel describes the
 * behavior of their processors as "undefined" if two or more mappings to the
 * same physical page have different memory types.
 *
 * Returns zero if the change completed successfully, and either EINVAL or
 * ENOMEM if the change failed.  Specifically, EINVAL is returned if some part
 * of the virtual address range was not mapped, and ENOMEM is returned if
 * there was insufficient memory available to complete the change.  In the
 * latter case, the memory type may have been changed on some part of the
 * virtual address range or the direct map.
 */
int
pmap_change_attr(vm_offset_t va, vm_size_t size, int mode)
{
	int error;

	PMAP_LOCK(kernel_pmap);
	error = pmap_change_attr_locked(va, size, mode);
	PMAP_UNLOCK(kernel_pmap);
	return (error);
}

static int
pmap_change_attr_locked(vm_offset_t va, vm_size_t size, int mode)
{
	vm_offset_t base, offset, tmpva;
	pt_entry_t l3, *pte, *newpte;
	int lvl;

	PMAP_LOCK_ASSERT(kernel_pmap, MA_OWNED);
	base = trunc_page(va);
	offset = va & PAGE_MASK;
	size = round_page(offset + size);

	if (!VIRT_IN_DMAP(base) &&
	    !(base >= VM_MIN_KERNEL_ADDRESS && base < VM_MAX_KERNEL_ADDRESS))
		return (EINVAL);

	for (tmpva = base; tmpva < base + size; ) {
		pte = pmap_pte(kernel_pmap, tmpva, &lvl);
		if (pte == NULL)
			return (EINVAL);

		if ((pmap_load(pte) & ATTR_S1_IDX_MASK) == ATTR_S1_IDX(mode)) {
			/*
			 * We already have the correct attribute,
			 * ignore this entry.
			 */
			switch (lvl) {
			default:
				panic("Invalid DMAP table level: %d\n", lvl);
			case 1:
				tmpva = (tmpva & ~L1_OFFSET) + L1_SIZE;
				break;
			case 2:
				tmpva = (tmpva & ~L2_OFFSET) + L2_SIZE;
				break;
			case 3:
				tmpva += PAGE_SIZE;
				break;
			}
		} else {
			/*
			 * Split the entry to an level 3 table, then
			 * set the new attribute.
			 */
			switch (lvl) {
			default:
				panic("Invalid DMAP table level: %d\n", lvl);
			case 1:
				newpte = pmap_demote_l1(kernel_pmap, pte,
				    tmpva & ~L1_OFFSET);
				if (newpte == NULL)
					return (EINVAL);
				pte = pmap_l1_to_l2(pte, tmpva);
			case 2:
				newpte = pmap_demote_l2(kernel_pmap, pte,
				    tmpva);
				if (newpte == NULL)
					return (EINVAL);
				pte = pmap_l2_to_l3(pte, tmpva);
			case 3:
				/* Update the entry */
				l3 = pmap_load(pte);
				l3 &= ~ATTR_S1_IDX_MASK;
				l3 |= ATTR_S1_IDX(mode);
				if (mode == VM_MEMATTR_DEVICE)
					l3 |= ATTR_S1_XN;

				pmap_update_entry(kernel_pmap, pte, l3, tmpva,
				    PAGE_SIZE);

				/*
				 * If moving to a non-cacheable entry flush
				 * the cache.
				 */
				if (mode == VM_MEMATTR_UNCACHEABLE)
					cpu_dcache_wbinv_range(tmpva, L3_SIZE);

				break;
			}
			tmpva += PAGE_SIZE;
		}
	}

	return (0);
}

/*
 * Create an L2 table to map all addresses within an L1 mapping.
 */
static pt_entry_t *
pmap_demote_l1(pmap_t pmap, pt_entry_t *l1, vm_offset_t va)
{
	pt_entry_t *l2, newl2, oldl1;
	vm_offset_t tmpl1;
	vm_paddr_t l2phys, phys;
	vm_page_t ml2;
	int i;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	oldl1 = pmap_load(l1);
	KASSERT((oldl1 & ATTR_DESCR_MASK) == L1_BLOCK,
	    ("pmap_demote_l1: Demoting a non-block entry"));
	KASSERT((va & L1_OFFSET) == 0,
	    ("pmap_demote_l1: Invalid virtual address %#lx", va));
	KASSERT((oldl1 & ATTR_SW_MANAGED) == 0,
	    ("pmap_demote_l1: Level 1 table shouldn't be managed"));

	tmpl1 = 0;
	if (va <= (vm_offset_t)l1 && va + L1_SIZE > (vm_offset_t)l1) {
		tmpl1 = kva_alloc(PAGE_SIZE);
		if (tmpl1 == 0)
			return (NULL);
	}

	if ((ml2 = vm_page_alloc(NULL, 0, VM_ALLOC_INTERRUPT |
	    VM_ALLOC_NOOBJ | VM_ALLOC_WIRED)) == NULL) {
		CTR2(KTR_PMAP, "pmap_demote_l1: failure for va %#lx"
		    " in pmap %p", va, pmap);
		return (NULL);
	}

	l2phys = VM_PAGE_TO_PHYS(ml2);
	l2 = (pt_entry_t *)PHYS_TO_DMAP(l2phys);

	/* Address the range points at */
	phys = oldl1 & ~ATTR_MASK;
	/* The attributed from the old l1 table to be copied */
	newl2 = oldl1 & ATTR_MASK;

	/* Create the new entries */
	for (i = 0; i < Ln_ENTRIES; i++) {
		l2[i] = newl2 | phys;
		phys += L2_SIZE;
	}
	KASSERT(l2[0] == ((oldl1 & ~ATTR_DESCR_MASK) | L2_BLOCK),
	    ("Invalid l2 page (%lx != %lx)", l2[0],
	    (oldl1 & ~ATTR_DESCR_MASK) | L2_BLOCK));

	if (tmpl1 != 0) {
		pmap_kenter(tmpl1, PAGE_SIZE,
		    DMAP_TO_PHYS((vm_offset_t)l1) & ~L3_OFFSET,
		    VM_MEMATTR_WRITE_BACK);
		l1 = (pt_entry_t *)(tmpl1 + ((vm_offset_t)l1 & PAGE_MASK));
	}

	pmap_update_entry(pmap, l1, l2phys | L1_TABLE, va, PAGE_SIZE);

	if (tmpl1 != 0) {
		pmap_kremove(tmpl1);
		kva_free(tmpl1, PAGE_SIZE);
	}

	return (l2);
}

static void
pmap_fill_l3(pt_entry_t *firstl3, pt_entry_t newl3)
{
	pt_entry_t *l3;

	for (l3 = firstl3; l3 - firstl3 < Ln_ENTRIES; l3++) {
		*l3 = newl3;
		newl3 += L3_SIZE;
	}
}

static void
pmap_demote_l2_abort(pmap_t pmap, vm_offset_t va, pt_entry_t *l2,
    struct rwlock **lockp)
{
	struct spglist free;

	SLIST_INIT(&free);
	(void)pmap_remove_l2(pmap, l2, va, pmap_load(pmap_l1(pmap, va)), &free,
	    lockp);
	vm_page_free_pages_toq(&free, true);
}

/*
 * Create an L3 table to map all addresses within an L2 mapping.
 */
static pt_entry_t *
pmap_demote_l2_locked(pmap_t pmap, pt_entry_t *l2, vm_offset_t va,
    struct rwlock **lockp)
{
	pt_entry_t *l3, newl3, oldl2;
	vm_offset_t tmpl2;
	vm_paddr_t l3phys;
	vm_page_t ml3;

	PMAP_LOCK_ASSERT(pmap, MA_OWNED);
	PMAP_ASSERT_STAGE1(pmap);
	l3 = NULL;
	oldl2 = pmap_load(l2);
	KASSERT((oldl2 & ATTR_DESCR_MASK) == L2_BLOCK,
	    ("pmap_demote_l2: Demoting a non-block entry"));
	va &= ~L2_OFFSET;

	tmpl2 = 0;
	if (va <= (vm_offset_t)l2 && va + L2_SIZE > (vm_offset_t)l2) {
		tmpl2 = kva_alloc(PAGE_SIZE);
		if (tmpl2 == 0)
			return (NULL);
	}

	/*
	 * Invalidate the 2MB page mapping and return "failure" if the
	 * mapping was never accessed.
	 */
	if ((oldl2 & ATTR_AF) == 0) {
		KASSERT((oldl2 & ATTR_SW_WIRED) == 0,
		    ("pmap_demote_l2: a wired mapping is missing ATTR_AF"));
		pmap_demote_l2_abort(pmap, va, l2, lockp);
		CTR2(KTR_PMAP, "pmap_demote_l2: failure for va %#lx in pmap %p",
		    va, pmap);
		goto fail;
	}

	if ((ml3 = pmap_remove_pt_page(pmap, va)) == NULL) {
		KASSERT((oldl2 & ATTR_SW_WIRED) == 0,
		    ("pmap_demote_l2: page table page for a wired mapping"
		    " is missing"));

		/*
		 * If the page table page is missing and the mapping
		 * is for a kernel address, the mapping must belong to
		 * the direct map.  Page table pages are preallocated
		 * for every other part of the kernel address space,
		 * so the direct map region is the only part of the
		 * kernel address space that must be handled here.
		 */
		KASSERT(va < VM_MAXUSER_ADDRESS || VIRT_IN_DMAP(va),
		    ("pmap_demote_l2: No saved mpte for va %#lx", va));

		/*
		 * If the 2MB page mapping belongs to the direct map
		 * region of the kernel's address space, then the page
		 * allocation request specifies the highest possible
		 * priority (VM_ALLOC_INTERRUPT).  Otherwise, the
		 * priority is normal.
		 */
		ml3 = vm_page_alloc(NULL, pmap_l2_pindex(va),
		    (VIRT_IN_DMAP(va) ? VM_ALLOC_INTERRUPT : VM_ALLOC_NORMAL) |
		    VM_ALLOC_NOOBJ | VM_ALLOC_WIRED);

		/*
		 * If the allocation of the new page table page fails,
		 * invalidate the 2MB page mapping and return "failure".
		 */
		if (ml3 == NULL) {
			pmap_demote_l2_abort(pmap, va, l2, lockp);
			CTR2(KTR_PMAP, "pmap_demote_l2: failure for va %#lx"
			    " in pmap %p", va, pmap);
			goto fail;
		}

		if (va < VM_MAXUSER_ADDRESS) {
			ml3->ref_count = NL3PG;
			pmap_resident_count_inc(pmap, 1);
		}
	}
	l3phys = VM_PAGE_TO_PHYS(ml3);
	l3 = (pt_entry_t *)PHYS_TO_DMAP(l3phys);
	newl3 = (oldl2 & ~ATTR_DESCR_MASK) | L3_PAGE;
	KASSERT((oldl2 & (ATTR_S1_AP_RW_BIT | ATTR_SW_DBM)) !=
	    (ATTR_S1_AP(ATTR_S1_AP_RO) | ATTR_SW_DBM),
	    ("pmap_demote_l2: L2 entry is writeable but not dirty"));

	/*
	 * If the page table page is not leftover from an earlier promotion,
	 * or the mapping attributes have changed, (re)initialize the L3 table.
	 *
	 * When pmap_update_entry() clears the old L2 mapping, it (indirectly)
	 * performs a dsb().  That dsb() ensures that the stores for filling
	 * "l3" are visible before "l3" is added to the page table.
	 */
	if (ml3->valid == 0 || (l3[0] & ATTR_MASK) != (newl3 & ATTR_MASK))
		pmap_fill_l3(l3, newl3);

	/*
	 * Map the temporary page so we don't lose access to the l2 table.
	 */
	if (tmpl2 != 0) {
		pmap_kenter(tmpl2, PAGE_SIZE,
		    DMAP_TO_PHYS((vm_offset_t)l2) & ~L3_OFFSET,
		    VM_MEMATTR_WRITE_BACK);
		l2 = (pt_entry_t *)(tmpl2 + ((vm_offset_t)l2 & PAGE_MASK));
	}

	/*
	 * The spare PV entries must be reserved prior to demoting the
	 * mapping, that is, prior to changing the PDE.  Otherwise, the state
	 * of the L2 and the PV lists will be inconsistent, which can result
	 * in reclaim_pv_chunk() attempting to remove a PV entry from the
	 * wrong PV list and pmap_pv_demote_l2() failing to find the expected
	 * PV entry for the 2MB page mapping that is being demoted.
	 */
	if ((oldl2 & ATTR_SW_MANAGED) != 0)
		reserve_pv_entries(pmap, Ln_ENTRIES - 1, lockp);

	/*
	 * Pass PAGE_SIZE so that a single TLB invalidation is performed on
	 * the 2MB page mapping.
	 */
	pmap_update_entry(pmap, l2, l3phys | L2_TABLE, va, PAGE_SIZE);

	/*
	 * Demote the PV entry.
	 */
	if ((oldl2 & ATTR_SW_MANAGED) != 0)
		pmap_pv_demote_l2(pmap, va, oldl2 & ~ATTR_MASK, lockp);

	atomic_add_long(&pmap_l2_demotions, 1);
	CTR3(KTR_PMAP, "pmap_demote_l2: success for va %#lx"
	    " in pmap %p %lx", va, pmap, l3[0]);

fail:
	if (tmpl2 != 0) {
		pmap_kremove(tmpl2);
		kva_free(tmpl2, PAGE_SIZE);
	}

	return (l3);

}

static pt_entry_t *
pmap_demote_l2(pmap_t pmap, pt_entry_t *l2, vm_offset_t va)
{
	struct rwlock *lock;
	pt_entry_t *l3;

	lock = NULL;
	l3 = pmap_demote_l2_locked(pmap, l2, va, &lock);
	if (lock != NULL)
		rw_wunlock(lock);
	return (l3);
}

/*
 * Perform the pmap work for mincore(2).  If the page is not both referenced and
 * modified by this pmap, returns its physical address so that the caller can
 * find other mappings.
 */
int
pmap_mincore(pmap_t pmap, vm_offset_t addr, vm_paddr_t *pap)
{
	pt_entry_t *pte, tpte;
	vm_paddr_t mask, pa;
	int lvl, val;
	bool managed;

	PMAP_ASSERT_STAGE1(pmap);
	PMAP_LOCK(pmap);
	pte = pmap_pte(pmap, addr, &lvl);
	if (pte != NULL) {
		tpte = pmap_load(pte);

		switch (lvl) {
		case 3:
			mask = L3_OFFSET;
			break;
		case 2:
			mask = L2_OFFSET;
			break;
		case 1:
			mask = L1_OFFSET;
			break;
		default:
			panic("pmap_mincore: invalid level %d", lvl);
		}

		managed = (tpte & ATTR_SW_MANAGED) != 0;
		val = MINCORE_INCORE;
		if (lvl != 3)
			val |= MINCORE_PSIND(3 - lvl);
		if ((managed && pmap_pte_dirty(pmap, tpte)) || (!managed &&
		    (tpte & ATTR_S1_AP_RW_BIT) == ATTR_S1_AP(ATTR_S1_AP_RW)))
			val |= MINCORE_MODIFIED | MINCORE_MODIFIED_OTHER;
		if ((tpte & ATTR_AF) == ATTR_AF)
			val |= MINCORE_REFERENCED | MINCORE_REFERENCED_OTHER;

		pa = (tpte & ~ATTR_MASK) | (addr & mask);
	} else {
		managed = false;
		val = 0;
	}

	if ((val & (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER)) !=
	    (MINCORE_MODIFIED_OTHER | MINCORE_REFERENCED_OTHER) && managed) {
		*pap = pa;
	}
	PMAP_UNLOCK(pmap);
	return (val);
}

/*
 * Garbage collect every ASID that is neither active on a processor nor
 * reserved.
 */
static void
pmap_reset_asid_set(pmap_t pmap)
{
	pmap_t curpmap;
	int asid, cpuid, epoch;
	struct asid_set *set;
	enum pmap_stage stage;

	set = pmap->pm_asid_set;
	stage = pmap->pm_stage;

	set = pmap->pm_asid_set;
	KASSERT(set != NULL, ("%s: NULL asid set", __func__));
	mtx_assert(&set->asid_set_mutex, MA_OWNED);

	/*
	 * Ensure that the store to asid_epoch is globally visible before the
	 * loads from pc_curpmap are performed.
	 */
	epoch = set->asid_epoch + 1;
	if (epoch == INT_MAX)
		epoch = 0;
	set->asid_epoch = epoch;
	dsb(ishst);
	if (stage == PM_STAGE1) {
		__asm __volatile("tlbi vmalle1is");
	} else {
		KASSERT(pmap_clean_stage2_tlbi != NULL,
		    ("%s: Unset stage 2 tlb invalidation callback\n",
		    __func__));
		pmap_clean_stage2_tlbi();
	}
	dsb(ish);
	bit_nclear(set->asid_set, ASID_FIRST_AVAILABLE,
	    set->asid_set_size - 1);
	CPU_FOREACH(cpuid) {
		if (cpuid == curcpu)
			continue;
		if (stage == PM_STAGE1) {
			curpmap = pcpu_find(cpuid)->pc_curpmap;
			PMAP_ASSERT_STAGE1(pmap);
		} else {
			curpmap = pcpu_find(cpuid)->pc_curvmpmap;
			if (curpmap == NULL)
				continue;
			PMAP_ASSERT_STAGE2(pmap);
		}
		KASSERT(curpmap->pm_asid_set == set, ("Incorrect set"));
		asid = COOKIE_TO_ASID(curpmap->pm_cookie);
		if (asid == -1)
			continue;
		bit_set(set->asid_set, asid);
		curpmap->pm_cookie = COOKIE_FROM(asid, epoch);
	}
}

/*
 * Allocate a new ASID for the specified pmap.
 */
static void
pmap_alloc_asid(pmap_t pmap)
{
	struct asid_set *set;
	int new_asid;

	set = pmap->pm_asid_set;
	KASSERT(set != NULL, ("%s: NULL asid set", __func__));

	mtx_lock_spin(&set->asid_set_mutex);

	/*
	 * While this processor was waiting to acquire the asid set mutex,
	 * pmap_reset_asid_set() running on another processor might have
	 * updated this pmap's cookie to the current epoch.  In which case, we
	 * don't need to allocate a new ASID.
	 */
	if (COOKIE_TO_EPOCH(pmap->pm_cookie) == set->asid_epoch)
		goto out;

	bit_ffc_at(set->asid_set, set->asid_next, set->asid_set_size,
	    &new_asid);
	if (new_asid == -1) {
		bit_ffc_at(set->asid_set, ASID_FIRST_AVAILABLE,
		    set->asid_next, &new_asid);
		if (new_asid == -1) {
			pmap_reset_asid_set(pmap);
			bit_ffc_at(set->asid_set, ASID_FIRST_AVAILABLE,
			    set->asid_set_size, &new_asid);
			KASSERT(new_asid != -1, ("ASID allocation failure"));
		}
	}
	bit_set(set->asid_set, new_asid);
	set->asid_next = new_asid + 1;
	pmap->pm_cookie = COOKIE_FROM(new_asid, set->asid_epoch);
out:
	mtx_unlock_spin(&set->asid_set_mutex);
}

/*
 * Compute the value that should be stored in ttbr0 to activate the specified
 * pmap.  This value may change from time to time.
 */
uint64_t
pmap_to_ttbr0(pmap_t pmap)
{

	return (ASID_TO_OPERAND(COOKIE_TO_ASID(pmap->pm_cookie)) |
	    pmap->pm_ttbr);
}

static bool
pmap_activate_int(pmap_t pmap)
{
	struct asid_set *set;
	int epoch;

	KASSERT(PCPU_GET(curpmap) != NULL, ("no active pmap"));
	KASSERT(pmap != kernel_pmap, ("kernel pmap activation"));

	if ((pmap->pm_stage == PM_STAGE1 && pmap == PCPU_GET(curpmap)) ||
	    (pmap->pm_stage == PM_STAGE2 && pmap == PCPU_GET(curvmpmap))) {
		/*
		 * Handle the possibility that the old thread was preempted
		 * after an "ic" or "tlbi" instruction but before it performed
		 * a "dsb" instruction.  If the old thread migrates to a new
		 * processor, its completion of a "dsb" instruction on that
		 * new processor does not guarantee that the "ic" or "tlbi"
		 * instructions performed on the old processor have completed.
		 */
		dsb(ish);
		return (false);
	}

	set = pmap->pm_asid_set;
	KASSERT(set != NULL, ("%s: NULL asid set", __func__));

	/*
	 * Ensure that the store to curpmap is globally visible before the
	 * load from asid_epoch is performed.
	 */
	if (pmap->pm_stage == PM_STAGE1)
		PCPU_SET(curpmap, pmap);
	else
		PCPU_SET(curvmpmap, pmap);
	dsb(ish);
	epoch = COOKIE_TO_EPOCH(pmap->pm_cookie);
	if (epoch >= 0 && epoch != set->asid_epoch)
		pmap_alloc_asid(pmap);

	if (pmap->pm_stage == PM_STAGE1) {
		set_ttbr0(pmap_to_ttbr0(pmap));
		if (PCPU_GET(bcast_tlbi_workaround) != 0)
			invalidate_local_icache();
	}
	return (true);
}

void
pmap_activate_vm(pmap_t pmap)
{

	PMAP_ASSERT_STAGE2(pmap);

	(void)pmap_activate_int(pmap);
}

void
pmap_activate(struct thread *td)
{
	pmap_t	pmap;

	pmap = vmspace_pmap(td->td_proc->p_vmspace);
	PMAP_ASSERT_STAGE1(pmap);
	critical_enter();
	(void)pmap_activate_int(pmap);
	critical_exit();
}

/*
 * To eliminate the unused parameter "old", we would have to add an instruction
 * to cpu_switch().
 */
struct pcb *
pmap_switch(struct thread *old __unused, struct thread *new)
{
	pcpu_bp_harden bp_harden;
	struct pcb *pcb;

	/* Store the new curthread */
	PCPU_SET(curthread, new);

	/* And the new pcb */
	pcb = new->td_pcb;
	PCPU_SET(curpcb, pcb);

	/*
	 * TODO: We may need to flush the cache here if switching
	 * to a user process.
	 */

	if (pmap_activate_int(vmspace_pmap(new->td_proc->p_vmspace))) {
		/*
		 * Stop userspace from training the branch predictor against
		 * other processes. This will call into a CPU specific
		 * function that clears the branch predictor state.
		 */
		bp_harden = PCPU_GET(bp_harden);
		if (bp_harden != NULL)
			bp_harden();
	}

	return (pcb);
}

void
pmap_sync_icache(pmap_t pmap, vm_offset_t va, vm_size_t sz)
{

	PMAP_ASSERT_STAGE1(pmap);
	if (va >= VM_MIN_KERNEL_ADDRESS) {
		cpu_icache_sync_range(va, sz);
	} else {
		u_int len, offset;
		vm_paddr_t pa;

		/* Find the length of data in this page to flush */
		offset = va & PAGE_MASK;
		len = imin(PAGE_SIZE - offset, sz);

		while (sz != 0) {
			/* Extract the physical address & find it in the DMAP */
			pa = pmap_extract(pmap, va);
			if (pa != 0)
				cpu_icache_sync_range(PHYS_TO_DMAP(pa), len);

			/* Move to the next page */
			sz -= len;
			va += len;
			/* Set the length for the next iteration */
			len = imin(PAGE_SIZE, sz);
		}
	}
}

static int
pmap_stage2_fault(pmap_t pmap, uint64_t esr, uint64_t far)
{
	pd_entry_t *pdep;
	pt_entry_t *ptep, pte;
	int rv, lvl, dfsc;

	PMAP_ASSERT_STAGE2(pmap);
	rv = KERN_FAILURE;

	/* Data and insn aborts use same encoding for FSC field. */
	dfsc = esr & ISS_DATA_DFSC_MASK;
	switch (dfsc) {
	case ISS_DATA_DFSC_TF_L0:
	case ISS_DATA_DFSC_TF_L1:
	case ISS_DATA_DFSC_TF_L2:
	case ISS_DATA_DFSC_TF_L3:
		PMAP_LOCK(pmap);
		pdep = pmap_pde(pmap, far, &lvl);
		if (pdep == NULL || lvl != (dfsc - ISS_DATA_DFSC_TF_L1)) {
			PMAP_LOCK(pmap);
			break;
		}

		switch (lvl) {
		case 0:
			ptep = pmap_l0_to_l1(pdep, far);
			break;
		case 1:
			ptep = pmap_l1_to_l2(pdep, far);
			break;
		case 2:
			ptep = pmap_l2_to_l3(pdep, far);
			break;
		default:
			panic("%s: Invalid pde level %d", __func__,lvl);
		}
		goto fault_exec;

	case ISS_DATA_DFSC_AFF_L1:
	case ISS_DATA_DFSC_AFF_L2:
	case ISS_DATA_DFSC_AFF_L3:
		PMAP_LOCK(pmap);
		ptep = pmap_pte(pmap, far, &lvl);
fault_exec:
		if (ptep != NULL && (pte = pmap_load(ptep)) != 0) {
			if (icache_vmid) {
				pmap_invalidate_vpipt_icache();
			} else {
				/*
				 * If accessing an executable page invalidate
				 * the I-cache so it will be valid when we
				 * continue execution in the guest. The D-cache
				 * is assumed to already be clean to the Point
				 * of Coherency.
				 */
				if ((pte & ATTR_S2_XN_MASK) !=
				    ATTR_S2_XN(ATTR_S2_XN_NONE)) {
					invalidate_icache();
				}
			}
			pmap_set_bits(ptep, ATTR_AF | ATTR_DESCR_VALID);
			rv = KERN_SUCCESS;
		}
		PMAP_UNLOCK(pmap);
		break;
	}

	return (rv);
}

int
pmap_fault(pmap_t pmap, uint64_t esr, uint64_t far)
{
	pt_entry_t pte, *ptep;
	register_t intr;
	uint64_t ec, par;
	int lvl, rv;

	rv = KERN_FAILURE;

	ec = ESR_ELx_EXCEPTION(esr);
	switch (ec) {
	case EXCP_INSN_ABORT_L:
	case EXCP_INSN_ABORT:
	case EXCP_DATA_ABORT_L:
	case EXCP_DATA_ABORT:
		break;
	default:
		return (rv);
	}

	if (pmap->pm_stage == PM_STAGE2)
		return (pmap_stage2_fault(pmap, esr, far));

	/* Data and insn aborts use same encoding for FSC field. */
	switch (esr & ISS_DATA_DFSC_MASK) {
	case ISS_DATA_DFSC_AFF_L1:
	case ISS_DATA_DFSC_AFF_L2:
	case ISS_DATA_DFSC_AFF_L3:
		PMAP_LOCK(pmap);
		ptep = pmap_pte(pmap, far, &lvl);
		if (ptep != NULL) {
			pmap_set_bits(ptep, ATTR_AF);
			rv = KERN_SUCCESS;
			/*
			 * XXXMJ as an optimization we could mark the entry
			 * dirty if this is a write fault.
			 */
		}
		PMAP_UNLOCK(pmap);
		break;
	case ISS_DATA_DFSC_PF_L1:
	case ISS_DATA_DFSC_PF_L2:
	case ISS_DATA_DFSC_PF_L3:
		if ((ec != EXCP_DATA_ABORT_L && ec != EXCP_DATA_ABORT) ||
		    (esr & ISS_DATA_WnR) == 0)
			return (rv);
		PMAP_LOCK(pmap);
		ptep = pmap_pte(pmap, far, &lvl);
		if (ptep != NULL &&
		    ((pte = pmap_load(ptep)) & ATTR_SW_DBM) != 0) {
			if ((pte & ATTR_S1_AP_RW_BIT) ==
			    ATTR_S1_AP(ATTR_S1_AP_RO)) {
				pmap_clear_bits(ptep, ATTR_S1_AP_RW_BIT);
				pmap_invalidate_page(pmap, far);
			}
			rv = KERN_SUCCESS;
		}
		PMAP_UNLOCK(pmap);
		break;
	case ISS_DATA_DFSC_TF_L0:
	case ISS_DATA_DFSC_TF_L1:
	case ISS_DATA_DFSC_TF_L2:
	case ISS_DATA_DFSC_TF_L3:
		/*
		 * Retry the translation.  A break-before-make sequence can
		 * produce a transient fault.
		 */
		if (pmap == kernel_pmap) {
			/*
			 * The translation fault may have occurred within a
			 * critical section.  Therefore, we must check the
			 * address without acquiring the kernel pmap's lock.
			 */
			if (pmap_klookup(far, NULL))
				rv = KERN_SUCCESS;
		} else {
			PMAP_LOCK(pmap);
			/* Ask the MMU to check the address. */
			intr = intr_disable();
			par = arm64_address_translate_s1e0r(far);
			intr_restore(intr);
			PMAP_UNLOCK(pmap);

			/*
			 * If the translation was successful, then we can
			 * return success to the trap handler.
			 */
			if (PAR_SUCCESS(par))
				rv = KERN_SUCCESS;
		}
		break;
	}

	return (rv);
}

/*
 *	Increase the starting virtual address of the given mapping if a
 *	different alignment might result in more superpage mappings.
 */
void
pmap_align_superpage(vm_object_t object, vm_ooffset_t offset,
    vm_offset_t *addr, vm_size_t size)
{
	vm_offset_t superpage_offset;

	if (size < L2_SIZE)
		return;
	if (object != NULL && (object->flags & OBJ_COLORED) != 0)
		offset += ptoa(object->pg_color);
	superpage_offset = offset & L2_OFFSET;
	if (size - ((L2_SIZE - superpage_offset) & L2_OFFSET) < L2_SIZE ||
	    (*addr & L2_OFFSET) == superpage_offset)
		return;
	if ((*addr & L2_OFFSET) < superpage_offset)
		*addr = (*addr & ~L2_OFFSET) + superpage_offset;
	else
		*addr = ((*addr + L2_OFFSET) & ~L2_OFFSET) + superpage_offset;
}

/**
 * Get the kernel virtual address of a set of physical pages. If there are
 * physical addresses not covered by the DMAP perform a transient mapping
 * that will be removed when calling pmap_unmap_io_transient.
 *
 * \param page        The pages the caller wishes to obtain the virtual
 *                    address on the kernel memory map.
 * \param vaddr       On return contains the kernel virtual memory address
 *                    of the pages passed in the page parameter.
 * \param count       Number of pages passed in.
 * \param can_fault   TRUE if the thread using the mapped pages can take
 *                    page faults, FALSE otherwise.
 *
 * \returns TRUE if the caller must call pmap_unmap_io_transient when
 *          finished or FALSE otherwise.
 *
 */
boolean_t
pmap_map_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count,
    boolean_t can_fault)
{
	vm_paddr_t paddr;
	boolean_t needs_mapping;
	int error, i;

	/*
	 * Allocate any KVA space that we need, this is done in a separate
	 * loop to prevent calling vmem_alloc while pinned.
	 */
	needs_mapping = FALSE;
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (__predict_false(!PHYS_IN_DMAP(paddr))) {
			error = vmem_alloc(kernel_arena, PAGE_SIZE,
			    M_BESTFIT | M_WAITOK, &vaddr[i]);
			KASSERT(error == 0, ("vmem_alloc failed: %d", error));
			needs_mapping = TRUE;
		} else {
			vaddr[i] = PHYS_TO_DMAP(paddr);
		}
	}

	/* Exit early if everything is covered by the DMAP */
	if (!needs_mapping)
		return (FALSE);

	if (!can_fault)
		sched_pin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (!PHYS_IN_DMAP(paddr)) {
			panic(
			   "pmap_map_io_transient: TODO: Map out of DMAP data");
		}
	}

	return (needs_mapping);
}

void
pmap_unmap_io_transient(vm_page_t page[], vm_offset_t vaddr[], int count,
    boolean_t can_fault)
{
	vm_paddr_t paddr;
	int i;

	if (!can_fault)
		sched_unpin();
	for (i = 0; i < count; i++) {
		paddr = VM_PAGE_TO_PHYS(page[i]);
		if (!PHYS_IN_DMAP(paddr)) {
			panic("ARM64TODO: pmap_unmap_io_transient: Unmap data");
		}
	}
}

boolean_t
pmap_is_valid_memattr(pmap_t pmap __unused, vm_memattr_t mode)
{

	return (mode >= VM_MEMATTR_DEVICE && mode <= VM_MEMATTR_WRITE_THROUGH);
}

/*
 * Track a range of the kernel's virtual address space that is contiguous
 * in various mapping attributes.
 */
struct pmap_kernel_map_range {
	vm_offset_t sva;
	pt_entry_t attrs;
	int l3pages;
	int l3contig;
	int l2blocks;
	int l1blocks;
};

static void
sysctl_kmaps_dump(struct sbuf *sb, struct pmap_kernel_map_range *range,
    vm_offset_t eva)
{
	const char *mode;
	int index;

	if (eva <= range->sva)
		return;

	index = range->attrs & ATTR_S1_IDX_MASK;
	switch (index) {
	case ATTR_S1_IDX(VM_MEMATTR_DEVICE):
		mode = "DEV";
		break;
	case ATTR_S1_IDX(VM_MEMATTR_UNCACHEABLE):
		mode = "UC";
		break;
	case ATTR_S1_IDX(VM_MEMATTR_WRITE_BACK):
		mode = "WB";
		break;
	case ATTR_S1_IDX(VM_MEMATTR_WRITE_THROUGH):
		mode = "WT";
		break;
	default:
		printf(
		    "%s: unknown memory type %x for range 0x%016lx-0x%016lx\n",
		    __func__, index, range->sva, eva);
		mode = "??";
		break;
	}

	sbuf_printf(sb, "0x%016lx-0x%016lx r%c%c%c %3s %d %d %d %d\n",
	    range->sva, eva,
	    (range->attrs & ATTR_S1_AP_RW_BIT) == ATTR_S1_AP_RW ? 'w' : '-',
	    (range->attrs & ATTR_S1_PXN) != 0 ? '-' : 'x',
	    (range->attrs & ATTR_S1_AP_USER) != 0 ? 'u' : 's',
	    mode, range->l1blocks, range->l2blocks, range->l3contig,
	    range->l3pages);

	/* Reset to sentinel value. */
	range->sva = 0xfffffffffffffffful;
}

/*
 * Determine whether the attributes specified by a page table entry match those
 * being tracked by the current range.
 */
static bool
sysctl_kmaps_match(struct pmap_kernel_map_range *range, pt_entry_t attrs)
{

	return (range->attrs == attrs);
}

static void
sysctl_kmaps_reinit(struct pmap_kernel_map_range *range, vm_offset_t va,
    pt_entry_t attrs)
{

	memset(range, 0, sizeof(*range));
	range->sva = va;
	range->attrs = attrs;
}

/*
 * Given a leaf PTE, derive the mapping's attributes.  If they do not match
 * those of the current run, dump the address range and its attributes, and
 * begin a new run.
 */
static void
sysctl_kmaps_check(struct sbuf *sb, struct pmap_kernel_map_range *range,
    vm_offset_t va, pd_entry_t l0e, pd_entry_t l1e, pd_entry_t l2e,
    pt_entry_t l3e)
{
	pt_entry_t attrs;

	attrs = l0e & (ATTR_S1_AP_MASK | ATTR_S1_XN);
	attrs |= l1e & (ATTR_S1_AP_MASK | ATTR_S1_XN);
	if ((l1e & ATTR_DESCR_MASK) == L1_BLOCK)
		attrs |= l1e & ATTR_S1_IDX_MASK;
	attrs |= l2e & (ATTR_S1_AP_MASK | ATTR_S1_XN);
	if ((l2e & ATTR_DESCR_MASK) == L2_BLOCK)
		attrs |= l2e & ATTR_S1_IDX_MASK;
	attrs |= l3e & (ATTR_S1_AP_MASK | ATTR_S1_XN | ATTR_S1_IDX_MASK);

	if (range->sva > va || !sysctl_kmaps_match(range, attrs)) {
		sysctl_kmaps_dump(sb, range, va);
		sysctl_kmaps_reinit(range, va, attrs);
	}
}

static int
sysctl_kmaps(SYSCTL_HANDLER_ARGS)
{
	struct pmap_kernel_map_range range;
	struct sbuf sbuf, *sb;
	pd_entry_t l0e, *l1, l1e, *l2, l2e;
	pt_entry_t *l3, l3e;
	vm_offset_t sva;
	vm_paddr_t pa;
	int error, i, j, k, l;

	error = sysctl_wire_old_buffer(req, 0);
	if (error != 0)
		return (error);
	sb = &sbuf;
	sbuf_new_for_sysctl(sb, NULL, PAGE_SIZE, req);

	/* Sentinel value. */
	range.sva = 0xfffffffffffffffful;

	/*
	 * Iterate over the kernel page tables without holding the kernel pmap
	 * lock.  Kernel page table pages are never freed, so at worst we will
	 * observe inconsistencies in the output.
	 */
	for (sva = 0xffff000000000000ul, i = pmap_l0_index(sva); i < Ln_ENTRIES;
	    i++) {
		if (i == pmap_l0_index(DMAP_MIN_ADDRESS))
			sbuf_printf(sb, "\nDirect map:\n");
		else if (i == pmap_l0_index(VM_MIN_KERNEL_ADDRESS))
			sbuf_printf(sb, "\nKernel map:\n");

		l0e = kernel_pmap->pm_l0[i];
		if ((l0e & ATTR_DESCR_VALID) == 0) {
			sysctl_kmaps_dump(sb, &range, sva);
			sva += L0_SIZE;
			continue;
		}
		pa = l0e & ~ATTR_MASK;
		l1 = (pd_entry_t *)PHYS_TO_DMAP(pa);

		for (j = pmap_l1_index(sva); j < Ln_ENTRIES; j++) {
			l1e = l1[j];
			if ((l1e & ATTR_DESCR_VALID) == 0) {
				sysctl_kmaps_dump(sb, &range, sva);
				sva += L1_SIZE;
				continue;
			}
			if ((l1e & ATTR_DESCR_MASK) == L1_BLOCK) {
				sysctl_kmaps_check(sb, &range, sva, l0e, l1e,
				    0, 0);
				range.l1blocks++;
				sva += L1_SIZE;
				continue;
			}
			pa = l1e & ~ATTR_MASK;
			l2 = (pd_entry_t *)PHYS_TO_DMAP(pa);

			for (k = pmap_l2_index(sva); k < Ln_ENTRIES; k++) {
				l2e = l2[k];
				if ((l2e & ATTR_DESCR_VALID) == 0) {
					sysctl_kmaps_dump(sb, &range, sva);
					sva += L2_SIZE;
					continue;
				}
				if ((l2e & ATTR_DESCR_MASK) == L2_BLOCK) {
					sysctl_kmaps_check(sb, &range, sva,
					    l0e, l1e, l2e, 0);
					range.l2blocks++;
					sva += L2_SIZE;
					continue;
				}
				pa = l2e & ~ATTR_MASK;
				l3 = (pt_entry_t *)PHYS_TO_DMAP(pa);

				for (l = pmap_l3_index(sva); l < Ln_ENTRIES;
				    l++, sva += L3_SIZE) {
					l3e = l3[l];
					if ((l3e & ATTR_DESCR_VALID) == 0) {
						sysctl_kmaps_dump(sb, &range,
						    sva);
						continue;
					}
					sysctl_kmaps_check(sb, &range, sva,
					    l0e, l1e, l2e, l3e);
					if ((l3e & ATTR_CONTIGUOUS) != 0)
						range.l3contig += l % 16 == 0 ?
						    1 : 0;
					else
						range.l3pages++;
				}
			}
		}
	}

	error = sbuf_finish(sb);
	sbuf_delete(sb);
	return (error);
}
SYSCTL_OID(_vm_pmap, OID_AUTO, kernel_maps,
    CTLTYPE_STRING | CTLFLAG_RD | CTLFLAG_MPSAFE | CTLFLAG_SKIP,
    NULL, 0, sysctl_kmaps, "A",
    "Dump kernel address layout");
