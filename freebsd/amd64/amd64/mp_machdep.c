/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1996, by Steve Passe
 * Copyright (c) 2003, by Peter Wemm
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the developer may NOT be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include "opt_acpi.h"
#include "opt_cpu.h"
#include "opt_ddb.h"
#include "opt_kstack_pages.h"
#include "opt_sched.h"
#include "opt_smp.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/cpuset.h>
#include <sys/domainset.h>
#ifdef GPROF
#include <sys/gmon.h>
#endif
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/memrange.h>
#include <sys/mutex.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>

#include <x86/apicreg.h>
#include <machine/clock.h>
#include <machine/cputypes.h>
#include <machine/cpufunc.h>
#include <x86/mca.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/psl.h>
#include <machine/smp.h>
#include <machine/specialreg.h>
#include <machine/tss.h>
#include <x86/ucode.h>
#include <machine/cpu.h>
#include <x86/init.h>

#ifdef DEV_ACPI
#include <contrib/dev/acpica/include/acpi.h>
#include <dev/acpica/acpivar.h>
#endif

#define WARMBOOT_TARGET		0
#define WARMBOOT_OFF		(KERNBASE + 0x0467)
#define WARMBOOT_SEG		(KERNBASE + 0x0469)

#define CMOS_REG		(0x70)
#define CMOS_DATA		(0x71)
#define BIOS_RESET		(0x0f)
#define BIOS_WARM		(0x0a)

#define GiB(v)			(v ## ULL << 30)

#define	AP_BOOTPT_SZ		(PAGE_SIZE * 4)

/* Temporary variables for init_secondary()  */
char *doublefault_stack;
char *mce_stack;
char *nmi_stack;
char *dbg_stack;

extern u_int mptramp_la57;

/*
 * Local data and functions.
 */

static int	start_ap(int apic_id);

static bool
is_kernel_paddr(vm_paddr_t pa)
{

	return (pa >= trunc_2mpage(btext - KERNBASE) &&
	   pa < round_page(_end - KERNBASE));
}

static bool
is_mpboot_good(vm_paddr_t start, vm_paddr_t end)
{

	return (start + AP_BOOTPT_SZ <= GiB(4) && atop(end) < Maxmem);
}

/*
 * Calculate usable address in base memory for AP trampoline code.
 */
void
mp_bootaddress(vm_paddr_t *physmap, unsigned int *physmap_idx)
{
	vm_paddr_t start, end;
	unsigned int i;
	bool allocated;

	alloc_ap_trampoline(physmap, physmap_idx);

	/*
	 * Find a memory region big enough below the 4GB boundary to
	 * store the initial page tables.  Region must be mapped by
	 * the direct map.
	 *
	 * Note that it needs to be aligned to a page boundary.
	 */
	allocated = false;
	for (i = *physmap_idx; i <= *physmap_idx; i -= 2) {
		/*
		 * First, try to chomp at the start of the physmap region.
		 * Kernel binary might claim it already.
		 */
		start = round_page(physmap[i]);
		end = start + AP_BOOTPT_SZ;
		if (start < end && end <= physmap[i + 1] &&
		    is_mpboot_good(start, end) &&
		    !is_kernel_paddr(start) && !is_kernel_paddr(end - 1)) {
			allocated = true;
			physmap[i] = end;
			break;
		}

		/*
		 * Second, try to chomp at the end.  Again, check
		 * against kernel.
		 */
		end = trunc_page(physmap[i + 1]);
		start = end - AP_BOOTPT_SZ;
		if (start < end && start >= physmap[i] &&
		    is_mpboot_good(start, end) &&
		    !is_kernel_paddr(start) && !is_kernel_paddr(end - 1)) {
			allocated = true;
			physmap[i + 1] = start;
			break;
		}
	}
	if (allocated) {
		mptramp_pagetables = start;
		if (physmap[i] == physmap[i + 1] && *physmap_idx != 0) {
			memmove(&physmap[i], &physmap[i + 2],
			    sizeof(*physmap) * (*physmap_idx - i + 2));
			*physmap_idx -= 2;
		}
	} else {
		mptramp_pagetables = trunc_page(boot_address) - AP_BOOTPT_SZ;
		if (bootverbose)
			printf(
"Cannot find enough space for the initial AP page tables, placing them at %#x",
			    mptramp_pagetables);
	}
}

/*
 * Initialize the IPI handlers and start up the AP's.
 */
void
cpu_mp_start(void)
{
	int i;

	/* Initialize the logical ID to APIC ID table. */
	for (i = 0; i < MAXCPU; i++) {
		cpu_apic_ids[i] = -1;
	}

	/* Install an inter-CPU IPI for cache and TLB invalidations. */
	setidt(IPI_INVLOP, pti ? IDTVEC(invlop_pti) : IDTVEC(invlop),
	    SDT_SYSIGT, SEL_KPL, 0);

	/* Install an inter-CPU IPI for all-CPU rendezvous */
	setidt(IPI_RENDEZVOUS, pti ? IDTVEC(rendezvous_pti) :
	    IDTVEC(rendezvous), SDT_SYSIGT, SEL_KPL, 0);

	/* Install generic inter-CPU IPI handler */
	setidt(IPI_BITMAP_VECTOR, pti ? IDTVEC(ipi_intr_bitmap_handler_pti) :
	    IDTVEC(ipi_intr_bitmap_handler), SDT_SYSIGT, SEL_KPL, 0);

	/* Install an inter-CPU IPI for CPU stop/restart */
	setidt(IPI_STOP, pti ? IDTVEC(cpustop_pti) : IDTVEC(cpustop),
	    SDT_SYSIGT, SEL_KPL, 0);

	/* Install an inter-CPU IPI for CPU suspend/resume */
	setidt(IPI_SUSPEND, pti ? IDTVEC(cpususpend_pti) : IDTVEC(cpususpend),
	    SDT_SYSIGT, SEL_KPL, 0);

	/* Install an IPI for calling delayed SWI */
	setidt(IPI_SWI, pti ? IDTVEC(ipi_swi_pti) : IDTVEC(ipi_swi),
	    SDT_SYSIGT, SEL_KPL, 0);

	/* Set boot_cpu_id if needed. */
	if (boot_cpu_id == -1) {
		boot_cpu_id = PCPU_GET(apic_id);
		cpu_info[boot_cpu_id].cpu_bsp = 1;
	} else
		KASSERT(boot_cpu_id == PCPU_GET(apic_id),
		    ("BSP's APIC ID doesn't match boot_cpu_id"));

	/* Probe logical/physical core configuration. */
	topo_probe();

	assign_cpu_ids();

	mptramp_la57 = la57;

	/* Start each Application Processor */
	init_ops.start_all_aps();

	set_interrupt_apic_ids();

#if defined(DEV_ACPI) && MAXMEMDOM > 1
	acpi_pxm_set_cpu_locality();
#endif
}

/*
 * AP CPU's call this to initialize themselves.
 */
void
init_secondary(void)
{
	struct pcpu *pc;
	struct nmi_pcpu *np;
	struct user_segment_descriptor *gdt;
	struct region_descriptor ap_gdt;
	u_int64_t cr0;
	int cpu, gsel_tss, x;

	/* Set by the startup code for us to use */
	cpu = bootAP;

	/* Update microcode before doing anything else. */
	ucode_load_ap(cpu);

	/* Get per-cpu data and save  */
	pc = &__pcpu[cpu];

	/* prime data page for it to use */
	pcpu_init(pc, cpu, sizeof(struct pcpu));
	dpcpu_init(dpcpu, cpu);
	pc->pc_apic_id = cpu_apic_ids[cpu];
	pc->pc_prvspace = pc;
	pc->pc_curthread = 0;
	pc->pc_tssp = &pc->pc_common_tss;
	pc->pc_rsp0 = 0;
	pc->pc_pti_rsp0 = (((vm_offset_t)&pc->pc_pti_stack +
	    PC_PTI_STACK_SZ * sizeof(uint64_t)) & ~0xful);
	gdt = pc->pc_gdt;
	pc->pc_tss = (struct system_segment_descriptor *)&gdt[GPROC0_SEL];
	pc->pc_fs32p = &gdt[GUFS32_SEL];
	pc->pc_gs32p = &gdt[GUGS32_SEL];
	pc->pc_ldt = (struct system_segment_descriptor *)&gdt[GUSERLDT_SEL];
	pc->pc_ucr3_load_mask = PMAP_UCR3_NOMASK;
	/* See comment in pmap_bootstrap(). */
	pc->pc_pcid_next = PMAP_PCID_KERN + 2;
	pc->pc_pcid_gen = 1;

	pc->pc_smp_tlb_gen = 1;

	/* Init tss */
	pc->pc_common_tss = __pcpu[0].pc_common_tss;
	pc->pc_common_tss.tss_iobase = sizeof(struct amd64tss) +
	    IOPERM_BITMAP_SIZE;
	pc->pc_common_tss.tss_rsp0 = 0;

	/* The doublefault stack runs on IST1. */
	np = ((struct nmi_pcpu *)&doublefault_stack[DBLFAULT_STACK_SIZE]) - 1;
	np->np_pcpu = (register_t)pc;
	pc->pc_common_tss.tss_ist1 = (long)np;

	/* The NMI stack runs on IST2. */
	np = ((struct nmi_pcpu *)&nmi_stack[NMI_STACK_SIZE]) - 1;
	np->np_pcpu = (register_t)pc;
	pc->pc_common_tss.tss_ist2 = (long)np;

	/* The MC# stack runs on IST3. */
	np = ((struct nmi_pcpu *)&mce_stack[MCE_STACK_SIZE]) - 1;
	np->np_pcpu = (register_t)pc;
	pc->pc_common_tss.tss_ist3 = (long)np;

	/* The DB# stack runs on IST4. */
	np = ((struct nmi_pcpu *)&dbg_stack[DBG_STACK_SIZE]) - 1;
	np->np_pcpu = (register_t)pc;
	pc->pc_common_tss.tss_ist4 = (long)np;

	/* Prepare private GDT */
	gdt_segs[GPROC0_SEL].ssd_base = (long)&pc->pc_common_tss;
	for (x = 0; x < NGDT; x++) {
		if (x != GPROC0_SEL && x != GPROC0_SEL + 1 &&
		    x != GUSERLDT_SEL && x != GUSERLDT_SEL + 1)
			ssdtosd(&gdt_segs[x], &gdt[x]);
	}
	ssdtosyssd(&gdt_segs[GPROC0_SEL],
	    (struct system_segment_descriptor *)&gdt[GPROC0_SEL]);
	ap_gdt.rd_limit = NGDT * sizeof(gdt[0]) - 1;
	ap_gdt.rd_base = (u_long)gdt;
	lgdt(&ap_gdt);			/* does magic intra-segment return */

	wrmsr(MSR_FSBASE, 0);		/* User value */
	wrmsr(MSR_GSBASE, (u_int64_t)pc);
	wrmsr(MSR_KGSBASE, (u_int64_t)pc);	/* XXX User value while we're in the kernel */
	fix_cpuid();

	lidt(&r_idt);

	gsel_tss = GSEL(GPROC0_SEL, SEL_KPL);
	ltr(gsel_tss);

	/*
	 * Set to a known state:
	 * Set by mpboot.s: CR0_PG, CR0_PE
	 * Set by cpu_setregs: CR0_NE, CR0_MP, CR0_TS, CR0_WP, CR0_AM
	 */
	cr0 = rcr0();
	cr0 &= ~(CR0_CD | CR0_NW | CR0_EM);
	load_cr0(cr0);

	amd64_conf_fast_syscall();

	/* signal our startup to the BSP. */
	mp_naps++;

	/* Spin until the BSP releases the AP's. */
	while (atomic_load_acq_int(&aps_ready) == 0)
		ia32_pause();

	init_secondary_tail();
}

/*******************************************************************
 * local functions and data
 */

#ifdef NUMA
static void
mp_realloc_pcpu(int cpuid, int domain)
{
	vm_page_t m;
	vm_offset_t oa, na;

	oa = (vm_offset_t)&__pcpu[cpuid];
	if (vm_phys_domain(pmap_kextract(oa)) == domain)
		return;
	m = vm_page_alloc_domain(NULL, 0, domain,
	    VM_ALLOC_NORMAL | VM_ALLOC_NOOBJ);
	if (m == NULL)
		return;
	na = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(m));
	pagecopy((void *)oa, (void *)na);
	pmap_qenter((vm_offset_t)&__pcpu[cpuid], &m, 1);
	/* XXX old pcpu page leaked. */
}
#endif

/*
 * start each AP in our list
 */
int
native_start_all_aps(void)
{
	u_int64_t *pt5, *pt4, *pt3, *pt2;
	u_int32_t mpbioswarmvec;
	int apic_id, cpu, domain, i, xo;
	u_char mpbiosreason;

	mtx_init(&ap_boot_mtx, "ap boot", NULL, MTX_SPIN);

	/* copy the AP 1st level boot code */
	bcopy(mptramp_start, (void *)PHYS_TO_DMAP(boot_address), bootMP_size);

	/* Locate the page tables, they'll be below the trampoline */
	if (la57) {
		pt5 = (uint64_t *)PHYS_TO_DMAP(mptramp_pagetables);
		xo = 1;
	} else {
		xo = 0;
	}
	pt4 = (uint64_t *)PHYS_TO_DMAP(mptramp_pagetables + xo * PAGE_SIZE);
	pt3 = pt4 + (PAGE_SIZE) / sizeof(u_int64_t);
	pt2 = pt3 + (PAGE_SIZE) / sizeof(u_int64_t);

	/* Create the initial 1GB replicated page tables */
	for (i = 0; i < 512; i++) {
		if (la57) {
			pt5[i] = (u_int64_t)(uintptr_t)(mptramp_pagetables +
			    PAGE_SIZE);
			pt5[i] |= PG_V | PG_RW | PG_U;
		}

		/*
		 * Each slot of the level 4 pages points to the same
		 * level 3 page.
		 */
		pt4[i] = (u_int64_t)(uintptr_t)(mptramp_pagetables +
		    (xo + 1) * PAGE_SIZE);
		pt4[i] |= PG_V | PG_RW | PG_U;

		/*
		 * Each slot of the level 3 pages points to the same
		 * level 2 page.
		 */
		pt3[i] = (u_int64_t)(uintptr_t)(mptramp_pagetables +
		    ((xo + 2) * PAGE_SIZE));
		pt3[i] |= PG_V | PG_RW | PG_U;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		pt2[i] = i * (2 * 1024 * 1024);
		pt2[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}

	/* save the current value of the warm-start vector */
	mpbioswarmvec = *((u_int32_t *) WARMBOOT_OFF);
	outb(CMOS_REG, BIOS_RESET);
	mpbiosreason = inb(CMOS_DATA);

	/* setup a vector to our boot code */
	*((volatile u_short *) WARMBOOT_OFF) = WARMBOOT_TARGET;
	*((volatile u_short *) WARMBOOT_SEG) = (boot_address >> 4);
	outb(CMOS_REG, BIOS_RESET);
	outb(CMOS_DATA, BIOS_WARM);	/* 'warm-start' */

	/* Relocate pcpu areas to the correct domain. */
#ifdef NUMA
	if (vm_ndomains > 1)
		for (cpu = 1; cpu < mp_ncpus; cpu++) {
			apic_id = cpu_apic_ids[cpu];
			domain = acpi_pxm_get_cpu_locality(apic_id);
			mp_realloc_pcpu(cpu, domain);
		}
#endif

	/* start each AP */
	domain = 0;
	for (cpu = 1; cpu < mp_ncpus; cpu++) {
		apic_id = cpu_apic_ids[cpu];
#ifdef NUMA
		if (vm_ndomains > 1)
			domain = acpi_pxm_get_cpu_locality(apic_id);
#endif
		/* allocate and set up an idle stack data page */
		bootstacks[cpu] = (void *)kmem_malloc(kstack_pages * PAGE_SIZE,
		    M_WAITOK | M_ZERO);
		doublefault_stack = (char *)kmem_malloc(DBLFAULT_STACK_SIZE,
		    M_WAITOK | M_ZERO);
		mce_stack = (char *)kmem_malloc(MCE_STACK_SIZE,
		    M_WAITOK | M_ZERO);
		nmi_stack = (char *)kmem_malloc_domainset(
		    DOMAINSET_PREF(domain), NMI_STACK_SIZE, M_WAITOK | M_ZERO);
		dbg_stack = (char *)kmem_malloc_domainset(
		    DOMAINSET_PREF(domain), DBG_STACK_SIZE, M_WAITOK | M_ZERO);
		dpcpu = (void *)kmem_malloc_domainset(DOMAINSET_PREF(domain),
		    DPCPU_SIZE, M_WAITOK | M_ZERO);

		bootSTK = (char *)bootstacks[cpu] +
		    kstack_pages * PAGE_SIZE - 8;
		bootAP = cpu;

		/* attempt to start the Application Processor */
		if (!start_ap(apic_id)) {
			/* restore the warmstart vector */
			*(u_int32_t *) WARMBOOT_OFF = mpbioswarmvec;
			panic("AP #%d (PHY# %d) failed!", cpu, apic_id);
		}

		CPU_SET(cpu, &all_cpus);	/* record AP in CPU map */
	}

	/* restore the warmstart vector */
	*(u_int32_t *) WARMBOOT_OFF = mpbioswarmvec;

	outb(CMOS_REG, BIOS_RESET);
	outb(CMOS_DATA, mpbiosreason);

	/* number of APs actually started */
	return (mp_naps);
}

/*
 * This function starts the AP (application processor) identified
 * by the APIC ID 'physicalCpu'.  It does quite a "song and dance"
 * to accomplish this.  This is necessary because of the nuances
 * of the different hardware we might encounter.  It isn't pretty,
 * but it seems to work.
 */
static int
start_ap(int apic_id)
{
	int vector, ms;
	int cpus;

	/* calculate the vector */
	vector = (boot_address >> 12) & 0xff;

	/* used as a watchpoint to signal AP startup */
	cpus = mp_naps;

	ipi_startup(apic_id, vector);

	/* Wait up to 5 seconds for it to start. */
	for (ms = 0; ms < 5000; ms++) {
		if (mp_naps > cpus)
			return 1;	/* return SUCCESS */
		DELAY(1000);
	}
	return 0;		/* return FAILURE */
}

/*
 * Flush the TLB on other CPU's
 */

/*
 * Invalidation request.  PCPU pc_smp_tlb_op uses u_int instead of the
 * enum to avoid both namespace and ABI issues (with enums).
 */
enum invl_op_codes {
      INVL_OP_TLB		= 1,
      INVL_OP_TLB_INVPCID	= 2,
      INVL_OP_TLB_INVPCID_PTI	= 3,
      INVL_OP_TLB_PCID		= 4,
      INVL_OP_PGRNG		= 5,
      INVL_OP_PGRNG_INVPCID	= 6,
      INVL_OP_PGRNG_PCID	= 7,
      INVL_OP_PG		= 8,
      INVL_OP_PG_INVPCID	= 9,
      INVL_OP_PG_PCID		= 10,
      INVL_OP_CACHE		= 11,
};

/*
 * These variables are initialized at startup to reflect how each of
 * the different kinds of invalidations should be performed on the
 * current machine and environment.
 */
static enum invl_op_codes invl_op_tlb;
static enum invl_op_codes invl_op_pgrng;
static enum invl_op_codes invl_op_pg;

/*
 * Scoreboard of IPI completion notifications from target to IPI initiator.
 *
 * Each CPU can initiate shootdown IPI independently from other CPUs.
 * Initiator enters critical section, then fills its local PCPU
 * shootdown info (pc_smp_tlb_ vars), then clears scoreboard generation
 * at location (cpu, my_cpuid) for each target cpu.  After that IPI is
 * sent to all targets which scan for zeroed scoreboard generation
 * words.  Upon finding such word the shootdown data is read from
 * corresponding cpu's pcpu, and generation is set.  Meantime initiator
 * loops waiting for all zeroed generations in scoreboard to update.
 */
static uint32_t *invl_scoreboard;

static void
invl_scoreboard_init(void *arg __unused)
{
	u_int i;

	invl_scoreboard = malloc(sizeof(uint32_t) * (mp_maxid + 1) *
	    (mp_maxid + 1), M_DEVBUF, M_WAITOK);
	for (i = 0; i < (mp_maxid + 1) * (mp_maxid + 1); i++)
		invl_scoreboard[i] = 1;

	if (pmap_pcid_enabled) {
		if (invpcid_works) {
			if (pti)
				invl_op_tlb = INVL_OP_TLB_INVPCID_PTI;
			else
				invl_op_tlb = INVL_OP_TLB_INVPCID;
			invl_op_pgrng = INVL_OP_PGRNG_INVPCID;
			invl_op_pg = INVL_OP_PG_INVPCID;
		} else {
			invl_op_tlb = INVL_OP_TLB_PCID;
			invl_op_pgrng = INVL_OP_PGRNG_PCID;
			invl_op_pg = INVL_OP_PG_PCID;
		}
	} else {
		invl_op_tlb = INVL_OP_TLB;
		invl_op_pgrng = INVL_OP_PGRNG;
		invl_op_pg = INVL_OP_PG;
	}
}
SYSINIT(invl_ops, SI_SUB_SMP, SI_ORDER_FIRST, invl_scoreboard_init, NULL);

static uint32_t *
invl_scoreboard_getcpu(u_int cpu)
{
	return (invl_scoreboard + cpu * (mp_maxid + 1));
}

static uint32_t *
invl_scoreboard_slot(u_int cpu)
{
	return (invl_scoreboard_getcpu(cpu) + PCPU_GET(cpuid));
}

/*
 * Used by the pmap to request cache or TLB invalidation on local and
 * remote processors.  Mask provides the set of remote CPUs that are
 * to be signalled with the invalidation IPI.  As an optimization, the
 * curcpu_cb callback is invoked on the calling CPU in a critical
 * section while waiting for the remote CPUs to complete the operation.
 *
 * The callback function is called unconditionally on the caller's
 * underlying processor, even when this processor is not set in the
 * mask.  So, the callback function must be prepared to handle such
 * spurious invocations.
 *
 * Interrupts must be enabled when calling the function with smp
 * started, to avoid deadlock with other IPIs that are protected with
 * smp_ipi_mtx spinlock at the initiator side.
 *
 * Function must be called with the thread pinned, and it unpins on
 * completion.
 */
static void
smp_targeted_tlb_shootdown(cpuset_t mask, pmap_t pmap, vm_offset_t addr1,
    vm_offset_t addr2, smp_invl_cb_t curcpu_cb, enum invl_op_codes op)
{
	cpuset_t other_cpus, mask1;
	uint32_t generation, *p_cpudone;
	int cpu;
	bool is_all;

	/*
	 * It is not necessary to signal other CPUs while booting or
	 * when in the debugger.
	 */
	if (kdb_active || KERNEL_PANICKED() || !smp_started)
		goto local_cb;

	KASSERT(curthread->td_pinned > 0, ("curthread not pinned"));

	/*
	 * Check for other cpus.  Return if none.
	 */
	is_all = !CPU_CMP(&mask, &all_cpus);
	CPU_CLR(PCPU_GET(cpuid), &mask);
	if (CPU_EMPTY(&mask))
		goto local_cb;

	/*
	 * Initiator must have interrupts enabled, which prevents
	 * non-invalidation IPIs that take smp_ipi_mtx spinlock,
	 * from deadlocking with us.  On the other hand, preemption
	 * must be disabled to pin initiator to the instance of the
	 * pcpu pc_smp_tlb data and scoreboard line.
	 */
	KASSERT((read_rflags() & PSL_I) != 0,
	    ("smp_targeted_tlb_shootdown: interrupts disabled"));
	critical_enter();

	PCPU_SET(smp_tlb_addr1, addr1);
	PCPU_SET(smp_tlb_addr2, addr2);
	PCPU_SET(smp_tlb_pmap, pmap);
	generation = PCPU_GET(smp_tlb_gen);
	if (++generation == 0)
		generation = 1;
	PCPU_SET(smp_tlb_gen, generation);
	PCPU_SET(smp_tlb_op, op);
	/* Fence between filling smp_tlb fields and clearing scoreboard. */
	atomic_thread_fence_rel();

	mask1 = mask;
	while ((cpu = CPU_FFS(&mask1)) != 0) {
		cpu--;
		CPU_CLR(cpu, &mask1);
		KASSERT(*invl_scoreboard_slot(cpu) != 0,
		    ("IPI scoreboard is zero, initiator %d target %d",
		    PCPU_GET(cpuid), cpu));
		*invl_scoreboard_slot(cpu) = 0;
	}

	/*
	 * IPI acts as a fence between writing to the scoreboard above
	 * (zeroing slot) and reading from it below (wait for
	 * acknowledgment).
	 */
	if (is_all) {
		ipi_all_but_self(IPI_INVLOP);
		other_cpus = all_cpus;
		CPU_CLR(PCPU_GET(cpuid), &other_cpus);
	} else {
		other_cpus = mask;
		ipi_selected(mask, IPI_INVLOP);
	}
	curcpu_cb(pmap, addr1, addr2);
	while ((cpu = CPU_FFS(&other_cpus)) != 0) {
		cpu--;
		CPU_CLR(cpu, &other_cpus);
		p_cpudone = invl_scoreboard_slot(cpu);
		while (atomic_load_int(p_cpudone) != generation)
			ia32_pause();
	}

	/*
	 * Unpin before leaving critical section.  If the thread owes
	 * preemption, this allows scheduler to select thread on any
	 * CPU from its cpuset.
	 */
	sched_unpin();
	critical_exit();

	return;

local_cb:
	critical_enter();
	curcpu_cb(pmap, addr1, addr2);
	sched_unpin();
	critical_exit();
}

void
smp_masked_invltlb(cpuset_t mask, pmap_t pmap, smp_invl_cb_t curcpu_cb)
{
	smp_targeted_tlb_shootdown(mask, pmap, 0, 0, curcpu_cb, invl_op_tlb);
#ifdef COUNT_XINVLTLB_HITS
	ipi_global++;
#endif
}

void
smp_masked_invlpg(cpuset_t mask, vm_offset_t addr, pmap_t pmap,
    smp_invl_cb_t curcpu_cb)
{
	smp_targeted_tlb_shootdown(mask, pmap, addr, 0, curcpu_cb, invl_op_pg);
#ifdef COUNT_XINVLTLB_HITS
	ipi_page++;
#endif
}

void
smp_masked_invlpg_range(cpuset_t mask, vm_offset_t addr1, vm_offset_t addr2,
    pmap_t pmap, smp_invl_cb_t curcpu_cb)
{
	smp_targeted_tlb_shootdown(mask, pmap, addr1, addr2, curcpu_cb,
	    invl_op_pgrng);
#ifdef COUNT_XINVLTLB_HITS
	ipi_range++;
	ipi_range_size += (addr2 - addr1) / PAGE_SIZE;
#endif
}

void
smp_cache_flush(smp_invl_cb_t curcpu_cb)
{
	smp_targeted_tlb_shootdown(all_cpus, NULL, 0, 0, curcpu_cb,
	    INVL_OP_CACHE);
}

/*
 * Handlers for TLB related IPIs
 */
static void
invltlb_handler(pmap_t smp_tlb_pmap)
{
#ifdef COUNT_XINVLTLB_HITS
	xhits_gbl[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invltlb_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	if (smp_tlb_pmap == kernel_pmap)
		invltlb_glob();
	else
		invltlb();
}

static void
invltlb_invpcid_handler(pmap_t smp_tlb_pmap)
{
	struct invpcid_descr d;

#ifdef COUNT_XINVLTLB_HITS
	xhits_gbl[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invltlb_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	d.pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid;
	d.pad = 0;
	d.addr = 0;
	invpcid(&d, smp_tlb_pmap == kernel_pmap ? INVPCID_CTXGLOB :
	    INVPCID_CTX);
}

static void
invltlb_invpcid_pti_handler(pmap_t smp_tlb_pmap)
{
	struct invpcid_descr d;

#ifdef COUNT_XINVLTLB_HITS
	xhits_gbl[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invltlb_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	d.pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid;
	d.pad = 0;
	d.addr = 0;
	if (smp_tlb_pmap == kernel_pmap) {
		/*
		 * This invalidation actually needs to clear kernel
		 * mappings from the TLB in the current pmap, but
		 * since we were asked for the flush in the kernel
		 * pmap, achieve it by performing global flush.
		 */
		invpcid(&d, INVPCID_CTXGLOB);
	} else {
		invpcid(&d, INVPCID_CTX);
		if (smp_tlb_pmap == PCPU_GET(curpmap))
			PCPU_SET(ucr3_load_mask, ~CR3_PCID_SAVE);
	}
}

static void
invltlb_pcid_handler(pmap_t smp_tlb_pmap)
{
	uint32_t pcid;

#ifdef COUNT_XINVLTLB_HITS
	xhits_gbl[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invltlb_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	if (smp_tlb_pmap == kernel_pmap) {
		invltlb_glob();
	} else {
		/*
		 * The current pmap might not be equal to
		 * smp_tlb_pmap.  The clearing of the pm_gen in
		 * pmap_invalidate_all() takes care of TLB
		 * invalidation when switching to the pmap on this
		 * CPU.
		 */
		if (smp_tlb_pmap == PCPU_GET(curpmap)) {
			pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid;
			load_cr3(smp_tlb_pmap->pm_cr3 | pcid);
			if (smp_tlb_pmap->pm_ucr3 != PMAP_NO_CR3)
				PCPU_SET(ucr3_load_mask, ~CR3_PCID_SAVE);
		}
	}
}

static void
invlpg_handler(vm_offset_t smp_tlb_addr1)
{
#ifdef COUNT_XINVLTLB_HITS
	xhits_pg[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlpg_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	invlpg(smp_tlb_addr1);
}

static void
invlpg_invpcid_handler(pmap_t smp_tlb_pmap, vm_offset_t smp_tlb_addr1)
{
	struct invpcid_descr d;

#ifdef COUNT_XINVLTLB_HITS
	xhits_pg[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlpg_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	invlpg(smp_tlb_addr1);
	if (smp_tlb_pmap == PCPU_GET(curpmap) &&
	    smp_tlb_pmap->pm_ucr3 != PMAP_NO_CR3 &&
	    PCPU_GET(ucr3_load_mask) == PMAP_UCR3_NOMASK) {
		d.pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid |
		    PMAP_PCID_USER_PT;
		d.pad = 0;
		d.addr = smp_tlb_addr1;
		invpcid(&d, INVPCID_ADDR);
	}
}

static void
invlpg_pcid_handler(pmap_t smp_tlb_pmap, vm_offset_t smp_tlb_addr1)
{
	uint64_t kcr3, ucr3;
	uint32_t pcid;

#ifdef COUNT_XINVLTLB_HITS
	xhits_pg[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlpg_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	invlpg(smp_tlb_addr1);
	if (smp_tlb_pmap == PCPU_GET(curpmap) &&
	    (ucr3 = smp_tlb_pmap->pm_ucr3) != PMAP_NO_CR3 &&
	    PCPU_GET(ucr3_load_mask) == PMAP_UCR3_NOMASK) {
		pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid;
		kcr3 = smp_tlb_pmap->pm_cr3 | pcid | CR3_PCID_SAVE;
		ucr3 |= pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
		pmap_pti_pcid_invlpg(ucr3, kcr3, smp_tlb_addr1);
	}
}

static void
invlrng_handler(vm_offset_t smp_tlb_addr1, vm_offset_t smp_tlb_addr2)
{
	vm_offset_t addr, addr2;

#ifdef COUNT_XINVLTLB_HITS
	xhits_rng[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlrng_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	addr = smp_tlb_addr1;
	addr2 = smp_tlb_addr2;
	do {
		invlpg(addr);
		addr += PAGE_SIZE;
	} while (addr < addr2);
}

static void
invlrng_invpcid_handler(pmap_t smp_tlb_pmap, vm_offset_t smp_tlb_addr1,
    vm_offset_t smp_tlb_addr2)
{
	struct invpcid_descr d;
	vm_offset_t addr, addr2;

#ifdef COUNT_XINVLTLB_HITS
	xhits_rng[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlrng_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	addr = smp_tlb_addr1;
	addr2 = smp_tlb_addr2;
	do {
		invlpg(addr);
		addr += PAGE_SIZE;
	} while (addr < addr2);
	if (smp_tlb_pmap == PCPU_GET(curpmap) &&
	    smp_tlb_pmap->pm_ucr3 != PMAP_NO_CR3 &&
	    PCPU_GET(ucr3_load_mask) == PMAP_UCR3_NOMASK) {
		d.pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid |
		    PMAP_PCID_USER_PT;
		d.pad = 0;
		d.addr = smp_tlb_addr1;
		do {
			invpcid(&d, INVPCID_ADDR);
			d.addr += PAGE_SIZE;
		} while (d.addr < addr2);
	}
}

static void
invlrng_pcid_handler(pmap_t smp_tlb_pmap, vm_offset_t smp_tlb_addr1,
    vm_offset_t smp_tlb_addr2)
{
	vm_offset_t addr, addr2;
	uint64_t kcr3, ucr3;
	uint32_t pcid;

#ifdef COUNT_XINVLTLB_HITS
	xhits_rng[PCPU_GET(cpuid)]++;
#endif /* COUNT_XINVLTLB_HITS */
#ifdef COUNT_IPIS
	(*ipi_invlrng_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */

	addr = smp_tlb_addr1;
	addr2 = smp_tlb_addr2;
	do {
		invlpg(addr);
		addr += PAGE_SIZE;
	} while (addr < addr2);
	if (smp_tlb_pmap == PCPU_GET(curpmap) &&
	    (ucr3 = smp_tlb_pmap->pm_ucr3) != PMAP_NO_CR3 &&
	    PCPU_GET(ucr3_load_mask) == PMAP_UCR3_NOMASK) {
		pcid = smp_tlb_pmap->pm_pcids[PCPU_GET(cpuid)].pm_pcid;
		kcr3 = smp_tlb_pmap->pm_cr3 | pcid | CR3_PCID_SAVE;
		ucr3 |= pcid | PMAP_PCID_USER_PT | CR3_PCID_SAVE;
		pmap_pti_pcid_invlrng(ucr3, kcr3, smp_tlb_addr1, addr2);
	}
}

static void
invlcache_handler(void)
{
#ifdef COUNT_IPIS
	(*ipi_invlcache_counts[PCPU_GET(cpuid)])++;
#endif /* COUNT_IPIS */
	wbinvd();
}

static void
invlop_handler_one_req(enum invl_op_codes smp_tlb_op, pmap_t smp_tlb_pmap,
    vm_offset_t smp_tlb_addr1, vm_offset_t smp_tlb_addr2)
{
	switch (smp_tlb_op) {
	case INVL_OP_TLB:
		invltlb_handler(smp_tlb_pmap);
		break;
	case INVL_OP_TLB_INVPCID:
		invltlb_invpcid_handler(smp_tlb_pmap);
		break;
	case INVL_OP_TLB_INVPCID_PTI:
		invltlb_invpcid_pti_handler(smp_tlb_pmap);
		break;
	case INVL_OP_TLB_PCID:
		invltlb_pcid_handler(smp_tlb_pmap);
		break;
	case INVL_OP_PGRNG:
		invlrng_handler(smp_tlb_addr1, smp_tlb_addr2);
		break;
	case INVL_OP_PGRNG_INVPCID:
		invlrng_invpcid_handler(smp_tlb_pmap, smp_tlb_addr1,
		    smp_tlb_addr2);
		break;
	case INVL_OP_PGRNG_PCID:
		invlrng_pcid_handler(smp_tlb_pmap, smp_tlb_addr1,
		    smp_tlb_addr2);
		break;
	case INVL_OP_PG:
		invlpg_handler(smp_tlb_addr1);
		break;
	case INVL_OP_PG_INVPCID:
		invlpg_invpcid_handler(smp_tlb_pmap, smp_tlb_addr1);
		break;
	case INVL_OP_PG_PCID:
		invlpg_pcid_handler(smp_tlb_pmap, smp_tlb_addr1);
		break;
	case INVL_OP_CACHE:
		invlcache_handler();
		break;
	default:
		__assert_unreachable();
		break;
	}
}

void
invlop_handler(void)
{
	struct pcpu *initiator_pc;
	pmap_t smp_tlb_pmap;
	vm_offset_t smp_tlb_addr1, smp_tlb_addr2;
	u_int initiator_cpu_id;
	enum invl_op_codes smp_tlb_op;
	uint32_t *scoreboard, smp_tlb_gen;

	scoreboard = invl_scoreboard_getcpu(PCPU_GET(cpuid));
	for (;;) {
		for (initiator_cpu_id = 0; initiator_cpu_id <= mp_maxid;
		    initiator_cpu_id++) {
			if (atomic_load_int(&scoreboard[initiator_cpu_id]) == 0)
				break;
		}
		if (initiator_cpu_id > mp_maxid)
			break;
		initiator_pc = cpuid_to_pcpu[initiator_cpu_id];

		/*
		 * This acquire fence and its corresponding release
		 * fence in smp_targeted_tlb_shootdown() is between
		 * reading zero scoreboard slot and accessing PCPU of
		 * initiator for pc_smp_tlb values.
		 */
		atomic_thread_fence_acq();
		smp_tlb_pmap = initiator_pc->pc_smp_tlb_pmap;
		smp_tlb_addr1 = initiator_pc->pc_smp_tlb_addr1;
		smp_tlb_addr2 = initiator_pc->pc_smp_tlb_addr2;
		smp_tlb_op = initiator_pc->pc_smp_tlb_op;
		smp_tlb_gen = initiator_pc->pc_smp_tlb_gen;

		/*
		 * Ensure that we do not make our scoreboard
		 * notification visible to the initiator until the
		 * pc_smp_tlb values are read.  The corresponding
		 * fence is implicitly provided by the barrier in the
		 * IPI send operation before the APIC ICR register
		 * write.
		 *
		 * As an optimization, the request is acknowledged
		 * before the actual invalidation is performed.  It is
		 * safe because target CPU cannot return to userspace
		 * before handler finishes. Only NMI can preempt the
		 * handler, but NMI would see the kernel handler frame
		 * and not touch not-invalidated user page table.
		 */
		atomic_thread_fence_acq();
		atomic_store_int(&scoreboard[initiator_cpu_id], smp_tlb_gen);

		invlop_handler_one_req(smp_tlb_op, smp_tlb_pmap, smp_tlb_addr1,
		    smp_tlb_addr2);
	}
}
