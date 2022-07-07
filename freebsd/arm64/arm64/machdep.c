/*-
 * Copyright (c) 2014 Andrew Turner
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
 *
 */

#include "opt_acpi.h"
#include "opt_platform.h"
#include "opt_ddb.h"

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/cons.h>
#include <sys/cpu.h>
#include <sys/csan.h>
#include <sys/devmap.h>
#include <sys/efi.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/limits.h>
#include <sys/linker.h>
#include <sys/msgbuf.h>
#include <sys/pcpu.h>
#include <sys/physmem.h>
#include <sys/proc.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/signalvar.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/ucontext.h>
#include <sys/vdso.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_phys.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_pager.h>

#include <machine/armreg.h>
#include <machine/cpu.h>
#include <machine/debug_monitor.h>
#include <machine/kdb.h>
#include <machine/machdep.h>
#include <machine/metadata.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/reg.h>
#include <machine/undefined.h>
#include <machine/vmparam.h>

#ifdef VFP
#include <machine/vfp.h>
#endif

#ifdef DEV_ACPI
#include <contrib/dev/acpica/include/acpi.h>
#include <machine/acpica_machdep.h>
#endif

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/openfirm.h>
#endif

static void get_fpcontext(struct thread *td, mcontext_t *mcp);
static void set_fpcontext(struct thread *td, mcontext_t *mcp);

enum arm64_bus arm64_bus_method = ARM64_BUS_NONE;

struct pcpu __pcpu[MAXCPU];

static struct trapframe proc0_tf;

int early_boot = 1;
int cold = 1;
static int boot_el;

struct kva_md_info kmi;

int64_t dczva_line_size;	/* The size of cache line the dc zva zeroes */
int has_pan;

/*
 * Physical address of the EFI System Table. Stashed from the metadata hints
 * passed into the kernel and used by the EFI code to call runtime services.
 */
vm_paddr_t efi_systbl_phys;
static struct efi_map_header *efihdr;

/* pagezero_* implementations are provided in support.S */
void pagezero_simple(void *);
void pagezero_cache(void *);

/* pagezero_simple is default pagezero */
void (*pagezero)(void *p) = pagezero_simple;

int (*apei_nmi)(void);

static void
pan_setup(void)
{
	uint64_t id_aa64mfr1;

	id_aa64mfr1 = READ_SPECIALREG(id_aa64mmfr1_el1);
	if (ID_AA64MMFR1_PAN_VAL(id_aa64mfr1) != ID_AA64MMFR1_PAN_NONE)
		has_pan = 1;
}

void
pan_enable(void)
{

	/*
	 * The LLVM integrated assembler doesn't understand the PAN
	 * PSTATE field. Because of this we need to manually create
	 * the instruction in an asm block. This is equivalent to:
	 * msr pan, #1
	 *
	 * This sets the PAN bit, stopping the kernel from accessing
	 * memory when userspace can also access it unless the kernel
	 * uses the userspace load/store instructions.
	 */
	if (has_pan) {
		WRITE_SPECIALREG(sctlr_el1,
		    READ_SPECIALREG(sctlr_el1) & ~SCTLR_SPAN);
		__asm __volatile(".inst 0xd500409f | (0x1 << 8)");
	}
}

bool
has_hyp(void)
{

	return (boot_el == 2);
}

static void
cpu_startup(void *dummy)
{
	vm_paddr_t size;
	int i;

	printf("real memory  = %ju (%ju MB)\n", ptoa((uintmax_t)realmem),
	    ptoa((uintmax_t)realmem) / 1024 / 1024);

	if (bootverbose) {
		printf("Physical memory chunk(s):\n");
		for (i = 0; phys_avail[i + 1] != 0; i += 2) {
			size = phys_avail[i + 1] - phys_avail[i];
			printf("%#016jx - %#016jx, %ju bytes (%ju pages)\n",
			    (uintmax_t)phys_avail[i],
			    (uintmax_t)phys_avail[i + 1] - 1,
			    (uintmax_t)size, (uintmax_t)size / PAGE_SIZE);
		}
	}

	printf("avail memory = %ju (%ju MB)\n",
	    ptoa((uintmax_t)vm_free_count()),
	    ptoa((uintmax_t)vm_free_count()) / 1024 / 1024);

	undef_init();
	install_cpu_errata();

	vm_ksubmap_init(&kmi);
	bufinit();
	vm_pager_bufferinit();
}

SYSINIT(cpu, SI_SUB_CPU, SI_ORDER_FIRST, cpu_startup, NULL);

static void
late_ifunc_resolve(void *dummy __unused)
{
	link_elf_late_ireloc();
}
SYSINIT(late_ifunc_resolve, SI_SUB_CPU, SI_ORDER_ANY, late_ifunc_resolve, NULL);

int
cpu_idle_wakeup(int cpu)
{

	return (0);
}

int
fill_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;

	frame = td->td_frame;
	regs->sp = frame->tf_sp;
	regs->lr = frame->tf_lr;
	regs->elr = frame->tf_elr;
	regs->spsr = frame->tf_spsr;

	memcpy(regs->x, frame->tf_x, sizeof(regs->x));

#ifdef COMPAT_FREEBSD32
	/*
	 * We may be called here for a 32bits process, if we're using a
	 * 64bits debugger. If so, put PC and SPSR where it expects it.
	 */
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
		regs->x[15] = frame->tf_elr;
		regs->x[16] = frame->tf_spsr;
	}
#endif
	return (0);
}

int
set_regs(struct thread *td, struct reg *regs)
{
	struct trapframe *frame;

	frame = td->td_frame;
	frame->tf_sp = regs->sp;
	frame->tf_lr = regs->lr;
	frame->tf_elr = regs->elr;
	frame->tf_spsr &= ~PSR_FLAGS;
	frame->tf_spsr |= regs->spsr & PSR_FLAGS;

	memcpy(frame->tf_x, regs->x, sizeof(frame->tf_x));

#ifdef COMPAT_FREEBSD32
	if (SV_PROC_FLAG(td->td_proc, SV_ILP32)) {
		/*
		 * We may be called for a 32bits process if we're using
		 * a 64bits debugger. If so, get PC and SPSR from where
		 * it put it.
		 */
		frame->tf_elr = regs->x[15];
		frame->tf_spsr = regs->x[16] & PSR_FLAGS;
	}
#endif
	return (0);
}

int
fill_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef VFP
	struct pcb *pcb;

	pcb = td->td_pcb;
	if ((pcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running VFP instructions we will
		 * need to save the state to memcpy it below.
		 */
		if (td == curthread)
			vfp_save_state(td, pcb);

		KASSERT(pcb->pcb_fpusaved == &pcb->pcb_fpustate,
		    ("Called fill_fpregs while the kernel is using the VFP"));
		memcpy(regs->fp_q, pcb->pcb_fpustate.vfp_regs,
		    sizeof(regs->fp_q));
		regs->fp_cr = pcb->pcb_fpustate.vfp_fpcr;
		regs->fp_sr = pcb->pcb_fpustate.vfp_fpsr;
	} else
#endif
		memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_fpregs(struct thread *td, struct fpreg *regs)
{
#ifdef VFP
	struct pcb *pcb;

	pcb = td->td_pcb;
	KASSERT(pcb->pcb_fpusaved == &pcb->pcb_fpustate,
	    ("Called set_fpregs while the kernel is using the VFP"));
	memcpy(pcb->pcb_fpustate.vfp_regs, regs->fp_q, sizeof(regs->fp_q));
	pcb->pcb_fpustate.vfp_fpcr = regs->fp_cr;
	pcb->pcb_fpustate.vfp_fpsr = regs->fp_sr;
#endif
	return (0);
}

int
fill_dbregs(struct thread *td, struct dbreg *regs)
{
	struct debug_monitor_state *monitor;
	int i;
	uint8_t debug_ver, nbkpts, nwtpts;

	memset(regs, 0, sizeof(*regs));

	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_DebugVer_SHIFT,
	    &debug_ver);
	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_BRPs_SHIFT,
	    &nbkpts);
	extract_user_id_field(ID_AA64DFR0_EL1, ID_AA64DFR0_WRPs_SHIFT,
	    &nwtpts);

	/*
	 * The BRPs field contains the number of breakpoints - 1. Armv8-A
	 * allows the hardware to provide 2-16 breakpoints so this won't
	 * overflow an 8 bit value. The same applies to the WRPs field.
	 */
	nbkpts++;
	nwtpts++;

	regs->db_debug_ver = debug_ver;
	regs->db_nbkpts = nbkpts;
	regs->db_nwtpts = nwtpts;

	monitor = &td->td_pcb->pcb_dbg_regs;
	if ((monitor->dbg_flags & DBGMON_ENABLED) != 0) {
		for (i = 0; i < nbkpts; i++) {
			regs->db_breakregs[i].dbr_addr = monitor->dbg_bvr[i];
			regs->db_breakregs[i].dbr_ctrl = monitor->dbg_bcr[i];
		}
		for (i = 0; i < nwtpts; i++) {
			regs->db_watchregs[i].dbw_addr = monitor->dbg_wvr[i];
			regs->db_watchregs[i].dbw_ctrl = monitor->dbg_wcr[i];
		}
	}

	return (0);
}

int
set_dbregs(struct thread *td, struct dbreg *regs)
{
	struct debug_monitor_state *monitor;
	uint64_t addr;
	uint32_t ctrl;
	int count;
	int i;

	monitor = &td->td_pcb->pcb_dbg_regs;
	count = 0;
	monitor->dbg_enable_count = 0;

	for (i = 0; i < DBG_BRP_MAX; i++) {
		addr = regs->db_breakregs[i].dbr_addr;
		ctrl = regs->db_breakregs[i].dbr_ctrl;

		/* Don't let the user set a breakpoint on a kernel address. */
		if (addr >= VM_MAXUSER_ADDRESS)
			return (EINVAL);

		/*
		 * The lowest 2 bits are ignored, so record the effective
		 * address.
		 */
		addr = rounddown2(addr, 4);

		/*
		 * Some control fields are ignored, and other bits reserved.
		 * Only unlinked, address-matching breakpoints are supported.
		 *
		 * XXX: fields that appear unvalidated, such as BAS, have
		 * constrained undefined behaviour. If the user mis-programs
		 * these, there is no risk to the system.
		 */
		ctrl &= DBG_BCR_EN | DBG_BCR_PMC | DBG_BCR_BAS;
		if ((ctrl & DBG_BCR_EN) != 0) {
			/* Only target EL0. */
			if ((ctrl & DBG_BCR_PMC) != DBG_BCR_PMC_EL0)
				return (EINVAL);

			monitor->dbg_enable_count++;
		}

		monitor->dbg_bvr[i] = addr;
		monitor->dbg_bcr[i] = ctrl;
	}

	for (i = 0; i < DBG_WRP_MAX; i++) {
		addr = regs->db_watchregs[i].dbw_addr;
		ctrl = regs->db_watchregs[i].dbw_ctrl;

		/* Don't let the user set a watchpoint on a kernel address. */
		if (addr >= VM_MAXUSER_ADDRESS)
			return (EINVAL);

		/*
		 * Some control fields are ignored, and other bits reserved.
		 * Only unlinked watchpoints are supported.
		 */
		ctrl &= DBG_WCR_EN | DBG_WCR_PAC | DBG_WCR_LSC | DBG_WCR_BAS |
		    DBG_WCR_MASK;

		if ((ctrl & DBG_WCR_EN) != 0) {
			/* Only target EL0. */
			if ((ctrl & DBG_WCR_PAC) != DBG_WCR_PAC_EL0)
				return (EINVAL);

			/* Must set at least one of the load/store bits. */
			if ((ctrl & DBG_WCR_LSC) == 0)
				return (EINVAL);

			/*
			 * When specifying the address range with BAS, the MASK
			 * field must be zero.
			 */
			if ((ctrl & DBG_WCR_BAS) != DBG_WCR_BAS_MASK &&
			    (ctrl & DBG_WCR_MASK) != 0)
				return (EINVAL);

			monitor->dbg_enable_count++;
		}
		monitor->dbg_wvr[i] = addr;
		monitor->dbg_wcr[i] = ctrl;
	}

	if (monitor->dbg_enable_count > 0)
		monitor->dbg_flags |= DBGMON_ENABLED;

	return (0);
}

#ifdef COMPAT_FREEBSD32
int
fill_regs32(struct thread *td, struct reg32 *regs)
{
	int i;
	struct trapframe *tf;

	tf = td->td_frame;
	for (i = 0; i < 13; i++)
		regs->r[i] = tf->tf_x[i];
	/* For arm32, SP is r13 and LR is r14 */
	regs->r_sp = tf->tf_x[13];
	regs->r_lr = tf->tf_x[14];
	regs->r_pc = tf->tf_elr;
	regs->r_cpsr = tf->tf_spsr;

	return (0);
}

int
set_regs32(struct thread *td, struct reg32 *regs)
{
	int i;
	struct trapframe *tf;

	tf = td->td_frame;
	for (i = 0; i < 13; i++)
		tf->tf_x[i] = regs->r[i];
	/* For arm 32, SP is r13 an LR is r14 */
	tf->tf_x[13] = regs->r_sp;
	tf->tf_x[14] = regs->r_lr;
	tf->tf_elr = regs->r_pc;
	tf->tf_spsr = regs->r_cpsr;

	return (0);
}

/* XXX fill/set dbregs/fpregs are stubbed on 32-bit arm. */
int
fill_fpregs32(struct thread *td, struct fpreg32 *regs)
{

	memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_fpregs32(struct thread *td, struct fpreg32 *regs)
{

	return (0);
}

int
fill_dbregs32(struct thread *td, struct dbreg32 *regs)
{

	memset(regs, 0, sizeof(*regs));
	return (0);
}

int
set_dbregs32(struct thread *td, struct dbreg32 *regs)
{

	return (0);
}
#endif

int
ptrace_set_pc(struct thread *td, u_long addr)
{

	td->td_frame->tf_elr = addr;
	return (0);
}

int
ptrace_single_step(struct thread *td)
{

	td->td_frame->tf_spsr |= PSR_SS;
	td->td_pcb->pcb_flags |= PCB_SINGLE_STEP;
	return (0);
}

int
ptrace_clear_single_step(struct thread *td)
{

	td->td_frame->tf_spsr &= ~PSR_SS;
	td->td_pcb->pcb_flags &= ~PCB_SINGLE_STEP;
	return (0);
}

void
exec_setregs(struct thread *td, struct image_params *imgp, uintptr_t stack)
{
	struct trapframe *tf = td->td_frame;

	memset(tf, 0, sizeof(struct trapframe));

	tf->tf_x[0] = stack;
	tf->tf_sp = STACKALIGN(stack);
	tf->tf_lr = imgp->entry_addr;
	tf->tf_elr = imgp->entry_addr;
}

/* Sanity check these are the same size, they will be memcpy'd to and fro */
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct gpregs *)0)->gp_x);
CTASSERT(sizeof(((struct trapframe *)0)->tf_x) ==
    sizeof((struct reg *)0)->x);

int
get_mcontext(struct thread *td, mcontext_t *mcp, int clear_ret)
{
	struct trapframe *tf = td->td_frame;

	if (clear_ret & GET_MC_CLEAR_RET) {
		mcp->mc_gpregs.gp_x[0] = 0;
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr & ~PSR_C;
	} else {
		mcp->mc_gpregs.gp_x[0] = tf->tf_x[0];
		mcp->mc_gpregs.gp_spsr = tf->tf_spsr;
	}

	memcpy(&mcp->mc_gpregs.gp_x[1], &tf->tf_x[1],
	    sizeof(mcp->mc_gpregs.gp_x[1]) * (nitems(mcp->mc_gpregs.gp_x) - 1));

	mcp->mc_gpregs.gp_sp = tf->tf_sp;
	mcp->mc_gpregs.gp_lr = tf->tf_lr;
	mcp->mc_gpregs.gp_elr = tf->tf_elr;
	get_fpcontext(td, mcp);

	return (0);
}

int
set_mcontext(struct thread *td, mcontext_t *mcp)
{
	struct trapframe *tf = td->td_frame;
	uint32_t spsr;

	spsr = mcp->mc_gpregs.gp_spsr;
	if ((spsr & PSR_M_MASK) != PSR_M_EL0t ||
	    (spsr & PSR_AARCH32) != 0 ||
	    (spsr & PSR_DAIF) != (td->td_frame->tf_spsr & PSR_DAIF))
		return (EINVAL);

	memcpy(tf->tf_x, mcp->mc_gpregs.gp_x, sizeof(tf->tf_x));

	tf->tf_sp = mcp->mc_gpregs.gp_sp;
	tf->tf_lr = mcp->mc_gpregs.gp_lr;
	tf->tf_elr = mcp->mc_gpregs.gp_elr;
	tf->tf_spsr = mcp->mc_gpregs.gp_spsr;
	set_fpcontext(td, mcp);

	return (0);
}

static void
get_fpcontext(struct thread *td, mcontext_t *mcp)
{
#ifdef VFP
	struct pcb *curpcb;

	critical_enter();

	curpcb = curthread->td_pcb;

	if ((curpcb->pcb_fpflags & PCB_FP_STARTED) != 0) {
		/*
		 * If we have just been running VFP instructions we will
		 * need to save the state to memcpy it below.
		 */
		vfp_save_state(td, curpcb);

		KASSERT(curpcb->pcb_fpusaved == &curpcb->pcb_fpustate,
		    ("Called get_fpcontext while the kernel is using the VFP"));
		KASSERT((curpcb->pcb_fpflags & ~PCB_FP_USERMASK) == 0,
		    ("Non-userspace FPU flags set in get_fpcontext"));
		memcpy(mcp->mc_fpregs.fp_q, curpcb->pcb_fpustate.vfp_regs,
		    sizeof(mcp->mc_fpregs));
		mcp->mc_fpregs.fp_cr = curpcb->pcb_fpustate.vfp_fpcr;
		mcp->mc_fpregs.fp_sr = curpcb->pcb_fpustate.vfp_fpsr;
		mcp->mc_fpregs.fp_flags = curpcb->pcb_fpflags;
		mcp->mc_flags |= _MC_FP_VALID;
	}

	critical_exit();
#endif
}

static void
set_fpcontext(struct thread *td, mcontext_t *mcp)
{
#ifdef VFP
	struct pcb *curpcb;

	critical_enter();

	if ((mcp->mc_flags & _MC_FP_VALID) != 0) {
		curpcb = curthread->td_pcb;

		/*
		 * Discard any vfp state for the current thread, we
		 * are about to override it.
		 */
		vfp_discard(td);

		KASSERT(curpcb->pcb_fpusaved == &curpcb->pcb_fpustate,
		    ("Called set_fpcontext while the kernel is using the VFP"));
		memcpy(curpcb->pcb_fpustate.vfp_regs, mcp->mc_fpregs.fp_q,
		    sizeof(mcp->mc_fpregs));
		curpcb->pcb_fpustate.vfp_fpcr = mcp->mc_fpregs.fp_cr;
		curpcb->pcb_fpustate.vfp_fpsr = mcp->mc_fpregs.fp_sr;
		curpcb->pcb_fpflags = mcp->mc_fpregs.fp_flags & PCB_FP_USERMASK;
	}

	critical_exit();
#endif
}

void
cpu_idle(int busy)
{

	spinlock_enter();
	if (!busy)
		cpu_idleclock();
	if (!sched_runnable())
		__asm __volatile(
		    "dsb sy \n"
		    "wfi    \n");
	if (!busy)
		cpu_activeclock();
	spinlock_exit();
}

void
cpu_halt(void)
{

	/* We should have shutdown by now, if not enter a low power sleep */
	intr_disable();
	while (1) {
		__asm __volatile("wfi");
	}
}

/*
 * Flush the D-cache for non-DMA I/O so that the I-cache can
 * be made coherent later.
 */
void
cpu_flush_dcache(void *ptr, size_t len)
{

	/* ARM64TODO TBD */
}

/* Get current clock frequency for the given CPU ID. */
int
cpu_est_clockrate(int cpu_id, uint64_t *rate)
{
	struct pcpu *pc;

	pc = pcpu_find(cpu_id);
	if (pc == NULL || rate == NULL)
		return (EINVAL);

	if (pc->pc_clock == 0)
		return (EOPNOTSUPP);

	*rate = pc->pc_clock;
	return (0);
}

void
cpu_pcpu_init(struct pcpu *pcpu, int cpuid, size_t size)
{

	pcpu->pc_acpi_id = 0xffffffff;
	pcpu->pc_mpidr = 0xffffffff;
}

void
spinlock_enter(void)
{
	struct thread *td;
	register_t daif;

	td = curthread;
	if (td->td_md.md_spinlock_count == 0) {
		daif = intr_disable();
		td->td_md.md_spinlock_count = 1;
		td->td_md.md_saved_daif = daif;
		critical_enter();
	} else
		td->td_md.md_spinlock_count++;
}

void
spinlock_exit(void)
{
	struct thread *td;
	register_t daif;

	td = curthread;
	daif = td->td_md.md_saved_daif;
	td->td_md.md_spinlock_count--;
	if (td->td_md.md_spinlock_count == 0) {
		critical_exit();
		intr_restore(daif);
	}
}

#ifndef	_SYS_SYSPROTO_H_
struct sigreturn_args {
	ucontext_t *ucp;
};
#endif

int
sys_sigreturn(struct thread *td, struct sigreturn_args *uap)
{
	ucontext_t uc;
	int error;

	if (copyin(uap->sigcntxp, &uc, sizeof(uc)))
		return (EFAULT);

	error = set_mcontext(td, &uc.uc_mcontext);
	if (error != 0)
		return (error);

	/* Restore signal mask. */
	kern_sigprocmask(td, SIG_SETMASK, &uc.uc_sigmask, NULL, 0);

	return (EJUSTRETURN);
}

/*
 * Construct a PCB from a trapframe. This is called from kdb_trap() where
 * we want to start a backtrace from the function that caused us to enter
 * the debugger. We have the context in the trapframe, but base the trace
 * on the PCB. The PCB doesn't have to be perfect, as long as it contains
 * enough for a backtrace.
 */
void
makectx(struct trapframe *tf, struct pcb *pcb)
{
	int i;

	for (i = 0; i < nitems(pcb->pcb_x); i++)
		pcb->pcb_x[i] = tf->tf_x[i];

	/* NB: pcb_lr is the PC, see PC_REGS() in db_machdep.h */
	pcb->pcb_lr = tf->tf_elr;
	pcb->pcb_sp = tf->tf_sp;
}

void
sendsig(sig_t catcher, ksiginfo_t *ksi, sigset_t *mask)
{
	struct thread *td;
	struct proc *p;
	struct trapframe *tf;
	struct sigframe *fp, frame;
	struct sigacts *psp;
	struct sysentvec *sysent;
	int onstack, sig;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	sig = ksi->ksi_signo;
	psp = p->p_sigacts;
	mtx_assert(&psp->ps_mtx, MA_OWNED);

	tf = td->td_frame;
	onstack = sigonstack(tf->tf_sp);

	CTR4(KTR_SIG, "sendsig: td=%p (%s) catcher=%p sig=%d", td, p->p_comm,
	    catcher, sig);

	/* Allocate and validate space for the signal handler context. */
	if ((td->td_pflags & TDP_ALTSTACK) != 0 && !onstack &&
	    SIGISMEMBER(psp->ps_sigonstack, sig)) {
		fp = (struct sigframe *)((uintptr_t)td->td_sigstk.ss_sp +
		    td->td_sigstk.ss_size);
#if defined(COMPAT_43)
		td->td_sigstk.ss_flags |= SS_ONSTACK;
#endif
	} else {
		fp = (struct sigframe *)td->td_frame->tf_sp;
	}

	/* Make room, keeping the stack aligned */
	fp--;
	fp = (struct sigframe *)STACKALIGN(fp);

	/* Fill in the frame to copy out */
	bzero(&frame, sizeof(frame));
	get_mcontext(td, &frame.sf_uc.uc_mcontext, 0);
	frame.sf_si = ksi->ksi_info;
	frame.sf_uc.uc_sigmask = *mask;
	frame.sf_uc.uc_stack = td->td_sigstk;
	frame.sf_uc.uc_stack.ss_flags = (td->td_pflags & TDP_ALTSTACK) != 0 ?
	    (onstack ? SS_ONSTACK : 0) : SS_DISABLE;
	mtx_unlock(&psp->ps_mtx);
	PROC_UNLOCK(td->td_proc);

	/* Copy the sigframe out to the user's stack. */
	if (copyout(&frame, fp, sizeof(*fp)) != 0) {
		/* Process has trashed its stack. Kill it. */
		CTR2(KTR_SIG, "sendsig: sigexit td=%p fp=%p", td, fp);
		PROC_LOCK(p);
		sigexit(td, SIGILL);
	}

	tf->tf_x[0]= sig;
	tf->tf_x[1] = (register_t)&fp->sf_si;
	tf->tf_x[2] = (register_t)&fp->sf_uc;

	tf->tf_elr = (register_t)catcher;
	tf->tf_sp = (register_t)fp;
	sysent = p->p_sysent;
	if (sysent->sv_sigcode_base != 0)
		tf->tf_lr = (register_t)sysent->sv_sigcode_base;
	else
		tf->tf_lr = (register_t)(sysent->sv_psstrings -
		    *(sysent->sv_szsigcode));

	CTR3(KTR_SIG, "sendsig: return td=%p pc=%#x sp=%#x", td, tf->tf_elr,
	    tf->tf_sp);

	PROC_LOCK(p);
	mtx_lock(&psp->ps_mtx);
}

static void
init_proc0(vm_offset_t kstack)
{
	struct pcpu *pcpup = &__pcpu[0];

	proc_linkup0(&proc0, &thread0);
	thread0.td_kstack = kstack;
	thread0.td_kstack_pages = KSTACK_PAGES;
	thread0.td_pcb = (struct pcb *)(thread0.td_kstack +
	    thread0.td_kstack_pages * PAGE_SIZE) - 1;
	thread0.td_pcb->pcb_fpflags = 0;
	thread0.td_pcb->pcb_fpusaved = &thread0.td_pcb->pcb_fpustate;
	thread0.td_pcb->pcb_vfpcpu = UINT_MAX;
	thread0.td_frame = &proc0_tf;
	pcpup->pc_curpcb = thread0.td_pcb;
}

typedef struct {
	uint32_t type;
	uint64_t phys_start;
	uint64_t virt_start;
	uint64_t num_pages;
	uint64_t attr;
} EFI_MEMORY_DESCRIPTOR;

typedef void (*efi_map_entry_cb)(struct efi_md *);

static void
foreach_efi_map_entry(struct efi_map_header *efihdr, efi_map_entry_cb cb)
{
	struct efi_md *map, *p;
	size_t efisz;
	int ndesc, i;

	/*
	 * Memory map data provided by UEFI via the GetMemoryMap
	 * Boot Services API.
	 */
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (struct efi_md *)((uint8_t *)efihdr + efisz);

	if (efihdr->descriptor_size == 0)
		return;
	ndesc = efihdr->memory_size / efihdr->descriptor_size;

	for (i = 0, p = map; i < ndesc; i++,
	    p = efi_next_descriptor(p, efihdr->descriptor_size)) {
		cb(p);
	}
}

static void
exclude_efi_map_entry(struct efi_md *p)
{

	switch (p->md_type) {
	case EFI_MD_TYPE_CODE:
	case EFI_MD_TYPE_DATA:
	case EFI_MD_TYPE_BS_CODE:
	case EFI_MD_TYPE_BS_DATA:
	case EFI_MD_TYPE_FREE:
		/*
		 * We're allowed to use any entry with these types.
		 */
		break;
	default:
		physmem_exclude_region(p->md_phys, p->md_pages * PAGE_SIZE,
		    EXFLAG_NOALLOC);
	}
}

static void
exclude_efi_map_entries(struct efi_map_header *efihdr)
{

	foreach_efi_map_entry(efihdr, exclude_efi_map_entry);
}

static void
add_efi_map_entry(struct efi_md *p)
{

	switch (p->md_type) {
	case EFI_MD_TYPE_RT_DATA:
		/*
		 * Runtime data will be excluded after the DMAP
		 * region is created to stop it from being added
		 * to phys_avail.
		 */
	case EFI_MD_TYPE_CODE:
	case EFI_MD_TYPE_DATA:
	case EFI_MD_TYPE_BS_CODE:
	case EFI_MD_TYPE_BS_DATA:
	case EFI_MD_TYPE_FREE:
		/*
		 * We're allowed to use any entry with these types.
		 */
		physmem_hardware_region(p->md_phys,
		    p->md_pages * PAGE_SIZE);
		break;
	}
}

static void
add_efi_map_entries(struct efi_map_header *efihdr)
{

	foreach_efi_map_entry(efihdr, add_efi_map_entry);
}

static void
print_efi_map_entry(struct efi_md *p)
{
	const char *type;
	static const char *types[] = {
		"Reserved",
		"LoaderCode",
		"LoaderData",
		"BootServicesCode",
		"BootServicesData",
		"RuntimeServicesCode",
		"RuntimeServicesData",
		"ConventionalMemory",
		"UnusableMemory",
		"ACPIReclaimMemory",
		"ACPIMemoryNVS",
		"MemoryMappedIO",
		"MemoryMappedIOPortSpace",
		"PalCode",
		"PersistentMemory"
	};

	if (p->md_type < nitems(types))
		type = types[p->md_type];
	else
		type = "<INVALID>";
	printf("%23s %012lx %12p %08lx ", type, p->md_phys,
	    p->md_virt, p->md_pages);
	if (p->md_attr & EFI_MD_ATTR_UC)
		printf("UC ");
	if (p->md_attr & EFI_MD_ATTR_WC)
		printf("WC ");
	if (p->md_attr & EFI_MD_ATTR_WT)
		printf("WT ");
	if (p->md_attr & EFI_MD_ATTR_WB)
		printf("WB ");
	if (p->md_attr & EFI_MD_ATTR_UCE)
		printf("UCE ");
	if (p->md_attr & EFI_MD_ATTR_WP)
		printf("WP ");
	if (p->md_attr & EFI_MD_ATTR_RP)
		printf("RP ");
	if (p->md_attr & EFI_MD_ATTR_XP)
		printf("XP ");
	if (p->md_attr & EFI_MD_ATTR_NV)
		printf("NV ");
	if (p->md_attr & EFI_MD_ATTR_MORE_RELIABLE)
		printf("MORE_RELIABLE ");
	if (p->md_attr & EFI_MD_ATTR_RO)
		printf("RO ");
	if (p->md_attr & EFI_MD_ATTR_RT)
		printf("RUNTIME");
	printf("\n");
}

static void
print_efi_map_entries(struct efi_map_header *efihdr)
{

	printf("%23s %12s %12s %8s %4s\n",
	    "Type", "Physical", "Virtual", "#Pages", "Attr");
	foreach_efi_map_entry(efihdr, print_efi_map_entry);
}

#ifdef FDT
static void
try_load_dtb(caddr_t kmdp)
{
	vm_offset_t dtbp;

	dtbp = MD_FETCH(kmdp, MODINFOMD_DTBP, vm_offset_t);
#if defined(FDT_DTB_STATIC)
	/*
	 * In case the device tree blob was not retrieved (from metadata) try
	 * to use the statically embedded one.
	 */
	if (dtbp == 0)
		dtbp = (vm_offset_t)&fdt_static_dtb;
#endif

	if (dtbp == (vm_offset_t)NULL) {
		printf("ERROR loading DTB\n");
		return;
	}

	if (OF_install(OFW_FDT, 0) == FALSE)
		panic("Cannot install FDT");

	if (OF_init((void *)dtbp) != 0)
		panic("OF_init failed with the found device tree");

	parse_fdt_bootargs();
}
#endif

static bool
bus_probe(void)
{
	bool has_acpi, has_fdt;
	char *order, *env;

	has_acpi = has_fdt = false;

#ifdef FDT
	has_fdt = (OF_peer(0) != 0);
#endif
#ifdef DEV_ACPI
	has_acpi = (AcpiOsGetRootPointer() != 0);
#endif

	env = kern_getenv("kern.cfg.order");
	if (env != NULL) {
		order = env;
		while (order != NULL) {
			if (has_acpi &&
			    strncmp(order, "acpi", 4) == 0 &&
			    (order[4] == ',' || order[4] == '\0')) {
				arm64_bus_method = ARM64_BUS_ACPI;
				break;
			}
			if (has_fdt &&
			    strncmp(order, "fdt", 3) == 0 &&
			    (order[3] == ',' || order[3] == '\0')) {
				arm64_bus_method = ARM64_BUS_FDT;
				break;
			}
			order = strchr(order, ',');
		}
		freeenv(env);

		/* If we set the bus method it is valid */
		if (arm64_bus_method != ARM64_BUS_NONE)
			return (true);
	}
	/* If no order or an invalid order was set use the default */
	if (arm64_bus_method == ARM64_BUS_NONE) {
		if (has_fdt)
			arm64_bus_method = ARM64_BUS_FDT;
		else if (has_acpi)
			arm64_bus_method = ARM64_BUS_ACPI;
	}

	/*
	 * If no option was set the default is valid, otherwise we are
	 * setting one to get cninit() working, then calling panic to tell
	 * the user about the invalid bus setup.
	 */
	return (env == NULL);
}

static void
cache_setup(void)
{
	int dczva_line_shift;
	uint32_t dczid_el0;

	identify_cache(READ_SPECIALREG(ctr_el0));

	dczid_el0 = READ_SPECIALREG(dczid_el0);

	/* Check if dc zva is not prohibited */
	if (dczid_el0 & DCZID_DZP)
		dczva_line_size = 0;
	else {
		/* Same as with above calculations */
		dczva_line_shift = DCZID_BS_SIZE(dczid_el0);
		dczva_line_size = sizeof(int) << dczva_line_shift;

		/* Change pagezero function */
		pagezero = pagezero_cache;
	}
}

int
memory_mapping_mode(vm_paddr_t pa)
{
	struct efi_md *map, *p;
	size_t efisz;
	int ndesc, i;

	if (efihdr == NULL)
		return (VM_MEMATTR_WRITE_BACK);

	/*
	 * Memory map data provided by UEFI via the GetMemoryMap
	 * Boot Services API.
	 */
	efisz = (sizeof(struct efi_map_header) + 0xf) & ~0xf;
	map = (struct efi_md *)((uint8_t *)efihdr + efisz);

	if (efihdr->descriptor_size == 0)
		return (VM_MEMATTR_WRITE_BACK);
	ndesc = efihdr->memory_size / efihdr->descriptor_size;

	for (i = 0, p = map; i < ndesc; i++,
	    p = efi_next_descriptor(p, efihdr->descriptor_size)) {
		if (pa < p->md_phys ||
		    pa >= p->md_phys + p->md_pages * EFI_PAGE_SIZE)
			continue;
		if (p->md_type == EFI_MD_TYPE_IOMEM ||
		    p->md_type == EFI_MD_TYPE_IOPORT)
			return (VM_MEMATTR_DEVICE);
		else if ((p->md_attr & EFI_MD_ATTR_WB) != 0 ||
		    p->md_type == EFI_MD_TYPE_RECLAIM)
			return (VM_MEMATTR_WRITE_BACK);
		else if ((p->md_attr & EFI_MD_ATTR_WT) != 0)
			return (VM_MEMATTR_WRITE_THROUGH);
		else if ((p->md_attr & EFI_MD_ATTR_WC) != 0)
			return (VM_MEMATTR_WRITE_COMBINING);
		break;
	}

	return (VM_MEMATTR_DEVICE);
}

void
initarm(struct arm64_bootparams *abp)
{
	struct efi_fb *efifb;
	struct pcpu *pcpup;
	char *env;
#ifdef FDT
	struct mem_region mem_regions[FDT_MEM_REGIONS];
	int mem_regions_sz;
#endif
	vm_offset_t lastaddr;
	caddr_t kmdp;
	bool valid;

	boot_el = abp->boot_el;

	/* Parse loader or FDT boot parametes. Determine last used address. */
	lastaddr = parse_boot_param(abp);

	/* Find the kernel address */
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");

	identify_cpu(0);
	update_special_regs(0);

	link_elf_ireloc(kmdp);
	try_load_dtb(kmdp);

	efi_systbl_phys = MD_FETCH(kmdp, MODINFOMD_FW_HANDLE, vm_paddr_t);

	/* Load the physical memory ranges */
	efihdr = (struct efi_map_header *)preload_search_info(kmdp,
	    MODINFO_METADATA | MODINFOMD_EFI_MAP);
	if (efihdr != NULL)
		add_efi_map_entries(efihdr);
#ifdef FDT
	else {
		/* Grab physical memory regions information from device tree. */
		if (fdt_get_mem_regions(mem_regions, &mem_regions_sz,
		    NULL) != 0)
			panic("Cannot get physical memory regions");
		physmem_hardware_regions(mem_regions, mem_regions_sz);
	}
	if (fdt_get_reserved_mem(mem_regions, &mem_regions_sz) == 0)
		physmem_exclude_regions(mem_regions, mem_regions_sz,
		    EXFLAG_NODUMP | EXFLAG_NOALLOC);
#endif

	/* Exclude the EFI framebuffer from our view of physical memory. */
	efifb = (struct efi_fb *)preload_search_info(kmdp,
	    MODINFO_METADATA | MODINFOMD_EFI_FB);
	if (efifb != NULL)
		physmem_exclude_region(efifb->fb_addr, efifb->fb_size,
		    EXFLAG_NOALLOC);

	/* Set the pcpu data, this is needed by pmap_bootstrap */
	pcpup = &__pcpu[0];
	pcpu_init(pcpup, 0, sizeof(struct pcpu));

	/*
	 * Set the pcpu pointer with a backup in tpidr_el1 to be
	 * loaded when entering the kernel from userland.
	 */
	__asm __volatile(
	    "mov x18, %0 \n"
	    "msr tpidr_el1, %0" :: "r"(pcpup));

	PCPU_SET(curthread, &thread0);
	PCPU_SET(midr, get_midr());

	/* Do basic tuning, hz etc */
	init_param1();

	cache_setup();
	pan_setup();

	/* Bootstrap enough of pmap  to enter the kernel proper */
	pmap_bootstrap(abp->kern_l0pt, abp->kern_l1pt,
	    KERNBASE - abp->kern_delta, lastaddr - KERNBASE);
	/* Exclude entries neexed in teh DMAP region, but not phys_avail */
	if (efihdr != NULL)
		exclude_efi_map_entries(efihdr);
	physmem_init_kernel_globals();

	devmap_bootstrap(0, NULL);

	valid = bus_probe();

	cninit();
	set_ttbr0(abp->kern_ttbr0);
	cpu_tlb_flushID();

	if (!valid)
		panic("Invalid bus configuration: %s",
		    kern_getenv("kern.cfg.order"));

	/*
	 * Dump the boot metadata. We have to wait for cninit() since console
	 * output is required. If it's grossly incorrect the kernel will never
	 * make it this far.
	 */
	if (getenv_is_true("debug.dump_modinfo_at_boot"))
		preload_dump();

	init_proc0(abp->kern_stack);
	msgbufinit(msgbufp, msgbufsize);
	mutex_init();
	init_param2(physmem);

	dbg_init();
	kdb_init();
	pan_enable();

	kcsan_cpu_init(0);

	env = kern_getenv("kernelname");
	if (env != NULL)
		strlcpy(kernelname, env, sizeof(kernelname));

	if (boothowto & RB_VERBOSE) {
		if (efihdr != NULL)
			print_efi_map_entries(efihdr);
		physmem_print_tables();
	}

	early_boot = 0;
}

void
dbg_init(void)
{

	/* Clear OS lock */
	WRITE_SPECIALREG(oslar_el1, 0);

	/* This permits DDB to use debug registers for watchpoints. */
	dbg_monitor_init();

	/* TODO: Eventually will need to initialize debug registers here. */
}

#ifdef DDB
#include <ddb/ddb.h>

DB_SHOW_COMMAND(specialregs, db_show_spregs)
{
#define	PRINT_REG(reg)	\
    db_printf(__STRING(reg) " = %#016lx\n", READ_SPECIALREG(reg))

	PRINT_REG(actlr_el1);
	PRINT_REG(afsr0_el1);
	PRINT_REG(afsr1_el1);
	PRINT_REG(aidr_el1);
	PRINT_REG(amair_el1);
	PRINT_REG(ccsidr_el1);
	PRINT_REG(clidr_el1);
	PRINT_REG(contextidr_el1);
	PRINT_REG(cpacr_el1);
	PRINT_REG(csselr_el1);
	PRINT_REG(ctr_el0);
	PRINT_REG(currentel);
	PRINT_REG(daif);
	PRINT_REG(dczid_el0);
	PRINT_REG(elr_el1);
	PRINT_REG(esr_el1);
	PRINT_REG(far_el1);
#if 0
	/* ARM64TODO: Enable VFP before reading floating-point registers */
	PRINT_REG(fpcr);
	PRINT_REG(fpsr);
#endif
	PRINT_REG(id_aa64afr0_el1);
	PRINT_REG(id_aa64afr1_el1);
	PRINT_REG(id_aa64dfr0_el1);
	PRINT_REG(id_aa64dfr1_el1);
	PRINT_REG(id_aa64isar0_el1);
	PRINT_REG(id_aa64isar1_el1);
	PRINT_REG(id_aa64pfr0_el1);
	PRINT_REG(id_aa64pfr1_el1);
	PRINT_REG(id_afr0_el1);
	PRINT_REG(id_dfr0_el1);
	PRINT_REG(id_isar0_el1);
	PRINT_REG(id_isar1_el1);
	PRINT_REG(id_isar2_el1);
	PRINT_REG(id_isar3_el1);
	PRINT_REG(id_isar4_el1);
	PRINT_REG(id_isar5_el1);
	PRINT_REG(id_mmfr0_el1);
	PRINT_REG(id_mmfr1_el1);
	PRINT_REG(id_mmfr2_el1);
	PRINT_REG(id_mmfr3_el1);
#if 0
	/* Missing from llvm */
	PRINT_REG(id_mmfr4_el1);
#endif
	PRINT_REG(id_pfr0_el1);
	PRINT_REG(id_pfr1_el1);
	PRINT_REG(isr_el1);
	PRINT_REG(mair_el1);
	PRINT_REG(midr_el1);
	PRINT_REG(mpidr_el1);
	PRINT_REG(mvfr0_el1);
	PRINT_REG(mvfr1_el1);
	PRINT_REG(mvfr2_el1);
	PRINT_REG(revidr_el1);
	PRINT_REG(sctlr_el1);
	PRINT_REG(sp_el0);
	PRINT_REG(spsel);
	PRINT_REG(spsr_el1);
	PRINT_REG(tcr_el1);
	PRINT_REG(tpidr_el0);
	PRINT_REG(tpidr_el1);
	PRINT_REG(tpidrro_el0);
	PRINT_REG(ttbr0_el1);
	PRINT_REG(ttbr1_el1);
	PRINT_REG(vbar_el1);
#undef PRINT_REG
}

DB_SHOW_COMMAND(vtop, db_show_vtop)
{
	uint64_t phys;

	if (have_addr) {
		phys = arm64_address_translate_s1e1r(addr);
		db_printf("EL1 physical address reg (read):  0x%016lx\n", phys);
		phys = arm64_address_translate_s1e1w(addr);
		db_printf("EL1 physical address reg (write): 0x%016lx\n", phys);
		phys = arm64_address_translate_s1e0r(addr);
		db_printf("EL0 physical address reg (read):  0x%016lx\n", phys);
		phys = arm64_address_translate_s1e0w(addr);
		db_printf("EL0 physical address reg (write): 0x%016lx\n", phys);
	} else
		db_printf("show vtop <virt_addr>\n");
}
#endif
