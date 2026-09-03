/*
 * F-Stack unit test common stub: fatal-function wraps (definitions).
 * See rte_stub.h header for rationale (spec 04 §8.2).
 */

/* CMocka required boilerplate before <cmocka.h> */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "rte_stub.h"

/*
 * __wrap_rte_exit: redirects rte_exit() to a cmocka-trapped failure.
 *
 * Real DPDK signature:  void rte_exit(int exit_code, const char *format, ...)
 * Behavior here: instead of calling exit(), record a mock_assert failure so
 * the test framework reports an unexpected fatal-path entry.
 */
void
__wrap_rte_exit(int exit_code, const char *format, ...)
{
    (void)exit_code;
    (void)format;
    /* mock_assert(0, ...) -> cmocka_assertion_handler -> longjmp to test runner */
    mock_assert(0, "rte_exit", __FILE__, __LINE__);
    /* unreachable */
}

/*
 * __wrap_rte_panic: redirects rte_panic() to a cmocka-trapped failure.
 *
 * Real DPDK signature is implemented as macro `rte_panic(...)` that expands
 * to `__rte_panic(__func__, ...)`. Some DPDK versions expose `rte_panic` as
 * a function symbol; we wrap the symbol regardless. Worst case the wrap is
 * unused (no symbol reference) and the linker silently ignores it.
 */
void
__wrap_rte_panic(const char *funcname, const char *format, ...)
{
    (void)funcname;
    (void)format;
    mock_assert(0, "rte_panic", __FILE__, __LINE__);
    /* unreachable */
}

/*
 * FreeBSD-stack bridge stubs (linker resolution only).
 *
 * lib/ff_dpdk_if.c references these symbols; their real definitions live in
 * the FreeBSD adapter objects (ff_freebsd_init.c / ff_kern_timeout.c /
 * ff_veth.c) which the integration harness does not link. Calling any of
 * them means coverage moved beyond the intended scope, so they are no-ops
 * that keep the state harmless (lro pointers stay NULL, which main_loop
 * already guards with `if (ctx->lro != NULL)`).
 */
void ff_stack_thread_init(int cpuid) { (void)cpuid; }
void ff_tcp_hpts_softclock(void) { }
void ff_hardclock_worker(void) { }

void *ff_lro_init(void *ifp) { (void)ifp; return NULL; }
void  ff_lro_free(void *lro) { (void)lro; }
int   ff_lro_rx(void *lro, void *m) { (void)lro; (void)m; return -1; }
void  ff_lro_flush(void *lro) { (void)lro; }
