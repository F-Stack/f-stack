/*
 * F-Stack unit test common stub: fatal-function wraps.
 *
 * Per spec 04 §8 (R-U-13), any code path that calls rte_exit() or
 * rte_panic() must be intercepted lest the test process is killed.
 *
 * These __wrap_* hooks redirect to mock_assert(0, ...) which throws a
 * cmocka-trapped failure that the parent test harness reports as a
 * test failure rather than a SIGABRT.
 *
 * Activated by linker flags: -Wl,--wrap=rte_exit -Wl,--wrap=rte_panic
 * (set via BASE_WRAPS in tests/unit/Makefile).
 */

#ifndef RTE_STUB_H
#define RTE_STUB_H

#include <stdarg.h>

void __wrap_rte_exit(int exit_code, const char *format, ...);
void __wrap_rte_panic(const char *funcname, const char *format, ...);

#endif /* RTE_STUB_H */
