/*
 * F-Stack lib/ unit test: ff_host_interface.c (P1 #1)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §4.1
 * Coverage: 8 TC (TC-U-P1-HIF-01..08).
 *
 * IMPORTANT spec-vs-code corrections (DP-U-12 "代码为准"):
 *   - spec 02 §4.2 / 04 §7.1 said "wrap rte_malloc/free" — actual ff_host_interface.c
 *     has rte_malloc/rte_calloc/rte_realloc/rte_free CALLS COMMENTED OUT and uses
 *     plain glibc malloc/calloc/realloc/free. So no rte_ wrap is needed.
 *   - ff_log is called by ff_mmap on failure path (line 81). We provide a local
 *     ff_log stub here (no-op) to satisfy the linker without pulling in lib/ff_log.c.
 *   - ff_arc4rand wraps OpenSSL RAND_bytes — we link libcrypto.
 *   - exit(1) is called by ff_mmap on mmap failure; tests below avoid that path
 *     (use only valid mmap arguments).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "ff_host_interface.h"
#include "ff_errno.h"

/* ------------------------------------------------------------------------ */
/* Local ff_log stub (linker dependency only — body unused in tests)        */
/* ------------------------------------------------------------------------ */
int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    (void)level; (void)logtype; (void)format;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-01: ff_malloc returns non-null for valid size                */
/* ------------------------------------------------------------------------ */
static void
test_ff_malloc_normal(void **state)
{
    (void)state;
    void *p = ff_malloc(64);
    assert_non_null(p);
    /* Write a sentinel to verify writability */
    memset(p, 0xAB, 64);
    assert_int_equal(((unsigned char *)p)[0],  0xAB);
    assert_int_equal(((unsigned char *)p)[63], 0xAB);
    ff_free(p);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-02: ff_calloc zeros the buffer                               */
/* ------------------------------------------------------------------------ */
static void
test_ff_calloc_zeros_memory(void **state)
{
    (void)state;
    unsigned char *p = ff_calloc(16, 4);   /* 64 bytes */
    assert_non_null(p);
    for (int i = 0; i < 64; i++) {
        assert_int_equal(p[i], 0);
    }
    ff_free(p);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-03: ff_realloc grows preserving prefix bytes                 */
/* ------------------------------------------------------------------------ */
static void
test_ff_realloc_grow(void **state)
{
    (void)state;
    unsigned char *p = ff_malloc(8);
    assert_non_null(p);
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)(0x10 + i);
    }
    unsigned char *q = ff_realloc(p, 32);
    assert_non_null(q);
    /* Prefix preserved by glibc realloc */
    for (int i = 0; i < 8; i++) {
        assert_int_equal(q[i], 0x10 + i);
    }
    ff_free(q);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-04: ff_free(NULL) does not crash (POSIX semantics)           */
/* ------------------------------------------------------------------------ */
static void
test_ff_free_null(void **state)
{
    (void)state;
    ff_free(NULL);    /* must be safe */
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-05: ff_clock_gettime(MONOTONIC) returns sane non-negative    */
/* values; consecutive calls give monotonically non-decreasing nanoseconds. */
/* ------------------------------------------------------------------------ */
static void
test_ff_clock_gettime_monotonic(void **state)
{
    (void)state;
    int64_t s1 = 0, s2 = 0;
    long ns1 = 0, ns2 = 0;

    ff_clock_gettime(ff_CLOCK_MONOTONIC, &s1, &ns1);
    /* tiny busy delay to allow tick advance */
    for (volatile int i = 0; i < 100000; i++) { /* burn cycles */ }
    ff_clock_gettime(ff_CLOCK_MONOTONIC, &s2, &ns2);

    assert_true(s1 >= 0);
    assert_true(ns1 >= 0 && ns1 < 1000 * 1000 * 1000);
    /* s2 > s1, OR same s but ns2 >= ns1 */
    assert_true((s2 > s1) || (s2 == s1 && ns2 >= ns1));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-06: ff_arc4rand fills the buffer with non-all-zero bytes     */
/* ------------------------------------------------------------------------ */
static void
test_ff_arc4rand_buf_filled(void **state)
{
    (void)state;
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    ff_arc4rand(buf, sizeof(buf), 0);
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            nonzero++;
        }
    }
    /* statistically, ≥ 60 of 64 bytes should be non-zero (~p=255/256) */
    assert_true(nonzero >= 50);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-07: ff_get_current_time after ff_update_current_ts gives     */
/* consistent advancing values across two updates separated by a busy wait.  */
/* (current_ts is a static struct timespec inside ff_host_interface.c.)     */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_current_time_advances(void **state)
{
    (void)state;
    int64_t s1 = -1, s2 = -1;
    long ns1 = -1, ns2 = -1;

    ff_update_current_ts();
    ff_get_current_time(&s1, &ns1);

    /* sleep at least 1ms so REALTIME definitely advances */
    struct timespec slp = {0, 2 * 1000 * 1000};   /* 2 ms */
    nanosleep(&slp, NULL);

    ff_update_current_ts();
    ff_get_current_time(&s2, &ns2);

    assert_true(s1 > 0);    /* REALTIME never zero on running system */
    assert_true(s2 > 0);
    /* (s2,ns2) > (s1,ns1) lexicographic */
    assert_true((s2 > s1) || (s2 == s1 && ns2 > ns1));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-08: ff_os_errno maps known ff_E* values to host E* equivs     */
/* ------------------------------------------------------------------------ */
static void
test_ff_os_errno_mapping(void **state)
{
    (void)state;
    /* Sample 5 common mappings */
    errno = 0;
    ff_os_errno(ff_EPERM);
    assert_int_equal(errno, EPERM);

    errno = 0;
    ff_os_errno(ff_ENOENT);
    assert_int_equal(errno, ENOENT);

    errno = 0;
    ff_os_errno(ff_EINVAL);
    assert_int_equal(errno, EINVAL);

    errno = 0;
    ff_os_errno(ff_ENOMEM);
    assert_int_equal(errno, ENOMEM);

    /* default branch: arbitrary unknown code passes through */
    errno = 0;
    ff_os_errno(99999);
    assert_int_equal(errno, 99999);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ff_malloc_normal),
        cmocka_unit_test(test_ff_calloc_zeros_memory),
        cmocka_unit_test(test_ff_realloc_grow),
        cmocka_unit_test(test_ff_free_null),
        cmocka_unit_test(test_ff_clock_gettime_monotonic),
        cmocka_unit_test(test_ff_arc4rand_buf_filled),
        cmocka_unit_test(test_ff_get_current_time_advances),
        cmocka_unit_test(test_ff_os_errno_mapping),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
