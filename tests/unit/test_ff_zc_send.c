/*
 * F-Stack unit test: FSTACK_ZC_SEND user-space logic (M2).
 *
 * Scope / honesty note (cross-validated, see 41-impl-plan.md DEV-2):
 *   lib/ff_veth.c and lib/ff_syscall_wrapper.c CANNOT be compiled by the
 *   host cmocka harness — they pull FreeBSD-only kernel headers
 *   (sys/ctype.h, sys/limits.h, sys/socketvar.h, net/if_var.h, ...).
 *   Verified by `gcc -fsyntax-only` failing at sys/ctype.h.
 *
 *   Therefore this is an ALGORITHM-CONFORMANCE test: it re-implements the
 *   EXACT ff_zc_mbuf_get / ff_zc_mbuf_write / ff_zc_send-validation logic
 *   against a minimal mbuf shim, locking in the invariants the spec cares
 *   about (M_PKTHDR set, pkthdr.len accumulated on the CHAIN HEAD, boundary
 *   returns). The real compiled binary is validated end-to-end in M3
 *   (functional helloworld_zc). KEEP THIS MIRROR IN SYNC with:
 *     - lib/ff_veth.c  ff_zc_mbuf_get / ff_zc_mbuf_write
 *     - lib/ff_syscall_wrapper.c  ff_zc_send (input validation)
 *
 * Covers spec 37 cases: U1,U2,U3,U4,U5,U6,U7,U8,U9,U10 + multi-segment +
 * INV-1 (M_PKTHDR/pkthdr.len consistency).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

/* ----------------------------------------------------------------------- */
/* Minimal FreeBSD mbuf shim (only what ff_zc_mbuf_get/write touch).        */
/* ----------------------------------------------------------------------- */
#define SHIM_M_PKTHDR        0x00000001
#define SHIM_SEG_CAP         128          /* per-segment data capacity */

struct shim_pkthdr { int len; };

struct shim_mbuf {
    struct shim_mbuf *m_next;
    int               m_len;
    int               m_flags;
    char             *m_data;
    struct shim_pkthdr m_pkthdr;
    char              store[SHIM_SEG_CAP];
};

#define SHIM_TRAILINGSPACE(m) ((int)(SHIM_SEG_CAP - (m)->m_len))
#define shim_mtod(m, t)       ((t)((m)->m_data))
#define shim_min(a, b)        ((a) < (b) ? (a) : (b))
#define shim_max(a, b)        ((a) > (b) ? (a) : (b))

/* struct ff_zc_mbuf layout mirrors lib/ff_api.h exactly. */
struct zc_mbuf {
    void *bsd_mbuf;       /* chain head */
    void *bsd_mbuf_off;   /* write cursor */
    int   off;
    int   len;
};

/* Allocate a chain large enough for `len` bytes (mirrors m_getm2 result),
 * with M_PKTHDR on the head when `with_pkthdr` (mirrors the M_PKTHDR arg). */
static struct shim_mbuf *
shim_chain_alloc(int len, int with_pkthdr)
{
    int need = shim_max(len, 1);
    struct shim_mbuf *head = NULL, *prev = NULL;
    int allocated = 0;

    do {
        struct shim_mbuf *m = calloc(1, sizeof(*m));
        assert_non_null(m);
        m->m_data = m->store;
        m->m_len = 0;
        if (head == NULL) {
            head = m;
            if (with_pkthdr) {
                m->m_flags |= SHIM_M_PKTHDR;
                m->m_pkthdr.len = 0;
            }
        } else {
            prev->m_next = m;
        }
        prev = m;
        allocated += SHIM_SEG_CAP;
    } while (allocated < need);

    return head;
}

static void
shim_chain_free(struct shim_mbuf *m)
{
    while (m != NULL) {
        struct shim_mbuf *n = m->m_next;
        free(m);
        m = n;
    }
}

/* ----------------------------------------------------------------------- */
/* MIRROR of lib/ff_veth.c ff_zc_mbuf_get (M_PKTHDR path).                  */
/* ----------------------------------------------------------------------- */
static int
mir_zc_mbuf_get(struct zc_mbuf *m, int len)
{
    struct shim_mbuf *mb;

    if (m == NULL || len < 0) {
        return -1;
    }
    mb = shim_chain_alloc(len, /*with_pkthdr*/1);
    if (mb == NULL) {
        return -1;
    }
    m->bsd_mbuf = m->bsd_mbuf_off = mb;
    m->off = 0;
    m->len = len;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* MIRROR of lib/ff_veth.c ff_zc_mbuf_write (head pkthdr.len accumulation). */
/* ----------------------------------------------------------------------- */
static int
mir_zc_mbuf_write(struct zc_mbuf *zm, const char *data, int len)
{
    int length, progress = 0;
    struct shim_mbuf *m, *mb, *head;

    if (zm == NULL || data == NULL || len < 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    head = (struct shim_mbuf *)zm->bsd_mbuf;
    m = (struct shim_mbuf *)zm->bsd_mbuf_off;

    if (zm->off + len > zm->len) {
        return -1;
    }

    for (mb = m; mb != NULL; mb = mb->m_next) {
        length = shim_min(SHIM_TRAILINGSPACE(mb), len - progress);
        if (length > 0) {
            memcpy(shim_mtod(mb, char *) + mb->m_len, data + progress, length);
            mb->m_len += length;
            progress += length;
        }
        if (len == progress) {
            break;
        }
    }

    head->m_pkthdr.len += progress;
    zm->off += progress;
    zm->bsd_mbuf_off = mb;
    return progress;
}

/* ----------------------------------------------------------------------- */
/* MIRROR of lib/ff_syscall_wrapper.c ff_zc_send input validation.         */
/* Returns 0 if it WOULD call kern_zc_sendit, or the errno it would fail   */
/* with (EINVAL) before the kernel call.                                   */
/* ----------------------------------------------------------------------- */
static int
mir_zc_send_validate(const void *mb, size_t nbytes)
{
    if (mb == NULL || nbytes == 0 || nbytes > INT_MAX) {
        return EINVAL;
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Test cases                                                              */
/* ----------------------------------------------------------------------- */

/* U1: get sets M_PKTHDR on chain head. */
static void
test_ff_zc_mbuf_get_pkthdr_flag_set(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 64), 0);
    struct shim_mbuf *head = zm.bsd_mbuf;
    assert_true((head->m_flags & SHIM_M_PKTHDR) != 0);
    shim_chain_free(head);
}

/* U2: get leaves pkthdr.len == 0. */
static void
test_ff_zc_mbuf_get_initial_pkthdr_len_zero(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 64), 0);
    struct shim_mbuf *head = zm.bsd_mbuf;
    assert_int_equal(head->m_pkthdr.len, 0);
    shim_chain_free(head);
}

/* U3: get with len<0 returns -1. */
static void
test_ff_zc_mbuf_get_negative_len_returns_error(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, -1), -1);
}

/* U4: get with len==0 still returns a (minimal) chain. */
static void
test_ff_zc_mbuf_get_zero_len_returns_minimal_chain(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 0), 0);
    assert_non_null(zm.bsd_mbuf);
    shim_chain_free(zm.bsd_mbuf);
}

/* U5: multiple writes accumulate pkthdr.len on the head. */
static void
test_ff_zc_mbuf_write_accumulates_pkthdr_len(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 64), 0);
    assert_int_equal(mir_zc_mbuf_write(&zm, "ab", 2), 2);
    assert_int_equal(mir_zc_mbuf_write(&zm, "cd", 2), 2);
    struct shim_mbuf *head = zm.bsd_mbuf;
    assert_int_equal(head->m_pkthdr.len, 4);
    assert_memory_equal(head->store, "abcd", 4);
    shim_chain_free(head);
}

/* U6: write exceeding zm->len returns -1. */
static void
test_ff_zc_mbuf_write_overflow_returns_error(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 4), 0);
    char big[8] = "abcdefg";
    assert_int_equal(mir_zc_mbuf_write(&zm, big, 8), -1);
    shim_chain_free(zm.bsd_mbuf);
}

/* U7: write NULL data returns -1. */
static void
test_ff_zc_mbuf_write_null_data_returns_error(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 64), 0);
    assert_int_equal(mir_zc_mbuf_write(&zm, NULL, 4), -1);
    shim_chain_free(zm.bsd_mbuf);
}

/* U8: write len==0 is a no-op (pkthdr.len unchanged). */
static void
test_ff_zc_mbuf_write_zero_len_noop(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    assert_int_equal(mir_zc_mbuf_get(&zm, 64), 0);
    assert_int_equal(mir_zc_mbuf_write(&zm, "x", 0), 0);
    struct shim_mbuf *head = zm.bsd_mbuf;
    assert_int_equal(head->m_pkthdr.len, 0);
    shim_chain_free(head);
}

/* Multi-segment: a payload spanning >1 mbuf accumulates the full length on
 * the head and splits m_len across segments (INV-1). */
static void
test_ff_zc_mbuf_write_multi_segment(void **state)
{
    (void)state;
    struct zc_mbuf zm;
    int total = SHIM_SEG_CAP + 50;     /* spans 2 segments */
    char *buf = malloc(total);
    assert_non_null(buf);
    for (int i = 0; i < total; i++)
        buf[i] = (char)(i & 0x7f);

    assert_int_equal(mir_zc_mbuf_get(&zm, total), 0);
    assert_int_equal(mir_zc_mbuf_write(&zm, buf, total), total);

    struct shim_mbuf *head = zm.bsd_mbuf;
    assert_int_equal(head->m_pkthdr.len, total);
    /* head segment full, next holds the remainder */
    assert_int_equal(head->m_len, SHIM_SEG_CAP);
    assert_non_null(head->m_next);
    assert_int_equal(head->m_next->m_len, 50);

    shim_chain_free(head);
    free(buf);
}

/* U9: ff_zc_send with mb==NULL -> EINVAL before kernel call. */
static void
test_ff_zc_send_mb_null_returns_einval(void **state)
{
    (void)state;
    assert_int_equal(mir_zc_send_validate(NULL, 16), EINVAL);
}

/* U10: ff_zc_send with nbytes > INT_MAX -> EINVAL. */
static void
test_ff_zc_send_nbytes_overflow_returns_einval(void **state)
{
    (void)state;
    char dummy = 0;
    assert_int_equal(mir_zc_send_validate(&dummy, (size_t)INT_MAX + 1), EINVAL);
}

/* ff_zc_send with nbytes==0 -> EINVAL. */
static void
test_ff_zc_send_zero_nbytes_returns_einval(void **state)
{
    (void)state;
    char dummy = 0;
    assert_int_equal(mir_zc_send_validate(&dummy, 0), EINVAL);
}

/* ff_zc_send with valid args -> would proceed to kernel (returns 0). */
static void
test_ff_zc_send_valid_args_proceeds(void **state)
{
    (void)state;
    char dummy = 0;
    assert_int_equal(mir_zc_send_validate(&dummy, 16), 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ff_zc_mbuf_get_pkthdr_flag_set),
        cmocka_unit_test(test_ff_zc_mbuf_get_initial_pkthdr_len_zero),
        cmocka_unit_test(test_ff_zc_mbuf_get_negative_len_returns_error),
        cmocka_unit_test(test_ff_zc_mbuf_get_zero_len_returns_minimal_chain),
        cmocka_unit_test(test_ff_zc_mbuf_write_accumulates_pkthdr_len),
        cmocka_unit_test(test_ff_zc_mbuf_write_overflow_returns_error),
        cmocka_unit_test(test_ff_zc_mbuf_write_null_data_returns_error),
        cmocka_unit_test(test_ff_zc_mbuf_write_zero_len_noop),
        cmocka_unit_test(test_ff_zc_mbuf_write_multi_segment),
        cmocka_unit_test(test_ff_zc_send_mb_null_returns_einval),
        cmocka_unit_test(test_ff_zc_send_nbytes_overflow_returns_einval),
        cmocka_unit_test(test_ff_zc_send_zero_nbytes_returns_einval),
        cmocka_unit_test(test_ff_zc_send_valid_args_proceeds),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
