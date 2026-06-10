/*
 * F-Stack lib/ unit test: ff_dpdk_kni.c — FU-S4-KNI subset
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/plan-stage5-p3-followups.md §1 Phase 2
 * Coverage: 4 TC over ff_kni_enqueue (the only ff_kni_* API that is testable
 * without booting the whole KNI/EAL hotplug subsystem).
 *
 * Strategy:
 *   - The ratelimit branches in ff_kni_enqueue are pure global-counter
 *     manipulations driven by ff_global_cfg.kni and kni_rate_limt; we can
 *     drive them by setting limits and invoking the API.
 *   - However, every code path eventually calls rte_pktmbuf_free (inline,
 *     requires a real mempool) or rte_ring_enqueue (inline, requires a
 *     real rte_ring). To service those we initialise EAL with --no-huge
 *     and create a tiny mempool + ring at module setup. If EAL init fails
 *     (e.g. permissions), all 4 TC are marked skip().
 *   - kni_stat[port_id] is set to a non-NULL stub struct so the error-path
 *     `kni_stat[port_id]->rx_dropped++` does not segfault.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "ff_config.h"
#include "ff_dpdk_kni.h"

/* `struct kni_interface_stats` is defined privately inside ff_dpdk_kni.c
 * (not exported via the header). Mirror the layout here so we can read
 * kni_stat[0]->rx_dropped from tests. Layout MUST match ff_dpdk_kni.c L72. */
struct kni_interface_stats {
    uint16_t port_id;
    uint64_t rx_packets;
    uint64_t rx_dropped;
    uint64_t tx_packets;
    uint64_t tx_dropped;
};

/* Symbols defined in ff_dpdk_kni.o that we read/write from tests */
extern struct rte_ring **kni_rp;
extern struct kni_interface_stats **kni_stat;
extern struct kni_ratelimit kni_rate_limt;

/* ------------------------------------------------------------------------ */
/* Linker-satisfaction stubs for ff_global_cfg + ff_log + ff_dpdk_kni       */
/* dependencies that are NOT exercised here.                                */
/* ------------------------------------------------------------------------ */
struct ff_config ff_global_cfg;
int ff_log(uint32_t l, uint32_t t, const char *f, ...) { (void)l;(void)t;(void)f; return 0; }
__thread unsigned int per_lcore__lcore_id = 0;

/* nb_dev_ports defined in ff_dpdk_if.c (which we don't link here) */
int nb_dev_ports = 0;

/* ------------------------------------------------------------------------ */
/* Module-level EAL/mempool/ring (one-time init via rte_eal_init)            */
/* ------------------------------------------------------------------------ */
#define KNI_TEST_PORT_ID  0
#define KNI_TEST_RING_SZ  16
#define KNI_TEST_POOL_SZ  64
#define KNI_TEST_MBUF_SZ  256

static int                eal_initialized = 0;   /* 1 = OK ; 0 = init failed */
static struct rte_mempool *test_pool       = NULL;
static struct rte_ring    *test_ring       = NULL;
static struct kni_interface_stats stub_stat;

static int
group_setup(void **state)
{
    (void)state;

    /* rte_eal_init parses argv-style; --no-huge avoids hugepage requirement,
     * --no-pci skips PCI probe, --no-shconf disables shared config to allow
     * running multiple test binaries concurrently on the same host. */
    char *argv[] = {
        (char *)"test_ff_dpdk_kni",
        (char *)"--no-huge",
        (char *)"--no-pci",
        (char *)"--no-shconf",
        (char *)"-m", (char *)"32",
        (char *)"--file-prefix=ff_kni_test",
        NULL
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

    /* Suppress noisy DPDK init output */
    int rv = rte_eal_init(argc, argv);
    if (rv < 0) {
        eal_initialized = 0;
        printf("[INFO] rte_eal_init failed (rv=%d); 4 TCs will be skipped\n", rv);
        return 0;   /* still let CMocka run; per-TC skip() will trigger */
    }
    eal_initialized = 1;

    /* Pre-allocate mbuf pool + tiny ring + stub stats; allocate kni_rp[] and
     * kni_stat[] arrays (1 slot each for port 0). */
    test_pool = rte_pktmbuf_pool_create("kni_test_pool",
                                        KNI_TEST_POOL_SZ, 0, 0,
                                        KNI_TEST_MBUF_SZ,
                                        SOCKET_ID_ANY);
    if (!test_pool) {
        printf("[INFO] rte_pktmbuf_pool_create failed; TCs will be skipped\n");
        eal_initialized = 0;
        return 0;
    }

    test_ring = rte_ring_create("kni_test_ring", KNI_TEST_RING_SZ,
                                SOCKET_ID_ANY,
                                RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!test_ring) {
        printf("[INFO] rte_ring_create failed; TCs will be skipped\n");
        eal_initialized = 0;
        return 0;
    }

    /* Wire kni_rp[0] = test_ring + kni_stat[0] = &stub_stat */
    kni_rp = malloc(sizeof(*kni_rp) * 1);
    kni_stat = malloc(sizeof(*kni_stat) * 1);
    assert_non_null(kni_rp);
    assert_non_null(kni_stat);
    kni_rp[0] = test_ring;
    memset(&stub_stat, 0, sizeof(stub_stat));
    kni_stat[0] = &stub_stat;
    return 0;
}

static int
group_teardown(void **state)
{
    (void)state;
    /* leave EAL up; OS reclaims on process exit. just free our arrays */
    free(kni_rp);
    free(kni_stat);
    kni_rp = NULL; kni_stat = NULL;
    return 0;
}

static int
test_setup(void **state)
{
    (void)state;
    /* Reset rate-limit counters + ff_global_cfg.kni.* between TCs */
    kni_rate_limt.console_packets = 0;
    kni_rate_limt.gerneal_packets = 0;
    kni_rate_limt.kernel_packets  = 0;
    memset(&ff_global_cfg.kni, 0, sizeof(ff_global_cfg.kni));
    /* Drain ring to leave a clean slate */
    if (test_ring) {
        void *junk;
        while (rte_ring_dequeue(test_ring, &junk) == 0) { /* drain */ }
    }
    if (kni_stat && kni_stat[0]) {
        memset(kni_stat[0], 0, sizeof(*kni_stat[0]));
    }
    return 0;
}

#define SKIP_IF_NO_EAL()  do { \
    if (!eal_initialized) { skip(); return; } \
} while (0)

/* ------------------------------------------------------------------------ */
/* TC-U-P3-KNI-01: no rate limit -> enqueue path returns 0; ring contains   */
/* the mbuf.                                                                */
/* ------------------------------------------------------------------------ */
static void
test_ff_kni_enqueue_no_ratelimit(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    ff_global_cfg.kni.console_packets_ratelimit = 0;   /* disabled */
    ff_global_cfg.kni.general_packets_ratelimit = 0;

    struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m);
    int rv = ff_kni_enqueue(FILTER_ARP, KNI_TEST_PORT_ID, m);
    assert_int_equal(rv, 0);
    assert_int_equal((int)rte_ring_count(test_ring), 1);
    /* Counters should NOT have advanced because limit was 0 */
    assert_int_equal((int)kni_rate_limt.console_packets, 0);

    /* Pop and free to clean up */
    void *got = NULL;
    rte_ring_dequeue(test_ring, &got);
    if (got) {
        rte_pktmbuf_free((struct rte_mbuf *)got);
    }
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-KNI-02: console ratelimit triggers on (limit+1)-th call          */
/* ------------------------------------------------------------------------ */
static void
test_ff_kni_enqueue_console_ratelimit_over(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    ff_global_cfg.kni.console_packets_ratelimit = 2;   /* small limit */

    /* First two calls: counter 1, 2 -> NOT over (over means > 2) -> enqueued */
    for (int i = 0; i < 2; i++) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(test_pool);
        assert_non_null(m);
        int rv = ff_kni_enqueue(FILTER_ARP, KNI_TEST_PORT_ID, m);
        assert_int_equal(rv, 0);
    }
    assert_int_equal((int)kni_rate_limt.console_packets, 2);
    /* Third call: counter becomes 3, > 2 -> goto error -> -1 */
    struct rte_mbuf *m3 = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m3);
    int rv = ff_kni_enqueue(FILTER_ARP, KNI_TEST_PORT_ID, m3);
    assert_int_equal(rv, -1);
    assert_int_equal((int)kni_rate_limt.console_packets, 3);
    /* error path increments rx_dropped */
    assert_int_equal((int)kni_stat[0]->rx_dropped, 1);

    /* Drain ring to leave clean state for next test */
    void *got = NULL;
    while (rte_ring_dequeue(test_ring, &got) == 0) {
        if (got) rte_pktmbuf_free((struct rte_mbuf *)got);
    }
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-KNI-03: general ratelimit triggers on (limit+1)-th call          */
/* (filter < FILTER_ARP triggers the general branch)                        */
/* ------------------------------------------------------------------------ */
static void
test_ff_kni_enqueue_general_ratelimit_over(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    ff_global_cfg.kni.general_packets_ratelimit = 1;

    struct rte_mbuf *m1 = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m1);
    int rv = ff_kni_enqueue(FILTER_KNI, KNI_TEST_PORT_ID, m1);
    assert_int_equal(rv, 0);                  /* counter 1, not > 1 */
    assert_int_equal((int)kni_rate_limt.gerneal_packets, 1);

    struct rte_mbuf *m2 = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m2);
    rv = ff_kni_enqueue(FILTER_KNI, KNI_TEST_PORT_ID, m2);
    assert_int_equal(rv, -1);                 /* counter 2, > 1 -> error */
    assert_int_equal((int)kni_rate_limt.gerneal_packets, 2);

    /* Drain */
    void *got = NULL;
    while (rte_ring_dequeue(test_ring, &got) == 0) {
        if (got) rte_pktmbuf_free((struct rte_mbuf *)got);
    }
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-KNI-04: filter classification — FILTER_ARP / FILTER_KNI use      */
/* different rate-limit counters.                                           */
/* ------------------------------------------------------------------------ */
static void
test_ff_kni_enqueue_filter_classification(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    /* No rate limits -> no counter mutation */
    ff_global_cfg.kni.console_packets_ratelimit = 100;   /* > triggered */
    ff_global_cfg.kni.general_packets_ratelimit = 100;

    /* FILTER_ARP -> increments console_packets only */
    struct rte_mbuf *m1 = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m1);
    int rv = ff_kni_enqueue(FILTER_ARP, KNI_TEST_PORT_ID, m1);
    assert_int_equal(rv, 0);
    assert_int_equal((int)kni_rate_limt.console_packets, 1);
    assert_int_equal((int)kni_rate_limt.gerneal_packets, 0);

    /* FILTER_KNI -> increments gerneal_packets only */
    struct rte_mbuf *m2 = rte_pktmbuf_alloc(test_pool);
    assert_non_null(m2);
    rv = ff_kni_enqueue(FILTER_KNI, KNI_TEST_PORT_ID, m2);
    assert_int_equal(rv, 0);
    assert_int_equal((int)kni_rate_limt.console_packets, 1);    /* unchanged */
    assert_int_equal((int)kni_rate_limt.gerneal_packets, 1);

    void *got = NULL;
    while (rte_ring_dequeue(test_ring, &got) == 0) {
        if (got) rte_pktmbuf_free((struct rte_mbuf *)got);
    }
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_kni_enqueue_no_ratelimit,            test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_enqueue_console_ratelimit_over,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_enqueue_general_ratelimit_over,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_enqueue_filter_classification,   test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
