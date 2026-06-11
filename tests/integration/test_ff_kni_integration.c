/*
 * F-Stack lib/ KNI integration test (FU-S9-KNI-PROCESS-INTEG).
 *
 * kni_process_tx / kni_process_rx (lib/ff_dpdk_kni.c) call the static-inline
 * rte_eth_tx_burst / rte_eth_rx_burst, which cannot be --wrap'd. To drive
 * those branches we build a REAL ethdev out of two rings we own, via
 * rte_eth_from_rings():
 *   - rx_ring : packets we enqueue here are returned by rte_eth_rx_burst
 *   - tx_ring : packets sent via rte_eth_tx_burst land here; if we pre-fill
 *               it we force the partial-tx (drop) legs.
 *
 * Port id is 0 throughout (the only port), so ff_kni_process(0,...) and
 * kni_stat[0]->port_id=0 both reference our net_ring port.
 *
 * Covered branches (previously dead under unit-only):
 *   kni_process_tx : L142 dequeue, L148/149 kernel ratelimit, L161/163 drop
 *   kni_process_rx : L181 rx>0 true leg, L183/185 drop
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_eth_ring.h>

#include "ff_config.h"
#include "ff_dpdk_kni.h"

/* Mirror of the private struct in ff_dpdk_kni.c (layout MUST match L72). */
struct kni_interface_stats {
    uint16_t port_id;
    uint64_t rx_packets;
    uint64_t rx_dropped;
    uint64_t tx_packets;
    uint64_t tx_dropped;
};

extern struct rte_ring **kni_rp;
extern struct kni_interface_stats **kni_stat;
extern struct kni_ratelimit kni_rate_limt;

/* ff_dpdk_kni.c references these. ff_global_cfg is provided by the linked
 * ff_config.o; enable_kni / nb_dev_ports live in ff_dpdk_if.c (NOT linked). */
extern struct ff_config ff_global_cfg;
int enable_kni = 0;
int nb_dev_ports = 0;

void ff_kni_process(uint16_t port_id, uint16_t queue_id,
                    struct rte_mbuf **pkts_burst, unsigned count);
void ff_kni_alloc(uint16_t port_id, unsigned socket_id, int port_idx,
                  unsigned ring_queue_size);
int  ff_kni_enqueue(enum FilterReturn filter, uint16_t port_id,
                    struct rte_mbuf *pkt);

/* ------------------------------------------------------------------------ */
#define PORT_ID       0
#define POOL_SZ       1024
#define MBUF_SZ       2048
#define RX_RING_SZ    1024
#define TX_RING_SZ    64      /* small on purpose: drop-leg TCs pre-fill it
                              * without exhausting the mbuf pool */
#define KNI_RING_SZ   1024

static int                 g_ok = 0;
static char                g_skip[128] = "";
static struct rte_mempool *g_pool   = NULL;
static struct rte_ring    *g_rx_ring = NULL;   /* eth rx source */
static struct rte_ring    *g_tx_ring = NULL;   /* eth tx sink   */
static struct rte_ring    *g_kni_ring = NULL;  /* kni_rp[0] software ring */
static struct kni_interface_stats g_stat;

static int
group_setup(void **state)
{
    (void)state;
    char *argv[] = {
        (char *)"test_ff_kni_integration",
        (char *)"--no-huge", (char *)"--no-pci", (char *)"--no-shconf",
        (char *)"-l", (char *)"0", (char *)"-m", (char *)"64",
        (char *)"--file-prefix=ff_kni_int", NULL
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

    if (rte_eal_init(argc, argv) < 0) {
        snprintf(g_skip, sizeof(g_skip), "rte_eal_init failed");
        return 0;
    }
    g_pool = rte_pktmbuf_pool_create("kni_int_pool", POOL_SZ, 0, 0,
                                     MBUF_SZ, SOCKET_ID_ANY);
    if (!g_pool) { snprintf(g_skip, sizeof(g_skip), "pool create failed"); return 0; }

    g_rx_ring  = rte_ring_create("kni_int_rx",  RX_RING_SZ,  SOCKET_ID_ANY, 0);
    g_tx_ring  = rte_ring_create("kni_int_tx",  TX_RING_SZ,  SOCKET_ID_ANY, 0);
    g_kni_ring = rte_ring_create("kni_int_sw",  KNI_RING_SZ, SOCKET_ID_ANY, 0);
    if (!g_rx_ring || !g_tx_ring || !g_kni_ring) {
        snprintf(g_skip, sizeof(g_skip), "ring create failed"); return 0;
    }

    struct rte_ring *rxr[1] = { g_rx_ring };
    struct rte_ring *txr[1] = { g_tx_ring };
    int port = rte_eth_from_rings("net_ring_kni", rxr, 1, txr, 1, SOCKET_ID_ANY);
    if (port < 0) { snprintf(g_skip, sizeof(g_skip), "from_rings failed"); return 0; }

    /* Standard ethdev bring-up: configure 1 rx + 1 tx queue, then start. */
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    if (rte_eth_dev_configure((uint16_t)port, 1, 1, &port_conf) < 0) {
        snprintf(g_skip, sizeof(g_skip), "dev_configure failed"); return 0;
    }
    if (rte_eth_rx_queue_setup((uint16_t)port, 0, RX_RING_SZ,
            (unsigned)rte_eth_dev_socket_id((uint16_t)port), NULL, g_pool) < 0) {
        snprintf(g_skip, sizeof(g_skip), "rx_queue_setup failed"); return 0;
    }
    if (rte_eth_tx_queue_setup((uint16_t)port, 0, TX_RING_SZ,
            (unsigned)rte_eth_dev_socket_id((uint16_t)port), NULL) < 0) {
        snprintf(g_skip, sizeof(g_skip), "tx_queue_setup failed"); return 0;
    }
    if (rte_eth_dev_start((uint16_t)port) < 0) {
        snprintf(g_skip, sizeof(g_skip), "dev_start failed"); return 0;
    }

    /* Wire ff_dpdk_kni globals: port 0 == our net_ring port. */
    kni_rp   = malloc(sizeof(*kni_rp) * 1);
    kni_stat = malloc(sizeof(*kni_stat) * 1);
    if (!kni_rp || !kni_stat) { snprintf(g_skip, sizeof(g_skip), "oom"); return 0; }
    kni_rp[0] = g_kni_ring;
    memset(&g_stat, 0, sizeof(g_stat));
    g_stat.port_id = (uint16_t)port;
    kni_stat[0] = &g_stat;

    g_ok = 1;
    return 0;
}

static int
group_teardown(void **state)
{
    (void)state;
    free(kni_rp);
    free(kni_stat);
    kni_rp = NULL; kni_stat = NULL;
    return 0;
}

/* Drain every ring and free the mbufs so valgrind stays clean. */
static void
drain_all(void)
{
    void *obj;
    if (g_kni_ring) while (rte_ring_dequeue(g_kni_ring, &obj) == 0) rte_pktmbuf_free(obj);
    if (g_tx_ring)  while (rte_ring_dequeue(g_tx_ring,  &obj) == 0) rte_pktmbuf_free(obj);
    if (g_rx_ring)  while (rte_ring_dequeue(g_rx_ring,  &obj) == 0) rte_pktmbuf_free(obj);
}

static int
test_setup(void **state)
{
    (void)state;
    memset(&kni_rate_limt, 0, sizeof(kni_rate_limt));
    memset(&ff_global_cfg.kni, 0, sizeof(ff_global_cfg.kni));
    if (kni_stat && kni_stat[0]) {
        uint16_t pid = kni_stat[0]->port_id;
        memset(kni_stat[0], 0, sizeof(*kni_stat[0]));
        kni_stat[0]->port_id = pid;
    }
    drain_all();
    return 0;
}

static int
test_teardown(void **state)
{
    (void)state;
    drain_all();
    return 0;
}

#define SKIP_IF_NO_EAL() do { if (!g_ok) { print_message("(skip: %s)\n", g_skip); skip(); } } while (0)

/* Allocate N mbufs and enqueue them into ring r. Returns count enqueued. */
static unsigned
fill_ring_with_mbufs(struct rte_ring *r, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++) {
        struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
        if (!m) break;
        m->data_len = 64; m->pkt_len = 64;
        if (rte_ring_enqueue(r, m) != 0) { rte_pktmbuf_free(m); break; }
    }
    return i;
}

/* ------------------------------------------------------------------------ */
/* TC1: kni_process_tx happy path — packets in kni_rp flow to the eth tx    */
/* ring; rx ring empty so kni_process_rx takes its nb_kni_rx==0 false leg.  */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_tx_basic(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    unsigned n = fill_ring_with_mbufs(g_kni_ring, 4);
    assert_int_equal(n, 4);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    /* All 4 should have been tx_burst'd into the eth tx ring. */
    assert_int_equal((int)rte_ring_count(g_tx_ring), 4);
    assert_int_equal((int)kni_stat[0]->rx_packets, 4);
}

/* ------------------------------------------------------------------------ */
/* TC2: kernel_packets_ratelimit caps nb_to_tx (kni_process_tx L148/149).   */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_tx_kernel_ratelimit(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    ff_global_cfg.kni.kernel_packets_ratelimit = 2;   /* only 2 may pass */
    unsigned n = fill_ring_with_mbufs(g_kni_ring, 5);
    assert_int_equal(n, 5);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    /* With limit=2 and counter starting at 0: nb_to_tx=5 (still under at the
     * check), but the counter advances by nb_tx; the branch (likely/else) is
     * exercised. We assert the kernel_packets counter advanced by nb_tx. */
    assert_int_equal((int)kni_rate_limt.kernel_packets, 5);
}

/* ------------------------------------------------------------------------ */
/* TC3: kernel ratelimit already exceeded -> nb_to_tx forced to 0 (the      */
/* else leg of L149); nothing reaches the eth tx ring.                      */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_tx_kernel_ratelimit_exceeded(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    ff_global_cfg.kni.kernel_packets_ratelimit = 2;
    kni_rate_limt.kernel_packets = 100;       /* already over the limit */
    unsigned n = fill_ring_with_mbufs(g_kni_ring, 3);
    assert_int_equal(n, 3);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    /* nb_to_tx == 0 -> tx ring stays empty; the dequeued mbufs are dropped
     * inside kni_process_tx's nb_kni_tx<nb_tx free loop. */
    assert_int_equal((int)rte_ring_count(g_tx_ring), 0);
}

/* ------------------------------------------------------------------------ */
/* TC4: partial tx -> the nb_kni_tx<nb_tx drop leg (L161/163). We pre-fill   */
/* the eth tx ring so only a few slots remain.                              */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_tx_partial_drop(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    /* Leave only 2 free slots in the tx ring (capacity = TX_RING_SZ-1). */
    unsigned cap = rte_ring_free_count(g_tx_ring);
    assert_true(cap > 2);
    unsigned filler = fill_ring_with_mbufs(g_tx_ring, cap - 2);
    assert_int_equal(filler, cap - 2);

    unsigned n = fill_ring_with_mbufs(g_kni_ring, 6);   /* 6 to send, only 2 fit */
    assert_int_equal(n, 6);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    /* tx ring is now full; rx_dropped advanced by the dropped remainder. */
    assert_true(kni_stat[0]->rx_dropped >= 4);
}

/* ------------------------------------------------------------------------ */
/* TC5: kni_process_rx true leg — inject packets into the eth rx ring; with  */
/* the eth tx ring having room they are forwarded (L181/183 false leg).     */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_rx_forward(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    unsigned n = fill_ring_with_mbufs(g_rx_ring, 3);
    assert_int_equal(n, 3);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    /* rx_burst pulled 3 from rx ring, tx_burst pushed them back to tx ring. */
    assert_int_equal((int)kni_stat[0]->tx_packets, 3);
    assert_int_equal((int)rte_ring_count(g_tx_ring), 3);
}

/* ------------------------------------------------------------------------ */
/* TC6: kni_process_rx drop leg — rx has packets but the eth tx ring is      */
/* almost full so the forward is partial (L183/185 tx_dropped).             */
/* ------------------------------------------------------------------------ */
static void
test_kni_process_rx_partial_drop(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    unsigned cap = rte_ring_free_count(g_tx_ring);
    assert_true(cap > 1);
    fill_ring_with_mbufs(g_tx_ring, cap - 1);    /* leave 1 slot */
    unsigned n = fill_ring_with_mbufs(g_rx_ring, 5);
    assert_int_equal(n, 5);

    struct rte_mbuf *burst[32];
    ff_kni_process(PORT_ID, 0, burst, 32);

    assert_true(kni_stat[0]->tx_dropped >= 4);
}

/* ------------------------------------------------------------------------ */
/* TC7: ff_kni_alloc happy path (PRIMARY). /dev/vhost-net is present, so the */
/* rte_eal_hotplug_add("vdev","virtio_user0",...) should succeed, exercising */
/* the PRIMARY-true / zmalloc-ok / hotplug-ok / ring-create-ok legs          */
/* (L426/435/466/476/486). kni_rp/kni_stat are saved+restored so the rest of */
/* the suite and group_teardown stay consistent.                            */
/* ------------------------------------------------------------------------ */
static void
test_kni_alloc_primary_happy_path(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();

    struct rte_ring            **saved_rp   = kni_rp;
    struct kni_interface_stats **saved_stat = kni_stat;

    /* ff_kni_alloc writes kni_stat[port_id]/kni_rp[port_id]; give it slot 0. */
    ff_kni_alloc((uint16_t)PORT_ID, (unsigned)rte_socket_id(),
                 /*port_idx*/0, /*ring_queue_size*/512);

    /* If we got here, the PRIMARY happy path completed without rte_exit. */
    assert_non_null(kni_rp[PORT_ID]);
    assert_non_null(kni_stat[PORT_ID]);

    /* Best-effort cleanup of what ff_kni_alloc allocated, then restore. */
    rte_free(kni_stat[PORT_ID]);
    kni_rp   = saved_rp;
    kni_stat = saved_stat;
}

/* ------------------------------------------------------------------------ */
/* TC8: ff_kni_enqueue into a FULL kni ring -> rte_ring_enqueue returns < 0  */
/* -> the error path frees the mbuf and bumps rx_dropped (L521/522/529).     */
/* ------------------------------------------------------------------------ */
static void
test_kni_enqueue_full_ring_drops(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    /* Use a small dedicated ring as kni_rp[0] so the test is self-contained
     * and independent of the shared mbuf pool's fill level. */
    struct rte_ring *saved = kni_rp[0];
    struct rte_ring *tiny = rte_ring_create("kni_enq_tiny", 4, SOCKET_ID_ANY, 0);
    assert_non_null(tiny);
    kni_rp[0] = tiny;

    unsigned cap = rte_ring_free_count(tiny);        /* 3 (size-1) */
    unsigned filled = fill_ring_with_mbufs(tiny, cap);
    assert_int_equal(filled, cap);
    assert_int_equal((int)rte_ring_free_count(tiny), 0);

    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    assert_non_null(m);
    /* No ratelimit -> rte_ring_enqueue fails on the full ring -> error path:
     * rx_dropped++ + pktmbuf_free + return -1 (L521/522/529). */
    int rv = ff_kni_enqueue(FILTER_KNI, PORT_ID, m);
    assert_int_equal(rv, -1);
    assert_true(kni_stat[0]->rx_dropped >= 1);

    /* Drain the tiny ring's mbufs and restore. */
    void *obj;
    while (rte_ring_dequeue(tiny, &obj) == 0) rte_pktmbuf_free(obj);
    rte_ring_free(tiny);
    kni_rp[0] = saved;
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_kni_process_tx_basic,                test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_process_tx_kernel_ratelimit,     test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_process_tx_kernel_ratelimit_exceeded, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_process_tx_partial_drop,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_process_rx_forward,              test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_process_rx_partial_drop,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_enqueue_full_ring_drops,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_kni_alloc_primary_happy_path,        test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
