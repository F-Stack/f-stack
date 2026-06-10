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

/* FU-S7-KNI-ENABLE: with -DFF_KNI compiled into ff_dpdk_kni.o, the lib
 * references `extern int enable_kni;` (defined in ff_dpdk_if.c which we
 * do NOT link). Provide the stub here; tests that need the
 * (!enable_kni) false-leg flip it to 1 around the call. */
int enable_kni = 0;

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

/* ======================================================================== */
/* Stage-6 Phase-4 coverage extensions: ff_kni_proto_filter + ff_kni_init   */
/* ======================================================================== */

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_ether.h>
#include <netinet/in.h>           /* IPPROTO_TCP / IPPROTO_UDP / IPPROTO_IPIP */

/* TC-U-P3-KNI-05: ff_kni_proto_filter on too-short IPv4 -> FILTER_UNKNOWN */
static void
test_ff_kni_proto_filter_ipv4_short(void **state)
{
    (void)state;
    uint8_t too_short[10] = {0};
    enum FilterReturn rv = ff_kni_proto_filter(too_short, 10, RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-06: ff_kni_proto_filter on non-IP frame -> FILTER_UNKNOWN */
static void
test_ff_kni_proto_filter_non_ip_frame(void **state)
{
    (void)state;
    uint8_t arp_payload[28] = {0};
    enum FilterReturn rv = ff_kni_proto_filter(arp_payload, sizeof(arp_payload),
                                               RTE_ETHER_TYPE_ARP);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-07: IPv4+TCP without enable_kni -> FILTER_UNKNOWN (break path) */
static void
test_ff_kni_proto_filter_ipv4_tcp_kni_disabled(void **state)
{
    (void)state;
    uint8_t pkt[64] = {0};
    pkt[0] = 0x45;                    /* version=4, IHL=5 */
    pkt[9] = IPPROTO_TCP;             /* next_proto_id */
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt), RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-08: IPv4+UDP without enable_kni -> FILTER_UNKNOWN */
static void
test_ff_kni_proto_filter_ipv4_udp_kni_disabled(void **state)
{
    (void)state;
    uint8_t pkt[64] = {0};
    pkt[0] = 0x45;
    pkt[9] = IPPROTO_UDP;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt), RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-09: IPv4 IHL beyond buffer -> FILTER_UNKNOWN */
static void
test_ff_kni_proto_filter_ipv4_oversized_ihl(void **state)
{
    (void)state;
    uint8_t pkt[24] = {0};
    pkt[0] = 0x4F;                    /* IHL = 15 -> 60 bytes > len */
    pkt[9] = IPPROTO_TCP;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt), RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-10: IPIP (IPv4-in-IPv4) recursion with too-short inner */
static void
test_ff_kni_proto_filter_ipv4_ipip_recurse(void **state)
{
    (void)state;
    uint8_t pkt[24] = {0};            /* outer 20 + only 4 inner */
    pkt[0] = 0x45;
    pkt[9] = IPPROTO_IPIP;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt), RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-U-P3-KNI-11: ff_kni_init builds bitmaps from "80,443,8000-8002" / "53" */
static void
test_ff_kni_init_tcp_udp_port_bitmaps(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();
    /* ff_kni_init re-allocates kni_rp/kni_stat via rte_zmalloc; group_setup
     * had used plain calloc(). Save the original pointers, run ff_kni_init,
     * then restore so group_teardown can free() the calloc'd arrays. */
    struct rte_ring **saved_kni_rp   = kni_rp;
    struct kni_interface_stats **saved_kni_stat = kni_stat;
    /* Range form (8000-8002) + comma list exercises both kni_set_bitmap
     * branches. nb_ports=1 keeps the alloc small. */
    ff_kni_init(/*nb_ports*/1, /*tcp*/"80,443,8000-8002", /*udp*/"53,5060");
    /* Free the rte_zmalloc'd arrays we just produced (best effort) and
     * restore the originals so group_teardown's free() is happy. */
    rte_free(kni_rp);
    rte_free(kni_stat);
    kni_rp   = saved_kni_rp;
    kni_stat = saved_kni_stat;
}

/* ======================================================================== */
/* Stage-7 follow-up FU-S7-KNI-ENABLE: branches gated by -DFF_KNI            */
/* ======================================================================== */

#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP 89
#endif

/* Helper: build a minimal IPv4 packet starting with version+IHL byte; the
 * caller patches proto and (optionally) appends an L4 header. The
 * packet's IPv4 header length is exactly 20 bytes (IHL=5). */
static void
ff_test_build_ipv4(uint8_t *buf, size_t buf_len, uint8_t proto)
{
    memset(buf, 0, buf_len);
    buf[0] = 0x45;       /* version=4 IHL=5 */
    buf[9] = proto;      /* next-proto */
}

/* TC-S7-KNI-12: IPv4+OSPF (proto=89) -> FILTER_OSPF. Covers the FF_KNI-
 * gated `case IPPROTO_OSPFIGP: return FILTER_OSPF;` branch (L335-338). */
static void
test_ff_kni_proto_filter_ipv4_ospf_returns_ospf(void **state)
{
    (void)state;
    uint8_t pkt[64];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_OSPFIGP);
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    assert_int_equal(rv, FILTER_OSPF);
}

/* TC-S7-KNI-13: IPv4+TCP with enable_kni=1 and a too-short L4 fragment
 * after the IP header -> FILTER_UNKNOWN via protocol_filter_tcp's
 * `len < sizeof(rte_tcp_hdr)` true leg (L209 br=0).                  */
static void
test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_short(void **state)
{
    (void)state;
    /* IP hdr 20 + 5 bytes TCP fragment (< sizeof(rte_tcp_hdr)=20). */
    uint8_t pkt[25];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_TCP);

    int saved = enable_kni; enable_kni = 1;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    enable_kni = saved;
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-S7-KNI-14: IPv4+UDP with enable_kni=1 and a too-short L4 fragment
 * -> FILTER_UNKNOWN via protocol_filter_udp's len<hdr true leg (L221). */
static void
test_ff_kni_proto_filter_ipv4_udp_kni_enabled_short(void **state)
{
    (void)state;
    /* IP hdr 20 + 5 bytes UDP fragment (< sizeof(rte_udp_hdr)=8). */
    uint8_t pkt[25];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_UDP);

    int saved = enable_kni; enable_kni = 1;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    enable_kni = saved;
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-S7-KNI-15: enable_kni=1, ff_kni_init had registered TCP port 80 in
 * the bitmap, packet has dst_port=80 (network order) -> FILTER_KNI.
 * Covers protocol_filter_l4's true leg (L199) AND the `if (!enable_kni)`
 * false leg in the IPPROTO_TCP case (L342).                            */
static void
test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_match_returns_kni(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();

    /* (Re)build the port bitmaps under our control. Save+restore the
     * caller-managed kni_rp/kni_stat as the existing TC-U-P3-KNI-11 does. */
    struct rte_ring **saved_kni_rp   = kni_rp;
    struct kni_interface_stats **saved_kni_stat = kni_stat;
    ff_kni_init(/*nb_ports*/1, /*tcp*/"80", /*udp*/"53");
    rte_free(kni_rp);
    rte_free(kni_stat);
    kni_rp   = saved_kni_rp;
    kni_stat = saved_kni_stat;

    /* IPv4(20) + TCP(20). dst_port lives at IP hdr offset 20 + TCP byte 2..3. */
    uint8_t pkt[40];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_TCP);
    /* dst_port=80 in network byte order. set_bitmap stores the htons-ed
     * port; get_bitmap is called with hdr->dst_port (already big-endian),
     * so writing 0x00,0x50 directly produces the same bit index. */
    pkt[20 + 2] = 0x00;
    pkt[20 + 3] = 0x50;

    int saved = enable_kni; enable_kni = 1;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    enable_kni = saved;
    assert_int_equal(rv, FILTER_KNI);
}

/* TC-S7-KNI-16: enable_kni=1, packet has dst_port=8080 NOT in the bitmap
 * -> FILTER_UNKNOWN (protocol_filter_l4 false leg, L199 br=0).         */
static void
test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_miss_returns_unknown(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();

    struct rte_ring **saved_kni_rp   = kni_rp;
    struct kni_interface_stats **saved_kni_stat = kni_stat;
    ff_kni_init(1, "80", "53");
    rte_free(kni_rp);
    rte_free(kni_stat);
    kni_rp   = saved_kni_rp;
    kni_stat = saved_kni_stat;

    uint8_t pkt[40];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_TCP);
    /* dst_port=8080=0x1F90 in network order. */
    pkt[20 + 2] = 0x1F;
    pkt[20 + 3] = 0x90;

    int saved = enable_kni; enable_kni = 1;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    enable_kni = saved;
    assert_int_equal(rv, FILTER_UNKNOWN);
}

/* TC-S7-KNI-17: enable_kni=1 + UDP dst_port=53 matches bitmap -> FILTER_KNI.
 * Covers `if (!enable_kni)` false leg in IPPROTO_UDP case (L350).         */
static void
test_ff_kni_proto_filter_ipv4_udp_kni_enabled_match_returns_kni(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();

    struct rte_ring **saved_kni_rp   = kni_rp;
    struct kni_interface_stats **saved_kni_stat = kni_stat;
    ff_kni_init(1, "80", "53");
    rte_free(kni_rp);
    rte_free(kni_stat);
    kni_rp   = saved_kni_rp;
    kni_stat = saved_kni_stat;

    /* IPv4(20) + UDP(8). dst_port=53 (0x0035) at IP+2..3. */
    uint8_t pkt[28];
    ff_test_build_ipv4(pkt, sizeof(pkt), IPPROTO_UDP);
    pkt[20 + 2] = 0x00;
    pkt[20 + 3] = 0x35;

    int saved = enable_kni; enable_kni = 1;
    enum FilterReturn rv = ff_kni_proto_filter(pkt, sizeof(pkt),
                                               RTE_ETHER_TYPE_IPV4);
    enable_kni = saved;
    assert_int_equal(rv, FILTER_KNI);
}

/* TC-S7-KNI-18: ff_kni_init with NULL tcp_ports / udp_ports exercises
 * kni_set_bitmap's L114 `if(!p) return;` early-return branch.          */
static void
test_ff_kni_init_null_port_lists(void **state)
{
    (void)state;
    SKIP_IF_NO_EAL();

    struct rte_ring **saved_kni_rp   = kni_rp;
    struct kni_interface_stats **saved_kni_stat = kni_stat;
    /* Both args NULL — kni_set_bitmap is invoked twice and returns
     * immediately on the !p check. Init must still succeed. */
    ff_kni_init(/*nb_ports*/1, /*tcp*/NULL, /*udp*/NULL);
    rte_free(kni_rp);
    rte_free(kni_stat);
    kni_rp   = saved_kni_rp;
    kni_stat = saved_kni_stat;
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
        /* Stage-6 Phase-4 coverage extensions */
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_short,         test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_non_ip_frame,       test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_tcp_kni_disabled, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_udp_kni_disabled, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_oversized_ihl, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_ipip_recurse,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_init_tcp_udp_port_bitmaps,       test_setup, NULL),
        /* Stage-7 follow-up FU-S7-KNI-ENABLE: branches gated by -DFF_KNI */
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_ospf_returns_ospf,                    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_short,                test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_udp_kni_enabled_short,                test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_match_returns_kni,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_tcp_kni_enabled_miss_returns_unknown, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_proto_filter_ipv4_udp_kni_enabled_match_returns_kni,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_kni_init_null_port_lists,                                   test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
