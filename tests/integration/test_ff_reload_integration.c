/*
 * F-Stack graceful-reload integration tests (IT-NR-A09 / IT-NR-A10 per
 * docs/nginx_reload_spec/zh_cn/08-testing.md v1.3+, C-NR-309/310/301/303).
 *
 * Boots a real DPDK EAL (--no-huge --no-pci --no-shconf --vdev=net_null0,
 * dedicated --file-prefix) with graceful_reload=1 and a test-owned
 * struct ff_reload_state attached BEFORE ff_dpdk_init(), so drain rings,
 * per-generation msg rings and the self-driven hardclock path all come up
 * for real inside one primary process.
 *
 * IT-NR-A09 (TX exclusivity, RV11): the process plays G_old (gen 0) pushed
 * into no-hardware mode via rx_owner_gen, then drives every public tx entry
 * point — ff_dpdk_if_send, ff_dpdk_raw_packet_send, dispatcher
 * FF_DISPATCH_RESPONSE staging (send_burst defensive short-circuit), and a
 * parked main_loop pass diverting pre-staged packets — asserting
 * rte_eth_tx_burst is NEVER invoked for the dpdk data ports, and that the
 * packets leave through drain_ring_tx when the owner side drains it.
 *
 * IT-NR-A10 (half-open connection window, framework): the complete RV12
 * criteria need M4 C-NR-312 plus a real FreeBSD syncache and a second
 * process (RT-02/RT-15 own the two-process timing). What this harness pins
 * is the dispatch-side mechanism both directions depend on: flow-map hit =>
 * handled locally (including the syncache stage, before accept()), miss =>
 * forwarded to the draining generation's drain_rx ring.
 *
 * tx counting: rte_eth_tx_burst() is static inline in this DPDK and
 * dispatches through the exported rte_eth_fp_ops[] fast-path table, so the
 * test swaps the tx_pkt_burst pointer of the dpdk data ports with a
 * counting shim — every invocation from any TU in the process is counted.
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
#include <rte_ethdev_core.h> /* struct rte_eth_fp_ops (fast-path table) */
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "ff_config.h"        /* MAX_PKT_BURST, ff_global_cfg, ff_port_cfg */
#include "ff_msg.h"           /* struct ff_traffic_args */
#include "ff_memory.h"        /* struct lcore_conf */
#include "ff_dpdk_if.h"       /* ff_dpdk_* API (includes ff_api.h) */
#include "ff_reload.h"
#include "ff_drain_ring.h"

/* ------------------------------------------------------------------------ */
/* tx_burst counting (RV11).                                                */
/*                                                                          */
/* rte_eth_tx_burst() is a static inline in this DPDK (dispatches through   */
/* the exported rte_eth_fp_ops[] fast-path table), so there is no symbol    */
/* to --wrap. Instead, swap the tx_pkt_burst pointer of every dpdk data     */
/* port with a counting shim: every inline invocation from any translation  */
/* unit in this process then passes through the shim — a stronger           */
/* guarantee than a link-time wrap, and per-port by construction.           */
/* Only ports listed in dpdk.portid_list are asserted against — a KNI vdev  */
/* port must never count as a data-port violation.                          */
/* ------------------------------------------------------------------------ */
typedef uint16_t (*it_tx_burst_fn)(void *, struct rte_mbuf **, uint16_t);

#define IT_MAX_TX_HOOKS 8
struct it_tx_hook {
    uint16_t       port;
    void          *qd;      /* queue data pointer identifies (port,queue) */
    it_tx_burst_fn fn;
};

static struct it_tx_hook g_tx_hooks[IT_MAX_TX_HOOKS];
static int      g_nb_tx_hooks;
static uint64_t g_tx_calls[RTE_MAX_ETHPORTS];
static uint64_t g_tx_pkts[RTE_MAX_ETHPORTS];

/* portid_list snapshot for the counting helpers: the main_loop TC detaches
 * ff_global_cfg's hand-built arrays before ff_dpdk_run, so from that point
 * the frozen copy is the only valid view */
static uint16_t g_frozen_ports[RTE_MAX_ETHPORTS];
static int      g_frozen_nb_ports;

static void
freeze_port_list(void)
{
    int i;

    g_frozen_nb_ports = (int)ff_global_cfg.dpdk.nb_ports;
    for (i = 0; i < g_frozen_nb_ports && i < RTE_MAX_ETHPORTS; i++)
        g_frozen_ports[i] = ff_global_cfg.dpdk.portid_list[i];
}

static uint16_t
it_count_tx_burst(void *qd, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    uint16_t port = RTE_MAX_ETHPORTS;
    it_tx_burst_fn fn = NULL;
    int i;

    for (i = 0; i < g_nb_tx_hooks; i++) {
        if (g_tx_hooks[i].qd == qd) {
            port = g_tx_hooks[i].port;
            fn = g_tx_hooks[i].fn;
            break;
        }
    }
    if (fn == NULL) {
        /* queue data we never hooked: harness bug, fail loudly */
        assert_true(fn != NULL);
        return 0;
    }
    g_tx_calls[port]++;
    g_tx_pkts[port] += nb_pkts;
    return fn(qd, pkts, nb_pkts);
}

/* Install after ff_dpdk_init() (fp_ops are populated once the port started). */
static void
hook_tx_burst(void)
{
    struct lcore_conf *qconf = ff_cur_lcore_conf();
    int i;

    for (i = 0; i < (int)ff_global_cfg.dpdk.nb_ports &&
         g_nb_tx_hooks < IT_MAX_TX_HOOKS; i++) {
        uint16_t p = ff_global_cfg.dpdk.portid_list[i];
        uint16_t q = qconf->tx_queue_id[p];
        void *qd = rte_eth_fp_ops[p].txq.data[q];

        if (qd == NULL || rte_eth_fp_ops[p].tx_pkt_burst == NULL)
            continue;
        g_tx_hooks[g_nb_tx_hooks].port = p;
        g_tx_hooks[g_nb_tx_hooks].qd = qd;
        g_tx_hooks[g_nb_tx_hooks].fn = rte_eth_fp_ops[p].tx_pkt_burst;
        g_nb_tx_hooks++;
        rte_eth_fp_ops[p].tx_pkt_burst = it_count_tx_burst;
    }
}

static uint64_t
hw_tx_calls(void)
{
    uint64_t n = 0;
    int i;

    for (i = 0; i < g_frozen_nb_ports; i++) {
        uint16_t p = g_frozen_ports[i];
        if (p < RTE_MAX_ETHPORTS)
            n += g_tx_calls[p];
    }
    return n;
}

static uint64_t
hw_tx_pkts(void)
{
    uint64_t n = 0;
    int i;

    for (i = 0; i < g_frozen_nb_ports; i++) {
        uint16_t p = g_frozen_ports[i];
        if (p < RTE_MAX_ETHPORTS)
            n += g_tx_pkts[p];
    }
    return n;
}

/* ------------------------------------------------------------------------ */
/* bridge stubs for ff_dpdk_if.c's non-DPDK externals (same set as           */
/* test_ff_dpdk_if_integration.c; the harness links no FreeBSD adapter).     */
/* ------------------------------------------------------------------------ */
static struct ff_tx_offload g_test_offload;
static int            g_copydata_fail = 0;
static unsigned char  g_test_pkt[128];

static void
ff_test_reset_send_ctl(void)
{
    memset(&g_test_offload, 0, sizeof(g_test_offload));
    g_copydata_fail = 0;
    memset(g_test_pkt, 0, sizeof(g_test_pkt));
    g_test_pkt[14] = 0x45;   /* IPv4, IHL 5 */
    g_test_pkt[46] = 0x50;   /* TCP data offset 5 */
}

static int
ff_test_copydata(void *d, int off, int len)
{
    if (g_copydata_fail) return -1;
    int avail = (int)sizeof(g_test_pkt) - off;
    if (avail <= 0) { memset(d, 0, (size_t)len); return 0; }
    int n = len < avail ? len : avail;
    memcpy(d, g_test_pkt + off, (size_t)n);
    if (n < len) memset((char *)d + n, 0, (size_t)(len - n));
    return 0;
}

static void
ff_test_fill_offload(void *o)
{
    memcpy(o, &g_test_offload, sizeof(g_test_offload));
}

void *ff_mbuf_gethdr(void *p, uint16_t l, void *d, uint16_t dl, uint8_t r)
{ (void)p;(void)l;(void)d;(void)dl;(void)r; return NULL; }
int   ff_mbuf_set_vlan_info(void *m, uint16_t v) { (void)m;(void)v; return 0; }
int   ff_mbuf_set_timestamp(void *m, uint64_t t) { (void)m;(void)t; return 0; }
void *ff_mbuf_get(void *p, void *m, void *d, uint16_t dl)
{ (void)p;(void)m;(void)d;(void)dl; return NULL; }
void  ff_mbuf_free(void *m) { (void)m; }
int   ff_mbuf_copydata(void *m, void *d, int o, int l)
{ (void)m; return ff_test_copydata(d, o, l); }
int   ff_mbuf_tx_offload(void *m, void *o, void *l)
{ (void)m;(void)l; ff_test_fill_offload(o); return 0; }

static unsigned char g_veth_ctx_buf[512];
void *ff_veth_attach(void *cfg) { (void)cfg; memset(g_veth_ctx_buf, 0, sizeof(g_veth_ctx_buf)); return g_veth_ctx_buf; }
void  ff_veth_process_packet(void *ifp, void *m) { (void)ifp;(void)m; }
void *ff_veth_get_softc(uint16_t portid) { (void)portid; return NULL; }
void  ff_veth_free_softc(void *sc) { (void)sc; }
void *ff_veth_softc_to_hostc(void *sc) { (void)sc; return NULL; }

int   ff_sysctl(const int *n, unsigned nl, void *o, size_t *ol, const void *i, size_t il)
{ (void)n;(void)nl;(void)o;(void)ol;(void)i;(void)il; return 0; }
int   ff_socket(int d, int t, int p) { (void)d;(void)t;(void)p; return -1; }
int   ff_ioctl_freebsd(int f, unsigned long r, ...) { (void)f;(void)r; return -1; }
int   ff_close(int f) { (void)f; return 0; }
int   ff_rtioctl(int f, void *d, unsigned int *l, unsigned int al)
{ (void)f;(void)d;(void)l;(void)al; return -1; }
void  ff_hardclock(void) { }
void  rte_timer_meta_init(void) { }

int   ff_dump_packets(const char *p, struct rte_mbuf *m, uint16_t s, uint32_t l, uint8_t t)
{ (void)p;(void)m;(void)s;(void)l;(void)t; return 0; }
int   ff_enable_pcap(const char *p, uint16_t s, uint8_t t)
{ (void)p;(void)s;(void)t; return 0; }

/* Globals defined in ff_dpdk_if.c that we inspect. */
extern uint16_t nb_dev_ports;

/* ------------------------------------------------------------------------ */
/* group state                                                               */
/* ------------------------------------------------------------------------ */
static int    g_init_ok = 0;
static char   g_init_skip_reason[128] = "";

static struct ff_reload_state g_st;
static struct rte_mempool *g_inj_pool;             /* test-owned rx-inject pool */
static struct ff_dpdk_if_context *g_ctx;           /* registered once for all TCs */

#define IT_PORT_ID  0
#define IT_LCORE_ID 0

static void
populate_graceful_cfg(void)
{
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));

    ff_global_cfg.dpdk.nb_procs   = 1;
    ff_global_cfg.dpdk.proc_id    = 0;
    ff_global_cfg.dpdk.proc_lcore = calloc(1, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.proc_lcore)
        ff_global_cfg.dpdk.proc_lcore[0] = IT_LCORE_ID;

    ff_global_cfg.dpdk.nb_ports    = 1;
    ff_global_cfg.dpdk.max_portid  = IT_PORT_ID;
    ff_global_cfg.dpdk.portid_list = calloc(1, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.portid_list)
        ff_global_cfg.dpdk.portid_list[0] = IT_PORT_ID;

    ff_global_cfg.dpdk.port_cfgs =
        calloc(1, sizeof(struct ff_port_cfg));
    if (ff_global_cfg.dpdk.port_cfgs) {
        ff_global_cfg.dpdk.port_cfgs[IT_PORT_ID].port_id = IT_PORT_ID;
        ff_global_cfg.dpdk.port_cfgs[IT_PORT_ID].nb_lcores = 1;
        ff_global_cfg.dpdk.port_cfgs[IT_PORT_ID].lcore_list[0] = IT_LCORE_ID;
    }

    /* the feature under test */
    ff_global_cfg.dpdk.graceful_reload = 1;
    ff_global_cfg.dpdk.drain_ring_size = 256;      /* power of two */

    ff_global_cfg.dpdk.numa_on = 0;
    ff_global_cfg.dpdk.idle_sleep = 0;
    ff_global_cfg.dpdk.pkt_tx_delay = 0;
    ff_global_cfg.dpdk.tso = 0;
    ff_global_cfg.dpdk.tx_csum_offoad_skip = 0;
    ff_global_cfg.dpdk.vlan_strip = 0;
    ff_global_cfg.dpdk.nb_vlan_filter = 0;
    ff_global_cfg.dpdk.symmetric_rss = 0;
    ff_global_cfg.dpdk.promiscuous = 0;
    ff_global_cfg.kni.enable = 0;
    ff_global_cfg.log.level = 0;
    ff_global_cfg.freebsd.hz = 100;
}

static int
group_setup(void **state)
{
    (void)state;

    populate_graceful_cfg();

    /* Reload window open, this process is generation 0. G_old-view TCs
     * flip rx_owner_gen to 1 (the peer "G_new" owns the hardware). */
    memset(&g_st, 0, sizeof(g_st));
    g_st.magic = FF_RELOAD_STATE_MAGIC;
    g_st.version = FF_RELOAD_STATE_VERSION;
    g_st.len = (uint32_t)sizeof(g_st);
    g_st.reload_active = 1;
    g_st.active_gen = 0;
    g_st.target_gen = 1;
    ff_reload_attach_state(&g_st);
    ff_reload_set_gen(0);

    char *argv[] = {
        (char *)"test_ff_reload_integration",
        (char *)"--no-huge",
        (char *)"--no-pci",
        (char *)"--no-shconf",
        (char *)"-l", (char *)"0",
        /* graceful mode builds gen0+gen1 app pools plus a shared RX pool
         * sized for 4096 rx descriptors — 64 MB is not enough for all of
         * them, so give the no-huge malloc heap real headroom */
        (char *)"-m", (char *)"512",
        (char *)"--vdev=net_null0",
        (char *)"--file-prefix=ff_reload_it",
        NULL
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

    int rv = ff_dpdk_init(argc, argv);
    if (rv != 0) {
        snprintf(g_init_skip_reason, sizeof(g_init_skip_reason),
                 "ff_dpdk_init returned %d", rv);
        g_init_ok = 0;
        printf("[INFO] %s; integration TCs will be skipped\n",
               g_init_skip_reason);
        return 0;
    }
    g_init_ok = 1;

    /* count every tx_burst leaving this process (see hook comment) */
    freeze_port_list();
    hook_tx_burst();

    g_inj_pool = rte_pktmbuf_pool_create("it_reload_inj", 512, 0, 0, 256,
        SOCKET_ID_ANY);
    return 0;
}

static int
group_teardown(void **state)
{
    (void)state;
    free(ff_global_cfg.dpdk.proc_lcore);
    free(ff_global_cfg.dpdk.portid_list);
    free(ff_global_cfg.dpdk.port_cfgs);
    return 0;
}

#define SKIP_IF_NO_INIT()  do { \
    if (!g_init_ok) { print_message("(skipped: %s)\n", g_init_skip_reason); skip(); } \
} while (0)

/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */
static struct ff_traffic_args
traffic_get(void)
{
    struct ff_traffic_args t;
    ff_get_traffic(&t);
    return t;
}

/* Play G_new for a moment: switch to the peer generation, drain G_old's
 * drain_tx ring straight to the hardware, switch back. Single-process
 * harness substitute for the owner's main_loop consumer (the real
 * cross-process pair is RT-02/RT-03). */
static unsigned
peer_drain_tx_all(void)
{
    struct rte_mbuf *b[MAX_PKT_BURST];
    unsigned total = 0, n;

    do {
        ff_reload_set_gen(1);
        n = ff_drain_ring_tx_drain(IT_PORT_ID, 0, b, MAX_PKT_BURST);
        ff_reload_set_gen(0);
        total += n;
    } while (n > 0);
    return total;
}

/* Ethernet + IPv4 + TCP-ACK with the given 4-tuple (all network order). */
static void
fill_tcp_ack(uint8_t *p, uint32_t foreign, uint32_t local,
    uint16_t sport, uint16_t dport)
{
    memset(p, 0, 54);
    p[12] = 0x08; p[13] = 0x00;              /* ethertype IPv4 */
    /* IPv4 header at 14 */
    p[14] = 0x45;                            /* v4, IHL 5 */
    p[16] = 0; p[17] = 40;                   /* total length */
    p[20] = 0x40; p[21] = 0x00;              /* DF, no fragment */
    p[22] = 64;                              /* TTL */
    p[23] = 6;                               /* proto TCP */
    memcpy(p + 26, &foreign, 4);             /* ip src (foreign) */
    memcpy(p + 30, &local, 4);               /* ip dst (local) */
    /* TCP header at 34 */
    p[46] = 0x50;                            /* data offset 5 */
    p[47] = 0x10;                            /* ACK */
    memcpy(p + 34, &sport, 2);
    memcpy(p + 36, &dport, 2);
}

static struct rte_mbuf *
inj_mbuf(uint32_t foreign, uint32_t local, uint16_t sport, uint16_t dport)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_inj_pool);

    if (m == NULL)
        return NULL;
    fill_tcp_ack(rte_pktmbuf_mtod(m, uint8_t *), foreign, local, sport, dport);
    rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m) = 54;
    return m;
}

static void
flow_key_v4(ff_flow_key_t *k, uint32_t foreign, uint32_t local,
    uint16_t sport, uint16_t dport)
{
    memset(k, 0, sizeof(*k));
    k->af = FF_FLOW_MAP_V4;
    k->src[0] = foreign;                     /* foreign address first */
    k->dst[0] = local;
    k->sport = sport;
    k->dport = dport;
}

/* ------------------------------------------------------------------------ */
/* TC 1: boot state under graceful_reload=1                                  */
/* ------------------------------------------------------------------------ */
static void
test_it_a09_boot_state(void **state)
{
    static int sc = 1, ifp = 2;

    (void)state;
    SKIP_IF_NO_INIT();

    assert_int_equal(ff_reload_state_attached(), 1);
    assert_int_equal(ff_reload_rx_owner_gen(), 0);
    assert_int_equal(ff_no_hw_mode(), 0);          /* owner == our gen */
    assert_int_equal(ff_drain_ring_ready(), 1);
    assert_non_null(rte_ring_lookup("drain_tx_p0_q0_g0"));
    assert_non_null(rte_ring_lookup("drain_tx_p0_q0_g1"));
    assert_non_null(rte_ring_lookup("drain_rx_p0_q0_g0"));
    assert_non_null(rte_ring_lookup("drain_rx_p0_q0_g1"));
    assert_int_equal((int)nb_dev_ports, 1);

    g_ctx = ff_dpdk_register_if(&sc, &ifp,
        &ff_global_cfg.dpdk.port_cfgs[IT_PORT_ID]);
    assert_non_null(g_ctx);
    assert_int_equal(ff_dpdk_if_up(), 0);          /* veth ctx for main_loop */

    /* the tx counter must be live on every data port, else the RV11
     * assertions below would silently degrade to tautologies */
    assert_int_equal(g_nb_tx_hooks, (int)ff_global_cfg.dpdk.nb_ports);

    /* nothing transmitted during init: clean RV11 baseline */
    assert_int_equal(hw_tx_calls(), 0);
    assert_int_equal(hw_tx_pkts(), 0);
}

/* ------------------------------------------------------------------------ */
/* TC 2 (IT-NR-A09 1/2): parked G_old diverts every tx entry point; the      */
/* owner side dequeues drain_ring_tx and performs the real tx_burst          */
/* ------------------------------------------------------------------------ */
static void
test_it_a09_tx_divert_no_hw(void **state)
{
    struct ff_traffic_args t0, t1;
    uint64_t rf, tf, td, rf2, tf2, td2;
    struct rte_ring *own_tx;
    int i, n_if = 8, n_raw = 4;

    (void)state;
    SKIP_IF_NO_INIT();
    own_tx = rte_ring_lookup("drain_tx_p0_q0_g0");
    assert_non_null(own_tx);

    /* G_old view: the peer generation owns the hardware */
    ff_reload_rx_owner_gen_set(1);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 1);

    t0 = traffic_get();
    ff_drain_ring_stats(&rf, &tf, &td);

    ff_test_reset_send_ctl();
    for (i = 0; i < n_if; i++)
        assert_int_equal(ff_dpdk_if_send(g_ctx, (void *)0x1, 64), 0);
    for (i = 0; i < n_raw; i++)
        assert_int_equal(ff_dpdk_raw_packet_send(g_test_pkt, 64, IT_PORT_ID), 0);

    /* judgment 1 (RV11 core): parked generation never touches tx_burst */
    assert_int_equal(hw_tx_calls(), 0);
    assert_int_equal(hw_tx_pkts(), 0);
    assert_int_equal((int)rte_ring_count(own_tx), n_if + n_raw);

    /* diverted accounting: enqueued and counted, never dropped */
    t1 = traffic_get();
    assert_int_equal((int)(t1.tx_packets - t0.tx_packets), n_if + n_raw);
    assert_int_equal((int)(t1.tx_dropped - t0.tx_dropped), 0);
    ff_drain_ring_stats(&rf2, &tf2, &td2);
    assert_int_equal((int)(tf2 - tf), 0);
    assert_int_equal((int)(td2 - td), 0);

    /* judgment 2: the owner side dequeues our ring and does the real
     * tx_burst on the net_null port (null PMD accepts and frees) */
    assert_int_equal((int)peer_drain_tx_all(), n_if + n_raw);
    assert_int_equal((int)rte_ring_count(own_tx), 0);
    assert_int_equal(hw_tx_calls(), 1);
    assert_int_equal(hw_tx_pkts(), (uint64_t)(n_if + n_raw));

    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
}

/* ------------------------------------------------------------------------ */
/* TC 3 (IT-NR-A09 3): drain_ring_tx watermark under sustained divert/drain, */
/* and an overflow probe must be counted + visible, never silent             */
/* ------------------------------------------------------------------------ */
static void
test_it_a09_drain_ring_tx_watermark(void **state)
{
    struct rte_ring *own_tx;
    uint64_t rf, tf, td, rf2, tf2, td2;
    uint64_t calls0, pkts0;
    unsigned cap;
    int r, i;

    (void)state;
    SKIP_IF_NO_INIT();
    own_tx = rte_ring_lookup("drain_tx_p0_q0_g0");
    assert_non_null(own_tx);
    assert_int_equal((int)peer_drain_tx_all(), 0);      /* no residue */
    calls0 = hw_tx_calls();
    pkts0 = hw_tx_pkts();

    ff_reload_rx_owner_gen_set(1);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 1);
    ff_drain_ring_stats(&rf, &tf, &td);

    /* 4 rounds x 64 packets through a 256-entry ring: well below the
     * watermark, zero full / zero drop, owner keeps up. The owner drains
     * in MAX_PKT_BURST(32) chunks -> 2 tx_burst calls per round. */
    ff_test_reset_send_ctl();
    for (r = 0; r < 4; r++) {
        for (i = 0; i < 64; i++)
            assert_int_equal(ff_dpdk_if_send(g_ctx, (void *)0x1, 64), 0);
        assert_int_equal((int)rte_ring_count(own_tx), 64);
        assert_int_equal((int)peer_drain_tx_all(), 64);
    }
    ff_drain_ring_stats(&rf2, &tf2, &td2);
    assert_int_equal((int)(tf2 - tf), 0);
    assert_int_equal((int)(td2 - td), 0);
    assert_int_equal(hw_tx_calls() - calls0, 8);
    assert_int_equal(hw_tx_pkts() - pkts0, 256);

    /* fill to capacity, then one past: counted drop + warning (C-NR-309-5) */
    cap = rte_ring_get_capacity(own_tx);
    for (i = 0; (unsigned)i < cap; i++)
        assert_int_equal(ff_dpdk_if_send(g_ctx, (void *)0x1, 64), 0);
    assert_int_equal((int)rte_ring_count(own_tx), (int)cap);
    assert_int_equal(hw_tx_calls() - calls0, 8);        /* still parked */

    /* one past capacity: enqueue fails, the divert path drops the packet
     * into ff_traffic.tx_dropped and the ring-full counter moves — never
     * a silent drop (C-NR-309-5). The drain-side g_tx_dropped counter is
     * untouched (it only counts owner-side tx shortfalls). */
    {
        struct ff_traffic_args ta = traffic_get();
        assert_int_equal(ff_dpdk_if_send(g_ctx, (void *)0x1, 64), 0);
        assert_int_equal((int)rte_ring_count(own_tx), (int)cap);
        ff_drain_ring_stats(&rf2, &tf2, &td2);
        assert_int_equal((int)(tf2 - tf), 1);           /* ring-full counted */
        assert_int_equal((int)(td2 - td), 0);
        {
            struct ff_traffic_args tb = traffic_get();
            assert_int_equal((int)(tb.tx_dropped - ta.tx_dropped), 1);
        }
    }

    assert_int_equal(peer_drain_tx_all(), cap);
    assert_int_equal(hw_tx_calls() - calls0, 16);
    assert_int_equal(hw_tx_pkts() - pkts0, 256 + (uint64_t)cap);

    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
}

/* ------------------------------------------------------------------------ */
/* TC 4 (IT-NR-A09 path 4): FF_DISPATCH_RESPONSE staging reaches send_burst  */
/* while parked — the defensive short-circuit must drop+count, never burst   */
/* ------------------------------------------------------------------------ */
static int it_resp_ret;
static int
it_response_dispatcher(void *data, uint16_t *len, uint16_t queue_id,
    uint16_t nb_queues, struct ff_dispatcher_context context)
{
    (void)data; (void)len; (void)queue_id; (void)nb_queues; (void)context;
    return it_resp_ret;
}

static void
test_it_a09_send_burst_guard(void **state)
{
    struct ff_traffic_args t0, t1;
    uint64_t calls0;
    int i;

    (void)state;
    SKIP_IF_NO_INIT();
    assert_non_null(g_inj_pool);
    assert_int_equal(lcore_conf[0].tx_mbufs[IT_PORT_ID].len, 0);
    calls0 = hw_tx_calls();

    ff_reload_rx_owner_gen_set(1);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 1);

    it_resp_ret = FF_DISPATCH_RESPONSE;
    ff_regist_packet_dispatcher_context(it_response_dispatcher);

    t0 = traffic_get();
    for (i = 0; i < MAX_PKT_BURST; i++) {
        struct rte_mbuf *m = inj_mbuf(0x0a000001, 0x0a000002,
            htons(5000 + i), htons(80));
        assert_non_null(m);
        ff_dpdk_process_packets(IT_PORT_ID, 0, &m, 1, g_ctx, 0);
    }
    ff_unregist_packet_dispatcher_context();

    /* the send_burst guard fired on the 32nd staged packet: hardware
     * untouched, the whole staged burst dropped and counted */
    assert_int_equal(hw_tx_calls() - calls0, 0);
    assert_int_equal(lcore_conf[0].tx_mbufs[IT_PORT_ID].len, 0);
    t1 = traffic_get();
    assert_int_equal((int)(t1.tx_dropped - t0.tx_dropped), MAX_PKT_BURST);
    assert_int_equal((int)rte_mempool_avail_count(g_inj_pool), 512);

    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
}

/* ------------------------------------------------------------------------ */
/* TC 5 (IT-NR-A10, dispatch-side sub-assertion): half-open window both ways */
/*                                                                           */
/* Round-2 topology in one process: gen 0 = G_new (rx owner, classifying),  */
/* gen 1 = G_old (holds the PCBs / syncache entries of pre-handover flows). */
/*                                                                           */
/* (a) SYN reached G_old before T3: the 3rd ACK is a flow-map miss here and */
/*     must be forwarded to G_old's drain_rx, never handled locally.        */
/* (b) SYN reached G_new after T3: the syncache hook (tcp_syncache.c:1788-  */
/*     1804, syncache_flow_map_insert) records the tuple at SYN-ACK time — */
/*     NOT at accept(). Simulating that exact insert call, the entry must   */
/*     already exist before the 3rd ACK arrives, so the ACK is classified   */
/*     "ours" and consumed by the local stack.                              */
/* ------------------------------------------------------------------------ */
static int
it_flow_dispatcher(void *data, uint16_t *len, uint16_t queue_id,
    uint16_t nb_queues, struct ff_dispatcher_context context)
{
    const uint8_t *p = (const uint8_t *)data;
    const uint8_t *ip, *tp;
    uint16_t et, l = *len;
    ff_flow_key_t k;

    (void)nb_queues; (void)context;
    /* mirror of ngx_ff_flow_map_dispatcher (C-NR-303): classify TCP flows
     * by flow_map; hit -> queue_id (ours, incl. syncache stage),
     * miss -> FF_DISPATCH_PEER (old flow, forward to the drainer) */
    if (l < 14 + 20 + 20)
        return (int)queue_id;                    /* unparsable: local */
    et = (uint16_t)((p[12] << 8) | p[13]);
    if (et == 0x8100) {                          /* one VLAN layer */
        p += 4; l -= 4;
        et = (uint16_t)((p[12] << 8) | p[13]);
    }
    if (et != 0x0800)
        return (int)queue_id;                    /* ARP/NDP never classified */
    ip = p + 14;
    if ((ip[0] >> 4) != 4)
        return (int)queue_id;
    if ((((uint16_t)ip[6] << 8) | ip[7]) & 0x3fff)
        return (int)queue_id;                    /* fragment: local */
    if (ip[9] != 6)
        return (int)queue_id;                    /* TCP only */
    tp = ip + ((ip[0] & 0x0f) << 2);

    memset(&k, 0, sizeof(k));
    k.af = FF_FLOW_MAP_V4;
    memcpy(&k.src[0], ip + 12, 4);               /* foreign */
    memcpy(&k.dst[0], ip + 16, 4);               /* local */
    memcpy(&k.sport, tp, 2);
    memcpy(&k.dport, tp + 2, 2);

    if (ff_flow_map_lookup(&k))
        return (int)queue_id;
    return FF_DISPATCH_PEER;
}

static void
test_it_a10_halfopen_dispatch(void **state)
{
    /* doc addresses only (192.168.1.0/24 fixture style) */
    const uint32_t cli = 0xc0a80110, srv = 0xc0a80120;
    struct rte_ring *peer_rx;
    struct rte_mbuf *m, *mm;
    ff_flow_key_t k_old, k_new;
    int avail;

    (void)state;
    SKIP_IF_NO_INIT();
    assert_non_null(g_inj_pool);

    /* we are G_new (gen 0): we own rx, the window is open */
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_flow_map_open();

    peer_rx = rte_ring_lookup("drain_rx_p0_q0_g1");    /* G_old inbound */
    assert_non_null(peer_rx);
    while (rte_ring_dequeue(peer_rx, (void **)&mm) == 0)
        rte_pktmbuf_free(mm);

    ff_regist_packet_dispatcher_context(it_flow_dispatcher);

    /* (a) old-generation half-open connection: 3rd ACK must be forwarded */
    flow_key_v4(&k_old, cli, srv, htons(40001), htons(80));
    assert_int_equal(ff_flow_map_lookup(&k_old), 0);   /* not ours */
    m = inj_mbuf(cli, srv, htons(40001), htons(80));
    assert_non_null(m);
    avail = (int)rte_mempool_avail_count(g_inj_pool);
    ff_dpdk_process_packets(IT_PORT_ID, 0, &m, 1, g_ctx, 0);
    assert_int_equal((int)rte_ring_count(peer_rx), 1); /* to G_old */
    /* ownership moved with the mbuf: not freed, not leaked */
    assert_int_equal((int)rte_mempool_avail_count(g_inj_pool), avail);

    /* (b) new-generation connection: entry recorded at syncache stage
     * (simulating the tcp_syncache.c hook — the same insert call), the
     * 3rd ACK still in the syncache window must be classified ours */
    flow_key_v4(&k_new, cli, srv, htons(40002), htons(80));
    assert_int_equal(ff_flow_map_lookup(&k_new), 0);
    assert_int_equal(ff_flow_map_insert(&k_new), 0);
    /* the entry exists BEFORE the 3rd ACK is injected: syncache-stage
     * timing, not accept()-time (the whole point of C-NR-301) */
    assert_int_equal(ff_flow_map_lookup(&k_new), 1);

    avail = (int)rte_mempool_avail_count(g_inj_pool);  /* before the alloc */
    m = inj_mbuf(cli, srv, htons(40002), htons(80));
    assert_non_null(m);
    ff_dpdk_process_packets(IT_PORT_ID, 0, &m, 1, g_ctx, 0);
    assert_int_equal((int)rte_ring_count(peer_rx), 1); /* NOT forwarded */
    /* consumed by the local stack path: the mbuf is back in the pool */
    assert_int_equal((int)rte_mempool_avail_count(g_inj_pool), avail);

    /* cleanup: free the forwarded packet, close the window */
    while (rte_ring_dequeue(peer_rx, (void **)&mm) == 0)
        rte_pktmbuf_free(mm);
    ff_unregist_packet_dispatcher_context();
    ff_flow_map_close();
}

/* ------------------------------------------------------------------------ */
/* TC 6 (IT-NR-A10 framework): complete RV12 criteria — M4 C-NR-312 gated.   */
/* Enable when "delay close listening" (or syncache export) lands; the      */
/* two-process timing itself is RT-02/RT-15.                                */
/* ------------------------------------------------------------------------ */
static void
test_it_a10_full_handshake_m4_pending(void **state)
{
    (void)state;
    print_message("[IT-NR-A10] full criteria (RV12) pending M4 C-NR-312:\n"
        "  SYN -> G_old before T3, handover, 3rd ACK after T3:\n"
        "  1) handshake completes (ESTABLISHED, no RST)\n"
        "  2) later data on the connection still served by G_old\n"
        "  3) success rate 100%% across (a) delayed-close and (b) syncache-export\n"
        "  Requires: real FreeBSD stack + two processes (this harness links no\n"
        "  stack adapter); run under RT-02/RT-15 once C-NR-312 is in.\n");
    skip();
}

/* ------------------------------------------------------------------------ */
/* TC 7 (IT-NR-A09 path 3, MUST RUN LAST — tears down EAL): a parked         */
/* main_loop pass diverts pre-staged tx_mbufs to drain_ring_tx               */
/* ------------------------------------------------------------------------ */
static uint64_t g_ml_calls_before;
static int      g_ml_staged;

static int
parked_loop_cb(void *arg)
{
    struct rte_ring *r;

    (void)arg;
    /* inside the parked pass, after the tx-drain section ran */
    r = rte_ring_lookup("drain_tx_p0_q0_g0");
    assert_non_null(r);
    assert_int_equal(hw_tx_calls(), g_ml_calls_before);  /* still no hw tx */
    assert_int_equal((int)rte_ring_count(r), g_ml_staged);
    ff_dpdk_stop();
    return 0;
}

static void
test_it_a09_main_loop_parked_pass(void **state)
{
    void *saved_pl, *saved_pll, *saved_pc;
    int i;

    (void)state;
    SKIP_IF_NO_INIT();
    assert_int_equal((int)peer_drain_tx_all(), 0);      /* no residue */

    /* stage as the hardware owner (transition-period residue, path 3) */
    ff_reload_rx_owner_gen_set(0);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 0);
    ff_test_reset_send_ctl();
    for (i = 0; i < 5; i++)
        assert_int_equal(ff_dpdk_if_send(g_ctx, (void *)0x1, 64), 0);
    g_ml_staged = lcore_conf[0].tx_mbufs[IT_PORT_ID].len;
    assert_int_equal(g_ml_staged, 5);
    g_ml_calls_before = hw_tx_calls();

    /* handover: the peer takes the hardware, we run one parked pass */
    ff_reload_rx_owner_gen_set(1);
    ff_reload_rx_stopped_set(0);
    assert_int_equal(ff_no_hw_mode(), 1);

    /* detach hand-built cfg arrays: ff_dpdk_run's ff_unload_config must
     * not free them (same pattern as test_ff_dpdk_if_integration.c) */
    saved_pl  = ff_global_cfg.dpdk.proc_lcore;
    saved_pll = ff_global_cfg.dpdk.portid_list;
    saved_pc  = ff_global_cfg.dpdk.port_cfgs;
    ff_global_cfg.dpdk.proc_lcore  = NULL;
    ff_global_cfg.dpdk.portid_list = NULL;
    ff_global_cfg.dpdk.port_cfgs   = NULL;

    ff_dpdk_run(parked_loop_cb, NULL);      /* one parked main_loop pass */

    free(saved_pl);
    free(saved_pll);
    free(saved_pc);
    g_init_ok = 0;
}

/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_it_a09_boot_state),
        cmocka_unit_test(test_it_a09_tx_divert_no_hw),
        cmocka_unit_test(test_it_a09_drain_ring_tx_watermark),
        cmocka_unit_test(test_it_a09_send_burst_guard),
        cmocka_unit_test(test_it_a10_halfopen_dispatch),
        cmocka_unit_test(test_it_a10_full_handshake_m4_pending),
        /* MUST be last: tears down the EAL via ff_dpdk_run */
        cmocka_unit_test(test_it_a09_main_loop_parked_pass),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
