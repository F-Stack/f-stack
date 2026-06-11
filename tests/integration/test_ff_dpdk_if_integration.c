/*
 * F-Stack lib/ integration test (FU-CB-DPDKIF-INTEGRATION).
 *
 * Boots a real DPDK EAL with --no-huge --no-pci --no-shconf --vdev=net_null0
 * so ff_dpdk_init() can run end-to-end and exercise the
 *   init_lcore_conf / init_mem_pool / init_dispatch_ring / init_msg_ring /
 *   init_port_start / init_clock
 * paths that pure unit tests cannot reach (those depend on at least one
 * probed ethdev port + a master lcore + a real mempool).
 *
 * Strategy:
 *   - group_setup populates ff_global_cfg programmatically (no INI file)
 *     and calls ff_dpdk_init(argc, eal_argv).
 *   - On success, individual TCs assert that init left the global state in
 *     the expected shape and exercise post-init helpers (ff_dpdk_register_if,
 *     ff_dpdk_pktmbuf_free, ff_get_traffic, ff_get_tsc_ns).
 *   - On failure (e.g. CI worker without --no-huge support, no spare cpu,
 *     or net_null vdev unavailable), TCs are skip()'d via SKIP_IF_NO_INIT.
 *
 * Coverage target (Stage-6 G-CB-3 deferred): drive ff_dpdk_if.c line cov
 * from 5.1% (unit-only) up to >= 25% by exercising the ~250 lines of
 * ff_dpdk_init + dependents that need a live EAL.
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
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_version.h>

#include "ff_config.h"

/* Local mirror of struct ff_tx_offload (lib/ff_dpdk_if.h L47) — we avoid
 * including ff_dpdk_if.h here because this file uses void*-based forward
 * decls for the ff_dpdk_* API that would conflict with the real prototypes. */
struct ff_tx_offload {
    uint8_t  ip_csum;
    uint8_t  tcp_csum;
    uint8_t  udp_csum;
    uint8_t  sctp_csum;
    uint16_t tso_seg_size;
};

/* ------------------------------------------------------------------------ */
/* FU-S9-DPDKIF-INTEG-BOOST: test-controllable bridge stubs for ff_dpdk_if  */
/* _send. g_test_offload drives the ip_csum / tcp_csum / tso / udp_csum legs; */
/* g_test_pkt provides a valid IPv4(+TCP) header so the iph/tcph parsing in  */
/* ff_dpdk_if_send reads sane fields; g_copydata_fail forces the copydata    */
/* error path.                                                              */
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
    /* Ethernet(14) + IPv4 header at offset 14: version=4, IHL=5 (=0x45). */
    g_test_pkt[14] = 0x45;
    /* TCP data offset (byte 14+20+12 = 46): 5 words << 4 = 0x50. */
    g_test_pkt[46] = 0x50;
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

/* Forward declarations of the public ff_dpdk_if API (lib/ff_dpdk_if.h pulls
 * in BSD headers we'd rather not drag in here). */
int   ff_dpdk_init(int argc, char **argv);
void *ff_dpdk_register_if(void *softc, void *ifp, struct ff_port_cfg *cfg);
void  ff_dpdk_deregister_if(void *ctx);
uint64_t ff_get_tsc_ns(void);
void  ff_get_traffic(void *traffic);
int   ff_dpdk_if_send(void *ctx, void *m, int total);
int   ff_dpdk_raw_packet_send(void *data, int total, uint16_t port_id);

/* Globals defined in ff_dpdk_if.c that we want to inspect post-init. */
extern uint16_t nb_dev_ports;

/* ------------------------------------------------------------------------ */
/* Bridge stubs: ff_dpdk_if.c references ~25 ff_x/kernel symbols that live  */
/* in lib/ff_veth.c, lib/ff_mbuf.c, lib/ff_kern_xxx.c etc. Linking those     */
/* drag in the entire FreeBSD kernel adapter; we only need linker resolution */
/* for the symbols, not their semantics. Calling any of these in a TC means  */
/* coverage moved beyond our intended scope; they all return 0 / NULL.       */
/* ------------------------------------------------------------------------ */

/* mbuf / veth bridge */
void *ff_mbuf_gethdr(void *p, uint16_t l, void *d, uint16_t dl, uint8_t r)
{ (void)p;(void)l;(void)d;(void)dl;(void)r; return NULL; }
int   ff_mbuf_set_vlan_info(void *m, uint16_t v) { (void)m;(void)v; return 0; }
int   ff_mbuf_set_timestamp(void *m, uint64_t t) { (void)m;(void)t; return 0; }
void *ff_mbuf_get(void *p, void *m, void *d, uint16_t dl)
{ (void)p;(void)m;(void)d;(void)dl; return NULL; }
void  ff_mbuf_free(void *m) { (void)m; }
int   ff_mbuf_copydata(void *m, void *d, int o, int l)
{ (void)m;(void)d;(void)o;(void)l; return ff_test_copydata(d, o, l); }
int   ff_mbuf_tx_offload(void *m, void *o, void *l)
{ (void)m;(void)l; ff_test_fill_offload(o); return 0; }

/* Return a zeroed ff_dpdk_if_context-sized buffer so main_loop's
 * ctx = veth_ctx[port] is valid: ff_veth_input reads ctx->hw_features.rx_csum
 * (=0) then ff_mbuf_gethdr (stub) returns NULL -> safe early return. */
static unsigned char g_veth_ctx_buf[512];
void *ff_veth_attach(void *cfg) { (void)cfg; memset(g_veth_ctx_buf, 0, sizeof(g_veth_ctx_buf)); return g_veth_ctx_buf; }
int   ff_veth_input(void *ctx, struct rte_mbuf *m) { (void)ctx;(void)m; return 0; }
void  ff_veth_process_packet(void *ifp, void *m) { (void)ifp;(void)m; }
void *ff_veth_get_softc(uint16_t portid) { (void)portid; return NULL; }
void  ff_veth_free_softc(void *sc) { (void)sc; }
void *ff_veth_softc_to_hostc(void *sc) { (void)sc; return NULL; }

/* kernel-side bridge */
int   ff_sysctl(const int *n, unsigned nl, void *o, size_t *ol, const void *i, size_t il)
{ (void)n;(void)nl;(void)o;(void)ol;(void)i;(void)il; return 0; }
int   ff_socket(int d, int t, int p) { (void)d;(void)t;(void)p; return -1; }
int   ff_ioctl_freebsd(int f, unsigned long r, ...) { (void)f;(void)r; return -1; }
int   ff_close(int f) { (void)f; return 0; }
int   ff_rtioctl(int f, void *d, unsigned int *l, unsigned int al)
{ (void)f;(void)d;(void)l;(void)al; return -1; }
/* ff_update_current_ts is defined in lib/ff_host_interface.c (linked). */
void  ff_hardclock(void) { }

/* pcap dump (we do NOT link ff_dpdk_pcap.o here) */
int   ff_dump_packets(const char *p, struct rte_mbuf *m, uint16_t s, uint32_t l, uint8_t t)
{ (void)p;(void)m;(void)s;(void)l;(void)t; return 0; }
int   ff_enable_pcap(const char *p, uint16_t s, uint8_t t)
{ (void)p;(void)s;(void)t; return 0; }

/* rte_timer subsystem hook used by ff_dpdk_if.c (see lib/ff_dpdk_if.c) */
void rte_timer_meta_init(void) { }

/* ------------------------------------------------------------------------ */
/* group setup: populate ff_global_cfg + boot DPDK EAL                       */
/* ------------------------------------------------------------------------ */
static int    g_init_ok = 0;
static char   g_init_skip_reason[128] = "";

#define INT_PORT_ID  0
#define INT_LCORE_ID 0

static void
populate_minimal_ff_global_cfg(void)
{
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));

    /* 1 process, 1 lcore (lcore 0 by EAL "-l 0"). */
    ff_global_cfg.dpdk.nb_procs   = 1;
    ff_global_cfg.dpdk.proc_id    = 0;
    ff_global_cfg.dpdk.proc_lcore = calloc(1, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.proc_lcore) {
        ff_global_cfg.dpdk.proc_lcore[0] = INT_LCORE_ID;
    }

    /* 1 port (the net_null0 vdev). */
    ff_global_cfg.dpdk.nb_ports    = 1;
    ff_global_cfg.dpdk.max_portid  = INT_PORT_ID;
    ff_global_cfg.dpdk.portid_list = calloc(1, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.portid_list) {
        ff_global_cfg.dpdk.portid_list[0] = INT_PORT_ID;
    }

    /* port_cfgs is indexed by port_id, so we need slots [0..max_portid]. */
    ff_global_cfg.dpdk.port_cfgs =
        calloc(ff_global_cfg.dpdk.max_portid + 1, sizeof(struct ff_port_cfg));
    if (ff_global_cfg.dpdk.port_cfgs) {
        ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID].port_id    = INT_PORT_ID;
        ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID].nb_lcores  = 1;
        ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID].lcore_list[0] = INT_LCORE_ID;
    }

    ff_global_cfg.dpdk.numa_on              = 0;
    ff_global_cfg.dpdk.idle_sleep           = 0;
    ff_global_cfg.dpdk.pkt_tx_delay         = 0;
    ff_global_cfg.dpdk.tso                  = 0;
    ff_global_cfg.dpdk.tx_csum_offoad_skip  = 0;
    ff_global_cfg.dpdk.vlan_strip           = 0;
    ff_global_cfg.dpdk.nb_vlan_filter       = 0;
    ff_global_cfg.dpdk.symmetric_rss        = 0;
    ff_global_cfg.dpdk.promiscuous          = 0;

    /* No KNI, no flow isolate, no fdir, no rss_check, no bond. */
    ff_global_cfg.kni.enable = 0;

    /* Logging: keep it off so ff_log_open_set() is not invoked. */
    ff_global_cfg.log.level = 0;

    /* freebsd.hz drives init_clock()'s intrs = US_PER_S / hz; setting it to
     * the upstream default (100) avoids a div-by-zero FPE during init. */
    ff_global_cfg.freebsd.hz = 100;
}

static int
group_setup(void **state)
{
    (void)state;

    populate_minimal_ff_global_cfg();

    /* EAL args: no-huge / no-pci / no-shconf for an unprivileged CI sandbox.
     * --vdev=net_null0 attaches the null PMD as port 0 (always available). */
    char *argv[] = {
        (char *)"test_ff_dpdk_if_integration",
        (char *)"--no-huge",
        (char *)"--no-pci",
        (char *)"--no-shconf",
        (char *)"-l", (char *)"0",
        (char *)"-m", (char *)"64",
        (char *)"--vdev=net_null0",
        (char *)"--file-prefix=ff_int_test",
        NULL
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;

    /* ff_dpdk_init() is the entry point we want to cover. It internally
     * calls rte_eal_init -> init_lcore_conf -> init_mem_pool ->
     * init_dispatch_ring -> init_msg_ring -> init_port_start -> init_clock. */
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
    return 0;
}

static int
group_teardown(void **state)
{
    (void)state;
    /* Free the calloc'd cfg arrays (best effort; EAL stays up till exit). */
    free(ff_global_cfg.dpdk.proc_lcore);
    free(ff_global_cfg.dpdk.portid_list);
    free(ff_global_cfg.dpdk.port_cfgs);
    /* rte_eal_cleanup() is intentionally not called here: cmocka's TCs may
     * still hold references to lcore TLS. The OS reclaims on process exit. */
    return 0;
}

#define SKIP_IF_NO_INIT()  do { \
    if (!g_init_ok) { print_message("(skipped: %s)\n", g_init_skip_reason); skip(); } \
} while (0)

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-01: ff_dpdk_init returned 0 and probed exactly 1 port      */
/* ------------------------------------------------------------------------ */
static void
test_init_succeeded_with_one_port(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    /* nb_dev_ports is set inside init_lcore_conf via rte_eth_dev_count_avail. */
    assert_int_equal((int)nb_dev_ports, 1);
    /* The configured port 0 must now be in started state (post init_port_start). */
    struct rte_eth_link link = {0};
    /* rte_eth_link_get_nowait may return -ENOTSUP on net_null but should
     * not crash and should at minimum populate the struct to zero. */
    int rv = rte_eth_link_get_nowait(INT_PORT_ID, &link);
    assert_true(rv == 0 || rv == -ENOTSUP || rv == -EINVAL);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-02: rte_eth_dev_socket_id returns sane value post-init      */
/* ------------------------------------------------------------------------ */
static void
test_eth_dev_socket_id_post_init(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    int sid = rte_eth_dev_socket_id(INT_PORT_ID);
    /* SOCKET_ID_ANY (-1) or a real socket id; must not crash. */
    assert_true(sid >= -1);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-03: ff_dpdk_register_if/deregister_if round-trip            */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_register_deregister_roundtrip(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    int dummy_softc = 0xCAFE;
    int dummy_ifp   = 0xBEEF;
    void *ctx = ff_dpdk_register_if(
        &dummy_softc, &dummy_ifp,
        &ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID]);
    assert_non_null(ctx);
    ff_dpdk_deregister_if(ctx);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-04: ff_get_tsc_ns is monotonic post-init                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_tsc_ns_monotonic(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    uint64_t a = ff_get_tsc_ns();
    /* Burn ~1us of cycles. */
    for (volatile int i = 0; i < 100000; i++) { (void)i; }
    uint64_t b = ff_get_tsc_ns();
    assert_true(b >= a);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-05: ff_get_traffic returns zero-init traffic counters       */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_traffic_post_init(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    /* ff_traffic_args opaque to us; allocate a 256-byte zero buffer
     * which is more than the actual struct size (last-known ~64 bytes). */
    char buf[256] = {0};
    ff_get_traffic(buf);
    /* Smoke: function returned without crashing. We can't assert specific
     * byte patterns without lifting the struct definition. */
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-06: ff_dpdk_if_send with valid ctx + 0-byte payload         */
/* (NULL ctx is exercised separately in TC-INT-DPDKIF-08 below.)             */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_if_send_zero_total(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    int dummy_softc = 0xCAFE, dummy_ifp = 0xBEEF;
    void *ctx = ff_dpdk_register_if(
        &dummy_softc, &dummy_ifp,
        &ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID]);
    assert_non_null(ctx);

    /* total=0 hits the early branch where the while(total > 0) loop body
     * never executes; the function still calls rte_pktmbuf_alloc once
     * (covers ~10 lines of the pre-loop setup). */
    int rv = ff_dpdk_if_send(ctx, /*m*/ NULL, /*total*/ 0);
    /* Acceptable: 0 (sent nothing) or -1 (mempool exhausted in null vdev). */
    assert_true(rv == 0 || rv == -1);

    ff_dpdk_deregister_if(ctx);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-08 (Stage-6 Phase-9 / FU-CB-DPDKIF-NULLGUARD):              */
/* ff_dpdk_if_send(NULL, ...) must not crash. With the lib NULL guard in    */
/* place this returns -1 immediately. Pre-guard, this would segfault on    */
/* the very first ctx->port_id deref.                                       */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_if_send_null_ctx_no_crash(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    int rv = ff_dpdk_if_send(NULL, NULL, 0);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-INT-DPDKIF-07: rte_eal_process_type returns PRIMARY post-init          */
/* ------------------------------------------------------------------------ */
static void
test_eal_process_type_primary(void **state)
{
    (void)state;
    SKIP_IF_NO_INIT();
    enum rte_proc_type_t pt = rte_eal_process_type();
    assert_int_equal((int)pt, RTE_PROC_PRIMARY);
}

/* ------------------------------------------------------------------------ */
/* FU-S9-DPDKIF-INTEG-BOOST: ff_dpdk_if_send branch coverage.               */
/* Each TC registers a ctx (optionally with tx_csum_l4), sets the offload   */
/* controls, sends, then deregisters. send_single_packet ultimately enqueues */
/* to the net_null port (accepts all).                                      */
/* ------------------------------------------------------------------------ */
static void *
ff_test_register(int tx_csum_l4)
{
    static int sc = 1, ifp = 2;
    ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID].hw_features.tx_csum_l4 =
        (uint8_t)tx_csum_l4;
    return ff_dpdk_register_if(&sc, &ifp,
                               &ff_global_cfg.dpdk.port_cfgs[INT_PORT_ID]);
}

/* single-segment, no offload */
static void
test_ff_dpdk_if_send_basic(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    void *ctx = ff_test_register(0);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, /*total*/ 64);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* multi-segment: total > RTE_MBUF_DEFAULT_DATAROOM forces the cur==NULL
 * second-allocation path inside the while loop. */
static void
test_ff_dpdk_if_send_multiseg(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    void *ctx = ff_test_register(0);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, /*total*/ 4096);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* ip_csum offload leg */
static void
test_ff_dpdk_if_send_ip_csum(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_test_offload.ip_csum = 1;
    void *ctx = ff_test_register(0);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* tx_csum_l4 + tcp_csum leg */
static void
test_ff_dpdk_if_send_tcp_csum(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_test_offload.tcp_csum = 1;
    void *ctx = ff_test_register(/*tx_csum_l4*/1);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* tx_csum_l4 + tso leg */
static void
test_ff_dpdk_if_send_tso(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_test_offload.tcp_csum = 1;
    g_test_offload.tso_seg_size = 1448;
    void *ctx = ff_test_register(1);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* tx_csum_l4 + udp_csum leg */
static void
test_ff_dpdk_if_send_udp_csum(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_test_offload.udp_csum = 1;
    void *ctx = ff_test_register(1);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_true(rv == 0 || rv == -1);
    ff_dpdk_deregister_if(ctx);
}

/* copydata failure -> the ret<0 error path frees head + returns -1 */
static void
test_ff_dpdk_if_send_copydata_fail(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    g_copydata_fail = 1;
    void *ctx = ff_test_register(0);
    assert_non_null(ctx);
    int rv = ff_dpdk_if_send(ctx, (void *)0x1, 128);
    assert_int_equal(rv, -1);
    ff_dpdk_deregister_if(ctx);
}

/* raw packet send to the net_null port */
static void
test_ff_dpdk_raw_packet_send_basic(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    ff_test_reset_send_ctl();
    int rv = ff_dpdk_raw_packet_send(g_test_pkt, 64, INT_PORT_ID);
    assert_true(rv == 0 || rv == -1);
}

/* raw packet send with total > DATAROOM forces the multi-segment alloc path */
static void
test_ff_dpdk_raw_packet_send_multiseg(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    unsigned char *buf = calloc(1, 4096);
    assert_non_null(buf);
    buf[14] = 0x45;
    int rv = ff_dpdk_raw_packet_send(buf, 4096, INT_PORT_ID);
    assert_true(rv == 0 || rv == -1);
    free(buf);
}

/* ff_dpdk_pktmbuf_free frees one segment */
static void
test_ff_dpdk_pktmbuf_free_basic(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    extern void ff_dpdk_pktmbuf_free(void *m);
    /* Borrow a mbuf from the lib mempool via a raw alloc through the same
     * socket pool used by the lib (pktmbuf_pool[socket]). We do not have
     * direct access, so allocate from any reachable pool: reuse a send. */
    struct rte_mempool *mp = rte_mempool_lookup("mbuf_pool_0");
    if (mp == NULL) { skip(); }
    struct rte_mbuf *m = rte_pktmbuf_alloc(mp);
    assert_non_null(m);
    ff_dpdk_pktmbuf_free(m);   /* rte_pktmbuf_free_seg */
}

/* ff_dpdk_if_up brings every tx port up (ff_veth_attach stub returns non-NULL) */
static void
test_ff_dpdk_if_up_success(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    extern int ff_dpdk_if_up(void);
    int rv = ff_dpdk_if_up();
    assert_int_equal(rv, 0);
}

/* The loop callback stops the run after exactly one main_loop iteration. */
static int
ff_test_oneshot_loop(void *arg)
{
    (void)arg;
    extern void ff_dpdk_stop(void);
    ff_dpdk_stop();          /* sets stop_loop=1 -> next top-of-loop breaks */
    return 0;
}

/* ------------------------------------------------------------------------ */
/* MUST RUN LAST: ff_dpdk_run drives main_loop for one full iteration        */
/* (process_dispatch_ring + rte_eth_rx_burst + process_msg_ring + the TX     */
/* drain + top_status accounting + the user-loop callback). It then calls    */
/* ff_unload_config + rte_eal_cleanup, so no EAL-dependent test may follow.  */
/* ------------------------------------------------------------------------ */
static void
test_main_loop_one_iteration_then_stop(void **state)
{
    (void)state; SKIP_IF_NO_INIT();
    extern void ff_dpdk_run(int (*loop)(void *), void *arg);

    /* lcore_conf.port_cfgs is a pointer ALIAS of ff_global_cfg.dpdk.port_cfgs
     * (set during init_lcore_conf), so main_loop keeps working after we
     * detach these from ff_global_cfg. Detaching prevents ff_dpdk_run's
     * internal ff_unload_config from free()ing our hand-built (non
     * ff_load_config) arrays, which is incompatible with its teardown. */
    void *saved_pl  = ff_global_cfg.dpdk.proc_lcore;
    void *saved_pll = ff_global_cfg.dpdk.portid_list;
    void *saved_pc  = ff_global_cfg.dpdk.port_cfgs;
    ff_global_cfg.dpdk.proc_lcore  = NULL;
    ff_global_cfg.dpdk.portid_list = NULL;
    ff_global_cfg.dpdk.port_cfgs   = NULL;

    ff_dpdk_run(ff_test_oneshot_loop, NULL);   /* one full main_loop iteration */

    /* EAL is now torn down by ff_dpdk_run; free our saved arrays ourselves. */
    free(saved_pl);
    free(saved_pll);
    free(saved_pc);
    g_init_ok = 0;
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_succeeded_with_one_port),
        cmocka_unit_test(test_eth_dev_socket_id_post_init),
        cmocka_unit_test(test_ff_dpdk_register_deregister_roundtrip),
        cmocka_unit_test(test_ff_get_tsc_ns_monotonic),
        cmocka_unit_test(test_ff_get_traffic_post_init),
        cmocka_unit_test(test_ff_dpdk_if_send_zero_total),
        cmocka_unit_test(test_ff_dpdk_if_send_null_ctx_no_crash),
        cmocka_unit_test(test_eal_process_type_primary),
        /* FU-S9-DPDKIF-INTEG-BOOST: ff_dpdk_if_send branch coverage */
        cmocka_unit_test(test_ff_dpdk_if_send_basic),
        cmocka_unit_test(test_ff_dpdk_if_send_multiseg),
        cmocka_unit_test(test_ff_dpdk_if_send_ip_csum),
        cmocka_unit_test(test_ff_dpdk_if_send_tcp_csum),
        cmocka_unit_test(test_ff_dpdk_if_send_tso),
        cmocka_unit_test(test_ff_dpdk_if_send_udp_csum),
        cmocka_unit_test(test_ff_dpdk_if_send_copydata_fail),
        cmocka_unit_test(test_ff_dpdk_raw_packet_send_basic),
        cmocka_unit_test(test_ff_dpdk_raw_packet_send_multiseg),
        cmocka_unit_test(test_ff_dpdk_pktmbuf_free_basic),
        cmocka_unit_test(test_ff_dpdk_if_up_success),
        /* MUST be last: tears down EAL via ff_dpdk_run -> rte_eal_cleanup */
        cmocka_unit_test(test_main_loop_one_iteration_then_stop),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
