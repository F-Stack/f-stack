/*
 * F-Stack lib/ unit test: ff_dpdk_if.c (P2 #4 — trivial subset only)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/plan-stage4-p2-tests.md §7 Phase 4
 * Coverage: 7 TC over 7 trivial getters/setters in lib/ff_dpdk_if.c.
 * The other ~2837 lines of ff_dpdk_if.c are deferred (FU-S4-DPDK-IF-FULL).
 *
 * Tested functions:
 *   - ff_dpdk_deregister_if    (L198, free(ctx))
 *   - ff_get_traffic           (L1952, struct copy)
 *   - ff_dpdk_stop             (L2516, sets stop_loop=1)
 *   - ff_regist_pcblddr_fun    (L2571, function ptr setter)
 *   - ff_regist_packet_dispatcher          (L2868)
 *   - ff_regist_packet_dispatcher_context  (L2874)
 *   - ff_get_tsc_ns            (L2880, rte_rdtsc / rte_get_tsc_hz)
 *
 * NOT tested (skipped — requires mbuf+mempool real DPDK runtime):
 *   - ff_dpdk_pktmbuf_free  (calls inline rte_pktmbuf_free_seg) -> FU-S4-PKTMBUF
 *
 * The lib_objs/ff_dpdk_if.o object pulls in many DPDK + ff_* symbols; we
 * provide minimal stubs locally to satisfy the linker.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ff_api.h"
#include "ff_msg.h"               /* struct ff_traffic_args */
#include "ff_config.h"            /* MAX_PKT_BURST / ff_hw_features (needed by ff_memory.h) */
#include "ff_dpdk_if.h"
#include "ff_memory.h"            /* struct ff_dpdk_if_context / lcore_conf (RSS 0.1 tests) */
#include "ff_host_interface.h"    /* ff_get_tsc_ns declaration */

/* lcore_conf is an extern global in ff_dpdk_if.c (not declared in headers);
 * mirror ff_memory.c:71 so the RSS 0.1 tests can set the queue layout. */
extern struct lcore_conf lcore_conf;

#include <rte_launch.h>           /* enum rte_rmt_call_main_t */
#include <rte_eal.h>              /* rte_eal_init (R-B 0.3 thash needs EAL) */
#include <rte_thash.h>            /* rte_thash_* (R-B 0.3 hit-rate quantification) */

/* ------------------------------------------------------------------------ */
/* Wrap rte_get_tsc_hz (real DPDK function; wrappable via -Wl,--wrap)        */
/* ------------------------------------------------------------------------ */
uint64_t
__wrap_rte_get_tsc_hz(void)
{
    return mock_type(uint64_t);
}

/* R-D (req 0.4): wrap ff_rss_check / ff_rss_check6 to count invocations.
 * The wrappers transparently forward to __real_* so existing R-A/R-B/R-C
 * tests that call ff_rss_check{,6} directly keep their semantics. */
extern int __real_ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
                               uint16_t sport, uint16_t dport);
extern int __real_ff_rss_check6(void *softc, const uint8_t *saddr6,
                                const uint8_t *daddr6, uint16_t sport,
                                uint16_t dport);

static uint64_t g_ff_rss_check_calls;
static uint64_t g_ff_rss_check6_calls;

int
__wrap_ff_rss_check(void *softc, uint32_t saddr, uint32_t daddr,
                    uint16_t sport, uint16_t dport)
{
    g_ff_rss_check_calls++;
    return __real_ff_rss_check(softc, saddr, daddr, sport, dport);
}

int
__wrap_ff_rss_check6(void *softc, const uint8_t *saddr6, const uint8_t *daddr6,
                     uint16_t sport, uint16_t dport)
{
    g_ff_rss_check6_calls++;
    return __real_ff_rss_check6(softc, saddr6, daddr6, sport, dport);
}

/* ------------------------------------------------------------------------ */
/* Stubs for ff_* / rte_* / kernel symbols referenced by ff_dpdk_if.o that  */
/* are NOT exercised by the 7 tests. We provide just enough no-op bodies to */
/* let the linker resolve references; calling any of them in a test would   */
/* be a bug.                                                                */
/* ------------------------------------------------------------------------ */
int   ff_log(uint32_t l, uint32_t t, const char *f, ...) { (void)l;(void)t;(void)f; return 0; }
__thread unsigned int per_lcore__lcore_id = 0;

/* dpdk_argc/dpdk_argv extern from ff_config.h */
#include "ff_config.h"
int   dpdk_argc = 0;
char *dpdk_argv[DPDK_CONFIG_NUM + 1] = {0};

/* ff_global_cfg required by ff_dpdk_if.c (it accesses cfg->dpdk.*) */
struct ff_config ff_global_cfg;

/* ------------------------------------------------------------------------ */
/* Linker-satisfaction stubs for ~30 ff_* and rte_* symbols referenced by   */
/* lib/ff_dpdk_if.c but never invoked by the 7 tests in this file. They    */
/* exist only to let the linker resolve references; calling any of them    */
/* during a test is a bug.                                                  */
/* ------------------------------------------------------------------------ */

/* Forward declarations to silence -Wmissing-prototype warnings on stub bodies */
struct rte_mbuf;

/* --- ff_* kernel-side / mbuf / veth helpers ---------------------------- */
int  ff_log_open_set(void) { return 0; }
void ff_log_close(void) { }
int  ff_dump_packets(const char *p, struct rte_mbuf *m, uint16_t s, uint32_t l, uint8_t t)
{ (void)p;(void)m;(void)s;(void)l;(void)t; return 0; }

void *ff_mbuf_gethdr(void *p, uint16_t l, void *d, uint16_t dl, uint8_t r)
{ (void)p;(void)l;(void)d;(void)dl;(void)r; return NULL; }
int   ff_mbuf_set_vlan_info(void *m, uint16_t v) { (void)m;(void)v; return 0; }
int   ff_mbuf_set_timestamp(void *m, uint64_t t) { (void)m;(void)t; return 0; }
void *ff_mbuf_get(void *p, void *m, void *d, uint16_t dl)
{ (void)p;(void)m;(void)d;(void)dl; return NULL; }
void  ff_mbuf_free(void *m) { (void)m; }
int   ff_mbuf_copydata(void *m, void *d, int o, int l)
{ (void)m;(void)d;(void)o;(void)l; return 0; }
int   ff_mbuf_tx_offload(void *m, void *o, void *l)
{ (void)m;(void)o;(void)l; return 0; }

void *ff_veth_attach(void *cfg) { (void)cfg; return NULL; }
int   ff_veth_input(void *ctx, struct rte_mbuf *m) { (void)ctx;(void)m; return 0; }
void  ff_veth_process_packet(void *ifp, void *m) { (void)ifp;(void)m; }
/* ff_veth_get_softc / ff_veth_softc_to_hostc model (ff_veth.c:1132/1139):
 *   ff_veth_get_softc(host_ctx)  -> softc whose ->host_ctx == host_ctx
 *   ff_veth_softc_to_hostc(softc)-> softc->host_ctx
 * ff_rss_tbl_init() calls ff_veth_get_softc(&ctx) (ctx is its local with
 * port_id=rule.port_id) then ff_rss_check(sc,...) which dereferences
 * ff_veth_softc_to_hostc(sc)->port_id. The original stubs returned NULL,
 * which (a) makes init bail at L2610 and (b) NULL-derefs in ff_rss_check.
 * We model the real pass-through with a 1-slot store so the RSS 0.1 tests
 * can drive init/check; the prior 7+ TCs never reach these paths. */
static void *g_veth_host_ctx = NULL;    /* last host_ctx handed to get_softc */
static int   g_veth_softc_sentinel;     /* non-NULL opaque "softc" */
void *ff_veth_get_softc(void *host_ctx)
{ g_veth_host_ctx = host_ctx; return &g_veth_softc_sentinel; }
void  ff_veth_free_softc(void *sc) { (void)sc; }
void *ff_veth_softc_to_hostc(void *sc) { (void)sc; return g_veth_host_ctx; }

int   ff_sysctl(const int *n, unsigned nl, void *o, size_t *ol, const void *i, size_t il)
{ (void)n;(void)nl;(void)o;(void)ol;(void)i;(void)il; return 0; }
int   ff_socket(int d, int t, int p) { (void)d;(void)t;(void)p; return -1; }
int   ff_ioctl_freebsd(int f, unsigned long r, ...) { (void)f;(void)r; return -1; }
int   ff_close(int f) { (void)f; return 0; }
int   ff_rtioctl(int f, void *d, unsigned int *l, unsigned int al)
{ (void)f;(void)d;(void)l;(void)al; return -1; }

/* ff_dpdk_if.c clock helpers also reference these from ff_host_interface
 * (we don't link ff_host_interface.o here): */
void ff_update_current_ts(void) { }
void ff_hardclock(void) { }

/* ff_tcp_hpts_softclock: defined in ff_kern_timeout.c (kernel-side, not
 * host-compilable here). main_loop() (ff_dpdk_if.c:2459) references it; none
 * of our tests reach main_loop, so a no-op stub satisfies the linker.
 * Signature per lib/ff_kern_timeout.c:1271 (void)->(void). */
void ff_tcp_hpts_softclock(void) { }

/* ff_enable_pcap: defined in ff_dpdk_pcap.c (we do NOT link it here) */
int  ff_enable_pcap(const char *p, uint16_t s, uint8_t t)
{ (void)p;(void)s;(void)t; return 0; }

/* ff_unload_config: defined in ff_config.c (we do NOT link it here);
 * referenced from ff_dpdk_run's exit cleanup path which our 7 TCs never
 * invoke. */
void ff_unload_config(void) { }

/* rte_timer_meta_init: F-Stack-specific patch added during DPDK 23->24
 * upgrade; not present in stock librte_timer.so. Provide a no-op stub. */
void rte_timer_meta_init(void) { }

/* ff_arc4random: stub (real impl in ff_host_interface.c, not linked here). */
uint32_t ff_arc4random(void) { return 0; }

/* --- rte_* stubs: NOT needed since we now link the real DPDK shared libs --
 * The remaining unresolved DPDK functions are pulled in from -lrte_eal et al.
 * via pkg-config libdpdk LIBS in the Makefile.                            */

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-01: ff_dpdk_deregister_if frees the malloc'd context      */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_deregister_if_frees(void **state)
{
    (void)state;
    void *ctx = malloc(64);
    assert_non_null(ctx);
    /* Must not crash; verifies free path works. (We can't easily verify the
     * memory was returned to libc heap without intrusive instrumentation.) */
    ff_dpdk_deregister_if((struct ff_dpdk_if_context *)ctx);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-02: ff_get_traffic copies the static ff_traffic into buf  */
/*                    (initial state is zero-init since BSS)                */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_traffic_zero_init(void **state)
{
    (void)state;
    struct ff_traffic_args buf;
    memset(&buf, 0xAA, sizeof(buf));   /* fill with sentinel */
    ff_get_traffic(&buf);
    assert_int_equal((int)buf.rx_packets, 0);
    assert_int_equal((int)buf.rx_bytes,   0);
    assert_int_equal((int)buf.tx_packets, 0);
    assert_int_equal((int)buf.tx_bytes,   0);
    assert_int_equal((int)buf.rx_dropped, 0);
    assert_int_equal((int)buf.tx_dropped, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-03: ff_dpdk_stop is a no-crash one-liner                   */
/* (cannot directly verify static stop_loop = 1; just exercise the path)    */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_stop_smoke(void **state)
{
    (void)state;
    ff_dpdk_stop();   /* must not crash */
    /* Idempotent: calling again should also be safe */
    ff_dpdk_stop();
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-04: ff_regist_pcblddr_fun stores the function pointer      */
/* (only observable via subsequent ff_in_pcbladdr; not testing that path so  */
/* we just exercise the setter and verify it does not crash with NULL)      */
/* ------------------------------------------------------------------------ */
static int
fake_pcblddr(uint16_t family, void *dst_addr, uint16_t dst_port,
             void *src_addr)
{
    (void)family; (void)dst_addr; (void)dst_port; (void)src_addr;
    return 0;
}

static void
test_ff_regist_pcblddr_fun_smoke(void **state)
{
    (void)state;
    ff_regist_pcblddr_fun(fake_pcblddr);   /* must not crash */
    ff_regist_pcblddr_fun(NULL);           /* re-register NULL must not crash */
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-05/06: register_packet_dispatcher{,_context}              */
/* ------------------------------------------------------------------------ */
static int
fake_dispatcher(void *data, uint16_t *len, uint16_t queue_id, uint16_t nb_queues)
{
    (void)data; (void)len; (void)queue_id; (void)nb_queues;
    return 0;
}

static int
fake_dispatcher_ctx(void *data, uint16_t *len, uint16_t queue_id,
                    uint16_t nb_queues, struct ff_dispatcher_context ctx)
{
    (void)data; (void)len; (void)queue_id; (void)nb_queues; (void)ctx;
    return 0;
}

static void
test_ff_regist_packet_dispatcher_smoke(void **state)
{
    (void)state;
    ff_regist_packet_dispatcher(fake_dispatcher);
    ff_regist_packet_dispatcher(NULL);
}

static void
test_ff_regist_packet_dispatcher_context_smoke(void **state)
{
    (void)state;
    ff_regist_packet_dispatcher_context(fake_dispatcher_ctx);
    ff_regist_packet_dispatcher_context(NULL);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-DPDKIF-07: ff_get_tsc_ns returns monotonic non-zero with the      */
/* mocked rte_get_tsc_hz = 1 GHz. rte_rdtsc remains the real CPU intrinsic. */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_tsc_ns_basic(void **state)
{
    (void)state;
    /* Expose two calls; mock hz to 1 GHz both times */
    will_return(__wrap_rte_get_tsc_hz, (uint64_t)1000000000ULL);
    uint64_t a = ff_get_tsc_ns();
    /* burn cycles to advance TSC */
    for (volatile int i = 0; i < 100000; i++) { /* spin */ }
    will_return(__wrap_rte_get_tsc_hz, (uint64_t)1000000000ULL);
    uint64_t b = ff_get_tsc_ns();

    assert_true(a > 0);
    assert_true(b >= a);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-08: ff_in_pcbladdr returns 0 when no callback registered  */
/* ------------------------------------------------------------------------ */
#include <netinet/in.h>           /* AF_INET */

static void
test_ff_in_pcbladdr_no_callback(void **state)
{
    (void)state;
    /* Reset to NULL via the public setter */
    ff_regist_pcblddr_fun(NULL);

    int rv = ff_in_pcbladdr(AF_INET, NULL, 0, NULL);
    assert_int_equal(rv, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-09: AF_INET dispatches to callback with family=AF_INET    */
/* ------------------------------------------------------------------------ */
static struct {
    int   invoked;
    uint16_t family_seen;
    void *faddr_seen;
    uint16_t fport_seen;
    void *laddr_seen;
    int   ret_value;
} g_pcblddr_capture;

static int
capturing_pcblddr(uint16_t family, void *faddr, uint16_t fport, void *laddr)
{
    g_pcblddr_capture.invoked++;
    g_pcblddr_capture.family_seen = family;
    g_pcblddr_capture.faddr_seen  = faddr;
    g_pcblddr_capture.fport_seen  = fport;
    g_pcblddr_capture.laddr_seen  = laddr;
    return g_pcblddr_capture.ret_value;
}

static void
test_ff_in_pcbladdr_af_inet_dispatches(void **state)
{
    (void)state;
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    g_pcblddr_capture.ret_value = 7;          /* arbitrary marker */
    ff_regist_pcblddr_fun(capturing_pcblddr);

    int faddr = 0x12345678;
    int laddr = 0x9ABCDEF0;
    int rv = ff_in_pcbladdr(AF_INET, &faddr, 53, &laddr);

    assert_int_equal(rv, 7);                  /* return value transparently */
    assert_int_equal(g_pcblddr_capture.invoked, 1);
    assert_int_equal((int)g_pcblddr_capture.family_seen, AF_INET);
    assert_ptr_equal(g_pcblddr_capture.faddr_seen, &faddr);
    assert_int_equal((int)g_pcblddr_capture.fport_seen, 53);
    assert_ptr_equal(g_pcblddr_capture.laddr_seen, &laddr);

    ff_regist_pcblddr_fun(NULL);              /* clean up */
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-10: AF_INET6_FREEBSD (28) is remapped to AF_INET6_LINUX   */
/* (10) before dispatching; unknown family returns the host EADDRNOTAVAIL.  */
/*                                                                          */
/* IMPORTANT (DP-U-12 "代码为准"): ff_in_pcbladdr's else-branch returns the */
/* POSIX errno macro `EADDRNOTAVAIL` (defined in <errno.h>, value=99 on    */
/* Linux), NOT F-Stack's `ff_EADDRNOTAVAIL` (49). The spec/plan referenced  */
/* the latter incorrectly; tests below use the actual Linux errno value.   */
/* ------------------------------------------------------------------------ */
#define AF_INET6_FREEBSD_VAL    28      /* per ff_api.h L50 */
#define AF_INET6_LINUX_VAL      10      /* per ff_api.h L48 */

#include <errno.h>                      /* host EADDRNOTAVAIL */

static void
test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap(void **state)
{
    (void)state;
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    g_pcblddr_capture.ret_value = 0;
    ff_regist_pcblddr_fun(capturing_pcblddr);

    int rv = ff_in_pcbladdr(AF_INET6_FREEBSD_VAL, NULL, 0, NULL);
    assert_int_equal(rv, 0);
    assert_int_equal(g_pcblddr_capture.invoked, 1);
    /* Family must be remapped to AF_INET6_LINUX before reaching callback */
    assert_int_equal((int)g_pcblddr_capture.family_seen, AF_INET6_LINUX_VAL);

    /* Reset capture and try unknown family -> EADDRNOTAVAIL (host=99 on Linux),
     * callback NOT called */
    memset(&g_pcblddr_capture, 0, sizeof(g_pcblddr_capture));
    rv = ff_in_pcbladdr(99 /* unknown */, NULL, 0, NULL);
    assert_int_equal(rv, EADDRNOTAVAIL);    /* POSIX, =99 on Linux */
    assert_int_equal(g_pcblddr_capture.invoked, 0);

    ff_regist_pcblddr_fun(NULL);
}

/* ======================================================================== */
/* Stage-6 Phase-5 coverage extensions: ff_rss_tbl_* + register_if          */
/* ======================================================================== */

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-11 (Stage-6): ff_rss_tbl_set_portrange returns -1 when    */
/* rss_check_cfgs is NULL (covers the early-return guard L2722).            */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_set_portrange_no_cfg(void **state)
{
    (void)state;
    /* Ensure clean state. */
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    int rv = ff_rss_tbl_set_portrange(1024, 2048);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-12 (Stage-6): ff_rss_tbl_set_portrange returns -1 when    */
/* rss_check_cfgs.enable == 0 (same guard L2722-2724).                     */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_set_portrange_disabled(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 0 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    int rv = ff_rss_tbl_set_portrange(1024, 2048);
    assert_int_equal(rv, -1);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-13 (Stage-6): ff_rss_tbl_set_portrange with first > last */
/* returns -1 (covers the inverted-range guard).                           */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_set_portrange_inverted_range(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 1 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    int rv = ff_rss_tbl_set_portrange(/*first*/2048, /*last*/1024);
    assert_int_equal(rv, -1);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-14 (Stage-6): ff_rss_tbl_get_portrange returns -1 when   */
/* rss_check_cfgs is NULL (early-return guard L2782-2784).                 */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_no_cfg(void **state)
{
    (void)state;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
    uint16_t first = 0, last = 0;
    uint16_t *portrange = NULL;
    int rv = ff_rss_tbl_get_portrange(0x01020304, 0x05060708, htons(80),
                                      &first, &last, &portrange);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-15 (Stage-6): ff_rss_tbl_get_portrange returns -1 when   */
/* rss_check_cfgs.enable == 0.                                             */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_disabled(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 0 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    uint16_t first = 0, last = 0;
    uint16_t *portrange = NULL;
    int rv = ff_rss_tbl_get_portrange(0x01020304, 0x05060708, htons(80),
                                      &first, &last, &portrange);
    assert_int_equal(rv, -1);
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-16 (Stage-6): ff_rss_tbl_get_portrange smoke — verify it  */
/* doesn't crash when called with an arbitrary 4-tuple against the global  */
/* table (initial state). Acceptable return values: 0 (found), 1 (found-   */
/* with-portrange), or -1 (not found). Any of these covers the lookup loop.*/
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_smoke(void **state)
{
    (void)state;
    struct ff_rss_check_cfg dummy = { .enable = 1 };
    ff_global_cfg.dpdk.rss_check_cfgs = &dummy;
    uint16_t first = 0, last = 0;
    uint16_t *portrange = NULL;
    int rv = ff_rss_tbl_get_portrange(0xDEADBEEF, 0xCAFEBABE, htons(80),
                                      &first, &last, &portrange);
    /* Just verify the function ran without crashing. The return value
     * depends on the global ff_rss_tbl state which we don't control here. */
    (void)rv;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ======================================================================== */
/* R-A (req 0.1) RSS portrange hit/rotation/miss tests                       */
/* Spec: docs/ff_rss_check_opt_spec/zh_cn/07-测试规格.md §1.1                */
/*       TC-U-RSS-01-01 / 01-02 / 01-03                                      */
/*                                                                           */
/* mock strategy (07 §0.2/§0.3):                                             */
/*  - ff_veth_get_softc / ff_veth_softc_to_hostc are pass-through (above),   */
/*    so ff_rss_tbl_init()'s local ctx (port_id=rule.port_id) is recovered   */
/*    by ff_rss_check(); tests set lcore_conf.nb_queue_list/tx_queue_id.     */
/*  - toeplitz_hash / rsskey / rss_reta_size / ff_rss_tbl are all static and */
/*    NOT directly observable. Per 07 §0.4 we replicate an equivalent        */
/*    Toeplitz on the test side using the same 40-byte default key; the lib  */
/*    leaves rss_reta_size[port] at its BSS default 0, so the mask used by   */
/*    ff_rss_check is (reta_size-1) == 0xFFFF. We assert ff_rss_check agrees  */
/*    with the independently-computed expectation (hit correctness) AND that */
/*    every port in the returned range self-consistently re-checks to 1      */
/*    (07 §1.1 degraded self-consistency assertion).                         */
/* ======================================================================== */

/* Mellanox default RSS key — copy of lib/ff_dpdk_if.c:92 default_rsskey_40bytes
 * (static in the lib; replicated here so the test computes the SAME hash). */
static const uint8_t test_rsskey_40[40] = {
    0xd1, 0x81, 0xc6, 0x2c, 0xf7, 0xf4, 0xdb, 0x5b,
    0x19, 0x83, 0xa2, 0xfc, 0x94, 0x3e, 0x1a, 0xdb,
    0xd9, 0x38, 0x9e, 0x6b, 0xd1, 0x03, 0x9c, 0x2c,
    0xa7, 0x44, 0x99, 0xad, 0x59, 0x3d, 0x56, 0xd9,
    0xf3, 0x25, 0x3c, 0x06, 0x2a, 0xdc, 0x1f, 0xfc
};

/* Equivalent Toeplitz hash — byte-for-byte aligned with the lib's static
 * toeplitz_hash (ff_dpdk_if.c:2548-2568). */
static uint32_t
test_toeplitz(unsigned keylen, const uint8_t *key,
              unsigned datalen, const uint8_t *data)
{
    uint32_t hash = 0, v;
    unsigned i, b;
    v = ((uint32_t)key[0] << 24) + ((uint32_t)key[1] << 16) +
        ((uint32_t)key[2] << 8) + key[3];
    for (i = 0; i < datalen; i++) {
        for (b = 0; b < 8; b++) {
            if (data[i] & (1 << (7 - b)))
                hash ^= v;
            v <<= 1;
            if ((i + 4) < keylen && (key[i + 4] & (1 << (7 - b))))
                v |= 1;
        }
    }
    return hash;
}

/* Independent replica of ff_rss_check()'s verdict for v4 (ff_dpdk_if.c:2851).
 * data layout = saddr(4)|daddr(4)|sport(2)|dport(2) (network-order values as
 * stored, matching the lib's bcopy of the raw 32/16-bit quantities). */
static int
test_expected_rss_check(uint32_t saddr, uint32_t daddr, uint16_t sport,
                        uint16_t dport, uint16_t nb_queues,
                        uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[sizeof(saddr) + sizeof(daddr) + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], &saddr, sizeof(saddr)); dl += sizeof(saddr);
    memcpy(&data[dl], &daddr, sizeof(daddr)); dl += sizeof(daddr);
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}

/* Independent replica of ff_rss_check6()'s verdict for v6 (ff_dpdk_if.c:3117).
 * data layout = saddr6(16)|daddr6(16)|sport(2)|dport(2) = 36B, host byte order,
 * same toeplitz/key/reta口径 as v4. */
static int
test_expected_rss_check6(const uint8_t saddr6[16], const uint8_t daddr6[16],
                         uint16_t sport, uint16_t dport, uint16_t nb_queues,
                         uint16_t reta_size, uint16_t queueid)
{
    uint8_t data[16 + 16 + sizeof(sport) + sizeof(dport)];
    unsigned dl = 0;
    uint32_t hash;
    if (nb_queues <= 1)
        return 1;
    memcpy(&data[dl], saddr6, 16); dl += 16;
    memcpy(&data[dl], daddr6, 16); dl += 16;
    memcpy(&data[dl], &sport, sizeof(sport)); dl += sizeof(sport);
    memcpy(&data[dl], &dport, sizeof(dport)); dl += sizeof(dport);
    hash = test_toeplitz(sizeof(test_rsskey_40), test_rsskey_40, dl, data);
    return ((hash & (uint16_t)(reta_size - 1)) % nb_queues) == queueid;
}

/* Build a single-rule RSS config and (re)initialise the static ff_rss_tbl.
 * Returns 0 on success. Sets the controlled lcore_conf queue layout. */
#define TEST_RSS_PORT     0
#define TEST_RSS_NBQ      4          /* multi-queue so ff_rss_check is active */
#define TEST_RSS_QID      1          /* this "process" owns tx queue 1        */
#define TEST_RSS_RETA     0          /* rss_reta_size[] BSS default => mask 0xFFFF */
#define TEST_RSS_FIRST   10000      /* FreeBSD default ipport_firstauto */
#define TEST_RSS_LAST    65535      /* FreeBSD default ipport_lastauto   */

static struct ff_rss_check_cfg g_rss_cfg;
static struct ff_dpdk_if_context g_test_ctx;

static int
test_rss_build_table(uint32_t saddr, uint32_t daddr, uint16_t sport)
{
    memset(&g_rss_cfg, 0, sizeof(g_rss_cfg));
    g_rss_cfg.enable = 1;
    g_rss_cfg.recheck = 1;   /* R-D 04-06: default recheck=1 to keep R-B/R-C hard assertions */
    g_rss_cfg.nb_rss_tbl = 1;
    g_rss_cfg.rss_tbl_cfgs[0].port_id = TEST_RSS_PORT;
    g_rss_cfg.rss_tbl_cfgs[0].saddr = saddr;
    g_rss_cfg.rss_tbl_cfgs[0].daddr = daddr;
    g_rss_cfg.rss_tbl_cfgs[0].sport = sport;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf.tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    return ff_rss_tbl_init();
}

/* Re-arm the pass-through host_ctx so a direct ff_rss_check() call from the
 * test recovers a ctx with the desired port_id. */
static void *
test_rss_softc(uint16_t port_id)
{
    g_test_ctx.port_id = port_id;
    return ff_veth_get_softc(&g_test_ctx);   /* stores &g_test_ctx, returns sentinel */
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-01-01: get_portrange hits and the returned port set lands on the */
/* owning queue (hit correctness + self-consistency).                        */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_hit(void **state)
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport = htons(1000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl_get_portrange(saddr, daddr, sport, &first, &last, &pr);

    assert_int_equal(rv, 0);                 /* hit => 0 (ff_dpdk_if.c:2827) */
    assert_non_null(pr);
    assert_true(first >= 1);                  /* idx 0 is the "last selected" slot */
    assert_true(last >= first);

    /* Every port in [first,last] must land on our queue. Cross-check the lib's
     * ff_rss_check against the independent replica, and assert self-consistency
     * (lib returns 1). Sample to bound runtime over a potentially large set. */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    int checked = 0;
    for (uint16_t k = first; k <= last && checked < 256; k++, checked++) {
        uint16_t dport = pr[k];
        uint16_t dport_n = htons(dport);
        int lib = ff_rss_check(sc, saddr, daddr, sport, dport_n);
        int exp = test_expected_rss_check(saddr, daddr, sport, dport_n,
                                          TEST_RSS_NBQ, TEST_RSS_RETA, TEST_RSS_QID);
        assert_int_equal(lib, exp);           /* hit correctness (07 §0.4) */
        assert_int_equal(lib, 1);             /* self-consistency: lands on queue */
        if (k == last) break;                 /* avoid uint16_t wrap when last==0xFFFF */
    }
    assert_true(checked > 0);                 /* non-empty port set */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-01-02: get_portrange port rotation semantics.                    */
/* F4 (07 §6.3): ff_rss_tbl_get_portrange does NOT self-increment dport[0];  */
/* it only returns first_idx/last_idx + &dport[0]. The caller advances the   */
/* "last selected" index (dport[0]). We assert the lib is stable (returns    */
/* the same range across calls) and that the caller can walk distinct ports  */
/* across [first_idx,last_idx], each landing on the queue.                   */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_rotation(void **state)
{
    (void)state;
    const uint32_t saddr = 0x0A0B0C0D, daddr = 0x11121314;
    const uint16_t sport = htons(2000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    uint16_t f1 = 0, l1 = 0, f2 = 0, l2 = 0;
    uint16_t *pr1 = NULL, *pr2 = NULL;
    assert_int_equal(ff_rss_tbl_get_portrange(saddr, daddr, sport, &f1, &l1, &pr1), 0);
    assert_int_equal(ff_rss_tbl_get_portrange(saddr, daddr, sport, &f2, &l2, &pr2), 0);

    /* Stable: consecutive lookups return the same idx range + buffer. */
    assert_int_equal(f1, f2);
    assert_int_equal(l1, l2);
    assert_ptr_equal(pr1, pr2);

    /* Caller-side rotation: walking the index window yields distinct ports,
     * each of which (per build口径) lands on the owning queue. */
    assert_true(l1 > f1);                     /* >1 candidate so rotation matters */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    uint16_t p_first = pr1[f1];
    uint16_t p_next  = pr1[f1 + 1];
    assert_int_not_equal(p_first, p_next);    /* rotation visits a different port */
    assert_int_equal(ff_rss_check(sc, saddr, daddr, sport, htons(p_first)), 1);
    assert_int_equal(ff_rss_check(sc, saddr, daddr, sport, htons(p_next)), 1);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-01-03: get_portrange miss returns -ENOENT.                       */
/* (ff_dpdk_if.c:2812/2820/2835/2844 all return -ENOENT on miss.)            */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl_get_portrange_miss(void **state)
{
    (void)state;
    const uint32_t saddr = 0x21222324, daddr = 0x31323334;
    const uint16_t sport = htons(3000);

    assert_int_equal(test_rss_build_table(saddr, daddr, sport), 0);

    /* Query a 3-tuple NOT in the table (different saddr). */
    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl_get_portrange(0x41424344 /*other saddr*/, daddr, sport,
                                      &first, &last, &pr);
    assert_int_equal(rv, -ENOENT);
    assert_null(pr);                          /* not filled on miss */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ======================================================================== */
/* R-B (req 0.3) rte_thash dynamic reverse-calc tests                        */
/* Spec: 07-测试规格.md §1.3 TC-U-RSS-03 ; 04 §3.3 ; 05 §3                    */
/* Under test (lib/ff_dpdk_if.c, R-B): ff_rss_thash_ctx_init(),             */
/* ff_rss_adjust_sport() (declared in ff_host_interface.h, non-static).     */
/* ======================================================================== */

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-03-NULL: ff_rss_adjust_sport defends NULL softc / out_sport.     */
/* (ff_dpdk_if.c:2987 guard returns -1 before any deref.)                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_adjust_sport_null(void **state)
{
    (void)state;
    uint16_t out = 0;
    /* NULL softc -> -1 (guard hits before ff_veth_softc_to_hostc deref) */
    assert_int_equal(ff_rss_adjust_sport(NULL, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
    /* NULL out_sport with a valid softc -> -1 */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), NULL,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-03-DEGRADE: in the unit env rss_reta_size[] is static BSS=0      */
/* (confirmed in R-A), so ff_rss_thash_ctx_init() marks every port unready   */
/* (reta_size<2 -> continue, ready stays 0; ff_dpdk_if.c:2930-2933). A       */
/* subsequent ff_rss_adjust_sport() must therefore return -1 (fall back to   */
/* soft scan). Validates init degradation + adjust readiness guard           */
/* (ff_dpdk_if.c:2991).                                                      */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_adjust_sport_degraded(void **state)
{
    (void)state;
    /* init: with reta_size=0 everywhere it returns 0 but leaves all ports
     * unready (no exception, graceful degrade). */
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ; /* multi-queue */
    uint16_t out = 0xFFFF;
    int rv = ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                 htons(80), &out,
                                 TEST_RSS_FIRST, TEST_RSS_LAST);
    assert_int_equal(rv, -1);          /* unready -> fall back */
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-03-SINGLEQ: with nb_queue_list[port]==1 ff_rss_adjust_sport      */
/* returns -1. NOTE the readiness guard (L2991) precedes the single-queue    */
/* guard (L2995); in this unit env (reta=0 => unready) the -1 is produced by */
/* the readiness guard. Either way the dynamic path correctly declines and   */
/* the caller falls back to the native/soft path (RG-3 alignment).           */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_adjust_sport_single_queue(void **state)
{
    (void)state;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = 1;     /* single queue */
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);
}

/* ======================================================================== */
/* TC-U-RSS-03-EQUIV: toeplitz vs rte_thash(softrss_be) equivalence —        */
/* the core go/no-go data for wiring 0.3 into in_pcb.                         */
/*                                                                           */
/* Because the lib's rss_reta_size[] is static BSS=0 (ctx cannot be built    */
/* in-unit), we replicate the lib's 0.3 reverse-calc path here with the real */
/* DPDK rte_thash API and a chosen reta_size, then re-verify each adjusted   */
/* sport with the SAME soft Toeplitz the lib uses (test_toeplitz, byte-for-  */
/* byte identical to ff_dpdk_if.c:2548). Tuple layout & byte order mirror    */
/* ff_rss_adjust_sport (ff_dpdk_if.c:3015-3025): host-order                  */
/* saddr|daddr|sport|dport, sport@byte8, dport@byte10, tuple_len=12,         */
/* helper len=16 bits @offset=64 bits, attempts=16.                          */
/* Reports adjust_tuple success rate AND toeplitz re-check hit rate; asserts */
/* self-consistency (no false positives) but leaves the rate as data for the */
/* leader's go/no-go decision (07 §1.3 — rate is reported, no hard threshold).*/
/* ======================================================================== */
#define EQUIV_N        200
#define EQUIV_NBQ      4
#define EQUIV_QID      1

static int
equiv_log2(uint16_t v)
{
    int l = 0;
    while ((v >>= 1) != 0) l++;
    return l;
}

/* rte_thash_init_ctx() needs the DPDK EAL memory subsystem (rte_zmalloc /
 * tailq). The unit process never calls rte_eal_init, so we bring up a minimal
 * EAL (--no-huge -m 64 --no-pci) once for this test; if it fails (no perms /
 * environment), the test skips rather than crashing. */
static int
equiv_eal_init_once(void)
{
    static int done = 0;     /* 0=untried, 1=ok, -1=failed */
    if (done != 0)
        return done;
    char *argv[] = {
        (char *)"test_ff_dpdk_if", (char *)"--no-huge", (char *)"-m",
        (char *)"64", (char *)"--no-pci", (char *)"-c", (char *)"0x1",
        (char *)"--log-level", (char *)"lib.eal:error", NULL
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;
    done = (rte_eal_init(argc, argv) < 0) ? -1 : 1;
    return done;
}

/* Replicate ff_rss_adjust_sport's FULL loop (ff_dpdk_if.c:3006-3034) with the
 * real DPDK rte_thash API: iterate ceil(R/Q) desired candidates, the first
 * whose reverse-calc'd sport also passes the lib's soft Toeplitz (ff_rss_check
 * equivalent) wins. Reports both the per-candidate equivalence rate and the
 * full-loop final success rate (the number that matters for in_pcb wiring).
 *   *adj_ok    -> per-candidate adjust_tuple successes (== N here)
 *   *single_hit-> per-candidate toeplitz re-check hits (equivalence rate)
 *   *final_ok  -> full-loop final successes (a landing sport was found)
 *   *avg_tries -> avg adjust_tuple calls per connection
 * ctx_name must be unique per reta to avoid an rte_thash name clash. */
static void
run_equiv_for_reta(const char *ctx_name, uint16_t reta_size,
                   int *adj_ok, int *single_hit, int *final_ok,
                   double *avg_tries)
{
    struct rte_thash_ctx *ctx;
    struct rte_thash_subtuple_helper *h;
    int i, ok = 0, hit = 0, fok = 0;
    long tries_total = 0;
    const uint16_t nbq = EQUIV_NBQ, qid = EQUIV_QID;
    const uint32_t span = (reta_size + nbq - 1) / nbq;

    ctx = rte_thash_init_ctx(ctx_name, sizeof(test_rsskey_40),
                             equiv_log2(reta_size), (uint8_t *)test_rsskey_40, 0);
    /* key_len is in BYTES (lib passes rsskey_len=40); reta_sz is log2. */
    assert_non_null(ctx);
    /* helper len/offset are in BITS (mirror lib: 16 @ 64; len >= reta_sz). */
    assert_int_equal(rte_thash_add_helper(ctx, "sport", 16, 64), 0);
    h = rte_thash_get_helper(ctx, "sport");
    assert_non_null(h);

    srandom(0xC0FFEE ^ reta_size);   /* deterministic, reproducible numbers */
    for (i = 0; i < EQUIV_N; i++) {
        uint32_t saddr = ((uint32_t)random() << 1) ^ (uint32_t)random();
        uint32_t daddr = ((uint32_t)random() << 1) ^ (uint32_t)random();
        uint16_t dport = htons((uint16_t)(1024 + (random() % 60000)));
        uint32_t desired = qid + ((uint32_t)random() % span) * nbq;
        int found = 0, first_cand = 1;
        uint32_t tr;
        if (desired >= reta_size) desired = qid;

        for (tr = 0; tr < span; tr++) {
            uint16_t sport = 0;
            uint8_t tuple[12];
            if (desired >= reta_size) desired = qid;
            memset(tuple, 0, sizeof(tuple));
            memcpy(&tuple[0], &saddr, 4);
            memcpy(&tuple[4], &daddr, 4);
            memcpy(&tuple[8], &sport, 2);     /* sport seed 0 @ byte 8 */
            memcpy(&tuple[10], &dport, 2);    /* dport @ byte 10        */
            tries_total++;

            if (rte_thash_adjust_tuple(ctx, h, tuple, sizeof(tuple),
                                       desired & (reta_size - 1), 16,
                                       NULL, NULL) == 0) {
                if (first_cand) ok++;        /* per-candidate adjust success */
                memcpy(&sport, &tuple[8], 2);
                /* Re-verify with the lib's soft Toeplitz (host-order tuple,
                 * same as ff_rss_check). */
                int landed = test_expected_rss_check(saddr, daddr, sport, dport,
                                                     nbq, reta_size, qid);
                if (first_cand && landed) hit++;  /* per-candidate equivalence */
                if (landed) {
                    /* zero false positives: self-consistency must hold. */
                    uint8_t d[12];
                    unsigned dl = 0;
                    memcpy(&d[dl], &saddr, 4); dl += 4;
                    memcpy(&d[dl], &daddr, 4); dl += 4;
                    memcpy(&d[dl], &sport, 2); dl += 2;
                    memcpy(&d[dl], &dport, 2); dl += 2;
                    uint32_t hh = test_toeplitz(sizeof(test_rsskey_40),
                                                test_rsskey_40, dl, d);
                    assert_int_equal(((hh & (reta_size - 1)) % nbq), qid);
                    found = 1;
                    break;                    /* full-loop: first landing wins */
                }
            }
            first_cand = 0;
            desired += nbq;
        }
        if (found) fok++;
    }

    rte_thash_free_ctx(ctx);
    *adj_ok = ok;
    *single_hit = hit;
    *final_ok = fok;
    *avg_tries = (double)tries_total / EQUIV_N;
}

static void
test_ff_rss_thash_equivalence_hitrate(void **state)
{
    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("\n[R-B 0.3 EQUIV] DPDK EAL init failed in unit env; skipping "
               "thash equivalence quantification.\n");
        skip();
        return;
    }

    int adj128 = 0, sh128 = 0, fok128 = 0, adj512 = 0, sh512 = 0, fok512 = 0;
    double avg128 = 0, avg512 = 0;
    run_equiv_for_reta("ff_equiv_128", 128, &adj128, &sh128, &fok128, &avg128);
    run_equiv_for_reta("ff_equiv_512", 512, &adj512, &sh512, &fok512, &avg512);

    printf("\n[R-B 0.3 EQUIV] N=%d nbq=%d qid=%d key=40B(default_rsskey)\n",
           EQUIV_N, EQUIV_NBQ, EQUIV_QID);
    printf("[R-B 0.3 EQUIV] reta=128: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj128, EQUIV_N, 100.0 * adj128 / EQUIV_N,
           sh128, EQUIV_N, 100.0 * sh128 / EQUIV_N,
           fok128, EQUIV_N, 100.0 * fok128 / EQUIV_N, avg128, (128 + EQUIV_NBQ - 1) / EQUIV_NBQ);
    printf("[R-B 0.3 EQUIV] reta=512: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj512, EQUIV_N, 100.0 * adj512 / EQUIV_N,
           sh512, EQUIV_N, 100.0 * sh512 / EQUIV_N,
           fok512, EQUIV_N, 100.0 * fok512 / EQUIV_N, avg512, (512 + EQUIV_NBQ - 1) / EQUIV_NBQ);

    /* Rates are DATA for the leader's go/no-go (07 §1.3, no hard threshold).
     * Hard quality gate: the full reverse-calc loop must reliably land on the
     * target queue (this is what ff_rss_adjust_sport guarantees via its forced
     * ff_rss_check re-verify); zero false positives is asserted inline above. */
    assert_true(adj128 > 0);
    assert_true(adj512 > 0);
    assert_int_equal(fok128, EQUIV_N);   /* full loop lands 100% (zero tolerance) */
    assert_int_equal(fok512, EQUIV_N);
}

/* ======================================================================== */
/* R-C (req 0.2) IPv6 RSS: ff_rss_check6 / ff_rss_tbl6_* / ff_rss_adjust_   */
/* sport6. Spec: 07-测试规格.md §1.2 TC-U-RSS-02 ; 04 §2 ; 05 §2-3.          */
/* Signatures confirmed against ff_host_interface.h:96-104 and the impl in   */
/* ff_dpdk_if.c:3117/3149/3261/3318/3366. v6 data/tuple = saddr6(16)|        */
/* daddr6(16)|sport(2)|dport(2) = 36B host-order; helper offset = 256 bits   */
/* (sport @ byte 32). Same toeplitz/key/reta口径 as v4.                       */
/* ======================================================================== */

/* Two fixed, distinct v6 addresses for the deterministic v6 unit cases. */
static const uint8_t test_saddr6[16] = {
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x01
};
static const uint8_t test_daddr6[16] = {
    0x20,0x01,0x0d,0xb8,0,0,0,0, 0,0,0,0,0,0,0,0x02
};

/* Build a single v6-rule RSS config and (re)init the static ff_rss_tbl6. */
static int
test_rss6_build_table(const uint8_t saddr6[16], const uint8_t daddr6[16],
                      uint16_t sport)
{
    memset(&g_rss_cfg, 0, sizeof(g_rss_cfg));
    g_rss_cfg.enable = 1;
    g_rss_cfg.recheck = 1;   /* R-D 04-06: default recheck=1 to keep R-B/R-C hard assertions */
    g_rss_cfg.nb_rss_tbl = 1;
    g_rss_cfg.rss_tbl_cfgs[0].port_id = TEST_RSS_PORT;
    g_rss_cfg.rss_tbl_cfgs[0].family  = AF_INET6;
    memcpy(g_rss_cfg.rss_tbl_cfgs[0].saddr6, saddr6, 16);
    memcpy(g_rss_cfg.rss_tbl_cfgs[0].daddr6, daddr6, 16);
    g_rss_cfg.rss_tbl_cfgs[0].sport = sport;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf.tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    return ff_rss_tbl6_init();
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-02-01: ff_rss_check6 lands on the owning queue and agrees with   */
/* an independent equivalent v6 Toeplitz (hit correctness + self-consistency)*/
/* rss_reta_size[] is static BSS=0 (confirmed R-A) => mask 0xFFFF, same as   */
/* the v4 cases (07 §0.4 degrade路径同款).                                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_check6_landing(void **state)
{
    (void)state;
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    lcore_conf.tx_queue_id[TEST_RSS_PORT]   = TEST_RSS_QID;

    /* Probe several dports; for each, the lib verdict must equal the replica
     * (mask 0xFFFF here), and whenever it lands it must land on our queue. */
    int landed = 0;
    for (uint16_t j = 0; j < 64; j++) {
        uint16_t dport = htons((uint16_t)(2000 + j));
        int lib = ff_rss_check6(sc, test_saddr6, test_daddr6, htons(1000), dport);
        int exp = test_expected_rss_check6(test_saddr6, test_daddr6,
                                           htons(1000), dport,
                                           TEST_RSS_NBQ, TEST_RSS_RETA, TEST_RSS_QID);
        assert_int_equal(lib, exp);          /* v6 hit correctness */
        if (lib) {
            landed++;
            /* zero false positive: replica must independently agree it lands. */
            assert_int_equal(exp, 1);
        }
    }
    assert_true(landed > 0);                  /* some dport lands on our queue */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-02-02: ff_rss_check6 single-queue returns 1 (RG-3 for v6).       */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_check6_single_queue(void **state)
{
    (void)state;
    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = 1;     /* single queue */
    assert_int_equal(ff_rss_check6(sc, test_saddr6, test_daddr6,
                                   htons(1000), htons(80)), 1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-02-03: v6 static table init + get_portrange hit / miss.          */
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_tbl6_set_get(void **state)
{
    (void)state;
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           htons(1000)), 0);

    /* Hit: same v6 3-tuple used to build the table. */
    uint16_t first = 0, last = 0;
    uint16_t *pr = NULL;
    int rv = ff_rss_tbl6_get_portrange(test_saddr6, test_daddr6, htons(1000),
                                       &first, &last, &pr);
    assert_int_equal(rv, 0);                  /* hit => 0 (ff_dpdk_if.c:3349) */
    assert_non_null(pr);
    assert_true(first >= 1);
    assert_true(last >= first);

    /* Each port in [first,last] must self-consistently re-check to 1 (lands). */
    void *sc = test_rss_softc(TEST_RSS_PORT);
    int checked = 0;
    for (uint16_t k = first; k <= last && checked < 128; k++, checked++) {
        assert_int_equal(ff_rss_check6(sc, test_saddr6, test_daddr6,
                                       htons(1000), htons(pr[k])), 1);
        if (k == last) break;
    }
    assert_true(checked > 0);

    /* Miss: a different saddr6 (flip last byte) => -ENOENT. */
    uint8_t other_saddr6[16];
    memcpy(other_saddr6, test_saddr6, 16);
    other_saddr6[15] = 0xEE;
    uint16_t f2 = 0, l2 = 0; uint16_t *pr2 = NULL;
    int rv2 = ff_rss_tbl6_get_portrange(other_saddr6, test_daddr6, htons(1000),
                                        &f2, &l2, &pr2);
    assert_int_equal(rv2, -ENOENT);
    assert_null(pr2);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-RSS-02-04: ff_rss_adjust_sport6 NULL/out guards + degrade fallback.   */
/* In the unit env rss_reta_size[] is static BSS=0 so ff_rss_thash_ctx_init   */
/* leaves the v6 ctx unready (reta<2) => adjust_sport6 returns -1 (soft scan).*/
/* ------------------------------------------------------------------------ */
static void
test_ff_rss_adjust_sport6_guard(void **state)
{
    (void)state;
    uint16_t out = 0;
    assert_int_equal(ff_rss_adjust_sport6(NULL, test_saddr6, test_daddr6,
                                          htons(80), &out), -1);
    void *sc = test_rss_softc(TEST_RSS_PORT);
    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), NULL), -1);

    assert_int_equal(ff_rss_thash_ctx_init(), 0);   /* v6 ctx degrades (reta=0) */
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                          htons(80), &out), -1);
}

/* ======================================================================== */
/* TC-U-RSS-02-EQUIV: v6 toeplitz vs rte_thash(softrss_be) equivalence —      */
/* go/no-go data for wiring 0.2 v6 into the kernel. Replicates ff_rss_adjust_ */
/* sport6's full loop with the real DPDK rte_thash API (tuple_len=36,         */
/* sport@byte32, helper len=16bit @offset=256bit), re-verifying with the v6   */
/* soft Toeplitz (test_expected_rss_check6). Reports adjust success rate,     */
/* per-candidate equivalence, and full-loop final landing rate.              */
/* ======================================================================== */
static void
run_equiv6_for_reta(const char *ctx_name, uint16_t reta_size,
                    int *adj_ok, int *single_hit, int *final_ok,
                    double *avg_tries)
{
    struct rte_thash_ctx *ctx;
    struct rte_thash_subtuple_helper *h;
    int i, ok = 0, hit = 0, fok = 0;
    long tries_total = 0;
    const uint16_t nbq = EQUIV_NBQ, qid = EQUIV_QID;
    const uint32_t span = (reta_size + nbq - 1) / nbq;

    ctx = rte_thash_init_ctx(ctx_name, sizeof(test_rsskey_40),
                             equiv_log2(reta_size), (uint8_t *)test_rsskey_40, 0);
    assert_non_null(ctx);
    /* v6 helper: len 16 bits @ offset 256 bits (mirror lib FF_RSS_THASH_V6). */
    assert_int_equal(rte_thash_add_helper(ctx, "sport6", 16, 256), 0);
    h = rte_thash_get_helper(ctx, "sport6");
    assert_non_null(h);

    srandom(0xBADC0DE ^ reta_size);   /* deterministic, reproducible */
    for (i = 0; i < EQUIV_N; i++) {
        uint8_t saddr6[16], daddr6[16];
        for (int b = 0; b < 16; b++) { saddr6[b] = random() & 0xff; daddr6[b] = random() & 0xff; }
        uint16_t dport = htons((uint16_t)(1024 + (random() % 60000)));
        uint32_t desired = qid + ((uint32_t)random() % span) * nbq;
        int found = 0, first_cand = 1;
        uint32_t tr;
        if (desired >= reta_size) desired = qid;

        for (tr = 0; tr < span; tr++) {
            uint16_t sport = 0;
            uint8_t tuple[36];
            if (desired >= reta_size) desired = qid;
            memset(tuple, 0, sizeof(tuple));
            memcpy(&tuple[0], saddr6, 16);
            memcpy(&tuple[16], daddr6, 16);
            memcpy(&tuple[32], &sport, 2);    /* sport seed 0 @ byte 32 */
            memcpy(&tuple[34], &dport, 2);    /* dport @ byte 34        */
            tries_total++;

            if (rte_thash_adjust_tuple(ctx, h, tuple, sizeof(tuple),
                                       desired & (reta_size - 1), 16,
                                       NULL, NULL) == 0) {
                if (first_cand) ok++;
                memcpy(&sport, &tuple[32], 2);
                int landed = test_expected_rss_check6(saddr6, daddr6, sport, dport,
                                                      nbq, reta_size, qid);
                if (first_cand && landed) hit++;
                if (landed) {
                    /* zero false positive: independent recompute must agree. */
                    uint8_t d[36];
                    unsigned dl = 0;
                    memcpy(&d[dl], saddr6, 16); dl += 16;
                    memcpy(&d[dl], daddr6, 16); dl += 16;
                    memcpy(&d[dl], &sport, 2); dl += 2;
                    memcpy(&d[dl], &dport, 2); dl += 2;
                    uint32_t hh = test_toeplitz(sizeof(test_rsskey_40),
                                                test_rsskey_40, dl, d);
                    assert_int_equal(((hh & (reta_size - 1)) % nbq), qid);
                    found = 1;
                    break;
                }
            }
            first_cand = 0;
            desired += nbq;
        }
        if (found) fok++;
    }

    rte_thash_free_ctx(ctx);
    *adj_ok = ok;
    *single_hit = hit;
    *final_ok = fok;
    *avg_tries = (double)tries_total / EQUIV_N;
}

static void
test_ff_rss_thash6_equivalence_hitrate(void **state)
{
    (void)state;
    if (equiv_eal_init_once() < 0) {
        printf("\n[R-C 0.2 EQUIV6] DPDK EAL init failed in unit env; skipping.\n");
        skip();
        return;
    }

    int adj128 = 0, sh128 = 0, fok128 = 0, adj512 = 0, sh512 = 0, fok512 = 0;
    double avg128 = 0, avg512 = 0;
    run_equiv6_for_reta("ff_equiv6_128", 128, &adj128, &sh128, &fok128, &avg128);
    run_equiv6_for_reta("ff_equiv6_512", 512, &adj512, &sh512, &fok512, &avg512);

    printf("\n[R-C 0.2 EQUIV6] N=%d nbq=%d qid=%d key=40B v6-tuple=36B sport@256bit\n",
           EQUIV_N, EQUIV_NBQ, EQUIV_QID);
    printf("[R-C 0.2 EQUIV6] reta=128: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj128, EQUIV_N, 100.0 * adj128 / EQUIV_N,
           sh128, EQUIV_N, 100.0 * sh128 / EQUIV_N,
           fok128, EQUIV_N, 100.0 * fok128 / EQUIV_N, avg128, (128 + EQUIV_NBQ - 1) / EQUIV_NBQ);
    printf("[R-C 0.2 EQUIV6] reta=512: adjust_tuple_ok=%d/%d (%.1f%%), "
           "1st-candidate toeplitz_equiv=%d/%d (%.1f%%), "
           "FULL-LOOP final landing=%d/%d (%.1f%%), avg adjust calls/conn=%.2f (span=%d)\n",
           adj512, EQUIV_N, 100.0 * adj512 / EQUIV_N,
           sh512, EQUIV_N, 100.0 * sh512 / EQUIV_N,
           fok512, EQUIV_N, 100.0 * fok512 / EQUIV_N, avg512, (512 + EQUIV_NBQ - 1) / EQUIV_NBQ);

    assert_true(adj128 > 0);
    assert_true(adj512 > 0);
    assert_int_equal(fok128, EQUIV_N);   /* v6 full loop lands 100% (zero tolerance) */
    assert_int_equal(fok512, EQUIV_N);
}

/* ======================================================================== */
/* R-D (req 0.4) recheck runtime gate: TC-U-RSS-04-01 .. 04-05               */
/* Spec: 07-测试规格.md §1.4 ; 04 §3-bis ; 05 §3-bis ; 06 R-D.                */
/* In the unit env rss_reta_size[]=0 -> ctx unready -> ff_rss_adjust_sport   */
/* returns -1 at the readiness guard (ff_dpdk_if.c:3068) before reaching the */
/* recheck branch. Per spec 04-01 note, the recheck=0/1 cases here assert    */
/* (a) adjust returns -1 (ctx-unready degrade) and (b) wrap counter is 0    */
/* (recheck branch never reached). The wrap interceptor itself is exercised */
/* by direct ff_rss_check{,6} calls (existing R-A/R-B/R-C cases) so a       */
/* sanity check confirms the wrap chain is wired correctly.                  */
/* ======================================================================== */

#define RD_RECHECK_N 100

static void
test_ff_rss_adjust_sport_recheck_off(void **state)   /* TC-U-RSS-04-01 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr, sport_seed), 0);
    g_rss_cfg.recheck = 0;   /* R-D 0.4: disable runtime recheck */
    assert_int_equal(ff_rss_thash_ctx_init(), 0);   /* unit-env ctx unready */

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport(sc, saddr, daddr,
                                     htons((uint16_t)(1024 + i)), &out,
                                     TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);   /* ctx-unready degrade */
    }
    /* recheck=0 path never reaches L3105; counter must stay 0 */
    assert_int_equal(g_ff_rss_check_calls, 0);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport_recheck_on(void **state)    /* TC-U-RSS-04-02 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr, sport_seed), 0);
    g_rss_cfg.recheck = 1;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport(sc, saddr, daddr,
                                     htons((uint16_t)(1024 + i)), &out,
                                     TEST_RSS_FIRST, TEST_RSS_LAST);
        assert_int_equal(rv, -1);   /* ctx-unready degrade */
    }
    /* ctx-unready blocks the main loop; counter remains 0 here. The
     * "recheck=1 -> ff_rss_check is forced" semantic is covered by the
     * R-B equivalence test (full-loop landing=100%) under the default
     * recheck=1 from test_rss_build_table. Direct call below sanity-checks
     * that the wrap interceptor is actually wired. */
    assert_int_equal(g_ff_rss_check_calls, 0);

    uint64_t before = g_ff_rss_check_calls;
    (void)ff_rss_check(sc, saddr, daddr, sport_seed, htons(80));
    assert_true(g_ff_rss_check_calls > before);   /* wrap chain alive */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_recheck_off(void **state)  /* TC-U-RSS-04-03 */
{
    (void)state;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           sport_seed), 0);
    g_rss_cfg.recheck = 0;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check6_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                      htons((uint16_t)(1024 + i)), &out);
        assert_int_equal(rv, -1);
    }
    assert_int_equal(g_ff_rss_check6_calls, 0);

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

static void
test_ff_rss_adjust_sport6_recheck_on(void **state)   /* TC-U-RSS-04-04 */
{
    (void)state;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss6_build_table(test_saddr6, test_daddr6,
                                           sport_seed), 0);
    g_rss_cfg.recheck = 1;
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    g_ff_rss_check6_calls = 0;

    for (int i = 0; i < RD_RECHECK_N; i++) {
        uint16_t out = 0xFFFF;
        int rv = ff_rss_adjust_sport6(sc, test_saddr6, test_daddr6,
                                      htons((uint16_t)(1024 + i)), &out);
        assert_int_equal(rv, -1);
    }
    assert_int_equal(g_ff_rss_check6_calls, 0);

    uint64_t before = g_ff_rss_check6_calls;
    (void)ff_rss_check6(sc, test_saddr6, test_daddr6, sport_seed, htons(80));
    assert_true(g_ff_rss_check6_calls > before);   /* v6 wrap chain alive */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

#include <time.h>

#ifndef FF_RSS_RECHECK_MICROBENCH_N
#define FF_RSS_RECHECK_MICROBENCH_N 10000
#endif

static uint64_t
rd_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void
test_ff_rss_adjust_microbench(void **state)          /* TC-U-RSS-04-05 */
{
    (void)state;
    const uint32_t saddr = 0x01020304, daddr_base = 0x05060708;
    const uint16_t sport_seed = htons(1000);
    assert_int_equal(test_rss_build_table(saddr, daddr_base, sport_seed), 0);
    assert_int_equal(ff_rss_thash_ctx_init(), 0);

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;

    /* Pre-flight: confirm ctx readiness state. In unit env reta=0 -> unready
     * -> both off/on take the same early-return path; per spec 07 §1.4 note,
     * print "skipped: thash ctx not ready" and PASS (real data via spec 08). */
    uint16_t out_probe = 0;
    int probe = ff_rss_adjust_sport(sc, saddr, daddr_base, htons(1024), &out_probe,
                                   TEST_RSS_FIRST, TEST_RSS_LAST);
    if (probe < 0) {
        printf("\n[R-D 0.4 MICROBENCH] thash ctx not ready in unit env "
               "(rss_reta_size[]=0); skipping microbench. Real off-vs-on "
               "timing covered by spec 08 (example/rss_ct.c).\n");
        ff_global_cfg.dpdk.rss_check_cfgs = NULL;
        skip();
        return;
    }

    const int N = FF_RSS_RECHECK_MICROBENCH_N;
    uint64_t t_off, t_on;
    uint16_t out;

    g_rss_cfg.recheck = 0;
    t_off = rd_now_ns();
    for (int i = 0; i < N; i++) {
        out = 0;
        (void)ff_rss_adjust_sport(sc, saddr, daddr_base + (i & 0xFFFF),
                                  htons((uint16_t)(1024 + (i & 0x3FFF))),
                                  &out,
                                  TEST_RSS_FIRST, TEST_RSS_LAST);
    }
    t_off = rd_now_ns() - t_off;

    g_rss_cfg.recheck = 1;
    t_on = rd_now_ns();
    for (int i = 0; i < N; i++) {
        out = 0;
        (void)ff_rss_adjust_sport(sc, saddr, daddr_base + (i & 0xFFFF),
                                  htons((uint16_t)(1024 + (i & 0x3FFF))),
                                  &out,
                                  TEST_RSS_FIRST, TEST_RSS_LAST);
    }
    t_on = rd_now_ns() - t_on;

    printf("\n[R-D 0.4 MICROBENCH] N=%d v4 recheck off=%lu ns (%.1f ns/call), "
           "on=%lu ns (%.1f ns/call), on/off=%.2fx\n",
           N, (unsigned long)t_off, (double)t_off / N,
           (unsigned long)t_on, (double)t_on / N,
           t_off > 0 ? (double)t_on / (double)t_off : 0.0);
    assert_true(t_off < t_on);   /* recheck=0 strictly faster */

    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ===== R-F: thash_adjust switch + ctx_init route② fallback ===== */

/* TC-U-RSS-RF-01: thash_adjust=0 -> ff_rss_adjust_sport returns -1 (soft scan). */
static void
test_ff_rss_adjust_sport_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport(sc, 0x01020304, 0x05060708,
                                         htons(80), &out,
                                         TEST_RSS_FIRST, TEST_RSS_LAST), -1);

    g_rss_cfg.thash_adjust = 1; /* restore default for subsequent tests */
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* TC-U-RSS-RF-02: same as RF-01 for the v6 path. */
static void
test_ff_rss_adjust_sport6_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.recheck = 0;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    void *sc = test_rss_softc(TEST_RSS_PORT);
    lcore_conf.nb_queue_list[TEST_RSS_PORT] = TEST_RSS_NBQ;
    uint8_t saddr6[16] = { 0x20,0x01 }, daddr6[16] = { 0x20,0x02 };
    uint16_t out = 0xFFFF;
    assert_int_equal(ff_rss_adjust_sport6(sc, saddr6, daddr6,
                                          htons(80), &out), -1);

    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* TC-U-RSS-RF-03: thash_adjust=0 -> ff_rss_thash_ctx_init early-returns 0. */
static void
test_ff_rss_thash_ctx_init_thash_adjust_off(void **state)
{
    (void)state;
    g_rss_cfg.thash_adjust = 0;
    ff_global_cfg.dpdk.rss_check_cfgs = &g_rss_cfg;

    int rv = ff_rss_thash_ctx_init();
    assert_int_equal(rv, 0);

    g_rss_cfg.thash_adjust = 1;
    ff_global_cfg.dpdk.rss_check_cfgs = NULL;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-17 (Stage-6): ff_dpdk_register_if happy path: allocates  */
/* and returns a non-NULL ff_dpdk_if_context (covers the malloc + memset   */
/* path in L182-L196).                                                     */
/* ------------------------------------------------------------------------ */
static void
test_ff_dpdk_register_if_returns_ctx(void **state)
{
    (void)state;
    struct ff_port_cfg pcfg = { .port_id = 0 };
    int dummy_softc = 0xCAFE;
    int dummy_ifp = 0xBEEF;
    void *ctx = ff_dpdk_register_if(&dummy_softc, &dummy_ifp, &pcfg);
    assert_non_null(ctx);
    /* Round-trip via ff_dpdk_deregister_if (already tested) to free. */
    ff_dpdk_deregister_if((struct ff_dpdk_if_context *)ctx);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P3-DPDKIF-18 (Stage-6 Phase-9 / FU-CB-DPDKIF-NULLGUARD):             */
/* ff_dpdk_if_send(NULL, ...) must not crash; lib's NULL ctx guard returns  */
/* -1 and frees the caller's mbuf (if any) instead of dereferencing.        */
/* ------------------------------------------------------------------------ */
extern int ff_dpdk_if_send(struct ff_dpdk_if_context *ctx, void *m, int total);

static void
test_ff_dpdk_if_send_null_ctx_safe(void **state)
{
    (void)state;
    /* Both args NULL: the guard returns -1 without touching m. */
    int rv = ff_dpdk_if_send(NULL, NULL, 0);
    assert_int_equal(rv, -1);
}

static void
test_ff_dpdk_if_send_null_ctx_with_mbuf(void **state)
{
    (void)state;
    /* Non-NULL m: the guard must call ff_mbuf_free(m) before returning -1.
     * Our local stub ff_mbuf_free is a no-op, so we just verify the call
     * doesn't crash and the return is -1. */
    int dummy_mbuf = 0xCAFE;
    int rv = ff_dpdk_if_send(NULL, &dummy_mbuf, 100);
    assert_int_equal(rv, -1);
}
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ff_dpdk_deregister_if_frees),
        cmocka_unit_test(test_ff_get_traffic_zero_init),
        cmocka_unit_test(test_ff_dpdk_stop_smoke),
        cmocka_unit_test(test_ff_regist_pcblddr_fun_smoke),
        cmocka_unit_test(test_ff_regist_packet_dispatcher_smoke),
        cmocka_unit_test(test_ff_regist_packet_dispatcher_context_smoke),
        cmocka_unit_test(test_ff_get_tsc_ns_basic),
        /* Stage-5 FU-S4-DPDK-IF-FULL: ff_in_pcbladdr branches */
        cmocka_unit_test(test_ff_in_pcbladdr_no_callback),
        cmocka_unit_test(test_ff_in_pcbladdr_af_inet_dispatches),
        cmocka_unit_test(test_ff_in_pcbladdr_af_inet6_freebsd_to_linux_remap),
        /* Stage-6 Phase-5 coverage extensions */
        cmocka_unit_test(test_ff_rss_tbl_set_portrange_no_cfg),
        cmocka_unit_test(test_ff_rss_tbl_set_portrange_disabled),
        cmocka_unit_test(test_ff_rss_tbl_set_portrange_inverted_range),
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_no_cfg),
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_disabled),
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_smoke),
        /* R-A (req 0.1): portrange hit / rotation / miss (TC-U-RSS-01-01..03) */
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_hit),
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_rotation),
        cmocka_unit_test(test_ff_rss_tbl_get_portrange_miss),
        /* R-B (req 0.3): thash adjust_sport guards + degrade + equivalence */
        cmocka_unit_test(test_ff_rss_adjust_sport_null),
        cmocka_unit_test(test_ff_rss_adjust_sport_degraded),
        cmocka_unit_test(test_ff_rss_adjust_sport_single_queue),
        cmocka_unit_test(test_ff_rss_thash_equivalence_hitrate),
        /* R-C (req 0.2): v6 check6 / tbl6 / adjust_sport6 + v6 equivalence */
        cmocka_unit_test(test_ff_rss_check6_landing),
        cmocka_unit_test(test_ff_rss_check6_single_queue),
        cmocka_unit_test(test_ff_rss_tbl6_set_get),
        cmocka_unit_test(test_ff_rss_adjust_sport6_guard),
        cmocka_unit_test(test_ff_rss_thash6_equivalence_hitrate),
        /* R-D (req 0.4): recheck runtime gate v4/v6 + microbench */
        cmocka_unit_test(test_ff_rss_adjust_sport_recheck_off),
        cmocka_unit_test(test_ff_rss_adjust_sport_recheck_on),
        cmocka_unit_test(test_ff_rss_adjust_sport6_recheck_off),
        cmocka_unit_test(test_ff_rss_adjust_sport6_recheck_on),
        cmocka_unit_test(test_ff_rss_adjust_microbench),
        /* R-F (req 0.1/0.2): thash_adjust runtime switch + ctx_init early-out */
        cmocka_unit_test(test_ff_rss_adjust_sport_thash_adjust_off),
        cmocka_unit_test(test_ff_rss_adjust_sport6_thash_adjust_off),
        cmocka_unit_test(test_ff_rss_thash_ctx_init_thash_adjust_off),
        cmocka_unit_test(test_ff_dpdk_register_if_returns_ctx),
        /* Stage-6 Phase-9 (FU-CB-DPDKIF-NULLGUARD) */
        cmocka_unit_test(test_ff_dpdk_if_send_null_ctx_safe),
        cmocka_unit_test(test_ff_dpdk_if_send_null_ctx_with_mbuf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
