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
#include "ff_dpdk_if.h"
#include "ff_host_interface.h"    /* ff_get_tsc_ns declaration */

#include <rte_launch.h>           /* enum rte_rmt_call_main_t */

/* ------------------------------------------------------------------------ */
/* Wrap rte_get_tsc_hz (real DPDK function; wrappable via -Wl,--wrap)        */
/* ------------------------------------------------------------------------ */
uint64_t
__wrap_rte_get_tsc_hz(void)
{
    return mock_type(uint64_t);
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

/* ff_dpdk_if.c clock helpers also reference these from ff_host_interface
 * (we don't link ff_host_interface.o here): */
void ff_update_current_ts(void) { }
void ff_hardclock(void) { }

/* ff_enable_pcap: defined in ff_dpdk_pcap.c (we do NOT link it here) */
int  ff_enable_pcap(const char *p, uint16_t s, uint8_t t)
{ (void)p;(void)s;(void)t; return 0; }

/* rte_timer_meta_init: F-Stack-specific patch added during DPDK 23->24
 * upgrade; not present in stock librte_timer.so. Provide a no-op stub. */
void rte_timer_meta_init(void) { }

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
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
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
        cmocka_unit_test(test_ff_dpdk_register_if_returns_ctx),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
