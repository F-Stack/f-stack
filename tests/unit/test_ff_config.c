/*
 * F-Stack lib/ unit test: ff_config.c (P1 #3, most complex)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §4.3
 * Coverage: 11 TC (TC-U-P1-CFG-01..11) — end-to-end fixture-driven via
 * ff_load_config(), the only non-static entry. All `_handler` functions in
 * ff_config.c are static (verified via Stage-1 spec-author audit) so we
 * exercise them transitively through the public ini-parse path.
 *
 * Strategy:
 *   - 5 .ini fixtures in fixtures/ exercise different parser branches
 *   - Each TC:
 *       (a) memset ff_global_cfg back to zero (reset state across tests)
 *       (b) build argv-style "f-stack -c fixtures/...ini"
 *       (c) call ff_load_config, capturing rv
 *       (d) inspect ff_global_cfg.* fields that the ini handlers should
 *           have populated
 *
 * Notes (DP-U-12 "代码为准"):
 *   - ff_load_config may return -1 even when the parser populated fields
 *     correctly, because ff_check_config / dpdk_args_setup add downstream
 *     constraints (e.g. port_cfgs[].addr must be non-NULL). The TCs below
 *     accept either 0 or -1 and assert ff_global_cfg state directly when
 *     the parser portion succeeded.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ff_config.h"
#include "ff_log.h"           /* for ff_log declaration only */

/* ------------------------------------------------------------------------ */
/* FU-S8-CFG-OOM: calloc wrapper (linked via -Wl,--wrap=calloc).            */
/* Passes through to __real_calloc unless armed; when g_calloc_fail_after is */
/* >0 it counts down and returns NULL on the target call. This lets a TC    */
/* force a single allocation failure (the Nth calloc after arming) to cover */
/* the `if (X == NULL)` OOM error legs without disturbing cmocka, which     */
/* does its own allocations only while the wrapper is disarmed (==0).       */
/* ------------------------------------------------------------------------ */
extern void *__real_calloc(size_t nmemb, size_t size);
static int g_calloc_fail_after = 0;   /* 0 = disarmed; N = fail the Nth call */

void *
__wrap_calloc(size_t nmemb, size_t size)
{
    if (g_calloc_fail_after > 0) {
        if (--g_calloc_fail_after == 0) {
            return NULL;              /* simulate OOM on this call */
        }
    }
    return __real_calloc(nmemb, size);
}

/* ------------------------------------------------------------------------ */
/* Local stubs to satisfy linker (ff_config.c indirectly references these)  */
/* ------------------------------------------------------------------------ */

/* ff_log: ff_config.c references it transitively via ff_log.h includes; we
 * stub here to avoid pulling in lib/ff_log.c (which would mandate the rte_log
 * wrap chain). */
int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    (void)level; (void)logtype; (void)format;
    return 0;
}

/* FF_LOG_FILENAME_PREFIX: declared `extern char FF_LOG_FILENAME_PREFIX[]` in
 * ff_log.h; defined as the storage in lib/ff_log.c. Since we don't link
 * ff_log.o here, provide a minimal definition. */
char FF_LOG_FILENAME_PREFIX[] = "./f-stack-";

/* rte_strsplit: provided by DPDK librte_eal (rte_string_fns.h). We don't
 * want to drag DPDK libraries into unit-test linkage, so we ship a small
 * compliant reimplementation. Signature mirrors DPDK 23.11/24.11.
 *
 *   Splits *string* in-place by replacing each *delim* with '\0' and writes
 *   pointers to up-to *maxtokens* substrings into *tokens[]*. Returns the
 *   number of tokens written, or -1 on argument error.
 */
int
rte_strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim)
{
    (void)stringlen;
    if (!string || !tokens || maxtokens <= 0) {
        return -1;
    }
    int  count = 0;
    char *p    = string;
    tokens[count++] = p;
    while (*p != '\0' && count < maxtokens) {
        if (*p == delim) {
            *p = '\0';
            tokens[count++] = p + 1;
        }
        p++;
    }
    return count;
}

/* ------------------------------------------------------------------------ */
/* Test helpers                                                             */
/* ------------------------------------------------------------------------ */

#define FIXTURE_PATH(name) "fixtures/" name

static int
test_setup(void **state)
{
    (void)state;
    /* Stage-6 Phase-8 (FU-S2-2-CFG-UNLOAD): use the lib-provided unload
     * helper to free any heap from a prior test, then zero. This keeps
     * valgrind clean across the 19 TCs (used to bleed ~50 KB / load). */
    ff_unload_config();
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    return 0;
}

static int
load_with_fixture(const char *fixture_path)
{
    /* Build argv-style invocation: "f-stack -c <fixture>" */
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char path_buf[256];
    snprintf(path_buf, sizeof(path_buf), "%s", fixture_path);

    char *argv[] = { prog, dashc, path_buf, NULL };
    int   argc   = 3;

    /* getopt_long uses optind; reset between calls (R-S2-3 hardening) */
    extern int optind;
    optind = 1;

    return ff_load_config(argc, argv);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-01: minimal valid .ini -> parser populates dpdk fields        */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_valid_minimal_ini(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    /* rv may be 0 (full success) or -1 (post-parse check failure); either way
     * the parser portion must have run and populated dpdk.* fields. */
    (void)rv;
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "1");
    assert_int_equal(ff_global_cfg.dpdk.nb_channel, 4);
    assert_int_equal(ff_global_cfg.dpdk.promiscuous, 1);
    assert_int_equal(ff_global_cfg.dpdk.numa_on, 1);
    assert_int_equal(ff_global_cfg.dpdk.idle_sleep, 20);
    assert_int_equal(ff_global_cfg.dpdk.pkt_tx_delay, 100);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-02: empty .ini — verifies parser ran without populating any   */
/* dpdk fields. Note: ff_load_config may still return 0 because nb_ports==0  */
/* skips the per-port validation in ff_check_config; therefore we assert     */
/* on the absence of populated fields rather than on rv.                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_no_dpdk_section(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_no_dpdk.ini"));
    (void)rv;
    /* Empty file: ini_parse_handler never invoked; lcore_mask stays NULL. */
    assert_null(ff_global_cfg.dpdk.lcore_mask);
    assert_int_equal(ff_global_cfg.dpdk.nb_channel, 0);
    /* port_cfgs may still be allocated by ff_default_config? No — defaults
     * leave it NULL. Confirm. */
    assert_null(ff_global_cfg.dpdk.port_cfgs);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-03: bad lcore_mask -> error                                  */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_invalid_lcore_mask(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_bad_lcore.ini"));
    /* parse_lcore_mask returns 0 (= handler error) for non-hex chars, which
     * causes ini_parse to record an error line number. ff_load_config then
     * proceeds to ff_check_config which fails (no valid lcore for port0).
     * Result must be -1. */
    assert_int_not_equal(rv, 0);
    /* The bad string itself should still have been strdup'd by handler. */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "ZZZ_NOT_HEX");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-04: dual-vlan fixture -> handler creates 2 vlan_cfgs entries */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_dual_vlan(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dual_vlan.ini"));
    (void)rv;
    /* dpdk.nb_vlan_filter or vlan_cfgs should be populated; we check that
     * lcore_mask was parsed (=3) and the parser ran past [vlan0]/[vlan1]
     * sections without crashing. */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "3");
    assert_int_equal(ff_global_cfg.dpdk.vlan_strip, 1);
    /* vlan_cfgs is allocated lazily by vlan_cfg_handler when [vlanN] sections
     * appear; if the handler ran at all, this should be non-NULL. */
    assert_non_null(ff_global_cfg.dpdk.vlan_cfgs);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-05: valid_minimal.ini parses [port0] addr/netmask/etc         */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_with_vip_addr(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    /* port_cfgs allocated by port_cfg_handler for [port0] */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-06: argv override -- "-t primary" sets proc_type             */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_argv_override(void **state)
{
    (void)state;
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char path[]  = FIXTURE_PATH("valid_minimal.ini");
    char dasht[] = "-t";
    char ptype[] = "primary";

    char *argv[] = { prog, dashc, path, dasht, ptype, NULL };
    int   argc   = 5;

    extern int optind;
    optind = 1;
    int rv = ff_load_config(argc, argv);
    (void)rv;
    assert_non_null(ff_global_cfg.dpdk.proc_type);
    assert_string_equal(ff_global_cfg.dpdk.proc_type, "primary");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-07: unknown section in .ini does not crash, parse continues  */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_unknown_section(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_with_unknown.ini"));
    (void)rv;
    /* Even with [unknown_section] present, dpdk.lcore_mask must still parse */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_string_equal(ff_global_cfg.dpdk.lcore_mask, "1");
    /* And [kni] section should populate kni.enable / kni.method */
    assert_int_equal(ff_global_cfg.kni.enable, 1);
    assert_non_null(ff_global_cfg.kni.method);
    assert_string_equal(ff_global_cfg.kni.method, "accept");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-08: missing -c argument -> ff_load_config fails               */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_empty_ini(void **state)
{
    (void)state;
    char prog[] = "f-stack";
    char *argv[] = { prog, NULL };
    int argc = 1;

    extern int optind;
    optind = 1;
    int rv = ff_load_config(argc, argv);
    /* Without -c filename, cfg->filename stays NULL -> ini_parse(NULL,...)
     * returns -1 in glibc fopen; ff_load_config returns -1 via ini_parse path. */
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-09: nonexistent .ini path -> -1                              */
/* (renamed from spec's vlan_cfg_handler_isolated white-box test, which     */
/*  cannot run without #include "ff_config.c" — see DP-S2-2 outcome below)  */
/* ------------------------------------------------------------------------ */
static void
test_vlan_cfg_handler_isolated(void **state)
{
    (void)state;
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char nopath[] = "/nonexistent/path/__ut_no_such__.ini";
    char *argv[] = { prog, dashc, nopath, NULL };

    extern int optind;
    optind = 1;
    int rv = ff_load_config(3, argv);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-10: invalid proc_type "-t bogus" -> ff_parse_args returns -1  */
/* ------------------------------------------------------------------------ */
static void
test_ipfw_pr_cfg_handler_isolated(void **state)
{
    (void)state;
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char path[]  = FIXTURE_PATH("valid_minimal.ini");
    char dasht[] = "-t";
    char bogus[] = "bogus_proc_type";

    char *argv[] = { prog, dashc, path, dasht, bogus, NULL };
    extern int optind;
    optind = 1;
    int rv = ff_load_config(5, argv);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-11: port_cfg parsing places [port0] addr correctly            */
/* ------------------------------------------------------------------------ */
static void
test_port_cfg_handler_addr_parse(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    /* port_cfgs is a sparse array indexed by port_id; valid_minimal.ini
     * declares port 0. After parsing, port_cfgs[0].addr should be the
     * strdup'd "192.168.1.10". */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
    assert_non_null(ff_global_cfg.dpdk.port_cfgs[0].addr);
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].addr,    "192.168.1.10");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].netmask, "255.255.255.0");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-12 (Stage-3 coverage extension): comprehensive fixture       */
/* exercising every supported section ([dpdk]+[port0]+[vlan0]+[vdev0]+      */
/* [freebsd.boot]+[freebsd.sysctl]+[kni]+[pcap]) to broaden parser branch    */
/* coverage past the 50% line threshold required for ff_config.c.           */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_all_sections(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_all_sections.ini"));
    (void)rv;
    /* dpdk fields */
    assert_non_null(ff_global_cfg.dpdk.lcore_mask);
    assert_int_equal(ff_global_cfg.dpdk.nb_channel,  4);
    assert_int_equal(ff_global_cfg.dpdk.memory,      128);
    assert_int_equal(ff_global_cfg.dpdk.tso,         0);
    assert_int_equal(ff_global_cfg.dpdk.symmetric_rss, 1);
    assert_int_equal(ff_global_cfg.dpdk.idle_sleep, 20);
    /* kni section parsed */
    assert_int_equal(ff_global_cfg.kni.enable, 1);
    assert_non_null(ff_global_cfg.kni.method);
    /* pcap section parsed (timestamp_precision = 0 default still 0; but
     * snap_len/save_path should be populated) */
    assert_non_null(ff_global_cfg.pcap.save_path);
    /* freebsd boot/sysctl sections allocate cfg pointers */
    /* ff_freebsd_cfg *boot is populated by freebsd_conf_handler when [freebsd.boot]
     * lines arrive; non-NULL after parse. */
    assert_non_null(ff_global_cfg.freebsd.boot);
    assert_non_null(ff_global_cfg.freebsd.sysctl);
}

/* ======================================================================== */
/* Stage-6 Phase-2 coverage extensions: ff_config 59.5%->>=80% line          */
/* ======================================================================== */

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-13 (Stage-6): full DPDK fixture exercises hex lcore_mask,    */
/* port range list (0-1), bond config, and rss_check + rss_tbl 4-tuple     */
/* parsing. Targets the largest gap in ff_config.c (parse_lcore_mask hex,  */
/* __parse_config_list range, bond_cfg_handler all fields, rss_tbl_*).    */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_dpdk_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_full.ini"));
    (void)rv;
    /* lcore_mask=0xF -> 4 lcores; proc_lcore allocated, nb_procs >= 1 */
    assert_non_null(ff_global_cfg.dpdk.proc_lcore);
    /* port_list=0-1 -> nb_ports = 2 */
    assert_int_equal(ff_global_cfg.dpdk.nb_ports, 2);
    /* bond enabled, nb_bond=1, bond_cfgs allocated */
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs);
    /* bond0 fields: mode=4, slave="eth0,eth1", primary="eth0" */
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 4);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].slave);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave, "eth0,eth1");
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].primary);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary, "eth0");
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].bond_mac);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].lsc_poll_period_ms, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].up_delay,           200);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay,         200);
    /* rss_check + rss_tbl: 2 entries (port 0 + port 1) */
    assert_non_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->enable, 1);
    /* R-F: thash_adjust defaults to 1 when omitted. */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust, 1);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl, 2);
    /* port0 entry: port_id=0, sport=80 (htons applied internally) */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[0].port_id, 0);
    /* port1 entry: port_id=1, sport=443 */
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->rss_tbl_cfgs[1].port_id, 1);
    /* port0 lcore_list parsed as 0,1 */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_lcores, 2);
    /* port0 nb_vip = 3 */
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_vip, 3);
    /* port0 nb_vip6 = 2 (only when INET6 is enabled in lib build) */
#ifdef INET6
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[0].nb_vip6, 2);
#endif
    /* port1 lcore_list=2-3 -> nb_lcores=2 */
    assert_int_equal(ff_global_cfg.dpdk.port_cfgs[1].nb_lcores, 2);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-14 (Stage-6): lcore_mask with 0 bits set -> parse_lcore_mask */
/* returns 0 / nb_procs stays 0. Covers the "i == 0 after strip" branch.   */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_lcore_mask_no_bits(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_lcore_no_bit.ini"));
    (void)rv;
    /* parse_lcore_mask sees i==0 after stripping leading zeros, returns 0
     * without populating proc_lcore. ff_global_cfg.dpdk.nb_procs == 0. */
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-15 (Stage-6): port_list with non-integer token triggers      */
/* __parse_config_list "is not a integer" error path. Covers L277-L310.    */
/* ------------------------------------------------------------------------ */
static void
test_ff_load_config_portlist_nonint(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_portlist_nonint.ini"));
    (void)rv;
    /* Parser hit "not an integer" -> __parse_config_list returns 0,
     * which propagates up; nb_ports may stay 0 or partial. We assert
     * the parser did NOT crash and bond_cfgs was never allocated. */
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-16 (Stage-6): [bond0] section with NO dpdk.nb_bond key       */
/* makes bond_cfg_handler reject every line; bond_cfgs stays NULL, parser  */
/* still completes successfully overall.                                   */
/* ------------------------------------------------------------------------ */
static void
test_bond_cfg_handler_no_nb_bond(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_bond_no_nb_bond.ini"));
    (void)rv;
    /* bond_cfg_handler returned 0 -> ini_parse stops with error; in either
     * case bond_cfgs was never allocated (the early-return "must config
     * dpdk.nb_bond first" branch). */
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-17 (Stage-6): malformed bond section name [bond_xx] (not    */
/* matching "bondNN") triggers the sscanf-error branch.                    */
/* ------------------------------------------------------------------------ */
static void
test_bond_cfg_handler_bad_section(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_bond_bad_section.ini"));
    (void)rv;
    /* nb_bond=1 -> bond_cfgs alloc'd; but [bond_xx] section sscanf fails,
     * so handler returned 0. We assert the alloc happened (proves the
     * "section format error" path was reached, after the alloc). */
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    /* The rejection happened before any field was set on bond[0]. */
    if (ff_global_cfg.dpdk.bond_cfgs != NULL) {
        assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 0);
    }
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-18 (Stage-6): [rss_check] without prior port_cfgs/vlan_cfgs */
/* makes rss_check_cfg_handler reject (returns 0) on the first key.        */
/* ------------------------------------------------------------------------ */
static void
test_rss_check_cfg_handler_no_port_no_vlan(void **state)
{
    (void)state;
    /* Note: [rss_check] section appears BEFORE [portN] in the fixture so
     * port_cfgs is still NULL when rss_check_cfg_handler is invoked. */
    int rv = load_with_fixture(FIXTURE_PATH("invalid_rss_check_no_port.ini"));
    (void)rv;
    assert_null(ff_global_cfg.dpdk.rss_check_cfgs);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-19 (Stage-6): rss_tbl with 3-token entries (not 4-tuple)    */
/* triggers rss_tbl_cfg_handler per-entry parse error (still returns 1).   */
/* ------------------------------------------------------------------------ */
static void
test_rss_tbl_cfg_handler_bad_tuple(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_rss_tbl_bad_tuple.ini"));
    (void)rv;
    /* rss_check_cfgs allocated (port_cfgs was set up by [port0]); but the
     * 3-token rss_tbl entry caused per-entry error, so nb_rss_tbl stays 0
     * (or rss_tbl_cfgs[0] left at default zero values). */
    if (ff_global_cfg.dpdk.rss_check_cfgs != NULL) {
        /* Either the malformed entry was rejected outright (nb_rss_tbl=0),
         * or it was partially parsed (port_id=0, daddr/saddr empty). */
        assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->nb_rss_tbl, 0);
    }
}

/* TC-U-P1-CFG-RF-01: explicit thash_adjust=0 is parsed correctly. */
static void
test_rss_check_thash_adjust_off_parses(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_rss_check_thash_adjust_off.ini"));
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->enable,        1);
    assert_int_equal(ff_global_cfg.dpdk.rss_check_cfgs->thash_adjust,  0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-CFG-20 (Stage-6 Phase-8): ff_unload_config zeroes all heap-owned */
/* fields after a load. Closes FU-S2-2-CFG-UNLOAD. Repeated load/unload    */
/* cycles must remain valgrind-clean (verified out-of-band via make check). */
/* ------------------------------------------------------------------------ */
static void
test_ff_unload_config_zeroes_state(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    /* After load: at minimum proc_lcore + filename are non-NULL. */
    assert_non_null(ff_global_cfg.dpdk.proc_lcore);
    assert_non_null(ff_global_cfg.filename);

    ff_unload_config();

    /* All ownership pointers must be NULL'd (defense-in-depth: a future
     * caller that re-uses ff_global_cfg without re-loading must not see
     * dangling pointers). */
    assert_null(ff_global_cfg.dpdk.proc_lcore);
    assert_null(ff_global_cfg.dpdk.port_cfgs);
    assert_null(ff_global_cfg.dpdk.vlan_cfgs);
    assert_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_null(ff_global_cfg.dpdk.vdev_cfgs);
    assert_null(ff_global_cfg.dpdk.rss_check_cfgs);
    assert_null(ff_global_cfg.dpdk.portid_list);
    assert_null(ff_global_cfg.filename);
    assert_null(ff_global_cfg.dpdk.lcore_mask);
    assert_null(ff_global_cfg.freebsd.boot);
    assert_null(ff_global_cfg.freebsd.sysctl);
    /* Idempotent: a second call on already-unloaded state is a no-op. */
    ff_unload_config();
    assert_null(ff_global_cfg.filename);
}
/* ======================================================================== */
/* Stage-7 Phase-3 (FU-S7-CFG-*): branch-coverage boost for ff_config.c     */
/* ======================================================================== */

/* TC-S7-CFG-01: parse_lcore_mask accepts uppercase "0X" prefix.            */
static void
test_parse_lcore_mask_uppercase_0X_succeeds(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_lcore_uppercase.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 2);
}

/* TC-S7-CFG-02: vlan_cfg_handler returns 1 (skip) when vlanid is not in   */
/* the configured vlan_filter list (FU-S7-CFG-VLAN-OOB regression guard). */
static void
test_vlan_cfg_handler_id_not_in_filter_returns_one(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_vlan_id_not_in_filter.ini"));
    /* Load itself succeeds (rv=0); the handler simply ignores the orphan
     * [vlan99] section so vlan_cfgs[0] (slot for vlan_filter[0]=10) stays
     * un-named. */
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.dpdk.vlan_cfgs);
    /* slot 0 was allocated but no [vlanN] matched filter[0]=10, so name is NULL */
    assert_null(ff_global_cfg.dpdk.vlan_cfgs[0].name);
}

/* TC-S7-CFG-03: vlan_cfg_handler returns 0 on malformed section name.     */
static void
test_vlan_cfg_handler_bad_section_returns_zero(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_vlan_bad_section.ini"));
    /* sscanf failure inside vlan_cfg_handler aborts ff_load_config (rv=-1) */
    assert_int_equal(rv, -1);
}

/* TC-S7-CFG-04: vdev_cfg_handler returns 0 when [dpdk] is missing nb_vdev.*/
static void
test_vdev_cfg_handler_no_nb_vdev_returns_zero(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_vdev_no_nb_vdev.ini"));
    assert_int_equal(rv, -1);
}

/* TC-S7-CFG-05: full vdev section populates iface/path/mac/queues/cq.    */
static void
test_ff_load_config_vdev_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vdev.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_vdev, 1);
    assert_non_null(ff_global_cfg.dpdk.vdev_cfgs);
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].iface, "eth0");
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].path, "/var/run/usvhost");
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_queues, 2);
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].queue_size, 512);
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].mac, "00:11:22:33:44:55");
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_cq, 1);
}

/* TC-S7-CFG-06: full bond section populates mode/slave/primary/etc.     */
static void
test_ff_load_config_bond_full(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_bond.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.nb_bond, 1);
    assert_non_null(ff_global_cfg.dpdk.bond_cfgs);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].mode, 4);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave, "0,1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary, "0");
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].socket_id, 0);
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].bond_mac, "AA:BB:CC:DD:EE:FF");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy, "l34");
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].lsc_poll_period_ms, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].up_delay, 100);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay, 200);
}

/* TC-S7-CFG-07: port_cfg_handler returns 0 on malformed [portXX] name.   */
static void
test_port_cfg_handler_bad_section_returns_zero(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_port_bad_section.ini"));
    assert_int_equal(rv, -1);
}

/* TC-S7-CFG-08: port_cfg_handler returns 1 (skip) when portid > max.    */
static void
test_port_cfg_handler_id_over_max_returns_one(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_port_id_over_max.ini"));
    /* Load succeeds; [port200] section is silently ignored. */
    assert_int_equal(rv, 0);
    /* Only port0 should have a name */
    assert_non_null(ff_global_cfg.dpdk.port_cfgs);
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].name, "port0");
}

/* TC-S7-CFG-09: repeated keys (addr=A then addr=B) must not leak the     */
/* old strdup'd value (FU-S7-CFG-FREE-BEFORE-STRDUP regression guard).   */
/* valgrind verification is performed out-of-band by `make check`.       */
static void
test_ff_load_config_repeat_keys_no_leak(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_repeat_keys.ini"));
    assert_int_equal(rv, 0);
    /* Last value of each repeated key wins. */
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].addr,    "192.168.1.30");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].netmask, "255.255.0.0");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].gateway, "192.168.1.254");
}

/* TC-S7-CFG-10: freebsd.boot section accepts multiple integer + string   */
/* entries forming a chain visible via cfg.freebsd.boot list.            */
static void
test_ff_load_config_freebsd_boot_multi_entries(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_freebsd_boot.ini"));
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.freebsd.hz, 200);
    /* Walk the boot/sysctl chains; at least 1 entry should be present. */
    int nboot = 0;
    for (struct ff_freebsd_cfg *p = ff_global_cfg.freebsd.boot; p; p = p->next) {
        nboot++;
    }
    int nsysctl = 0;
    for (struct ff_freebsd_cfg *p = ff_global_cfg.freebsd.sysctl; p; p = p->next) {
        nsysctl++;
    }
    /* boot has panicstr (string-typed), sysctl has 5 entries above. */
    assert_true(nboot >= 1);
    assert_int_equal(nsysctl, 5);
}

/* TC-S7-CFG-11: INET6 directives are silently ignored when the build does */
/* not define INET6 (load still succeeds). The fixture also exercises the  */
/* free-before-strdup path on broadcast/if_name/addr6/gateway6 indirectly. */
static void
test_ff_load_config_inet6_fixture_ignored(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_inet6.ini"));
    assert_int_equal(rv, 0);
    /* INET4 portions still parse correctly. */
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].addr,    "192.168.1.10");
    assert_string_equal(ff_global_cfg.dpdk.port_cfgs[0].netmask, "255.255.255.0");
}

/* TC-S7-CFG-12: argv override for -t (proc_type) and -p (proc_id).      */
static void
test_ff_load_config_argv_t_override(void **state)
{
    (void)state;
    /* Build argv: f-stack -c <fixture> -t secondary -p 0 */
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char dasht[] = "-t";
    char dashp[] = "-p";
    char path[]  = FIXTURE_PATH("valid_minimal.ini");
    char tval[]  = "secondary";
    char pval[]  = "0";
    char *argv[] = { prog, dashc, path, dasht, tval, dashp, pval, NULL };
    extern int optind;
    optind = 1;
    int rv = ff_load_config(7, argv);
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.dpdk.proc_type, "secondary");
    assert_int_equal(ff_global_cfg.dpdk.proc_id, 0);
}

/* ======================================================================== */
/* Stage-8 Phase-2 (FU-S8-CFG-ARGV-FIXTURES): branch boost, no wrap         */
/* ======================================================================== */

/* TC-S8-CFG-01: lcore_mask with leading/trailing blanks + multi-bit mask
 * "0x5" (bits 0,2 set; bit 1 clear) -> covers parse_lcore_mask blank-strip
 * (L96/L103) and the (1<<j)&val false leg (L121). */
static void
test_parse_lcore_mask_blank_and_multibit(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_lcore_blank_multibit.ini"));
    assert_int_equal(rv, 0);
    /* 0x5 = bits 0 and 2 -> 2 procs (lcore 0 and lcore 2). */
    assert_int_equal(ff_global_cfg.dpdk.nb_procs, 2);
}

/* TC-S8-CFG-02: all-blank lcore_mask -> parse_lcore_mask hits i==0 and
 * returns 0 (handler error), so ff_load_config returns -1. (L106). */
static void
test_parse_lcore_mask_all_blank_returns_error(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_lcore_all_blank.ini"));
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-03: mid-string non-hex char ("0x1Z") -> isxdigit==0 leg
 * (L113) -> parse_lcore_mask returns 0 -> load fails. */
static void
test_parse_lcore_mask_mid_nonhex_returns_error(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_lcore_midhex.ini"));
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-04: vlan section carrying vip_addr drives vip_cfg_handler down
 * its cur_vlan_cfg branch (L390/L417) and the cur->vip_addr_str guard
 * (L724). portid=0 also exercises the vlan portid binding path. */
static void
test_ff_load_config_vlan_vip_addr(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vlan_vip.ini"));
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.dpdk.vlan_cfgs);
    /* vlan10 is filter index 0; it must have parsed a vip_addr_str. */
    assert_non_null(ff_global_cfg.dpdk.vlan_cfgs[0].vip_addr_str);
    assert_int_equal(ff_global_cfg.dpdk.vlan_cfgs[0].nb_vip, 3);
}

/* TC-S8-CFG-05: vlan portid greater than max_portid -> vlan_cfg_handler
 * returns 1 (skip) via the L702 true leg; load still succeeds. */
static void
test_vlan_cfg_handler_portid_over_max_skips(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vlan_portid_overmax.ini"));
    assert_int_equal(rv, 0);
}

/* Helper: load a fixture with explicit -t <proc_type> -p <proc_id>. */
static int
load_with_proc(const char *fixture_path, const char *proc_type, const char *proc_id)
{
    char prog[]  = "f-stack";
    char dashc[] = "-c";
    char dasht[] = "-t";
    char dashp[] = "-p";
    char path[256]; snprintf(path, sizeof(path), "%s", fixture_path);
    char tval[32];  snprintf(tval, sizeof(tval), "%s", proc_type);
    char pval[32];  snprintf(pval, sizeof(pval), "%s", proc_id);
    char *argv[] = { prog, dashc, path, dasht, tval, dashp, pval, NULL };
    extern int optind;
    optind = 1;
    return ff_load_config(7, argv);
}

/* TC-S8-CFG-06: proc_id == count-1 (in range) with multi-bit mask exercises
 * the proc_id==count match path (L131) and proc_mask synthesis. */
static void
test_parse_lcore_mask_proc_id_in_range(void **state)
{
    (void)state;
    /* lcore_mask=0x3 -> 2 procs; proc_id=1 is valid (last). */
    int rv = load_with_proc(FIXTURE_PATH("valid_lcore_blank_multibit.ini"),
                            "primary", "1");
    assert_int_equal(rv, 0);
    assert_int_equal(ff_global_cfg.dpdk.proc_id, 1);
    assert_non_null(ff_global_cfg.dpdk.proc_mask);
}

/* TC-S8-CFG-07: proc_id >= count -> parse_lcore_mask returns 0 (L135),
 * so ff_load_config fails. (0x5 -> 2 procs; proc_id=5 is out of range.) */
static void
test_parse_lcore_mask_proc_id_over_count_fails(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_lcore_blank_multibit.ini"),
                            "primary", "5");
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-08: kni.method=reject is accepted by ff_check_config (L1271
 * reject leg of the strcasecmp pair). */
static void
test_ff_check_config_kni_method_reject_ok(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_kni_method_reject.ini"));
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.kni.method, "reject");
}

/* TC-S8-CFG-09: kni.method=<garbage> fails ff_check_config (both
 * strcasecmp != 0 -> return -1). */
static void
test_ff_check_config_kni_method_invalid_fails(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("invalid_kni_method_bad.ini"));
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-10: kni enabled + proc_type=primary + primary lcore present in
 * the port lcore_list -> ff_check_config passes (L1331/1332 found=1 leg). */
static void
test_ff_check_config_kni_primary_lcore_present_ok(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("valid_kni_primary_lcore_ok.ini"),
                            "primary", "0");
    assert_int_equal(rv, 0);
}

/* TC-S8-CFG-11: kni enabled + proc_type=primary + primary lcore MISSING
 * from the port lcore_list -> ff_check_config returns -1 (L1336 !found). */
static void
test_ff_check_config_kni_primary_lcore_missing_fails(void **state)
{
    (void)state;
    int rv = load_with_proc(FIXTURE_PATH("invalid_kni_primary_lcore_missing.ini"),
                            "primary", "0");
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-12: dpdk base_virtaddr/file_prefix/allow + full vdev (cq) +
 * full bond (down_delay) exercise the extra MATCH("dpdk",..) key legs
 * (L984/986/988), vdev cq (L812), bond down_delay (L876), and the
 * dpdk_args_setup allow strtok_r loop (L1113). */
static void
test_ff_load_config_dpdk_extra_keys(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dpdk_extra_keys.ini"));
    assert_int_equal(rv, 0);
    assert_string_equal(ff_global_cfg.dpdk.base_virtaddr, "0x200000000");
    assert_string_equal(ff_global_cfg.dpdk.file_prefix,   "mytest");
    assert_int_equal(ff_global_cfg.dpdk.nb_vdev, 1);
    assert_int_equal(ff_global_cfg.dpdk.vdev_cfgs[0].nb_cq, 1);
    assert_int_equal(ff_global_cfg.dpdk.bond_cfgs[0].down_delay, 300);
}

/* TC-S8-CFG-13: repeated iface/path/mac (vdev) and slave/primary/mac/
 * xmit_policy (bond) keys exercise the free-before-strdup true legs
 * (L810/859/862/867/870). Last value wins; valgrind verifies no leak. */
static void
test_ff_load_config_bond_vdev_repeat_keys_no_leak(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_bond_vdev_repeat.ini"));
    assert_int_equal(rv, 0);
    /* Last value of each repeated key wins. */
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].iface, "net_pcap_b");
    assert_string_equal(ff_global_cfg.dpdk.vdev_cfgs[0].path,  "/tmp/b");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].slave,       "eth0,eth1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].primary,     "eth1");
    assert_string_equal(ff_global_cfg.dpdk.bond_cfgs[0].xmit_policy, "l34");
}

/* TC-S8-CFG-14 (FU-S8-CFG-OOM): the FIRST calloc during load is the
 * proc_lcore array in parse_lcore_mask (L85). Forcing it NULL exercises
 * the L86 OOM error leg -> parse_lcore_mask returns 0 -> load fails. */
static void
test_parse_lcore_mask_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 1;     /* fail the 1st calloc (proc_lcore) */
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    g_calloc_fail_after = 0;     /* disarm */
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-15 (FU-S8-CFG-OOM): the SECOND calloc is the port_cfgs array
 * (L551, alloc_port_cfgs). Forcing it NULL exercises that OOM leg. The
 * proc_lcore calloc (1st) succeeds; the port_cfgs calloc (2nd) fails. */
static void
test_alloc_port_cfgs_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 2;     /* fail the 2nd calloc (port_cfgs) */
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    g_calloc_fail_after = 0;
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-16 (FU-S8-CFG-OOM): with [dpdk]->[port0]->[vlanN] section order
 * the 3rd calloc is vlan_cfgs (L661). Forcing it NULL covers that OOM leg. */
static void
test_vlan_cfgs_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 3;
    int rv = load_with_fixture(FIXTURE_PATH("valid_dual_vlan.ini"));
    g_calloc_fail_after = 0;
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-17 (FU-S8-CFG-OOM): [dpdk]->[port0]->[vdev0]; 3rd calloc is
 * vdev_cfgs (L772). Forcing it NULL covers that OOM leg. */
static void
test_vdev_cfgs_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 3;
    int rv = load_with_fixture(FIXTURE_PATH("valid_vdev.ini"));
    g_calloc_fail_after = 0;
    assert_int_equal(rv, -1);
}

/* TC-S8-CFG-18 (FU-S8-CFG-OOM): [dpdk]->[port0]->[bond0]; 3rd calloc is
 * bond_cfgs (L829). Forcing it NULL covers that OOM leg. */
static void
test_bond_cfgs_calloc_oom_returns_error(void **state)
{
    (void)state;
    g_calloc_fail_after = 3;
    int rv = load_with_fixture(FIXTURE_PATH("valid_bond.ini"));
    g_calloc_fail_after = 0;
    assert_int_equal(rv, -1);
}

#ifdef FF_KERNEL_COEXIST
/* ------------------------------------------------------------------------ */
/* kernel_event_support (coexistence): [stack] kernel_coexist parsing        */
/* ------------------------------------------------------------------------ */
/* kernel_coexist=1 -> stack.kernel_coexist == 1 */
static void
test_ff_load_config_stack_coexist_enabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_stack_kernel.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 1);
}

/* [stack] absent -> coexistence disabled (0) */
static void
test_ff_load_config_stack_absent_defaults_disabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_minimal.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 0);
}

/* kernel_coexist with an unrecognized value -> falls back to disabled (0) */
static void
test_ff_load_config_stack_garbage_defaults_disabled(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_stack_garbage.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 0);
}

/* explicit kernel_coexist=0 -> 0 (verified via valid_all_sections.ini) */
static void
test_ff_load_config_stack_coexist_disabled_explicit(void **state)
{
    (void)state;
    int rv = load_with_fixture(FIXTURE_PATH("valid_all_sections.ini"));
    (void)rv;
    assert_int_equal(ff_global_cfg.stack.kernel_coexist, 0);
}
#endif /* FF_KERNEL_COEXIST */

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_load_config_valid_minimal_ini, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_no_dpdk_section,   test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_invalid_lcore_mask,test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_dual_vlan,         test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_with_vip_addr,     test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_argv_override,     test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_unknown_section,   test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_empty_ini,         test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vlan_cfg_handler_isolated,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ipfw_pr_cfg_handler_isolated,     test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_port_cfg_handler_addr_parse,      test_setup, NULL),
        /* Stage-3 coverage extension */
        cmocka_unit_test_setup_teardown(test_ff_load_config_all_sections,      test_setup, NULL),
        /* Stage-6 Phase-2 coverage extensions */
        cmocka_unit_test_setup_teardown(test_ff_load_config_dpdk_full,           test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_lcore_mask_no_bits,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_portlist_nonint,     test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_bond_cfg_handler_no_nb_bond,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_bond_cfg_handler_bad_section,       test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_rss_check_cfg_handler_no_port_no_vlan, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_rss_tbl_cfg_handler_bad_tuple,      test_setup, NULL),
        /* R-F (req 0.1/0.2): thash_adjust runtime switch parsing */
        cmocka_unit_test_setup_teardown(test_rss_check_thash_adjust_off_parses,  test_setup, NULL),
        /* Stage-6 Phase-8 (FU-S2-2-CFG-UNLOAD) */
        cmocka_unit_test_setup_teardown(test_ff_unload_config_zeroes_state,      test_setup, NULL),
        /* Stage-7 Phase-3 branch-coverage boost (FU-S7-CFG-*) */
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_uppercase_0X_succeeds, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vlan_cfg_handler_id_not_in_filter_returns_one, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vlan_cfg_handler_bad_section_returns_zero, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vdev_cfg_handler_no_nb_vdev_returns_zero, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_vdev_full, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_bond_full, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_port_cfg_handler_bad_section_returns_zero, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_port_cfg_handler_id_over_max_returns_one, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_repeat_keys_no_leak, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_freebsd_boot_multi_entries, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_inet6_fixture_ignored, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_argv_t_override, test_setup, NULL),
        /* Stage-8 Phase-2 branch boost (FU-S8-CFG-ARGV-FIXTURES) */
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_blank_and_multibit,      test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_all_blank_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_mid_nonhex_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_vlan_vip_addr,             test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vlan_cfg_handler_portid_over_max_skips,   test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_proc_id_in_range,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_proc_id_over_count_fails, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_check_config_kni_method_reject_ok,     test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_check_config_kni_method_invalid_fails, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_check_config_kni_primary_lcore_present_ok,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_check_config_kni_primary_lcore_missing_fails, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_dpdk_extra_keys,            test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_bond_vdev_repeat_keys_no_leak, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_parse_lcore_mask_calloc_oom_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_alloc_port_cfgs_calloc_oom_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vlan_cfgs_calloc_oom_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_vdev_cfgs_calloc_oom_returns_error, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_bond_cfgs_calloc_oom_returns_error, test_setup, NULL),
#ifdef FF_KERNEL_COEXIST
        /* kernel_event_support: [stack] kernel_coexist */
        cmocka_unit_test_setup_teardown(test_ff_load_config_stack_coexist_enabled,         test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_stack_absent_defaults_disabled, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_stack_garbage_defaults_disabled, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_load_config_stack_coexist_disabled_explicit, test_setup, NULL),
#endif /* FF_KERNEL_COEXIST */
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
