/*
 * F-Stack lib/ unit test: ff_log.c (P0 #2)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §3
 * Coverage: 13 TC (TC-U-P0-LOG-01..13).
 *
 * IMPORTANT spec correction (verified against lib/ff_log.{h,c}):
 *   - ff_log_open_set() takes NO arguments (spec 06 §3.3 had `dir, proc_id`
 *     in the textual description; the real signature is `int ff_log_open_set(void)`).
 *     The function reads ff_global_cfg.log.dir and ff_global_cfg.dpdk.proc_id
 *     directly from the global config struct.
 *   - The function name is `ff_log_open_set` (spec was correct on this).
 *
 * Per workspace mandate "代码 vs 文档不一致以代码为准", the TCs below align
 * with the actual API signature. The 13-TC count from spec is preserved by
 * mapping each spec scenario onto an equivalent test against the real API.
 *
 * Mock strategy (spec 04 §7.2 #2):
 *   - 4 rte_log API wraps via -Wl,--wrap=:
 *       __wrap_rte_openlog_stream
 *       __wrap_rte_log_set_global_level
 *       __wrap_rte_log_set_level
 *       __wrap_rte_vlog
 *   - common/ff_log_stub.c provides storage for `struct ff_config ff_global_cfg`
 *   - common/rte_stub.c wraps rte_exit/rte_panic (BASE_WRAPS in Makefile)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ff_config.h"      /* struct ff_config / ff_global_cfg */
#include "ff_log.h"         /* under-test API */

/* ------------------------------------------------------------------------ */
/* Wrap definitions for rte_log family                                      */
/* ------------------------------------------------------------------------ */

int
__wrap_rte_openlog_stream(FILE *f)
{
    check_expected_ptr(f);
    return mock_type(int);
}

void
__wrap_rte_log_set_global_level(uint32_t level)
{
    check_expected(level);
}

int
__wrap_rte_log_set_level(uint32_t logtype, uint32_t level)
{
    check_expected(logtype);
    check_expected(level);
    return mock_type(int);
}

/*
 * rte_vlog: variadic-style with va_list. We deliberately do NOT touch `ap`
 * (would mis-align in user space if format-args mismatch); only assert
 * level/logtype/format-pointer-non-null. (spec 04 §7.2 / R-S2-5)
 */
int
__wrap_rte_vlog(uint32_t level, uint32_t logtype, const char *fmt, va_list ap)
{
    (void)ap;
    check_expected(level);
    check_expected(logtype);
    assert_non_null(fmt);
    return mock_type(int);
}

/* ------------------------------------------------------------------------ */
/* Test helpers                                                             */
/* ------------------------------------------------------------------------ */

static char g_tmp_dir[256] = "/tmp/ff_log_test_dir_XXXXXX";
static int  g_tmp_dir_owned = 0;

static int
test_setup(void **state)
{
    (void)state;
    /* fresh per-test ff_global_cfg.log scratch */
    memset(&ff_global_cfg.log,  0, sizeof(ff_global_cfg.log));
    memset(&ff_global_cfg.dpdk, 0, sizeof(ff_global_cfg.dpdk));

    /* mkdtemp for tests that need a real writable dir */
    char tmpl[] = "/tmp/ff_log_test_dir_XXXXXX";
    char *d = mkdtemp(tmpl);
    if (d) {
        snprintf(g_tmp_dir, sizeof(g_tmp_dir), "%s/", d);  /* trailing slash */
        g_tmp_dir_owned = 1;
    } else {
        snprintf(g_tmp_dir, sizeof(g_tmp_dir), "/tmp/");
        g_tmp_dir_owned = 0;
    }
    ff_global_cfg.log.dir = g_tmp_dir;
    return 0;
}

static int
test_teardown(void **state)
{
    (void)state;
    if (ff_global_cfg.log.f) {
        fclose(ff_global_cfg.log.f);
        ff_global_cfg.log.f = NULL;
    }
    if (g_tmp_dir_owned && strncmp(g_tmp_dir, "/tmp/ff_log_test_dir_", 21) == 0) {
        /* cleanup log file then dir, both via wrapper */
        char cmd[768];
        /* Strip trailing slash for cleanup wrapper */
        char dir[256];
        snprintf(dir, sizeof(dir), "%s", g_tmp_dir);
        size_t dlen = strlen(dir);
        if (dlen > 0 && dir[dlen - 1] == '/') {
            dir[dlen - 1] = '\0';
        }
        snprintf(cmd, sizeof(cmd),
                 "/data/workspace/rm_tmp_file.sh %s >/dev/null 2>&1", dir);
        int sysrc = system(cmd);
        (void)sysrc;
        g_tmp_dir_owned = 0;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-01: open_set normal path                                     */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_open_set_normal(void **state)
{
    (void)state;
    ff_global_cfg.dpdk.proc_id = 0;
    ff_global_cfg.log.level    = FF_LOG_INFO;

    /* ff_log_open_set will:
     *   fopen(<dir>0.log, "a+") -> non-NULL FILE*
     *   call ff_log_reset_stream(f) -> __wrap_rte_openlog_stream(f)
     *   call ff_log_set_level(LIB,  level) -> __wrap_rte_log_set_level
     *   call ff_log_set_level(FBSD, level) -> __wrap_rte_log_set_level
     */
    expect_any(__wrap_rte_openlog_stream, f);
    will_return(__wrap_rte_openlog_stream, 0);

    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_LIB);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_INFO);
    will_return(__wrap_rte_log_set_level, 0);

    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_FREEBSD);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_INFO);
    will_return(__wrap_rte_log_set_level, 0);

    int rv = ff_log_open_set();
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.log.f);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-02: open_set with non-writable dir -> -1                     */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_open_set_dir_invalid(void **state)
{
    (void)state;
    /* Path that fopen() should reject (component is not a directory). */
    ff_global_cfg.log.dir = "/nonexistent_path_xyz_zzz/";
    ff_global_cfg.dpdk.proc_id = 0;

    /* Failure path inside ff_log_open_set tries to log a warning via
     * ff_log -> rte_vlog, so wrap rte_vlog once. */
    expect_value(__wrap_rte_vlog, level,   FF_LOG_WARNING);
    expect_value(__wrap_rte_vlog, logtype, FF_LOGTYPE_FSTACK_LIB);
    will_return(__wrap_rte_vlog, 0);

    int rv = ff_log_open_set();
    assert_int_equal(rv, -1);
    assert_null(ff_global_cfg.log.f);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-03: open_set with proc_id encoded into filename              */
/* (Validates the snprintf "%s%u.log" path with proc_id != 0 succeeds.)     */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_open_set_long_filename(void **state)
{
    (void)state;
    ff_global_cfg.dpdk.proc_id = 42;
    ff_global_cfg.log.level    = FF_LOG_DEBUG;

    expect_any(__wrap_rte_openlog_stream, f);
    will_return(__wrap_rte_openlog_stream, 0);
    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_LIB);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_DEBUG);
    will_return(__wrap_rte_log_set_level, 0);
    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_FREEBSD);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_DEBUG);
    will_return(__wrap_rte_log_set_level, 0);

    int rv = ff_log_open_set();
    assert_int_equal(rv, 0);
    assert_non_null(ff_global_cfg.log.f);
    /* Filename should reflect proc_id 42 */
    char expect_path[512];
    snprintf(expect_path, sizeof(expect_path), "%s42.log", g_tmp_dir);
    struct stat st;
    assert_int_equal(stat(expect_path, &st), 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-04: ff_log_close when f is non-NULL                          */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_close_when_open(void **state)
{
    (void)state;
    /* Pre-open via tmpfile() so we exercise close path without rte wraps */
    ff_global_cfg.log.f = tmpfile();
    assert_non_null(ff_global_cfg.log.f);

    ff_log_close();

    assert_null(ff_global_cfg.log.f);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-05: ff_log_close when f is NULL (no crash)                   */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_close_when_null(void **state)
{
    (void)state;
    ff_global_cfg.log.f = NULL;
    ff_log_close();              /* must not crash */
    assert_null(ff_global_cfg.log.f);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-06: ff_log_reset_stream forwards to rte_openlog_stream       */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_reset_stream_normal(void **state)
{
    (void)state;
    FILE *f = tmpfile();
    assert_non_null(f);

    expect_value(__wrap_rte_openlog_stream, f, f);
    will_return(__wrap_rte_openlog_stream, 0);

    int rv = ff_log_reset_stream(f);
    assert_int_equal(rv, 0);

    fclose(f);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-07: ff_log_set_global_level forwards level                   */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_set_global_level(void **state)
{
    (void)state;
    expect_value(__wrap_rte_log_set_global_level, level, FF_LOG_INFO);
    ff_log_set_global_level(FF_LOG_INFO);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-08: ff_log_set_level forwards (logtype, level)               */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_set_level_normal(void **state)
{
    (void)state;
    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_LIB);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_DEBUG);
    will_return(__wrap_rte_log_set_level, 0);

    int rv = ff_log_set_level(FF_LOGTYPE_FSTACK_LIB, FF_LOG_DEBUG);
    assert_int_equal(rv, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-09: ff_log_set_level passes through return value (-1)        */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_set_level_returns_value(void **state)
{
    (void)state;
    expect_value(__wrap_rte_log_set_level, logtype, FF_LOGTYPE_FSTACK_LIB);
    expect_value(__wrap_rte_log_set_level, level,   FF_LOG_DEBUG);
    will_return(__wrap_rte_log_set_level, -1);

    int rv = ff_log_set_level(FF_LOGTYPE_FSTACK_LIB, FF_LOG_DEBUG);
    assert_int_equal(rv, -1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-10: ff_log variadic basic                                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_variadic_basic(void **state)
{
    (void)state;
    expect_value(__wrap_rte_vlog, level,   FF_LOG_INFO);
    expect_value(__wrap_rte_vlog, logtype, FF_LOGTYPE_FSTACK_LIB);
    will_return(__wrap_rte_vlog, 0);

    int rv = ff_log(FF_LOG_INFO, FF_LOGTYPE_FSTACK_LIB, "x=%d", 42);
    assert_int_equal(rv, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-11: ff_log with zero variadic args (literal-only fmt)        */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_variadic_zero_args(void **state)
{
    (void)state;
    expect_value(__wrap_rte_vlog, level,   FF_LOG_NOTICE);
    expect_value(__wrap_rte_vlog, logtype, FF_LOGTYPE_FSTACK_LIB);
    will_return(__wrap_rte_vlog, 1);

    int rv = ff_log(FF_LOG_NOTICE, FF_LOGTYPE_FSTACK_LIB, "static msg");
    assert_int_equal(rv, 1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-12: ff_vlog forwards level/logtype/fmt to rte_vlog           */
/* ------------------------------------------------------------------------ */
static void
fill_va_and_call_vlog(uint32_t lvl, uint32_t lt, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int rv = ff_vlog(lvl, lt, fmt, ap);
    va_end(ap);
    assert_int_equal(rv, 7);   /* must equal will_return value below */
}

static void
test_ff_vlog_normal(void **state)
{
    (void)state;
    expect_value(__wrap_rte_vlog, level,   FF_LOG_WARNING);
    expect_value(__wrap_rte_vlog, logtype, FF_LOGTYPE_FSTACK_LIB);
    will_return(__wrap_rte_vlog, 7);

    fill_va_and_call_vlog(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB, "a=%d", 5);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-LOG-13: ff_log returns whatever rte_vlog returns                 */
/* ------------------------------------------------------------------------ */
static void
test_ff_log_returns_rte_vlog_value(void **state)
{
    (void)state;
    expect_value(__wrap_rte_vlog, level,   FF_LOG_DEBUG);
    expect_value(__wrap_rte_vlog, logtype, FF_LOGTYPE_FSTACK_LIB);
    will_return(__wrap_rte_vlog, 5);

    int rv = ff_log(FF_LOG_DEBUG, FF_LOGTYPE_FSTACK_LIB, "x");
    assert_int_equal(rv, 5);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_log_open_set_normal,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_open_set_dir_invalid,    test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_open_set_long_filename,  test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_close_when_open,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_close_when_null,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_reset_stream_normal,     test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_set_global_level,        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_set_level_normal,        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_set_level_returns_value, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_variadic_basic,          test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_variadic_zero_args,      test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_vlog_normal,                 test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ff_log_returns_rte_vlog_value,  test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
