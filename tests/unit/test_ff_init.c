/*
 * F-Stack lib/ unit test: ff_init.c (P2 #2)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/plan-stage4-p2-tests.md §7 Phase 2b
 * Coverage: 4 TC — happy path / 4 step-failure paths.
 *
 * Strategy:
 *   - ff_init.c is a thin orchestration of 4 init steps; each step that
 *     returns < 0 leads to exit(1).
 *   - We stub the 6 external functions (ff_load_config / ff_dpdk_init /
 *     ff_freebsd_init / ff_dpdk_if_up / ff_dpdk_run / ff_dpdk_stop) as
 *     CMocka mock_type-driven, plus dpdk_argc/dpdk_argv extern globals.
 *   - exit() is wrapped via -Wl,--wrap=exit -> mock_assert so that a TC
 *     can verify the failure path triggered the right step's exit.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ff_api.h"          /* ff_init / ff_run / ff_stop_run, loop_func_t */
#include "ff_config.h"       /* DPDK_CONFIG_NUM, dpdk_argc, dpdk_argv extern */

/* ------------------------------------------------------------------------ */
/* extern globals required by ff_init.c                                     */
/* ------------------------------------------------------------------------ */
int   dpdk_argc = 0;
char *dpdk_argv[DPDK_CONFIG_NUM + 1] = {0};

/* ------------------------------------------------------------------------ */
/* Stubs for the 4 init steps + run/stop                                    */
/*                                                                          */
/* Each step records its invocation count + reads its return value from a   */
/* per-test will_return queue. ff_dpdk_run / ff_dpdk_stop just record.      */
/* ------------------------------------------------------------------------ */

static int g_load_config_calls   = 0;
static int g_dpdk_init_calls     = 0;
static int g_freebsd_init_calls  = 0;
static int g_if_up_calls         = 0;
static int g_dpdk_run_calls      = 0;
static int g_dpdk_stop_calls     = 0;

int
ff_load_config(int argc, char * const argv[])
{
    (void)argc; (void)argv;
    g_load_config_calls++;
    return mock_type(int);
}

int
ff_dpdk_init(int argc, char **argv)
{
    (void)argc; (void)argv;
    g_dpdk_init_calls++;
    return mock_type(int);
}

int
ff_freebsd_init(void)
{
    g_freebsd_init_calls++;
    return mock_type(int);
}

int
ff_dpdk_if_up(void)
{
    g_if_up_calls++;
    return mock_type(int);
}

void
ff_dpdk_run(loop_func_t loop, void *arg)
{
    (void)loop; (void)arg;
    g_dpdk_run_calls++;
}

void
ff_dpdk_stop(void)
{
    g_dpdk_stop_calls++;
}

/* ------------------------------------------------------------------------ */
/* exit() wrap — fail-fast via cmocka so the test process is not killed.    */
/* When ff_init's exit(1) path triggers, we record the code and longjmp     */
/* back to the cmocka harness via mock_assert.                              */
/*                                                                          */
/* Activated by Makefile: -Wl,--wrap=exit                                   */
/* ------------------------------------------------------------------------ */

static int g_last_exit_code = 0;
static int g_exit_called     = 0;

void __attribute__((noreturn))
__wrap_exit(int code)
{
    g_last_exit_code = code;
    g_exit_called    = 1;
    /* mock_assert with cmocka_set_expect_assert_failure_set causes the test
     * to exit cleanly via longjmp instead of really exiting. */
    mock_assert(0, "exit", __FILE__, __LINE__);
    /* unreachable */
    __builtin_unreachable();
}

/* ------------------------------------------------------------------------ */
/* Test fixture                                                             */
/* ------------------------------------------------------------------------ */

static int
test_setup(void **state)
{
    (void)state;
    g_load_config_calls = g_dpdk_init_calls = g_freebsd_init_calls =
        g_if_up_calls = g_dpdk_run_calls = g_dpdk_stop_calls = 0;
    g_last_exit_code = 0;
    g_exit_called    = 0;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-01: ff_init happy path — all 4 steps return 0, no exit       */
/* ------------------------------------------------------------------------ */
static void
test_ff_init_happy_path(void **state)
{
    (void)state;
    will_return(ff_load_config,  0);
    will_return(ff_dpdk_init,    0);
    will_return(ff_freebsd_init, 0);
    will_return(ff_dpdk_if_up,   0);

    char *argv[] = { (char *)"f-stack" };
    int rv = ff_init(1, argv);

    assert_int_equal(rv, 0);
    assert_int_equal(g_load_config_calls,  1);
    assert_int_equal(g_dpdk_init_calls,    1);
    assert_int_equal(g_freebsd_init_calls, 1);
    assert_int_equal(g_if_up_calls,        1);
    assert_int_equal(g_exit_called,        0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-02: ff_load_config failure -> exit(1) before dpdk_init       */
/* ------------------------------------------------------------------------ */
static void
test_ff_init_fail_load_config(void **state)
{
    (void)state;
    will_return(ff_load_config, -1);

    char *argv[] = { (char *)"f-stack" };
    /* ff_init calls exit(1) which our __wrap_exit converts to a cmocka
     * expected assertion failure. */
    expect_assert_failure(ff_init(1, argv));

    /* Steps after the failed one should not have been called. */
    assert_int_equal(g_load_config_calls,  1);
    assert_int_equal(g_dpdk_init_calls,    0);
    assert_int_equal(g_freebsd_init_calls, 0);
    assert_int_equal(g_if_up_calls,        0);
    assert_int_equal(g_exit_called,        1);
    assert_int_equal(g_last_exit_code,     1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-03: ff_dpdk_init failure -> exit(1) before freebsd_init      */
/* ------------------------------------------------------------------------ */
static void
test_ff_init_fail_dpdk_init(void **state)
{
    (void)state;
    will_return(ff_load_config, 0);
    will_return(ff_dpdk_init,  -1);

    char *argv[] = { (char *)"f-stack" };
    expect_assert_failure(ff_init(1, argv));

    assert_int_equal(g_load_config_calls,  1);
    assert_int_equal(g_dpdk_init_calls,    1);
    assert_int_equal(g_freebsd_init_calls, 0);
    assert_int_equal(g_if_up_calls,        0);
    assert_int_equal(g_exit_called,        1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-04: ff_run + ff_stop_run forward to dpdk_run / dpdk_stop     */
/* ------------------------------------------------------------------------ */
static int
trivial_loop(void *arg)
{
    (void)arg;
    return 0;
}

static void
test_ff_run_and_stop_forward(void **state)
{
    (void)state;
    ff_run(trivial_loop, (void *)(intptr_t)0x42);
    assert_int_equal(g_dpdk_run_calls, 1);

    ff_stop_run();
    assert_int_equal(g_dpdk_stop_calls, 1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-05 (Stage-6): ff_freebsd_init failure -> exit(1)             */
/* before ff_dpdk_if_up. Covers ff_init.c L46-47 exit branch.                */
/* ------------------------------------------------------------------------ */
static void
test_ff_init_fail_freebsd_init(void **state)
{
    (void)state;
    will_return(ff_load_config,  0);
    will_return(ff_dpdk_init,    0);
    will_return(ff_freebsd_init, -1);

    char *argv[] = { (char *)"f-stack" };
    expect_assert_failure(ff_init(1, argv));

    assert_int_equal(g_load_config_calls,  1);
    assert_int_equal(g_dpdk_init_calls,    1);
    assert_int_equal(g_freebsd_init_calls, 1);
    assert_int_equal(g_if_up_calls,        0);
    assert_int_equal(g_exit_called,        1);
    assert_int_equal(g_last_exit_code,     1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-INIT-06 (Stage-6): ff_dpdk_if_up failure -> exit(1).              */
/* Covers ff_init.c L50-51 final exit branch (the last init step).          */
/* ------------------------------------------------------------------------ */
static void
test_ff_init_fail_dpdk_if_up(void **state)
{
    (void)state;
    will_return(ff_load_config,  0);
    will_return(ff_dpdk_init,    0);
    will_return(ff_freebsd_init, 0);
    will_return(ff_dpdk_if_up,   -1);

    char *argv[] = { (char *)"f-stack" };
    expect_assert_failure(ff_init(1, argv));

    assert_int_equal(g_load_config_calls,  1);
    assert_int_equal(g_dpdk_init_calls,    1);
    assert_int_equal(g_freebsd_init_calls, 1);
    assert_int_equal(g_if_up_calls,        1);
    assert_int_equal(g_exit_called,        1);
    assert_int_equal(g_last_exit_code,     1);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_init_happy_path,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_init_fail_load_config,  test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_init_fail_dpdk_init,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_run_and_stop_forward,   test_setup, NULL),
        /* Stage-6 coverage extensions */
        cmocka_unit_test_setup_teardown(test_ff_init_fail_freebsd_init, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_init_fail_dpdk_if_up,   test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
