/*
 * F-Stack tools unit test: tools/compat/ff_ipc.c argument parsing
 * (F-M5-2: explicit "<proc>[:<gen>[:<epoch>]]" addressing).
 *
 * tools/compat/ff_ipc.c is #included instead of linked: the epoch argument
 * and the resolved ring name are file-static, so this is the only way to
 * assert which ring an explicit argument really addresses without bringing
 * up a stack and a resident primary to probe.
 */

/* CMocka required boilerplate before <cmocka.h> */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../tools/compat/ff_ipc.c"

/* A malformed argument is reported with exit(1). */
void __wrap_exit(int code);

void
__wrap_exit(int code)
{
    (void)code;
    mock_assert(0, "exit", __FILE__, __LINE__);
}

static int
ff_ipc_arg_reset(void **state)
{
    (void)state;

    ff_proc_id = 0;
    ff_gen_arg = FF_IPC_GEN_AUTO;
    ff_ring_gen = FF_IPC_GEN_AUTO;
    ff_epoch_arg = FF_RELOAD_EPOCH_NONE;
    ff_ring_epoch = 0;

    return 0;
}

/* Resolve the in-ring an explicit argument addresses, the way ff_ipc_send
 * does it (probe-free: an explicit generation short-circuits the probe). */
static void
resolve_ring(char *buf, size_t buflen)
{
    int gen = ff_ipc_ring_gen();

    assert_int_not_equal(gen, FF_IPC_GEN_AUTO);
    assert_int_equal(ff_msg_ring_name(buf, buflen, FF_MSG_RING_IN,
        ff_proc_id, -1, gen, ff_ring_epoch, 1), 0);
}

/* "1": unchanged pre-M5 behaviour — no generation, no epoch, auto probe. */
static void
test_ff_ipc_proc_id_plain(void **state)
{
    (void)state;

    assert_int_equal(ff_set_proc_id_str("1"), 1);
    assert_int_equal((int)ff_proc_id, 1);
    assert_int_equal(ff_gen_arg, FF_IPC_GEN_AUTO);
    assert_int_equal((int)(ff_epoch_arg == FF_RELOAD_EPOCH_NONE), 1);
}

/* "1:0": slot 0, so the name is the pre-M5 one byte for byte. */
static void
test_ff_ipc_proc_id_gen(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    assert_int_equal(ff_set_proc_id_str("1:0"), 1);
    assert_int_equal(ff_gen_arg, 0);
    assert_int_equal((int)(ff_epoch_arg == FF_RELOAD_EPOCH_NONE), 1);

    resolve_ring(name, sizeof(name));
    assert_string_equal(name, "ff_msg_ring_in_1_g0");
}

/* "1:0:3": F-M5-2 — epoch 3 is slot 3, which is what the USR2 rings live
 * in. Before this the epoch was forced to 0 and the lookup failed. */
static void
test_ff_ipc_proc_id_gen_epoch(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    assert_int_equal(ff_set_proc_id_str("1:0:3"), 1);
    assert_int_equal(ff_gen_arg, 0);
    assert_int_equal((int)ff_epoch_arg, 3);
    assert_int_equal((int)ff_reload_epoch_slot_of(ff_epoch_arg), 3);

    resolve_ring(name, sizeof(name));
    assert_string_equal(name, "ff_msg_ring_in_1_e3_g0");
}

/* "2:1:1": both numbers explicit, slot 1. */
static void
test_ff_ipc_proc_id_full_coordinate(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    assert_int_equal(ff_set_proc_id_str("2:1:1"), 2);
    assert_int_equal((int)ff_proc_id, 2);
    assert_int_equal(ff_gen_arg, 1);
    assert_int_equal((int)ff_epoch_arg, 1);

    resolve_ring(name, sizeof(name));
    assert_string_equal(name, "ff_msg_ring_in_2_e1_g1");
}

/* -g "1:2": the generation-only option carries the epoch too. */
static void
test_ff_ipc_gen_str_epoch(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    ff_set_gen_str("1:2");
    assert_int_equal(ff_gen_arg, 1);
    assert_int_equal((int)ff_epoch_arg, 2);

    resolve_ring(name, sizeof(name));
    assert_string_equal(name, "ff_msg_ring_in_0_e2_g1");
}

/* -g "0": no epoch, exactly what atoi() used to produce. */
static void
test_ff_ipc_gen_str_plain(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    ff_set_gen_str("0");
    assert_int_equal(ff_gen_arg, 0);
    assert_int_equal((int)(ff_epoch_arg == FF_RELOAD_EPOCH_NONE), 1);

    resolve_ring(name, sizeof(name));
    assert_string_equal(name, "ff_msg_ring_in_0_g0");
}

/* Malformed arguments are reported, never silently truncated to a guess. */
static void
test_ff_ipc_rejects_malformed(void **state)
{
    (void)state;

    expect_assert_failure(ff_set_proc_id_str("1:0:3:4"));
    expect_assert_failure(ff_set_proc_id_str("1:0:"));
    expect_assert_failure(ff_set_proc_id_str("1:0:x"));
    expect_assert_failure(ff_set_proc_id_str("1:x"));
    expect_assert_failure(ff_set_proc_id_str("x"));
    expect_assert_failure(ff_set_gen_str("x"));
    /* the FF_RELOAD_EPOCH_NONE sentinel cannot be expressed, and neither
     * can a negative or out-of-range epoch */
    expect_assert_failure(ff_set_proc_id_str("1:0:4294967295"));
    expect_assert_failure(ff_set_proc_id_str("1:0:-1"));
    expect_assert_failure(ff_set_epoch(FF_RELOAD_EPOCH_NONE));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_ipc_proc_id_plain,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_proc_id_gen,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_proc_id_gen_epoch,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_proc_id_full_coordinate,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_gen_str_epoch,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_gen_str_plain,
            ff_ipc_arg_reset, NULL),
        cmocka_unit_test_setup_teardown(test_ff_ipc_rejects_malformed,
            ff_ipc_arg_reset, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
