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
#include <unistd.h>             /* fork/_exit for the dead-owner case */
#include <sys/wait.h>

#include "../../tools/compat/ff_ipc.c"

/* P4: the ring geometry the stack creates (lib/ff_memory.h is not on this
 * translation unit's include path). */
#define P4_MSG_RING_SIZE    32
#define P4_MSG_RING_FLAGS   0   /* MP/MC: several tools plus the stack */

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

/* ---- P4 (C01-5): reply ownership, driven with a real EAL ---------------
 *
 * ff_ipc_init() itself always attaches as a DPDK secondary to a running
 * stack, which no unit test can provide, so the group brings up its own
 * EAL (--no-huge/--no-pci) and sets inited / message_pool directly — the
 * .c is #included, so the file-statics are reachable. Coordinates are
 * pinned explicitly (no probe). EAL failure skips the group; a SKIP is
 * never counted as a pass. */
static int p4_eal_tried;
static int p4_eal_ok;
static struct rte_ring *p4_in_ring;
static struct rte_ring *p4_out_ring;
static struct rte_ring *p4_out_reload;

static void
p4_eal_init(void)
{
    char prefix[64];
    char *argv[] = { (char *) "test_ff_ipc",
        (char *) "--no-huge", (char *) "--no-pci", (char *) "--no-shconf",
        (char *) "-m", (char *) "32", prefix, (char *) "--no-telemetry",
        (char *) "-l", (char *) "0", NULL };
    int argc;

    if (p4_eal_tried)
        return;
    p4_eal_tried = 1;
    snprintf(prefix, sizeof(prefix), "--file-prefix=ff_p4_ipc_%ld",
        (long)getpid());
    argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;
    p4_eal_ok = rte_eal_init(argc, argv) >= 0;
}

static int
p4_setup(void **state)
{
    char name[RTE_RING_NAMESIZE];

    (void)state;

    p4_eal_init();
    if (!p4_eal_ok)
        skip();

    ff_proc_id = 0;
    ff_gen_arg = 0;                 /* explicit coordinate: no probe */
    ff_ring_gen = 0;
    ff_epoch_arg = 0;               /* slot 0 */
    ff_ring_epoch = 0;

    if (message_pool == NULL) {
        message_pool = rte_mempool_create("ff_msg_pool", 64,
            sizeof(struct ff_msg), 0, 0, NULL, NULL, NULL, NULL,
            SOCKET_ID_ANY, 0);
    }
    assert_non_null(message_pool);

    assert_int_equal(ff_msg_ring_name(name, sizeof(name), FF_MSG_RING_IN,
        ff_proc_id, -1, ff_ring_gen, ff_ring_epoch, 1), 0);
    if (p4_in_ring == NULL)
        p4_in_ring = rte_ring_create(name, P4_MSG_RING_SIZE, SOCKET_ID_ANY,
            P4_MSG_RING_FLAGS);
    assert_non_null(p4_in_ring);

    assert_int_equal(ff_ipc_ring_name(name, sizeof(name), FF_MSG_RING_OUT,
        FF_SYSCTL), 0);
    if (p4_out_ring == NULL)
        p4_out_ring = rte_ring_create(name, P4_MSG_RING_SIZE, SOCKET_ID_ANY,
            P4_MSG_RING_FLAGS);
    assert_non_null(p4_out_ring);

    assert_int_equal(ff_ipc_ring_name(name, sizeof(name), FF_MSG_RING_OUT,
        FF_RELOAD), 0);
    if (p4_out_reload == NULL)
        p4_out_reload = rte_ring_create(name, P4_MSG_RING_SIZE, SOCKET_ID_ANY,
            P4_MSG_RING_FLAGS);
    assert_non_null(p4_out_reload);

    inited = 1;
    ff_pending_msg = NULL;
    ff_ipc_stash_n = 0;
    memset(ff_ipc_stash, 0, sizeof(ff_ipc_stash));
    memset(ff_ipc_foreign, 0, sizeof(ff_ipc_foreign));
    ff_ipc_foreign_requeued = 0;
    ff_ipc_orphan_dropped = 0;
    ff_ipc_reply_lost = 0;

    return 0;
}

static int
p4_teardown(void **state)
{
    void *obj;

    (void)state;

    if (!p4_eal_ok)
        return 0;

    while (rte_ring_dequeue(p4_in_ring, &obj) == 0)
        rte_mempool_put(message_pool, obj);
    while (rte_ring_dequeue(p4_out_ring, &obj) == 0)
        rte_mempool_put(message_pool, obj);
    while (rte_ring_dequeue(p4_out_reload, &obj) == 0)
        rte_mempool_put(message_pool, obj);
    while (ff_ipc_stash_n > 0)
        rte_mempool_put(message_pool, ff_ipc_stash[--ff_ipc_stash_n]);

    ff_pending_msg = NULL;
    inited = 0;

    return 0;
}

/* The stack side of one round trip: answer whatever is queued. */
static void
p4_answer(void)
{
    void *obj;

    assert_int_equal(rte_ring_dequeue(p4_in_ring, &obj), 0);
    assert_int_equal(rte_ring_enqueue(p4_out_ring, obj), 0);
}

/* C-P4-1/3: the reply to the query this process sent is recognised by its
 * ownership tag, not by pointer equality. */
static void
test_p4_recv_own_reply(void **state)
{
    struct ff_msg *m, *got = (struct ff_msg *)0x1;

    (void)state;

    m = ff_ipc_msg_alloc();
    assert_non_null(m);
    assert_int_equal(ff_ipc_send(m), 0);
    p4_answer();

    assert_int_equal(ff_ipc_recv(&got, FF_SYSCTL), 0);
    assert_ptr_equal((void *)got, (void *)m);
    ff_ipc_msg_free(got);
}

/* C-P4-2: another client's reply is put back, never freed, and never
 * returned as an answer. */
static void
test_p4_recv_foreign_live_owner(void **state)
{
    struct ff_msg *foreign, *got = (struct ff_msg *)0x1;
    uint64_t requeued = 0, orphan = 0, lost = 0;
    void *obj;

    (void)state;

    foreign = ff_ipc_msg_alloc();
    assert_non_null(foreign);
    foreign->ipc_owner_pid = (uint32_t)getppid();   /* a live other client */
    assert_int_equal(rte_ring_enqueue(p4_out_ring, foreign), 0);

    assert_int_not_equal(ff_ipc_recv(&got, FF_SYSCTL), 0);
    assert_ptr_equal((void *)got, (void *)0x1);     /* never answered */

    ff_ipc_reply_stats(&requeued, &orphan, &lost);
    assert_int_equal((int)orphan, 0);
    assert_true(requeued >= 1);
    assert_int_equal((int)lost, 0);
    /* requeued, not freed: still in the ring */
    assert_int_equal((int)rte_ring_count(p4_out_ring), 1);

    assert_int_equal(rte_ring_dequeue(p4_out_ring, &obj), 0);
    assert_ptr_equal(obj, (void *)foreign);
    rte_mempool_put(message_pool, obj);
}

/* C-P4-3: with nothing pending, a foreign reply must not be accepted. */
static void
test_p4_recv_foreign_without_send(void **state)
{
    struct ff_msg *foreign, *got = (struct ff_msg *)0x1;
    void *obj;

    (void)state;

    foreign = ff_ipc_msg_alloc();
    assert_non_null(foreign);
    foreign->ipc_owner_pid = (uint32_t)getppid();
    assert_int_equal(rte_ring_enqueue(p4_out_ring, foreign), 0);

    assert_int_not_equal(ff_ipc_recv(&got, FF_SYSCTL), 0);
    assert_ptr_equal((void *)got, (void *)0x1);
    assert_int_equal((int)rte_ring_count(p4_out_ring), 1);

    assert_int_equal(rte_ring_dequeue(p4_out_ring, &obj), 0);
    rte_mempool_put(message_pool, obj);
}

/* C-P4-2: only a reply whose owner is provably gone may be reclaimed. */
static void
test_p4_recv_orphan_dead_owner(void **state)
{
    struct ff_msg *foreign, *got = (struct ff_msg *)0x1;
    uint64_t orphan = 0;
    pid_t child;
    int wstatus = 0;

    (void)state;

    child = fork();
    assert_true(child >= 0);
    if (child == 0)
        _exit(0);
    assert_int_equal(waitpid(child, &wstatus, 0), child);

    foreign = ff_ipc_msg_alloc();
    assert_non_null(foreign);
    foreign->ipc_owner_pid = (uint32_t)child;      /* certainly gone */
    assert_int_equal(rte_ring_enqueue(p4_out_ring, foreign), 0);

    assert_int_not_equal(ff_ipc_recv(&got, FF_SYSCTL), 0);
    assert_ptr_equal((void *)got, (void *)0x1);

    ff_ipc_reply_stats(NULL, &orphan, NULL);
    assert_true(orphan >= 1);
    assert_int_equal((int)rte_ring_count(p4_out_ring), 0);
}

/* C-P4-5: the probe must not consume or free anybody's reply. */
static void
test_p4_probe_is_non_destructive(void **state)
{
    struct ff_msg *foreign;
    uint64_t orphan = 0;
    uint32_t epoch = 0;
    int gen = -1;
    void *obj;

    (void)state;

    foreign = ff_ipc_msg_alloc();
    assert_non_null(foreign);
    foreign->ipc_owner_pid = (uint32_t)getppid();
    assert_int_equal(rte_ring_enqueue(p4_out_reload, foreign), 0);

    /* nobody answers: the probe gives up within its budget */
    assert_int_not_equal(ff_ipc_probe_coord(&epoch, &gen), 0);

    ff_ipc_reply_stats(NULL, &orphan, NULL);
    assert_int_equal((int)orphan, 0);
    assert_int_equal((int)rte_ring_count(p4_out_reload), 1);

    assert_int_equal(rte_ring_dequeue(p4_out_reload, &obj), 0);
    rte_mempool_put(message_pool, obj);
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
        /* P4 (C01-5): reply ownership, real EAL */
        cmocka_unit_test_setup_teardown(test_p4_recv_own_reply,
            p4_setup, p4_teardown),
        cmocka_unit_test_setup_teardown(test_p4_recv_foreign_live_owner,
            p4_setup, p4_teardown),
        cmocka_unit_test_setup_teardown(test_p4_recv_foreign_without_send,
            p4_setup, p4_teardown),
        cmocka_unit_test_setup_teardown(test_p4_recv_orphan_dead_owner,
            p4_setup, p4_teardown),
        cmocka_unit_test_setup_teardown(test_p4_probe_is_non_destructive,
            p4_setup, p4_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
