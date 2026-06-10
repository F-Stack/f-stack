/*
 * F-Stack lib/ unit test: ff_thread.c (P2 #1)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/plan-stage4-p2-tests.md §7 Phase 2a
 * Coverage: 3 TC — pthread_create / pthread_join / errno path
 *
 * Strategy:
 *   - ff_thread.c references `extern __thread struct thread *pcurthread` and
 *     calls ff_malloc / ff_free (lib/ff_host_interface.c). We provide a
 *     minimal `struct thread` placeholder + the `__thread` storage as a
 *     local stub, link real ff_host_interface.o, and use real glibc
 *     pthread for the thread create/join cycle.
 *   - The `start_routine` actually executes inside the spawned thread;
 *     we use a trivial routine that flips a flag, then assert the flag.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <pthread.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ff_thread.c expects `struct thread` to exist (opaque pointer type). */
struct thread {
    int dummy;
};

/* The TLS slot referenced by ff_thread.c via `extern __thread`. */
__thread struct thread *pcurthread = NULL;

/* ff_host_interface.c references ff_log() on its mmap failure path; provide
 * a no-op stub to satisfy the linker without pulling in lib/ff_log.c. */
int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    (void)level; (void)logtype; (void)format;
    return 0;
}

#include "ff_api.h"            /* ff_pthread_create / ff_pthread_join decls */

/* ------------------------------------------------------------------------ */
/* Test routine + capture state                                             */
/* ------------------------------------------------------------------------ */

static int g_routine_invoked = 0;
static struct thread *g_routine_observed_pcur = (struct thread *)(intptr_t)-1;

static void *
trivial_thread_routine(void *arg)
{
    g_routine_invoked++;
    /* Capture the pcurthread visible inside the spawned thread; the
     * implementation should set it to whatever pcurthread was at the time
     * ff_pthread_create was called. */
    g_routine_observed_pcur = pcurthread;
    return arg;
}

static int
test_setup(void **state)
{
    (void)state;
    g_routine_invoked = 0;
    g_routine_observed_pcur = (struct thread *)(intptr_t)-1;
    pcurthread = NULL;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-THR-01: ff_pthread_create successfully spawns + propagates pcur  */
/* ------------------------------------------------------------------------ */
static void
test_ff_pthread_create_basic(void **state)
{
    (void)state;
    static struct thread parent = { .dummy = 0xC0FFEE };
    pcurthread = &parent;

    pthread_t tid;
    int rv = ff_pthread_create(&tid, NULL, trivial_thread_routine, NULL);
    assert_int_equal(rv, 0);

    void *retval = (void *)(intptr_t)-1;
    rv = ff_pthread_join(tid, &retval);
    assert_int_equal(rv, 0);
    assert_int_equal(g_routine_invoked, 1);
    /* The child thread should observe pcurthread == parent (propagated by
     * ff_set_thread inside ff_start_routine). */
    assert_ptr_equal(g_routine_observed_pcur, &parent);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-THR-02: ff_pthread_create propagates argument to start_routine    */
/* ------------------------------------------------------------------------ */
static int g_arg_received = 0;
static void *
arg_capture_routine(void *arg)
{
    g_arg_received = (int)(intptr_t)arg;
    return NULL;
}

static void
test_ff_pthread_create_arg_passed(void **state)
{
    (void)state;
    pcurthread = NULL;
    g_arg_received = 0;

    pthread_t tid;
    int rv = ff_pthread_create(&tid, NULL, arg_capture_routine,
                               (void *)(intptr_t)0x42);
    assert_int_equal(rv, 0);

    rv = ff_pthread_join(tid, NULL);
    assert_int_equal(rv, 0);
    assert_int_equal(g_arg_received, 0x42);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-THR-03: ff_pthread_join always yields NULL retval.                */
/*                                                                          */
/* IMPORTANT (DP-U-12 "代码为准"): ff_thread.c's ff_start_routine wrapper    */
/* discards the original start_routine return value and unconditionally     */
/* returns NULL (lib/ff_thread.c L28-29). So pthread_join's retval slot is  */
/* always NULL regardless of what start_routine returned. We assert this    */
/* observed behavior rather than the (intuitive but incorrect) pass-through.*/
/* ------------------------------------------------------------------------ */
static void
test_ff_pthread_join_retval(void **state)
{
    (void)state;
    pcurthread = NULL;

    pthread_t tid;
    int rv = ff_pthread_create(&tid, NULL, trivial_thread_routine,
                               (void *)(intptr_t)0xDEAD);
    assert_int_equal(rv, 0);

    void *retval = (void *)(intptr_t)-1;
    rv = ff_pthread_join(tid, &retval);
    assert_int_equal(rv, 0);
    /* ff_start_routine returns NULL irrespective of trivial_thread_routine's
     * return; verify the wrapper behavior is consistent. */
    assert_null(retval);
    /* Cross-check: routine actually ran (with arg) */
    assert_int_equal(g_routine_invoked, 1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P2-THR-04 (Stage-6): ff_pthread_create returns -ff_ENOMEM when the   */
/* internal ff_malloc fails. Covers ff_thread.c L37-39 (errno=ENOMEM /       */
/* return -ff_ENOMEM). Uses --wrap=ff_malloc to force a NULL return.         */
/* ------------------------------------------------------------------------ */
#include "ff_errno.h"           /* ff_ENOMEM */

extern void *__real_ff_malloc(size_t size);
static int g_force_malloc_null;
void *
__wrap_ff_malloc(size_t size)
{
    if (g_force_malloc_null) {
        return NULL;
    }
    return __real_ff_malloc(size);
}

static void
test_ff_pthread_create_malloc_failure(void **state)
{
    (void)state;
    pcurthread = NULL;

    g_force_malloc_null = 1;
    pthread_t tid;
    int saved_errno = errno;
    errno = 0;
    int rv = ff_pthread_create(&tid, NULL, trivial_thread_routine,
                               (void *)(intptr_t)0xCAFE);
    int observed_errno = errno;
    g_force_malloc_null = 0;
    errno = saved_errno;

    assert_int_equal(rv, -ff_ENOMEM);
    assert_int_equal(observed_errno, ENOMEM);
    /* The pthread was never spawned, so the routine flag stays 0. */
    assert_int_equal(g_routine_invoked, 0);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_pthread_create_basic,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_pthread_create_arg_passed, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_pthread_join_retval,     test_setup, NULL),
        /* Stage-6 coverage extension */
        cmocka_unit_test_setup_teardown(test_ff_pthread_create_malloc_failure, test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
