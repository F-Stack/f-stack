/*
 * F-Stack lib/ unit test: ff_epoll.c (P1 #2)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §4.2
 * Coverage: 7 TC (TC-U-P1-EPL-01..07).
 *
 * Strategy:
 *   - ff_epoll_create / ff_epoll_ctl / ff_epoll_wait are the 3 public APIs
 *   - they delegate to ff_kqueue / ff_kevent / ff_kevent_do_each which live
 *     in the FreeBSD-kernel-side glue (ff_syscall_wrapper.c, KERN_SRCS).
 *   - We stub those 3 kernel-side functions in this test file with cmocka
 *     mock helpers (will_return / mock_type) so the host test process never
 *     crosses into kernel-side code.
 *   - struct kevent layout comes from lib/ff_event.h (already on the include
 *     path), so EV_ADD/EV_DELETE/EVFILT_READ etc. are visible.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "ff_api.h"
#include "ff_epoll.h"
#include "ff_event.h"

/* ------------------------------------------------------------------------ */
/* Capture buffer for kevent stubs                                          */
/* ------------------------------------------------------------------------ */

#define MAX_CAPTURED_KEV 8

typedef struct {
    int           call_count;
    int           last_kq;
    int           last_nchanges;
    struct kevent captured[MAX_CAPTURED_KEV];
} kev_capture_t;

static kev_capture_t g_kev_cap;

static void
reset_kev_capture(void)
{
    memset(&g_kev_cap, 0, sizeof(g_kev_cap));
}

/* ------------------------------------------------------------------------ */
/* Stubs for kernel-side glue (ff_syscall_wrapper.c symbols)                */
/* ------------------------------------------------------------------------ */

int
ff_kqueue(void)
{
    /* Return a fixed positive fd to pretend a kqueue file descriptor */
    return 42;
}

int
ff_kevent(int kq, const struct kevent *changelist, int nchanges,
          struct kevent *eventlist, int nevents,
          const struct timespec *timeout)
{
    (void)eventlist; (void)nevents; (void)timeout;
    g_kev_cap.call_count++;
    g_kev_cap.last_kq = kq;
    g_kev_cap.last_nchanges = nchanges;
    int n = nchanges < MAX_CAPTURED_KEV ? nchanges : MAX_CAPTURED_KEV;
    if (changelist) {
        for (int i = 0; i < n; i++) {
            g_kev_cap.captured[i] = changelist[i];
        }
    }
    return 0;
}

/*
 * For ff_epoll_wait we feed a single synthesized kevent into the do_each
 * callback so that the test can verify ff_event_to_epoll's translation.
 */
static struct kevent g_synth_kev;
static int           g_synth_count = 0;   /* how many synth kevents to deliver */

int
ff_kevent_do_each(int kq, const struct kevent *changelist, int nchanges,
                  void *eventlist, int nevents,
                  const struct timespec *timeout,
                  void (*do_each)(void **, struct kevent *))
{
    (void)kq; (void)changelist; (void)nchanges; (void)timeout;
    if (g_synth_count <= 0 || nevents <= 0 || !eventlist || !do_each) {
        return 0;
    }
    void *cur = eventlist;
    int delivered = 0;
    while (delivered < g_synth_count && delivered < nevents) {
        do_each(&cur, &g_synth_kev);
        delivered++;
    }
    return delivered;
}

static int
test_setup(void **state)
{
    (void)state;
    reset_kev_capture();
    memset(&g_synth_kev, 0, sizeof(g_synth_kev));
    g_synth_count = 0;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-01: ff_epoll_create returns a positive fd                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_create_returns_fd(void **state)
{
    (void)state;
    int fd = ff_epoll_create(1024);   /* size param is ignored per impl */
    assert_int_equal(fd, 42);
    /* Verify that another `size` value still returns the same stub fd
     * (i.e. confirms parameter is unused by ff_kqueue). */
    fd = ff_epoll_create(0);
    assert_int_equal(fd, 42);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-02: EPOLL_CTL_ADD with EPOLLIN translates to EV_ADD/EV_ENABLE */
/* on EVFILT_READ + EV_ADD/EV_DISABLE on EVFILT_WRITE.                       */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_add_event(void **state)
{
    (void)state;
    struct epoll_event ev = {0};
    ev.events  = EPOLLIN;
    ev.data.fd = 7;

    int rv = ff_epoll_ctl(42, EPOLL_CTL_ADD, 7, &ev);
    assert_int_equal(rv, 0);
    assert_int_equal(g_kev_cap.call_count, 1);
    assert_int_equal(g_kev_cap.last_kq, 42);
    assert_int_equal(g_kev_cap.last_nchanges, 2);
    /* Read filter: EV_ADD | EV_ENABLE */
    assert_int_equal(g_kev_cap.captured[0].filter, EVFILT_READ);
    assert_true((g_kev_cap.captured[0].flags & EV_ADD)    != 0);
    assert_true((g_kev_cap.captured[0].flags & EV_ENABLE) != 0);
    /* Write filter: EV_ADD | EV_DISABLE (EPOLLOUT not set) */
    assert_int_equal(g_kev_cap.captured[1].filter, EVFILT_WRITE);
    assert_true((g_kev_cap.captured[1].flags & EV_ADD)     != 0);
    assert_true((g_kev_cap.captured[1].flags & EV_DISABLE) != 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-03: EPOLL_CTL_DEL emits two EV_DELETE kevents                */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_del_event(void **state)
{
    (void)state;
    /* event arg can be NULL for DEL per ff_epoll_ctl logic */
    int rv = ff_epoll_ctl(42, EPOLL_CTL_DEL, 7, NULL);
    assert_int_equal(rv, 0);
    assert_int_equal(g_kev_cap.call_count, 1);
    assert_int_equal(g_kev_cap.last_nchanges, 2);
    assert_int_equal(g_kev_cap.captured[0].filter, EVFILT_READ);
    assert_true((g_kev_cap.captured[0].flags & EV_DELETE) != 0);
    assert_int_equal(g_kev_cap.captured[1].filter, EVFILT_WRITE);
    assert_true((g_kev_cap.captured[1].flags & EV_DELETE) != 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-04: EPOLL_CTL_MOD with EPOLLIN+EPOLLOUT enables both filters */
/* (no EV_ADD this time; both ENABLE)                                       */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_mod_event(void **state)
{
    (void)state;
    struct epoll_event ev = {0};
    ev.events  = EPOLLIN | EPOLLOUT;
    ev.data.fd = 7;

    int rv = ff_epoll_ctl(42, EPOLL_CTL_MOD, 7, &ev);
    assert_int_equal(rv, 0);
    assert_int_equal(g_kev_cap.call_count, 1);
    /* EPOLL_CTL_MOD: no EV_ADD, both ENABLE */
    assert_true((g_kev_cap.captured[0].flags & EV_ADD)     == 0);
    assert_true((g_kev_cap.captured[0].flags & EV_ENABLE)  != 0);
    assert_true((g_kev_cap.captured[1].flags & EV_ADD)     == 0);
    assert_true((g_kev_cap.captured[1].flags & EV_ENABLE)  != 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-05: ff_epoll_wait translates EVFILT_READ kevent -> EPOLLIN   */
/* via ff_event_to_epoll (private, exercised through public wait API).      */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_event_translation(void **state)
{
    (void)state;
    struct epoll_event events[4] = {0};

    /* Synthesize one read-readiness kevent for the do_each path */
    g_synth_kev.ident  = 99;
    g_synth_kev.filter = EVFILT_READ;
    g_synth_kev.flags  = 0;
    g_synth_kev.data   = 1;        /* non-zero data => EPOLLIN set */
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    int n = ff_epoll_wait(42, events, 4, 0);
    assert_int_equal(n, 1);
    assert_true((events[0].events & EPOLLIN) != 0);
    assert_int_equal(events[0].data.fd, 99);     /* udata==NULL => fd path */
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-06: ff_epoll_wait with timeout=0 + zero events -> 0 events   */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_zero_timeout(void **state)
{
    (void)state;
    struct epoll_event events[2] = {0};
    g_synth_count = 0;

    int n = ff_epoll_wait(42, events, 2, 0);
    assert_int_equal(n, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-07: ff_epoll_wait invalid args -> -1 / EINVAL                */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_invalid_args(void **state)
{
    (void)state;
    /* maxevents <= 0 */
    errno = 0;
    int n = ff_epoll_wait(42, NULL, 0, 0);
    assert_int_equal(n, -1);
    assert_int_equal(errno, EINVAL);

    /* events == NULL */
    struct epoll_event ev[1];
    errno = 0;
    n = ff_epoll_wait(42, NULL, 1, 0);
    (void)ev;
    assert_int_equal(n, -1);
    assert_int_equal(errno, EINVAL);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ff_epoll_create_returns_fd,      test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_add_event,          test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_del_event,          test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_mod_event,          test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_event_translation, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_zero_timeout,      test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_invalid_args,      test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
