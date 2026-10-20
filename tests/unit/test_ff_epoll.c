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

/*
 * ff_epoll.c references the kernel-stack coexistence host bridge
 * (ff_host_epoll_create1/ctl/wait) for managed kernel fds. This unit test
 * exercises only the F-Stack kqueue path (no kernel fds are ever registered),
 * so those bridge functions are never invoked at runtime; provide no-op stubs
 * to satisfy the linker.
 */
#ifdef FF_KERNEL_COEXIST
int ff_host_epoll_create1(int flags) { (void)flags; return -1; }
int ff_host_epoll_ctl(int epfd, int op, int fd, void *event)
{ (void)epfd; (void)op; (void)fd; (void)event; return -1; }
int ff_host_epoll_wait(int epfd, void *events, int maxevents, int timeout)
{ (void)epfd; (void)events; (void)maxevents; (void)timeout; return -1; }
int ff_host_close(int fd) { (void)fd; return 0; }
int ff_native_map_get(int fstack_fd) { (void)fstack_fd; return 0; }
#endif /* FF_KERNEL_COEXIST */

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
    (void)timeout;
    /* Under FF_KERNEL_COEXIST, ff_epoll_ctl routes its F-Stack-side kevent
     * registration through ff_kevent_do_each (changelist + nchanges, no
     * do_each callback) rather than ff_kevent. Capture those changes here so
     * the ctl-path TCs work regardless of which entry point the lib uses. */
    if (nchanges > 0 && changelist) {
        g_kev_cap.call_count++;
        g_kev_cap.last_kq = kq;
        g_kev_cap.last_nchanges = nchanges;
        int c = nchanges < MAX_CAPTURED_KEV ? nchanges : MAX_CAPTURED_KEV;
        for (int i = 0; i < c; i++) {
            g_kev_cap.captured[i] = changelist[i];
        }
    }
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
/* TC-U-P1-EPL-08 (Stage-6): ff_epoll_ctl with NULL event for non-DEL ops   */
/* returns -1 / EINVAL (covers L46-47).                                     */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_null_event_non_del(void **state)
{
    (void)state;
    errno = 0;
    int rv = ff_epoll_ctl(42, EPOLL_CTL_ADD, 7, NULL);
    assert_int_equal(rv, -1);
    assert_int_equal(errno, EINVAL);
    assert_int_equal(g_kev_cap.call_count, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-09 (Stage-6): ff_epoll_ctl with invalid op returns -1/EINVAL */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_invalid_op(void **state)
{
    (void)state;
    struct epoll_event ev = { .events = EPOLLIN };
    errno = 0;
    int rv = ff_epoll_ctl(42, /*invalid op*/ 99, 7, &ev);
    assert_int_equal(rv, -1);
    assert_int_equal(errno, EINVAL);
    assert_int_equal(g_kev_cap.call_count, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-10 (Stage-6): EPOLLET flag yields EV_CLEAR (covers L75-76).  */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_epollet_sets_ev_clear(void **state)
{
    (void)state;
    struct epoll_event ev = { .events = EPOLLIN | EPOLLET };
    int rv = ff_epoll_ctl(42, EPOLL_CTL_ADD, 7, &ev);
    assert_int_equal(rv, 0);
    assert_true((g_kev_cap.captured[0].flags & EV_CLEAR) != 0);
    assert_true((g_kev_cap.captured[1].flags & EV_CLEAR) != 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-11 (Stage-6): EPOLLONESHOT yields EV_ONESHOT (covers L79-80).*/
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_ctl_epolloneshot_sets_ev_oneshot(void **state)
{
    (void)state;
    struct epoll_event ev = { .events = EPOLLIN | EPOLLONESHOT };
    int rv = ff_epoll_ctl(42, EPOLL_CTL_ADD, 7, &ev);
    assert_int_equal(rv, 0);
    assert_true((g_kev_cap.captured[0].flags & EV_ONESHOT) != 0);
    assert_true((g_kev_cap.captured[1].flags & EV_ONESHOT) != 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-12 (Stage-6): EVFILT_WRITE without EOF -> EPOLLOUT only.     */
/* Covers L116-117 (write filter -> EPOLLOUT).                              */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_write_filter_to_epollout(void **state)
{
    (void)state;
    struct epoll_event events[2] = {0};
    g_synth_kev.ident  = 88;
    g_synth_kev.filter = EVFILT_WRITE;
    g_synth_kev.flags  = 0;
    g_synth_kev.fflags = 0;
    g_synth_kev.data   = 0;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    int n = ff_epoll_wait(42, events, 2, 0);
    assert_int_equal(n, 1);
    assert_true((events[0].events & EPOLLOUT) != 0);
    assert_true((events[0].events & EPOLLERR) == 0);
    assert_int_equal(events[0].data.fd, 88);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-13 (Stage-6): EV_ERROR flag -> EPOLLERR (covers L120-121).   */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_ev_error_to_epollerr(void **state)
{
    (void)state;
    struct epoll_event events[2] = {0};
    g_synth_kev.ident  = 77;
    g_synth_kev.filter = EVFILT_READ;
    g_synth_kev.flags  = EV_ERROR;
    g_synth_kev.data   = 1;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    int n = ff_epoll_wait(42, events, 2, 0);
    assert_int_equal(n, 1);
    assert_true((events[0].events & EPOLLERR) != 0);
    assert_int_equal(events[0].data.fd, 77);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-14 (Stage-6): EV_EOF on EVFILT_READ -> EPOLLHUP+EPOLLIN      */
/* (covers L124-125, L131-132).                                             */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_ev_eof_read_to_hup_in(void **state)
{
    (void)state;
    struct epoll_event events[2] = {0};
    g_synth_kev.ident  = 66;
    g_synth_kev.filter = EVFILT_READ;
    g_synth_kev.flags  = EV_EOF;
    g_synth_kev.fflags = 0;
    g_synth_kev.data   = 0;          /* data=0 + EV_EOF -> NO EPOLLIN via top branch */
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    int n = ff_epoll_wait(42, events, 2, 0);
    assert_int_equal(n, 1);
    assert_true((events[0].events & EPOLLHUP) != 0);
    /* The EV_EOF + EVFILT_READ branch (L131-132) re-asserts EPOLLIN. */
    assert_true((events[0].events & EPOLLIN)  != 0);
    assert_int_equal(events[0].data.fd, 66);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-EPL-15 (Stage-6): EV_EOF + non-zero fflags -> additional EPOLLERR*/
/* and EVFILT_WRITE branch -> EPOLLERR (covers L127-128, L133-134).        */
/* ------------------------------------------------------------------------ */
static void
test_ff_epoll_wait_ev_eof_write_with_fflags(void **state)
{
    (void)state;
    struct epoll_event events[2] = {0};
    g_synth_kev.ident  = 55;
    g_synth_kev.filter = EVFILT_WRITE;
    g_synth_kev.flags  = EV_EOF;
    g_synth_kev.fflags = ECONNRESET;     /* any non-zero -> EPOLLERR */
    g_synth_kev.data   = 0;
    g_synth_kev.udata  = (void *)(intptr_t)0xDEAD;   /* udata != NULL -> ptr path */
    g_synth_count = 1;

    int n = ff_epoll_wait(42, events, 2, 0);
    assert_int_equal(n, 1);
    assert_true((events[0].events & EPOLLHUP) != 0);
    assert_true((events[0].events & EPOLLERR) != 0);
    /* udata path: data.ptr is set instead of data.fd */
    assert_ptr_equal(events[0].data.ptr, (void *)(intptr_t)0xDEAD);
}

/* ------------------------------------------------------------------------ */
/* Stage-7 Phase-5 (FU-S7-EPOLL-*): branch-coverage boost                  */
/* ------------------------------------------------------------------------ */

/* TC-S7-EPOLL-01: EPOLL_CTL_ADD with EPOLLOUT-only events leaves the     */
/* read kevent in EV_DISABLE state (covers BRDA L89 br=1, the false leg  */
/* of `if (event->events & EPOLLIN)`).                                    */
static void
test_ff_epoll_ctl_add_writeonly_only_epollout(void **state)
{
    (void)state;
    int epfd = ff_epoll_create(1);
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events  = EPOLLOUT;          /* deliberately NOT EPOLLIN */
    ev.data.fd = 7;

    int rc = ff_epoll_ctl(epfd, EPOLL_CTL_ADD, 7, &ev);
    assert_int_equal(rc, 0);
    assert_int_equal(g_kev_cap.last_nchanges, 2);
    /* read kevent: EV_DISABLE is preserved (EPOLLIN absent) */
    assert_true((g_kev_cap.captured[0].flags & EV_DISABLE) != 0);
    /* write kevent: EV_ENABLE is set (EPOLLOUT present) */
    assert_true((g_kev_cap.captured[1].flags & EV_ENABLE) != 0);
}

/* TC-S7-EPOLL-02: a synthesized kevent with an unknown filter (e.g.     */
/* EVFILT_TIMER) translates to events=0 -- covers BRDA L116 br=1.        */
static void
test_ff_epoll_wait_unknown_filter_yields_zero_events(void **state)
{
    (void)state;
    g_synth_kev.ident  = 33;
    g_synth_kev.filter = EVFILT_TIMER;       /* not READ, not WRITE */
    g_synth_kev.flags  = 0;
    g_synth_kev.data   = 1;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    struct epoll_event events[1];
    int n = ff_epoll_wait(42, events, 1, 0);
    assert_int_equal(n, 1);
    assert_int_equal(events[0].events, 0);   /* no EPOLL* bits set */
}

/* TC-S7-EPOLL-03: EV_EOF with an unknown filter still yields EPOLLHUP   */
/* (without EPOLLERR or EPOLLIN/OUT) -- covers BRDA L133 br=1.           */
static void
test_ff_epoll_wait_eof_unknown_filter_only_hup(void **state)
{
    (void)state;
    g_synth_kev.ident  = 44;
    g_synth_kev.filter = EVFILT_TIMER;       /* unknown */
    g_synth_kev.flags  = EV_EOF;
    g_synth_kev.fflags = 0;
    g_synth_kev.data   = 0;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    struct epoll_event events[1];
    int n = ff_epoll_wait(42, events, 1, 0);
    assert_int_equal(n, 1);
    /* EPOLLHUP set, EPOLLERR/IN/OUT not set */
    assert_true(events[0].events & EPOLLHUP);
    assert_false(events[0].events & EPOLLIN);
    assert_false(events[0].events & EPOLLOUT);
}

/* TC-S7-EPOLL-04: events!=NULL but maxevents=0 still rejects with -1    */
/* / errno=EINVAL (covers BRDA L152 br=2, the maxevents<1 leg with       */
/* events being valid).                                                 */
static void
test_ff_epoll_wait_zero_maxevents_returns_einval(void **state)
{
    (void)state;
    struct epoll_event events[1];
    errno = 0;
    int n = ff_epoll_wait(42, events, /*maxevents*/ 0, 0);
    assert_int_equal(n, -1);
    assert_int_equal(errno, EINVAL);
}

/* TC-S7-EPOLL-05: EVFILT_READ with data=0 and EV_EOF set still produces  */
/* EPOLLIN via the EV_EOF branch (covers BRDA L113 br=2 partial leg).    */
static void
test_ff_epoll_wait_evfilt_read_eof_data_zero_yields_in_hup(void **state)
{
    (void)state;
    g_synth_kev.ident  = 55;
    g_synth_kev.filter = EVFILT_READ;
    g_synth_kev.flags  = EV_EOF;       /* EOF set, data=0 */
    g_synth_kev.data   = 0;
    g_synth_kev.fflags = 0;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    struct epoll_event events[1];
    int n = ff_epoll_wait(42, events, 1, 0);
    assert_int_equal(n, 1);
    /* The L113 branch (data=0 && !EV_EOF) is FALSE (because EV_EOF=1) so   */
    /* the first block sets nothing; the EV_EOF block then sets EPOLLHUP   */
    /* and (filter==READ) sets EPOLLIN.                                    */
    assert_true(events[0].events & EPOLLHUP);
    assert_true(events[0].events & EPOLLIN);
}

/* TC-S8-EPOLL-01 (FU-S8-EPOLL-DEAD): EVFILT_READ with data==0 and NO EV_EOF
 * takes the `!(kev->flags & EV_EOF)` TRUE leg (branch idx 2 of L113) via the
 * `kev->data` FALSE short-circuit path, still setting EPOLLIN. */
static void
test_ff_epoll_wait_evfilt_read_data_zero_no_eof_yields_in(void **state)
{
    (void)state;
    g_synth_kev.ident  = 66;
    g_synth_kev.filter = EVFILT_READ;
    g_synth_kev.flags  = 0;        /* no EV_EOF -> !(flags&EV_EOF) is true */
    g_synth_kev.data   = 0;        /* zero -> evaluate the EV_EOF term */
    g_synth_kev.fflags = 0;
    g_synth_kev.udata  = NULL;
    g_synth_count = 1;

    struct epoll_event events[1];
    int n = ff_epoll_wait(42, events, 1, 0);
    assert_int_equal(n, 1);
    assert_true(events[0].events & EPOLLIN);
    assert_false(events[0].events & EPOLLHUP);
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
        /* Stage-6 coverage extensions (TC-U-P1-EPL-08..15) */
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_null_event_non_del,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_invalid_op,            test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_epollet_sets_ev_clear, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_epolloneshot_sets_ev_oneshot, test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_write_filter_to_epollout,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_ev_error_to_epollerr,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_ev_eof_read_to_hup_in,       test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_ev_eof_write_with_fflags,    test_setup, NULL),
        /* Stage-7 Phase-5 branch-coverage boost (FU-S7-EPOLL-*) */
        cmocka_unit_test_setup_teardown(test_ff_epoll_ctl_add_writeonly_only_epollout,           test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_unknown_filter_yields_zero_events,    test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_eof_unknown_filter_only_hup,          test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_zero_maxevents_returns_einval,        test_setup, NULL),
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_evfilt_read_eof_data_zero_yields_in_hup, test_setup, NULL),
        /* Stage-8 Phase-5 (FU-S8-EPOLL-DEAD) */
        cmocka_unit_test_setup_teardown(test_ff_epoll_wait_evfilt_read_data_zero_no_eof_yields_in, test_setup, NULL),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
