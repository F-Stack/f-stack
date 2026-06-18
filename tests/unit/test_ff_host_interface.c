/*
 * F-Stack lib/ unit test: ff_host_interface.c (P1 #1)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §4.1
 * Coverage: 8 TC (TC-U-P1-HIF-01..08).
 *
 * IMPORTANT spec-vs-code corrections (DP-U-12 "代码为准"):
 *   - spec 02 §4.2 / 04 §7.1 said "wrap rte_malloc/free" — actual ff_host_interface.c
 *     has rte_malloc/rte_calloc/rte_realloc/rte_free CALLS COMMENTED OUT and uses
 *     plain glibc malloc/calloc/realloc/free. So no rte_ wrap is needed.
 *   - ff_log is called by ff_mmap on failure path (line 81). We provide a local
 *     ff_log stub here (no-op) to satisfy the linker without pulling in lib/ff_log.c.
 *   - ff_arc4rand wraps OpenSSL RAND_bytes — we link libcrypto.
 *   - exit(1) is called by ff_mmap on mmap failure; tests below avoid that path
 *     (use only valid mmap arguments).
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
#include <time.h>
#include <unistd.h>

#include "ff_host_interface.h"
#include "ff_errno.h"

/* ------------------------------------------------------------------------ */
/* FU-S9-HIF-ASSERT-WRAP: cover the assert(0==rv) FALSE legs after          */
/* clock_gettime in ff_clock_gettime (L176) and ff_update_current_ts (L209).*/
/*                                                                          */
/* --wrap=clock_gettime forces a failure (rv=-1) when armed; the lib's      */
/* glibc assert() then expands to __assert_fail (a real, wrappable symbol). */
/* --wrap=__assert_fail longjmp's back to the TC so the abort is observed   */
/* instead of crashing the harness.                                         */
/* ------------------------------------------------------------------------ */
extern int __real_clock_gettime(clockid_t clk, struct timespec *tp);
static int g_clock_fail = 0;

int
__wrap_clock_gettime(clockid_t clk, struct timespec *tp)
{
    if (g_clock_fail) {
        errno = EINVAL;
        return -1;                 /* force assert(0==rv) to fail */
    }
    return __real_clock_gettime(clk, tp);
}

static jmp_buf  g_assert_jmp;
static int      g_assert_fired = 0;

void
__wrap___assert_fail(const char *assertion, const char *file,
                     unsigned int line, const char *function)
{
    (void)assertion; (void)file; (void)line; (void)function;
    g_assert_fired = 1;
    longjmp(g_assert_jmp, 1);       /* unwind back to the TC */
}

/* ------------------------------------------------------------------------ */
/* Local ff_log stub (linker dependency only — body unused in tests)        */
/* ------------------------------------------------------------------------ */
int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    (void)level; (void)logtype; (void)format;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-01: ff_malloc returns non-null for valid size                */
/* ------------------------------------------------------------------------ */
static void
test_ff_malloc_normal(void **state)
{
    (void)state;
    void *p = ff_malloc(64);
    assert_non_null(p);
    /* Write a sentinel to verify writability */
    memset(p, 0xAB, 64);
    assert_int_equal(((unsigned char *)p)[0],  0xAB);
    assert_int_equal(((unsigned char *)p)[63], 0xAB);
    ff_free(p);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-02: ff_calloc zeros the buffer                               */
/* ------------------------------------------------------------------------ */
static void
test_ff_calloc_zeros_memory(void **state)
{
    (void)state;
    unsigned char *p = ff_calloc(16, 4);   /* 64 bytes */
    assert_non_null(p);
    for (int i = 0; i < 64; i++) {
        assert_int_equal(p[i], 0);
    }
    ff_free(p);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-03: ff_realloc grows preserving prefix bytes                 */
/* ------------------------------------------------------------------------ */
static void
test_ff_realloc_grow(void **state)
{
    (void)state;
    unsigned char *p = ff_malloc(8);
    assert_non_null(p);
    for (int i = 0; i < 8; i++) {
        p[i] = (unsigned char)(0x10 + i);
    }
    unsigned char *q = ff_realloc(p, 32);
    assert_non_null(q);
    /* Prefix preserved by glibc realloc */
    for (int i = 0; i < 8; i++) {
        assert_int_equal(q[i], 0x10 + i);
    }
    ff_free(q);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-04: ff_free(NULL) does not crash (POSIX semantics)           */
/* ------------------------------------------------------------------------ */
static void
test_ff_free_null(void **state)
{
    (void)state;
    ff_free(NULL);    /* must be safe */
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-05: ff_clock_gettime(MONOTONIC) returns sane non-negative    */
/* values; consecutive calls give monotonically non-decreasing nanoseconds. */
/* ------------------------------------------------------------------------ */
static void
test_ff_clock_gettime_monotonic(void **state)
{
    (void)state;
    int64_t s1 = 0, s2 = 0;
    long ns1 = 0, ns2 = 0;

    ff_clock_gettime(ff_CLOCK_MONOTONIC, &s1, &ns1);
    /* tiny busy delay to allow tick advance */
    for (volatile int i = 0; i < 100000; i++) { /* burn cycles */ }
    ff_clock_gettime(ff_CLOCK_MONOTONIC, &s2, &ns2);

    assert_true(s1 >= 0);
    assert_true(ns1 >= 0 && ns1 < 1000 * 1000 * 1000);
    /* s2 > s1, OR same s but ns2 >= ns1 */
    assert_true((s2 > s1) || (s2 == s1 && ns2 >= ns1));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-06: ff_arc4rand fills the buffer with non-all-zero bytes     */
/* ------------------------------------------------------------------------ */
static void
test_ff_arc4rand_buf_filled(void **state)
{
    (void)state;
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    ff_arc4rand(buf, sizeof(buf), 0);
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            nonzero++;
        }
    }
    /* statistically, ≥ 60 of 64 bytes should be non-zero (~p=255/256) */
    assert_true(nonzero >= 50);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-07: ff_get_current_time after ff_update_current_ts gives     */
/* consistent advancing values across two updates separated by a busy wait.  */
/* (current_ts is a static struct timespec inside ff_host_interface.c.)     */
/* ------------------------------------------------------------------------ */
static void
test_ff_get_current_time_advances(void **state)
{
    (void)state;
    int64_t s1 = -1, s2 = -1;
    long ns1 = -1, ns2 = -1;

    ff_update_current_ts();
    ff_get_current_time(&s1, &ns1);

    /* sleep at least 1ms so REALTIME definitely advances */
    struct timespec slp = {0, 2 * 1000 * 1000};   /* 2 ms */
    nanosleep(&slp, NULL);

    ff_update_current_ts();
    ff_get_current_time(&s2, &ns2);

    assert_true(s1 > 0);    /* REALTIME never zero on running system */
    assert_true(s2 > 0);
    /* (s2,ns2) > (s1,ns1) lexicographic */
    assert_true((s2 > s1) || (s2 == s1 && ns2 > ns1));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-08: ff_os_errno maps known ff_E* values to host E* equivs     */
/*                                                                          */
/* The ff_os_errno function has a 60+ case switch covering most POSIX       */
/* errno values. This TC iterates a comprehensive table to drive coverage   */
/* through every case + the default branch.                                 */
/* ------------------------------------------------------------------------ */
static void
test_ff_os_errno_mapping(void **state)
{
    (void)state;

    /* Comprehensive (ff_input, expected_host_errno) table. Keep in sync
     * with the switch in lib/ff_host_interface.c. Order does not matter. */
    struct ff_errno_map { int in; int out; };
    static const struct ff_errno_map T[] = {
        { ff_EPERM,           EPERM           },
        { ff_ENOENT,          ENOENT          },
        { ff_ESRCH,           ESRCH           },
        { ff_EINTR,           EINTR           },
        { ff_EIO,             EIO             },
        { ff_ENXIO,           ENXIO           },
        { ff_E2BIG,           E2BIG           },
        { ff_ENOEXEC,         ENOEXEC         },
        { ff_EBADF,           EBADF           },
        { ff_ECHILD,          ECHILD          },
        { ff_EDEADLK,         EDEADLK         },
        { ff_ENOMEM,          ENOMEM          },
        { ff_EACCES,          EACCES          },
        { ff_EFAULT,          EFAULT          },
        { ff_ENOTBLK,         ENOTBLK         },
        { ff_EBUSY,           EBUSY           },
        { ff_EEXIST,          EEXIST          },
        { ff_EXDEV,           EXDEV           },
        { ff_ENODEV,          ENODEV          },
        { ff_ENOTDIR,         ENOTDIR         },
        { ff_EISDIR,          EISDIR          },
        { ff_EINVAL,          EINVAL          },
        { ff_ENFILE,          ENFILE          },
        { ff_EMFILE,          EMFILE          },
        { ff_ENOTTY,          ENOTTY          },
        { ff_ETXTBSY,         ETXTBSY         },
        { ff_EFBIG,           EFBIG           },
        { ff_ENOSPC,          ENOSPC          },
        { ff_ESPIPE,          ESPIPE          },
        { ff_EROFS,           EROFS           },
        { ff_EMLINK,          EMLINK          },
        { ff_EPIPE,           EPIPE           },
        { ff_EDOM,            EDOM            },
        { ff_ERANGE,          ERANGE          },
        { ff_EWOULDBLOCK,     EWOULDBLOCK     },
        { ff_EINPROGRESS,     EINPROGRESS     },
        { ff_EALREADY,        EALREADY        },
        { ff_ENOTSOCK,        ENOTSOCK        },
        { ff_EDESTADDRREQ,    EDESTADDRREQ    },
        { ff_EMSGSIZE,        EMSGSIZE        },
        { ff_EPROTOTYPE,      EPROTOTYPE      },
        { ff_ENOPROTOOPT,     ENOPROTOOPT     },
        { ff_EPROTONOSUPPORT, EPROTONOSUPPORT },
        { ff_ESOCKTNOSUPPORT, ESOCKTNOSUPPORT },
        { ff_ENOTSUP,         ENOTSUP         },
        { ff_EPFNOSUPPORT,    EPFNOSUPPORT    },
        { ff_EAFNOSUPPORT,    EAFNOSUPPORT    },
        { ff_EADDRINUSE,      EADDRINUSE      },
        { ff_EADDRNOTAVAIL,   EADDRNOTAVAIL   },
        { ff_ENETDOWN,        ENETDOWN        },
        { ff_ENETUNREACH,     ENETUNREACH     },
        { ff_ENETRESET,       ENETRESET       },
        { ff_ECONNABORTED,    ECONNABORTED    },
        { ff_ECONNRESET,      ECONNRESET      },
        { ff_ENOBUFS,         ENOBUFS         },
        { ff_EISCONN,         EISCONN         },
        { ff_ENOTCONN,        ENOTCONN        },
        { ff_ESHUTDOWN,       ESHUTDOWN       },
        { ff_ETOOMANYREFS,    ETOOMANYREFS    },
        { ff_ETIMEDOUT,       ETIMEDOUT       },
        { ff_ECONNREFUSED,    ECONNREFUSED    },
        { ff_ELOOP,           ELOOP           },
        { ff_ENAMETOOLONG,    ENAMETOOLONG    },
        { ff_EHOSTDOWN,       EHOSTDOWN       },
        { ff_EHOSTUNREACH,    EHOSTUNREACH    },
        { ff_ENOTEMPTY,       ENOTEMPTY       },
        { ff_EUSERS,          EUSERS          },
        { ff_EDQUOT,          EDQUOT          },
        { ff_ESTALE,          ESTALE          },
        { ff_EREMOTE,         EREMOTE         },
        { ff_ENOLCK,          ENOLCK          },
        { ff_ENOSYS,          ENOSYS          },
        { ff_EIDRM,           EIDRM           },
        { ff_ENOMSG,          ENOMSG          },
        { ff_EOVERFLOW,       EOVERFLOW       },
        { ff_ECANCELED,       ECANCELED       },
        { ff_EILSEQ,          EILSEQ          },
        { ff_EBADMSG,         EBADMSG         },
        { ff_EMULTIHOP,       EMULTIHOP       },
        { ff_ENOLINK,         ENOLINK         },
        { ff_EPROTO,          EPROTO          },
    };
    const size_t N = sizeof(T) / sizeof(T[0]);

    for (size_t i = 0; i < N; i++) {
        errno = 0;
        ff_os_errno(T[i].in);
        if (errno != T[i].out) {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "ff_os_errno(%d) -> errno=%d, expected %d",
                     T[i].in, errno, T[i].out);
            fail_msg("%s", msg);
        }
    }

    /* default branch: arbitrary unknown code passes through */
    errno = 0;
    ff_os_errno(99999);
    assert_int_equal(errno, 99999);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-09 (extra): ff_clock_gettime_ns returns reasonable nanoseconds*/
/* ------------------------------------------------------------------------ */
static void
test_ff_clock_gettime_ns_advances(void **state)
{
    (void)state;
    uint64_t a = ff_clock_gettime_ns(ff_CLOCK_MONOTONIC);
    for (volatile int i = 0; i < 100000; i++) { /* burn cycles */ }
    uint64_t b = ff_clock_gettime_ns(ff_CLOCK_MONOTONIC);
    assert_true(a > 0);
    assert_true(b >= a);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-10 (extra): ff_arc4random returns 32-bit values, not all-zero */
/* across multiple invocations.                                              */
/* ------------------------------------------------------------------------ */
static void
test_ff_arc4random_distribution(void **state)
{
    (void)state;
    uint32_t prev = 0;
    int distinct = 0;
    for (int i = 0; i < 16; i++) {
        uint32_t v = ff_arc4random();
        if (v != prev) {
            distinct++;
        }
        prev = v;
    }
    /* Statistically, near-all 16 draws should differ */
    assert_true(distinct >= 12);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-12 (extra): ff_setenv / ff_getenv round-trip                  */
/* ------------------------------------------------------------------------ */
static void
test_ff_setenv_getenv_roundtrip(void **state)
{
    (void)state;
    int rv = ff_setenv("FF_UNIT_TEST_VAR", "hello-world");
    assert_int_equal(rv, 0);
    char *got = ff_getenv("FF_UNIT_TEST_VAR");
    assert_non_null(got);
    assert_string_equal(got, "hello-world");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-13 (extra): ff_mmap + ff_munmap round-trip with sane args     */
/* ------------------------------------------------------------------------ */
static void
test_ff_mmap_munmap_roundtrip(void **state)
{
    (void)state;
    void *p = ff_mmap(NULL, 4096,
                      ff_PROT_READ | ff_PROT_WRITE,
                      ff_MAP_PRIVATE | ff_MAP_ANON,
                      -1, 0);
    assert_non_null(p);
    assert_ptr_not_equal(p, ff_MAP_FAILED);
    /* writable */
    memset(p, 0xAB, 4096);
    assert_int_equal(((unsigned char *)p)[0],    0xAB);
    assert_int_equal(((unsigned char *)p)[4095], 0xAB);
    int rv = ff_munmap(p, 4096);
    assert_int_equal(rv, 0);
}

/* ------------------------------------------------------------------------ */
/* Stage-6 wraps for exit / abort (used by mmap-failure / panic TCs).       */
/* ------------------------------------------------------------------------ */
void
__wrap_exit(int code)
{
    (void)code;
    mock_assert(0, "exit", __FILE__, __LINE__);
    /* unreachable */
    while (1) {}
}

void
__wrap_abort(void)
{
    mock_assert(0, "abort", __FILE__, __LINE__);
    /* unreachable */
    while (1) {}
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-14 (Stage-6): ff_mmap with conflicting MAP_SHARED+MAP_PRIVATE */
/* flags makes the underlying mmap(2) fail (EINVAL), which triggers the     */
/* fatal exit branch in ff_host_interface.c L80-82.                         */
/* ------------------------------------------------------------------------ */
static void
test_ff_mmap_failure_exits(void **state)
{
    (void)state;
    /* MAP_SHARED + MAP_PRIVATE both set is invalid per mmap(2). */
    expect_assert_failure(
        ff_mmap(NULL, 4096, ff_PROT_READ | ff_PROT_WRITE,
                ff_MAP_SHARED | ff_MAP_PRIVATE | ff_MAP_ANON,
                -1, 0));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-15 (Stage-6): ff_realloc with size=0 returns the original    */
/* pointer untouched (covers ff_host_interface.c L121-126 size-0 branch).   */
/* ------------------------------------------------------------------------ */
static void
test_ff_realloc_zero_size_returns_p(void **state)
{
    (void)state;
    int sentinel = 0xCAFE;
    void *p = &sentinel;
    void *rv = ff_realloc(p, 0);
    assert_ptr_equal(rv, p);          /* untouched per F-Stack semantics */
    assert_int_equal(sentinel, 0xCAFE);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-16 (Stage-6): panic() variadic eventually aborts; covers     */
/* ff_host_interface.c L142-150 (panic body: va_start/vprintf/va_end/abort).*/
/*                                                                          */
/* panic() is __noreturn__, calls vprintf to stdout then abort(); we wrap   */
/* abort() to mock_assert which cmocka catches via expect_assert_failure.  */
/* ------------------------------------------------------------------------ */
extern void panic(const char *fmt, ...) __attribute__((__noreturn__));

static void
test_panic_aborts(void **state)
{
    (void)state;
    expect_assert_failure(panic("intentional panic %d %s", 42, "stage6"));
}

/* ------------------------------------------------------------------------ */
/* TC-U-P1-HIF-17 (Stage-6): ff_clock_gettime with ff_CLOCK_REALTIME maps   */
/* to host CLOCK_REALTIME (covers L161-163 case branch).                    */
/* ------------------------------------------------------------------------ */
static void
test_ff_clock_gettime_realtime(void **state)
{
    (void)state;
    int64_t sec = 0;
    long    nsec = -1;
    ff_clock_gettime(ff_CLOCK_REALTIME, &sec, &nsec);
    /* CLOCK_REALTIME on Linux returns wall-clock seconds since epoch;
     * any sane system clock is well past 2020-01-01 = 1577836800. */
    assert_true(sec > 1577836800);
    /* nsec must have been written (at minimum >= 0 after the syscall). */
    assert_true(nsec >= 0);
}

/* ------------------------------------------------------------------------ */
/* Stage-7 Phase-6 (FU-S7-HIF-*): branch-coverage boost                     */
/* ------------------------------------------------------------------------ */

/* TC-S7-HIF-01: ff_mmap with PROT_WRITE only (no PROT_READ) covers the    */
/* false leg of `(prot & ff_PROT_READ) == ff_PROT_READ` (BRDA L70 br=1).   */
static void
test_ff_mmap_prot_writeonly(void **state)
{
    (void)state;
    void *p = ff_mmap(NULL, 4096, ff_PROT_WRITE,
                      ff_MAP_PRIVATE | ff_MAP_ANON, -1, 0);
    assert_ptr_not_equal(p, ff_MAP_FAILED);
    int rv = ff_munmap(p, 4096);
    assert_int_equal(rv, 0);
}

/* TC-S7-HIF-02: ff_mmap with PROT_READ only (no PROT_WRITE) covers       */
/* BRDA L71 br=1 (false leg of PROT_WRITE bit test).                      */
static void
test_ff_mmap_prot_readonly(void **state)
{
    (void)state;
    void *p = ff_mmap(NULL, 4096, ff_PROT_READ,
                      ff_MAP_PRIVATE | ff_MAP_ANON, -1, 0);
    assert_ptr_not_equal(p, ff_MAP_FAILED);
    /* Read a byte; PROT_READ-only anon mapping is zero-filled. */
    volatile unsigned char b = ((volatile unsigned char *)p)[0];
    assert_int_equal(b, 0);
    int rv = ff_munmap(p, 4096);
    assert_int_equal(rv, 0);
}

/* TC-S7-HIF-03: ff_mmap with MAP_SHARED|MAP_ANON (no MAP_PRIVATE) covers */
/* BRDA L75 br=1 (false leg of MAP_PRIVATE bit test).                     */
static void
test_ff_mmap_map_shared_anon(void **state)
{
    (void)state;
    void *p = ff_mmap(NULL, 4096, ff_PROT_READ | ff_PROT_WRITE,
                      ff_MAP_SHARED | ff_MAP_ANON, -1, 0);
    assert_ptr_not_equal(p, ff_MAP_FAILED);
    int rv = ff_munmap(p, 4096);
    assert_int_equal(rv, 0);
}

/* TC-S7-HIF-04: ff_mmap file-backed (MAP_PRIVATE without MAP_ANON)       */
/* covers BRDA L76 br=1 (false leg of MAP_ANON bit test).                 */
static void
test_ff_mmap_file_backed_no_anon(void **state)
{
    (void)state;
    char tmpl[] = "/tmp/ff_hif_mmap_XXXXXX";
    int fd = mkstemp(tmpl);
    assert_true(fd >= 0);
    int t = ftruncate(fd, 4096);
    assert_int_equal(t, 0);
    void *p = ff_mmap(NULL, 4096, ff_PROT_READ | ff_PROT_WRITE,
                      ff_MAP_PRIVATE, fd, 0);
    assert_ptr_not_equal(p, ff_MAP_FAILED);
    int rv = ff_munmap(p, 4096);
    assert_int_equal(rv, 0);
    close(fd);
    /* clean up via wrapper script */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "/data/workspace/rm_tmp_file.sh %s >/dev/null 2>&1", tmpl);
    int s = system(cmd); (void)s;
}

/* TC-S7-HIF-05: ff_get_current_time(NULL, &nsec) covers BRDA L196 br=1   */
/* (sec==NULL false branch of the first guard). Must not crash.          */
static void
test_ff_get_current_time_null_sec(void **state)
{
    (void)state;
    long ns = -1;
    ff_update_current_ts();
    ff_get_current_time(NULL, &ns);
    assert_true(ns >= 0);
}

/* TC-S7-HIF-06: ff_get_current_time(&sec, NULL) covers BRDA L200 br=1   */
/* (nsec==NULL false branch of the second guard). Must not crash.       */
static void
test_ff_get_current_time_null_nsec(void **state)
{
    (void)state;
    time_t s = 0;
    ff_update_current_ts();
    ff_get_current_time(&s, NULL);
    assert_true(s > 1577836800);
}

/* TC-S9-HIF-01 (FU-S9-HIF-ASSERT-WRAP): clock_gettime failing inside
 * ff_clock_gettime trips assert(0==rv) -> __assert_fail -> longjmp.
 * Covers the L176 assert FALSE leg. */
static void
test_ff_clock_gettime_assert_fail_on_clock_error(void **state)
{
    (void)state;
    g_assert_fired = 0;
    g_clock_fail = 1;
    int64_t sec = 0; long nsec = 0;
    if (setjmp(g_assert_jmp) == 0) {
        ff_clock_gettime(ff_CLOCK_MONOTONIC, &sec, &nsec);
        /* must not reach here: the assert should have fired */
        g_clock_fail = 0;
        fail_msg("ff_clock_gettime did not assert on clock_gettime failure");
    }
    g_clock_fail = 0;
    assert_int_equal(g_assert_fired, 1);
}

/* TC-S9-HIF-02 (FU-S9-HIF-ASSERT-WRAP): clock_gettime failing inside
 * ff_update_current_ts trips assert(rv==0) -> __assert_fail -> longjmp.
 * Covers the L209 assert FALSE leg. */
static void
test_ff_update_current_ts_assert_fail_on_clock_error(void **state)
{
    (void)state;
    g_assert_fired = 0;
    g_clock_fail = 1;
    if (setjmp(g_assert_jmp) == 0) {
        ff_update_current_ts();
        g_clock_fail = 0;
        fail_msg("ff_update_current_ts did not assert on clock_gettime failure");
    }
    g_clock_fail = 0;
    assert_int_equal(g_assert_fired, 1);
}

#ifdef FF_KERNEL_COEXIST
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Kernel-stack coexistence fd-space: a managed kernel fd is encoded as
 * (host_fd + FF_KERNEL_FD_BASE) and must never collide with FreeBSD fds
 * (< FF_KERNEL_FD_BASE). Verify the ff_is_kernel_fd/encode/real helpers. */
static void
test_ff_kernel_fd_encode_roundtrip(void **state)
{
    (void)state;
    assert_false(ff_is_kernel_fd(0));
    assert_false(ff_is_kernel_fd(1024));
    assert_false(ff_is_kernel_fd(FF_KERNEL_FD_BASE - 1));
    assert_true(ff_is_kernel_fd(FF_KERNEL_FD_BASE));

    int host_fds[] = {0, 3, 1024, 65535};
    for (size_t i = 0; i < sizeof(host_fds) / sizeof(host_fds[0]); i++) {
        int enc = ff_kernel_fd_encode(host_fds[i]);
        assert_true(ff_is_kernel_fd(enc));
        assert_int_equal(ff_kernel_fd_real(enc), host_fds[i]);
    }
}

/* Native dual-stack fd map: set/get/clear and out-of-range safety. */
static void
test_ff_native_fd_map(void **state)
{
    (void)state;
    assert_int_equal(ff_native_map_get(7), 0);
    ff_native_map_set(7, 42);
    assert_int_equal(ff_native_map_get(7), 42);
    ff_native_map_set(7, 99);
    assert_int_equal(ff_native_map_get(7), 99);
    ff_native_map_clear(7);
    assert_int_equal(ff_native_map_get(7), 0);
    /* out-of-range indices are safe no-ops returning 0 */
    assert_int_equal(ff_native_map_get(-1), 0);
    assert_int_equal(ff_native_map_get(1 << 30), 0);
    ff_native_map_set(-1, 5);
    ff_native_map_set(1 << 30, 5);
}

/*
 * R8 host bridges: ff_host_sendmsg/recvmsg/getpeername/getsockname/shutdown.
 * Drive them over a real loopback AF_INET TCP pair (no mock) so the bridge's
 * direct host-libc passthrough is exercised end to end.
 */
static void
test_ff_host_msg_name_shutdown_bridges(void **state)
{
    (void)state;
    int ln = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(ln >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert_int_equal(bind(ln, (struct sockaddr *)&sa, sizeof(sa)), 0);
    assert_int_equal(listen(ln, 1), 0);

    socklen_t slen = sizeof(sa);
    assert_int_equal(getsockname(ln, (struct sockaddr *)&sa, &slen), 0);

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(cli >= 0);
    assert_int_equal(connect(cli, (struct sockaddr *)&sa, sizeof(sa)), 0);
    int srv = accept(ln, NULL, NULL);
    assert_true(srv >= 0);

    struct sockaddr_in pn;
    socklen_t pnlen = sizeof(pn);
    assert_int_equal(ff_host_getsockname(cli, &pn, &pnlen), 0);
    assert_int_equal(pn.sin_addr.s_addr, htonl(INADDR_LOOPBACK));

    pnlen = sizeof(pn);
    assert_int_equal(ff_host_getpeername(cli, &pn, &pnlen), 0);
    assert_int_equal(pn.sin_port, sa.sin_port);

    char wbuf[] = "ping";
    struct iovec wio = { wbuf, sizeof(wbuf) };
    struct msghdr wmsg;
    memset(&wmsg, 0, sizeof(wmsg));
    wmsg.msg_iov = &wio;
    wmsg.msg_iovlen = 1;
    assert_int_equal(ff_host_sendmsg(cli, &wmsg, 0), (ssize_t)sizeof(wbuf));

    char rbuf[16] = {0};
    struct iovec rio = { rbuf, sizeof(rbuf) };
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_iov = &rio;
    rmsg.msg_iovlen = 1;
    assert_int_equal(ff_host_recvmsg(srv, &rmsg, 0), (ssize_t)sizeof(wbuf));
    assert_string_equal(rbuf, "ping");

    assert_int_equal(ff_host_shutdown(cli, SHUT_WR), 0);
    assert_int_equal(ff_host_recvmsg(srv, &rmsg, 0), 0);

    ff_host_close(srv);
    ff_host_close(cli);
    ff_host_close(ln);
}

/*
 * R9 P1: ff_host_set_v6only forces IPV6_V6ONLY=1 on a host AF_INET6 socket,
 * enabling a dual-stack pair to share the same port with an AF_INET socket
 * (even when the host net.ipv6.bindv6only sysctl is 0).
 */
static void
test_ff_host_set_v6only(void **state)
{
    (void)state;
    int s6 = socket(AF_INET6, SOCK_STREAM, 0);
    assert_true(s6 >= 0);

    assert_int_equal(ff_host_set_v6only(s6), 0);

    int v6only = 0;
    socklen_t olen = sizeof(v6only);
    assert_int_equal(getsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY,
                                &v6only, &olen), 0);
    assert_int_equal(v6only, 1);

    /* bind the v6-only socket to [::]:0 and learn the ephemeral port */
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_addr = in6addr_any;
    sa6.sin6_port = 0;
    assert_int_equal(bind(s6, (struct sockaddr *)&sa6, sizeof(sa6)), 0);
    socklen_t s6len = sizeof(sa6);
    assert_int_equal(getsockname(s6, (struct sockaddr *)&sa6, &s6len), 0);
    uint16_t port = sa6.sin6_port;

    /* An AF_INET socket may now bind 0.0.0.0:<same-port> without EADDRINUSE,
     * proving v6-only frees the IPv4 namespace for the dual-stack pair. */
    int s4 = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(s4 >= 0);
    struct sockaddr_in sa4;
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_addr.s_addr = htonl(INADDR_ANY);
    sa4.sin_port = port;
    if (bind(s4, (struct sockaddr *)&sa4, sizeof(sa4)) != 0) {
        char m[96];
        snprintf(m, sizeof(m),
                 "AF_INET bind of shared port failed: errno=%d (%s)",
                 errno, strerror(errno));
        fail_msg("%s", m);
    }

    ff_host_close(s4);
    ff_host_close(s6);
}

/*
 * R9 P2: ff_host_kqueue_ctl registers a host fd into the host epoll paired
 * with a kqueue; ff_host_kqueue_poll drains it as (app_fd, is_write, is_eof)
 * triples. Drive it with a real loopback TCP listener: register listen_fd with
 * a synthetic app_fd, connect a client, and confirm the readable event carries
 * the registered app_fd with is_write=0. Then DEL and confirm de-registration.
 */
static void
test_ff_host_kqueue_ctl_poll(void **state)
{
    (void)state;
    int epfd = ff_host_epoll_create1(0);
    assert_true(epfd >= 0);

    int ln = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(ln >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert_int_equal(bind(ln, (struct sockaddr *)&sa, sizeof(sa)), 0);
    assert_int_equal(listen(ln, 1), 0);
    socklen_t slen = sizeof(sa);
    assert_int_equal(getsockname(ln, (struct sockaddr *)&sa, &slen), 0);

    const int app_fd = 0x40000123;   /* synthetic kernel-namespace app fd */

    /* poll with nothing pending -> 0 events */
    int triples[3 * 8];
    assert_int_equal(ff_host_kqueue_poll(epfd, triples, 8), 0);

    /* register listen fd for read readiness, carrying app_fd in data.fd */
    ff_host_kqueue_ctl(epfd, 0, ln, app_fd, 0);

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(cli >= 0);
    assert_int_equal(connect(cli, (struct sockaddr *)&sa, sizeof(sa)), 0);

    /* the listener becomes readable; retry briefly for delivery */
    int n = 0;
    for (int tries = 0; tries < 50 && n == 0; tries++) {
        n = ff_host_kqueue_poll(epfd, triples, 8);
        if (n == 0) {
            struct timespec slp = {0, 2 * 1000 * 1000};
            nanosleep(&slp, NULL);
        }
    }
    assert_int_equal(n, 1);
    assert_int_equal(triples[0], app_fd);   /* app_fd round-trips via data.fd */
    assert_int_equal(triples[1], 0);        /* is_write=0 (registered EPOLLIN) */

    /* de-register; subsequent poll must report nothing for this fd */
    int srv = accept(ln, NULL, NULL);       /* drain backlog so it's not re-fired */
    assert_true(srv >= 0);
    ff_host_kqueue_ctl(epfd, 1, ln, app_fd, 0);
    assert_int_equal(ff_host_kqueue_poll(epfd, triples, 8), 0);

    ff_host_close(srv);
    ff_host_close(cli);
    ff_host_close(ln);
    ff_host_close(epfd);
}

/*
 * R9 P2 (optional): ff_host_kqueue_ctl is idempotent on a repeated ADD of the
 * same fd. The first ADD succeeds; a second ADD returns EEXIST inside the
 * helper and silently falls back to EPOLL_CTL_MOD. The fd must still be
 * pollable exactly once afterward (no error, no duplicate registration).
 */
static void
test_ff_host_kqueue_ctl_add_idempotent(void **state)
{
    (void)state;
    int epfd = ff_host_epoll_create1(0);
    assert_true(epfd >= 0);

    int ln = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(ln >= 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    assert_int_equal(bind(ln, (struct sockaddr *)&sa, sizeof(sa)), 0);
    assert_int_equal(listen(ln, 1), 0);
    socklen_t slen = sizeof(sa);
    assert_int_equal(getsockname(ln, (struct sockaddr *)&sa, &slen), 0);

    const int app_fd1 = 0x40000777;
    const int app_fd2 = 0x40000888;   /* second ADD re-maps app_fd via MOD */

    ff_host_kqueue_ctl(epfd, 0, ln, app_fd1, 0);
    /* repeat ADD on same hfd -> EEXIST -> MOD fallback (no error surfaced) */
    ff_host_kqueue_ctl(epfd, 0, ln, app_fd2, 0);

    int cli = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(cli >= 0);
    assert_int_equal(connect(cli, (struct sockaddr *)&sa, sizeof(sa)), 0);

    int triples[3 * 8];
    int n = 0;
    for (int tries = 0; tries < 50 && n == 0; tries++) {
        n = ff_host_kqueue_poll(epfd, triples, 8);
        if (n == 0) {
            struct timespec slp = {0, 2 * 1000 * 1000};
            nanosleep(&slp, NULL);
        }
    }
    /* exactly one registration: the MOD-updated app_fd2 is reported once */
    assert_int_equal(n, 1);
    assert_int_equal(triples[0], app_fd2);
    assert_int_equal(triples[1], 0);

    int srv = accept(ln, NULL, NULL);
    assert_true(srv >= 0);
    ff_host_kqueue_ctl(epfd, 1, ln, app_fd2, 0);

    ff_host_close(srv);
    ff_host_close(cli);
    ff_host_close(ln);
    ff_host_close(epfd);
}

#include <sys/ioctl.h>
#include <fcntl.h>

/*
 * R10 P: ff_host_readv / ff_host_writev over a real socketpair. Scatter-write
 * three iov segments and gather-read them back into two segments; verify the
 * total byte count and the reassembled payload match exactly (passthrough to
 * host readv/writev preserves order and length).
 */
static void
test_ff_host_readv_writev(void **state)
{
    (void)state;
    int sp[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);

    char s0[] = "alpha";    /* 5 */
    char s1[] = "-beta-";   /* 6 */
    char s2[] = "gamma!";   /* 6 */
    struct iovec wiov[3] = {
        { s0, 5 }, { s1, 6 }, { s2, 6 },
    };
    ssize_t total = 5 + 6 + 6;
    assert_int_equal(ff_host_writev(sp[0], wiov, 3), total);

    char rb0[8] = {0};
    char rb1[16] = {0};
    struct iovec riov[2] = {
        { rb0, 8 }, { rb1, sizeof(rb1) },
    };
    assert_int_equal(ff_host_readv(sp[1], riov, 2), total);

    char joined[32] = {0};
    memcpy(joined, rb0, 8);
    memcpy(joined + 8, rb1, (size_t)(total - 8));
    assert_memory_equal(joined, "alpha-beta-gamma!", (size_t)total);

    ff_host_close(sp[0]);
    ff_host_close(sp[1]);
}

/*
 * R10 P: ff_host_ioctl with FIONBIO sets non-blocking on a real socket; confirm
 * via fcntl(F_GETFL) that O_NONBLOCK is now set, then clear it and re-check.
 */
static void
test_ff_host_ioctl_fionbio(void **state)
{
    (void)state;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert_true(fd >= 0);

    int on = 1;
    assert_int_equal(ff_host_ioctl(fd, FIONBIO, &on), 0);
    int fl = fcntl(fd, F_GETFL, 0);
    assert_true(fl >= 0);
    assert_true((fl & O_NONBLOCK) != 0);

    int off = 0;
    assert_int_equal(ff_host_ioctl(fd, FIONBIO, &off), 0);
    fl = fcntl(fd, F_GETFL, 0);
    assert_true(fl >= 0);
    assert_int_equal(fl & O_NONBLOCK, 0);

    ff_host_close(fd);
}

/*
 * R10 P: ff_host_dup duplicates one end of a socketpair. Writing through the
 * duplicated fd is observed on the peer (same underlying object). Closing the
 * dup leaves the original fd fully usable.
 */
static void
test_ff_host_dup(void **state)
{
    (void)state;
    int sp[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);

    int dupfd = ff_host_dup(sp[0]);
    assert_true(dupfd >= 0);
    assert_int_not_equal(dupfd, sp[0]);

    assert_int_equal(write(dupfd, "x", 1), 1);
    char c = 0;
    assert_int_equal(read(sp[1], &c, 1), 1);
    assert_int_equal(c, 'x');

    ff_host_close(dupfd);
    /* original still usable after the dup is closed */
    assert_int_equal(write(sp[0], "y", 1), 1);
    assert_int_equal(read(sp[1], &c, 1), 1);
    assert_int_equal(c, 'y');

    ff_host_close(sp[0]);
    ff_host_close(sp[1]);
}

/*
 * R10 P (optional): ff_host_dup2 duplicates onto a chosen target fd. After the
 * dup2 the target refers to the same socket; a write on it reaches the peer.
 */
static void
test_ff_host_dup2(void **state)
{
    (void)state;
    int sp[2];
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);

    /* a spare fd to be the dup2 target */
    int spare = dup(sp[0]);
    assert_true(spare >= 0);

    assert_int_equal(ff_host_dup2(sp[0], spare), spare);

    assert_int_equal(write(spare, "z", 1), 1);
    char c = 0;
    assert_int_equal(read(sp[1], &c, 1), 1);
    assert_int_equal(c, 'z');

    ff_host_close(spare);
    ff_host_close(sp[0]);
    ff_host_close(sp[1]);
}
#endif /* FF_KERNEL_COEXIST */

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ff_malloc_normal),
        cmocka_unit_test(test_ff_calloc_zeros_memory),
        cmocka_unit_test(test_ff_realloc_grow),
        cmocka_unit_test(test_ff_free_null),
        cmocka_unit_test(test_ff_clock_gettime_monotonic),
        cmocka_unit_test(test_ff_arc4rand_buf_filled),
        cmocka_unit_test(test_ff_get_current_time_advances),
        cmocka_unit_test(test_ff_os_errno_mapping),
        /* Stage-3 coverage extensions (TC-U-P1-HIF-09..13) */
        cmocka_unit_test(test_ff_clock_gettime_ns_advances),
        cmocka_unit_test(test_ff_arc4random_distribution),
        cmocka_unit_test(test_ff_setenv_getenv_roundtrip),
        cmocka_unit_test(test_ff_mmap_munmap_roundtrip),
        /* Stage-6 coverage extensions (TC-U-P1-HIF-14..17) */
        cmocka_unit_test(test_ff_mmap_failure_exits),
        cmocka_unit_test(test_ff_realloc_zero_size_returns_p),
        cmocka_unit_test(test_panic_aborts),
        cmocka_unit_test(test_ff_clock_gettime_realtime),
        /* Stage-7 Phase-6 branch-coverage boost (FU-S7-HIF-*) */
        cmocka_unit_test(test_ff_mmap_prot_writeonly),
        cmocka_unit_test(test_ff_mmap_prot_readonly),
        cmocka_unit_test(test_ff_mmap_map_shared_anon),
        cmocka_unit_test(test_ff_mmap_file_backed_no_anon),
        cmocka_unit_test(test_ff_get_current_time_null_sec),
        cmocka_unit_test(test_ff_get_current_time_null_nsec),
        /* Stage-9 (FU-S9-HIF-ASSERT-WRAP) clock assert-fail legs */
        cmocka_unit_test(test_ff_clock_gettime_assert_fail_on_clock_error),
        cmocka_unit_test(test_ff_update_current_ts_assert_fail_on_clock_error),
#ifdef FF_KERNEL_COEXIST
        cmocka_unit_test(test_ff_kernel_fd_encode_roundtrip),
        cmocka_unit_test(test_ff_native_fd_map),
        cmocka_unit_test(test_ff_host_msg_name_shutdown_bridges),
        /* R9 P1/P2 coexistence: v6only + host-epoll kqueue ctl/poll */
        cmocka_unit_test(test_ff_host_set_v6only),
        cmocka_unit_test(test_ff_host_kqueue_ctl_poll),
        cmocka_unit_test(test_ff_host_kqueue_ctl_add_idempotent),
        /* R10 coexistence: readv/writev + ioctl(FIONBIO) + dup/dup2 bridges */
        cmocka_unit_test(test_ff_host_readv_writev),
        cmocka_unit_test(test_ff_host_ioctl_fionbio),
        cmocka_unit_test(test_ff_host_dup),
        cmocka_unit_test(test_ff_host_dup2),
#endif /* FF_KERNEL_COEXIST */
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
