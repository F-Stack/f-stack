/*
 * F-Stack unit test: tick-wheel callout sbt helpers (P0 TCP-timer fix).
 *
 * Compiles the REAL implementation (lib/ff_callout_sbt.h — the same code
 * lib/ff_kern_timeout.c compiles into libfstack) against a host shim that
 * pins tick_sbt / sbinuptime() / tc_precexp. This is deliberately NOT a
 * mirror: the P0 bug was a no-op callout_when() stub that linked fine, so
 * only testing the real bodies catches that class of defect.
 *
 * tcp_timer_next() itself is a static inline in freebsd/netinet/tcp_timer.c
 * which cannot be host-compiled; a faithful mirror is used here instead.
 * KEEP IN SYNC with:
 *   - freebsd/netinet/tcp_timer.c  tcp_timer_next()
 *   - freebsd/netinet/tcp_var.h    tt_which enum order
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <limits.h>

/* ----------------------------------------------------------------------- */
/* Host shim: minimal kernel time/callout surface expected by the impl.     */
/* ----------------------------------------------------------------------- */

typedef int64_t sbintime_t;
#define SBT_1S		((sbintime_t)1 << 32)
#define SBT_1MS		(SBT_1S / 1000)
#define SBT_MAX		0x7fffffffffffffffLL

/* hz = 100, so one wheel tick is 10 ms; fully controllable by the tests. */
static sbintime_t shim_tick_sbt = SBT_1S / 100;
static int shim_tc_precexp = 5;
static sbintime_t shim_now = 60 * SBT_1S;

/* Bind the kernel-visible names used by the impl to the shim storage. */
#define tick_sbt	shim_tick_sbt
#define tc_precexp	shim_tc_precexp
#define sbinuptime()	shim_now

#define C_PRELBITS	7
#define C_PRELRANGE	((1 << C_PRELBITS) - 1)
#define C_PREL(x)	(((x) + 1) << 1)
#define C_PRELGET(x)	(int)((((x) >> 1) & C_PRELRANGE) - 1)
#define C_HARDCLOCK	0x0100
#define C_ABSOLUTE	0x0200
#define C_PRECALC	0x0400

/* Real implementation under test. */
#include "../../lib/ff_callout_sbt.h"

/* ----------------------------------------------------------------------- */
/* Mirror of tcp_timer_next() + minimal tcpcb timer arrays.                 */
/* KEEP IN SYNC with freebsd/netinet/tcp_timer.c / tcp_var.h.               */
/* ----------------------------------------------------------------------- */

#define M_MIN(a, b)	((a) < (b) ? (a) : (b))

enum tt_which_m {
	TT_REXMT_M = 0,
	TT_PERSIST_M,
	TT_KEEP_M,
	TT_2MSL_M,
	TT_DELACK_M,
	TT_N_M,
};

struct tcpcb_m {
	sbintime_t t_timers[TT_N_M];
	sbintime_t t_precisions[TT_N_M];
};

static void
tcpcb_m_init(struct tcpcb_m *tp)
{
	int i;

	/* Mirrors tcp_subr.c: every slot starts at SBT_MAX (== inactive). */
	for (i = 0; i < TT_N_M; i++) {
		tp->t_timers[i] = SBT_MAX;
		tp->t_precisions[i] = 0;
	}
}

static int
mirror_tcp_timer_next(struct tcpcb_m *tp, sbintime_t *precision)
{
	int i, rv;
	sbintime_t after, before;

	for (i = 0, rv = TT_N_M, after = before = SBT_MAX; i < TT_N_M; i++) {
		if (tp->t_timers[i] < after) {
			after = tp->t_timers[i];
			rv = i;
		}
		before = M_MIN(before, tp->t_timers[i] + tp->t_precisions[i]);
	}
	if (precision != NULL)
		*precision = before - after;

	return (rv);
}

/* Exactly what tcp_timer_activate(tp, which, delta) does for delta > 0. */
static void
mirror_tcp_timer_activate(struct tcpcb_m *tp, int which, sbintime_t delta_sbt)
{
	callout_when(delta_sbt, 0, C_HARDCLOCK,
	    &tp->t_timers[which], &tp->t_precisions[which]);
}

/* ----------------------------------------------------------------------- */
/* Tests.                                                                   */
/* ----------------------------------------------------------------------- */

/* TC-1: relative + C_HARDCLOCK path writes both outputs (the P0 stub left
 * them untouched) and resolves to an absolute fire time >= now + sbt. */
static void
test_callout_when_relative_hardclock(void **state)
{
	sbintime_t res, prec;
	const sbintime_t sbt = 40 * tick_sbt;	/* 400 ms at hz=100 */

	(void)state;
	shim_now = 60 * SBT_1S;
	res = -1;
	prec = -1;

	callout_when(sbt, 0, C_HARDCLOCK, &res, &prec);
	assert_true(res != -1);			/* outputs were written */
	assert_true(prec != -1);
	assert_int_equal(res, shim_now + sbt);	/* pinned clock: exact */
	/* C_PRELGET(C_HARDCLOCK) < 0 => precision = sbt >> tc_precexp */
	assert_int_equal(prec, sbt >> shim_tc_precexp);

	/* Encoded precision exponent wins when larger than the argument. */
	res = prec = -1;
	callout_when(sbt, 0, C_HARDCLOCK | C_PREL(3), &res, &prec);
	assert_int_equal(res, shim_now + sbt);
	assert_int_equal(prec, sbt >> 3);

	/* Explicit precision argument larger than computed floor is kept. */
	res = prec = -1;
	callout_when(sbt, sbt, C_HARDCLOCK, &res, &prec);
	assert_int_equal(prec, sbt);

	/* C_HARDCLOCK clamps sub-tick delays to one full tick. */
	res = -1;
	callout_when(tick_sbt / 2, 0, C_HARDCLOCK, &res, &prec);
	assert_int_equal(res, shim_now + tick_sbt);
}

/* TC-2: C_ABSOLUTE / C_PRECALC pass through unchanged. */
static void
test_callout_when_absolute_precalc_passthrough(void **state)
{
	sbintime_t res, prec;
	const sbintime_t abs = 123 * SBT_1S;

	(void)state;
	res = -1;
	prec = -1;
	callout_when(abs, 7 * SBT_1MS, C_ABSOLUTE, &res, &prec);
	assert_int_equal(res, abs);
	assert_int_equal(prec, 7 * SBT_1MS);

	res = -1;
	prec = -1;
	callout_when(abs, 7 * SBT_1MS, C_PRECALC, &res, &prec);
	assert_int_equal(res, abs);
	assert_int_equal(prec, 7 * SBT_1MS);
}

/* TC-3: near-SBT_MAX delay saturates instead of overflowing. */
static void
test_callout_when_overflow_clamps_to_sbt_max(void **state)
{
	sbintime_t res, prec;

	(void)state;
	shim_now = 60 * SBT_1S;
	res = -1;
	prec = -1;
	callout_when(SBT_MAX, 0, C_HARDCLOCK, &res, &prec);
	assert_int_equal(res, SBT_MAX);
}

/* TC-4: absolute -> relative tick conversion (macro path semantics). */
static void
test_callout_sbt_to_ticks_absolute(void **state)
{
	sbintime_t abs;

	(void)state;
	shim_now = 60 * SBT_1S;

	/* Future, non-tick-aligned: rounds up and adds the safety tick. */
	abs = shim_now + 10 * tick_sbt + tick_sbt / 2;
	assert_int_equal(callout_sbt_to_ticks(abs, C_ABSOLUTE), 11);

	/* Future, tick-aligned: (delta) + 1. */
	abs = shim_now + 10 * tick_sbt;
	assert_int_equal(callout_sbt_to_ticks(abs, C_ABSOLUTE), 11);

	/* Far future, just one tick away. */
	abs = shim_now + 1;
	assert_int_equal(callout_sbt_to_ticks(abs, C_ABSOLUTE), 1);

	/* Already expired / exactly now: 0 (callout_reset_tick_on clamps
	 * to fire on the next tick). */
	abs = shim_now - 1;
	assert_int_equal(callout_sbt_to_ticks(abs, C_ABSOLUTE), 0);
	assert_int_equal(callout_sbt_to_ticks(shim_now, C_ABSOLUTE), 0);

	/* Absurdly far future clamps to INT_MAX instead of wrapping. */
	assert_int_equal(callout_sbt_to_ticks(SBT_MAX, C_ABSOLUTE), INT_MAX);
}

/* TC-5: relative conversion keeps the historical sbt/tick_sbt semantics. */
static void
test_callout_sbt_to_ticks_relative(void **state)
{
	(void)state;

	assert_int_equal(callout_sbt_to_ticks(7 * tick_sbt, 0), 7);
	assert_int_equal(callout_sbt_to_ticks(SBT_1S, 0), 100); /* hz=100 */
	/* Sub-tick relative delay truncates to 0 (clamped to 1 downstream). */
	assert_int_equal(callout_sbt_to_ticks(tick_sbt / 2, 0), 0);
	/* Huge delay clamps instead of truncating a 64-bit quotient to int. */
	assert_int_equal(
	    callout_sbt_to_ticks((sbintime_t)4 * INT_MAX * tick_sbt, 0),
	    INT_MAX);
	/* Negative (overflowed) input stays <= 0; downstream clamp -> 1 tick. */
	assert_true(callout_sbt_to_ticks(-5 * tick_sbt, 0) <= 0);
}

/* TC-6: the tcp_timer_activate() state machine now arms timers.
 * Before the fix: callout_when() wrote nothing, t_timers[] stayed SBT_MAX,
 * tcp_timer_next() returned TT_N and tcp_timer_activate() always took the
 * callout_stop() branch. */
static void
test_tcp_timer_activation_chain(void **state)
{
	struct tcpcb_m tp;
	sbintime_t precision;
	int which, ticks;

	(void)state;
	shim_now = 60 * SBT_1S;
	tcpcb_m_init(&tp);

	/* Fresh tcpcb: no timer armed. */
	assert_int_equal(mirror_tcp_timer_next(&tp, &precision), TT_N_M);

	/* Activate RTO (delta = 5 ticks) exactly like tcp_timer_activate(). */
	mirror_tcp_timer_activate(&tp, TT_REXMT_M, 5 * tick_sbt);
	assert_true(tp.t_timers[TT_REXMT_M] != SBT_MAX);

	which = mirror_tcp_timer_next(&tp, &precision);
	assert_int_equal(which, TT_REXMT_M);

	/* Activate a closer 2MSL (delta = 2 ticks): it must win the min(). */
	mirror_tcp_timer_activate(&tp, TT_2MSL_M, 2 * tick_sbt);
	which = mirror_tcp_timer_next(&tp, &precision);
	assert_int_equal(which, TT_2MSL_M);

	/* And the armed callout gets a sane tick count via the fixed macro
	 * path: with the clock pinned, exactly delta + 1 ticks. */
	ticks = callout_sbt_to_ticks(tp.t_timers[which], C_ABSOLUTE);
	assert_int_equal(ticks, 3);

	/* Clock drift between arming and conversion keeps the fire time in
	 * [delta, delta + 1] ticks. */
	shim_now += tick_sbt / 2;
	ticks = callout_sbt_to_ticks(tp.t_timers[which], C_ABSOLUTE);
	assert_in_range(ticks, 2, 3);

	/* Deactivate (delta == 0 branch of tcp_timer_activate). */
	tp.t_timers[TT_2MSL_M] = SBT_MAX;
	tp.t_precisions[TT_2MSL_M] = 0;
	which = mirror_tcp_timer_next(&tp, &precision);
	assert_int_equal(which, TT_REXMT_M);
}

int
main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_callout_when_relative_hardclock),
		cmocka_unit_test(test_callout_when_absolute_precalc_passthrough),
		cmocka_unit_test(test_callout_when_overflow_clamps_to_sbt_max),
		cmocka_unit_test(test_callout_sbt_to_ticks_absolute),
		cmocka_unit_test(test_callout_sbt_to_ticks_relative),
		cmocka_unit_test(test_tcp_timer_activation_chain),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}
