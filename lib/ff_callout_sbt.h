/*-
 * F-Stack tick-wheel callout sbt helpers.
 *
 * Single-source implementation shared by lib/ff_kern_timeout.c (kernel
 * build; kernel headers supply the prerequisites below) and
 * tests/unit/test_ff_callout.c (host build; a shim supplies them).
 *
 * Prerequisites at the inclusion point: sbintime_t, SBT_MAX, INT_MAX,
 * tick_sbt, tc_precexp, sbinuptime(), C_ABSOLUTE, C_HARDCLOCK, C_PRECALC,
 * C_PRELGET().
 *
 * Include guard note: the functions below have external linkage; include
 * this file exactly once per binary.
 */

#ifndef _FF_CALLOUT_SBT_H_
#define _FF_CALLOUT_SBT_H_

/*
 * callout_when() adapted to the F-Stack tick wheel: resolve a relative sbt
 * delay into an absolute fire time. There is no hardclocktime snapshot in
 * user space, so base on sbinuptime(); the caller-side sbt->tick conversion
 * rounds up, which bounds the extra latency to one tick.
 */
void
callout_when(sbintime_t sbt, sbintime_t precision, int flags,
    sbintime_t *res, sbintime_t *prec_res)
{
	sbintime_t now, to_sbt, to_pr;

	if ((flags & (C_ABSOLUTE | C_PRECALC)) != 0) {
		*res = sbt;
		*prec_res = precision;
		return;
	}
	if ((flags & C_HARDCLOCK) != 0 && sbt < tick_sbt)
		sbt = tick_sbt;
	now = sbinuptime();
	if (SBT_MAX - now < sbt)
		to_sbt = SBT_MAX;
	else
		to_sbt = now + sbt;
	*res = to_sbt;
	to_pr = ((C_PRELGET(flags) < 0) ? sbt >> tc_precexp :
	    sbt >> C_PRELGET(flags));
	*prec_res = to_pr > precision ? to_pr : precision;
}

/*
 * Convert the sbt argument of callout_reset_sbt_on() into wheel ticks.
 * C_ABSOLUTE values are converted to relative ticks against current uptime
 * (same formula as kern_event.c kqtimer_sched_callout(), rounding up so the
 * callout never fires early); relative values keep the historical
 * sbt / tick_sbt semantics. Expired absolute times return 0, which
 * callout_reset_tick_on() clamps to fire on the next tick.
 */
int
callout_sbt_to_ticks(sbintime_t sbt, int flags)
{
	sbintime_t now, ticks;

	if ((flags & C_ABSOLUTE) == 0) {
		ticks = sbt / tick_sbt;
		return (ticks > INT_MAX ? INT_MAX : (int)ticks);
	}
	now = sbinuptime();
	if (sbt <= now)
		return (0);
	ticks = (sbt - now) / tick_sbt;
	return (ticks >= INT_MAX ? INT_MAX : (int)ticks + 1);
}

#endif /* _FF_CALLOUT_SBT_H_ */
