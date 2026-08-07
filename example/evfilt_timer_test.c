/*
 * EVFILT_TIMER precision test for issue #331.
 * Sets a 1-second periodic kqueue timer, prints the real wall-clock
 * interval between triggers. Every 10 triggers it re-arms the timer
 * to exercise the reschedule path. Exits after 30 triggers.
 */
#include <errno.h>
#include <ff_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_EVENTS 8
#define PERIOD_SEC 1
#define REARM_EVERY 10
#define TOTAL_TRIGGERS 30

static struct kevent events[MAX_EVENTS];
static int kq = -1;

static double
now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void
arm_timer(void)
{
	struct kevent kev;

	EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD, NOTE_SECONDS, PERIOD_SEC, NULL);
	if (ff_kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		printf("arm_timer ff_kevent error:%d, %s\n", errno,
		    strerror(errno));
}

static int
loop(void *arg __attribute__((unused)))
{
	static int ntrigs = 0;
	static double last = 0;
	int nevents, i;

	nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
	if (nevents == -1) {
		perror("loop::ff_kevent");
		return 0;
	}
	for (i = 0; i < nevents; i++) {
		if (events[i].filter != EVFILT_TIMER)
			continue;
		double cur = now_sec();
		double since_last = last ? cur - last : 0;
		ntrigs++;
		printf("TRIGGER #%d since_last=%.3f\n", ntrigs,
		    since_last);
		fflush(stdout);
		last = cur;
		if (ntrigs % REARM_EVERY == 0) {
			printf("REARM TIMER\n");
			fflush(stdout);
			arm_timer();
		}
		if (ntrigs >= TOTAL_TRIGGERS) {
			printf("DONE %d triggers\n", ntrigs);
			fflush(stdout);
			exit(0);
		}
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	if (ff_init(argc, argv) != 0) {
		fprintf(stderr, "ff_init failed: %d, %s\n", errno,
		    strerror(errno));
		return 1;
	}
	kq = ff_kqueue();
	if (kq == -1) {
		fprintf(stderr, "ff_kqueue failed: %d, %s\n", errno,
		    strerror(errno));
		return 1;
	}
	arm_timer();
	printf("START evfilt_timer_test period=%ds total=%d\n",
	    PERIOD_SEC, TOTAL_TRIGGERS);
	fflush(stdout);
	ff_run(loop, NULL);
	return 0;
}
