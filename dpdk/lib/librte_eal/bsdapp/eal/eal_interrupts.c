/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_spinlock.h>
#include <rte_common.h>
#include <rte_interrupts.h>

#include "eal_private.h"
#include "eal_alarm_private.h"

#define MAX_INTR_EVENTS 16

/**
 * union buffer for reading on different devices
 */
union rte_intr_read_buffer {
	char charbuf[16];                /* for others */
};

TAILQ_HEAD(rte_intr_cb_list, rte_intr_callback);
TAILQ_HEAD(rte_intr_source_list, rte_intr_source);

struct rte_intr_callback {
	TAILQ_ENTRY(rte_intr_callback) next;
	rte_intr_callback_fn cb_fn;  /**< callback address */
	void *cb_arg;                /**< parameter for callback */
};

struct rte_intr_source {
	TAILQ_ENTRY(rte_intr_source) next;
	struct rte_intr_handle intr_handle; /**< interrupt handle */
	struct rte_intr_cb_list callbacks;  /**< user callbacks */
	uint32_t active;
};

/* global spinlock for interrupt data operation */
static rte_spinlock_t intr_lock = RTE_SPINLOCK_INITIALIZER;

/* interrupt sources list */
static struct rte_intr_source_list intr_sources;

/* interrupt handling thread */
static pthread_t intr_thread;

static volatile int kq = -1;

static int
intr_source_to_kevent(const struct rte_intr_handle *ih, struct kevent *ke)
{
	/* alarm callbacks are special case */
	if (ih->type == RTE_INTR_HANDLE_ALARM) {
		uint64_t timeout_ns;

		/* get soonest alarm timeout */
		if (eal_alarm_get_timeout_ns(&timeout_ns) < 0)
			return -1;

		ke->filter = EVFILT_TIMER;
		/* timers are one shot */
		ke->flags |= EV_ONESHOT;
		ke->fflags = NOTE_NSECONDS;
		ke->data = timeout_ns;
	} else {
		ke->filter = EVFILT_READ;
	}
	ke->ident = ih->fd;

	return 0;
}

int
rte_intr_callback_register(const struct rte_intr_handle *intr_handle,
		rte_intr_callback_fn cb, void *cb_arg)
{
	struct rte_intr_callback *callback = NULL;
	struct rte_intr_source *src = NULL;
	int ret, add_event;

	/* first do parameter checking */
	if (intr_handle == NULL || intr_handle->fd < 0 || cb == NULL) {
		RTE_LOG(ERR, EAL,
			"Registering with invalid input parameter\n");
		return -EINVAL;
	}
	if (kq < 0) {
		RTE_LOG(ERR, EAL, "Kqueue is not active: %d\n", kq);
		return -ENODEV;
	}

	/* allocate a new interrupt callback entity */
	callback = calloc(1, sizeof(*callback));
	if (callback == NULL) {
		RTE_LOG(ERR, EAL, "Can not allocate memory\n");
		return -ENOMEM;
	}
	callback->cb_fn = cb;
	callback->cb_arg = cb_arg;

	rte_spinlock_lock(&intr_lock);

	/* check if there is at least one callback registered for the fd */
	TAILQ_FOREACH(src, &intr_sources, next) {
		if (src->intr_handle.fd == intr_handle->fd) {
			/* we had no interrupts for this */
			if (TAILQ_EMPTY(&src->callbacks))
				add_event = 1;

			TAILQ_INSERT_TAIL(&(src->callbacks), callback, next);
			ret = 0;
			break;
		}
	}

	/* no existing callbacks for this - add new source */
	if (src == NULL) {
		src = calloc(1, sizeof(*src));
		if (src == NULL) {
			RTE_LOG(ERR, EAL, "Can not allocate memory\n");
			ret = -ENOMEM;
			goto fail;
		} else {
			src->intr_handle = *intr_handle;
			TAILQ_INIT(&src->callbacks);
			TAILQ_INSERT_TAIL(&(src->callbacks), callback, next);
			TAILQ_INSERT_TAIL(&intr_sources, src, next);
			add_event = 1;
			ret = 0;
		}
	}

	/* add events to the queue. timer events are special as we need to
	 * re-set the timer.
	 */
	if (add_event || src->intr_handle.type == RTE_INTR_HANDLE_ALARM) {
		struct kevent ke;

		memset(&ke, 0, sizeof(ke));
		ke.flags = EV_ADD; /* mark for addition to the queue */

		if (intr_source_to_kevent(intr_handle, &ke) < 0) {
			RTE_LOG(ERR, EAL, "Cannot convert interrupt handle to kevent\n");
			ret = -ENODEV;
			goto fail;
		}

		/**
		 * add the intr file descriptor into wait list.
		 */
		if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) {
			/* currently, nic_uio does not support interrupts, so
			 * this error will always be triggered and output to the
			 * user. so, don't output it unless debug log level set.
			 */
			if (errno == ENODEV)
				RTE_LOG(DEBUG, EAL, "Interrupt handle %d not supported\n",
					src->intr_handle.fd);
			else
				RTE_LOG(ERR, EAL, "Error adding fd %d "
						"kevent, %s\n",
						src->intr_handle.fd,
						strerror(errno));
			ret = -errno;
			goto fail;
		}
	}
	rte_spinlock_unlock(&intr_lock);

	return ret;
fail:
	/* clean up */
	if (src != NULL) {
		TAILQ_REMOVE(&(src->callbacks), callback, next);
		if (TAILQ_EMPTY(&(src->callbacks))) {
			TAILQ_REMOVE(&intr_sources, src, next);
			free(src);
		}
	}
	free(callback);
	rte_spinlock_unlock(&intr_lock);
	return ret;
}

int
rte_intr_callback_unregister(const struct rte_intr_handle *intr_handle,
		rte_intr_callback_fn cb_fn, void *cb_arg)
{
	int ret;
	struct rte_intr_source *src;
	struct rte_intr_callback *cb, *next;

	/* do parameter checking first */
	if (intr_handle == NULL || intr_handle->fd < 0) {
		RTE_LOG(ERR, EAL,
		"Unregistering with invalid input parameter\n");
		return -EINVAL;
	}
	if (kq < 0) {
		RTE_LOG(ERR, EAL, "Kqueue is not active\n");
		return -ENODEV;
	}

	rte_spinlock_lock(&intr_lock);

	/* check if the insterrupt source for the fd is existent */
	TAILQ_FOREACH(src, &intr_sources, next)
		if (src->intr_handle.fd == intr_handle->fd)
			break;

	/* No interrupt source registered for the fd */
	if (src == NULL) {
		ret = -ENOENT;

	/* interrupt source has some active callbacks right now. */
	} else if (src->active != 0) {
		ret = -EAGAIN;

	/* ok to remove. */
	} else {
		struct kevent ke;

		ret = 0;

		/* remove it from the kqueue */
		memset(&ke, 0, sizeof(ke));
		ke.flags = EV_DELETE; /* mark for deletion from the queue */

		if (intr_source_to_kevent(intr_handle, &ke) < 0) {
			RTE_LOG(ERR, EAL, "Cannot convert to kevent\n");
			ret = -ENODEV;
			goto out;
		}

		/**
		 * remove intr file descriptor from wait list.
		 */
		if (kevent(kq, &ke, 1, NULL, 0, NULL) < 0) {
			RTE_LOG(ERR, EAL, "Error removing fd %d kevent, %s\n",
				src->intr_handle.fd, strerror(errno));
			/* removing non-existent even is an expected condition
			 * in some circumstances (e.g. oneshot events).
			 */
		}

		/*walk through the callbacks and remove all that match. */
		for (cb = TAILQ_FIRST(&src->callbacks); cb != NULL; cb = next) {
			next = TAILQ_NEXT(cb, next);
			if (cb->cb_fn == cb_fn && (cb_arg == (void *)-1 ||
					cb->cb_arg == cb_arg)) {
				TAILQ_REMOVE(&src->callbacks, cb, next);
				free(cb);
				ret++;
			}
		}

		/* all callbacks for that source are removed. */
		if (TAILQ_EMPTY(&src->callbacks)) {
			TAILQ_REMOVE(&intr_sources, src, next);
			free(src);
		}
	}
out:
	rte_spinlock_unlock(&intr_lock);

	return ret;
}

int
rte_intr_enable(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle && intr_handle->type == RTE_INTR_HANDLE_VDEV)
		return 0;

	if (!intr_handle || intr_handle->fd < 0 || intr_handle->uio_cfg_fd < 0)
		return -1;

	switch (intr_handle->type) {
	/* not used at this moment */
	case RTE_INTR_HANDLE_ALARM:
		return -1;
	/* not used at this moment */
	case RTE_INTR_HANDLE_DEV_EVENT:
		return -1;
	/* unknown handle type */
	default:
		RTE_LOG(ERR, EAL,
			"Unknown handle type of fd %d\n",
					intr_handle->fd);
		return -1;
	}

	return 0;
}

int
rte_intr_disable(const struct rte_intr_handle *intr_handle)
{
	if (intr_handle && intr_handle->type == RTE_INTR_HANDLE_VDEV)
		return 0;

	if (!intr_handle || intr_handle->fd < 0 || intr_handle->uio_cfg_fd < 0)
		return -1;

	switch (intr_handle->type) {
	/* not used at this moment */
	case RTE_INTR_HANDLE_ALARM:
		return -1;
	/* not used at this moment */
	case RTE_INTR_HANDLE_DEV_EVENT:
		return -1;
	/* unknown handle type */
	default:
		RTE_LOG(ERR, EAL,
			"Unknown handle type of fd %d\n",
					intr_handle->fd);
		return -1;
	}

	return 0;
}

static void
eal_intr_process_interrupts(struct kevent *events, int nfds)
{
	struct rte_intr_callback active_cb;
	union rte_intr_read_buffer buf;
	struct rte_intr_callback *cb;
	struct rte_intr_source *src;
	bool call = false;
	int n, bytes_read;

	for (n = 0; n < nfds; n++) {
		int event_fd = events[n].ident;

		rte_spinlock_lock(&intr_lock);
		TAILQ_FOREACH(src, &intr_sources, next)
			if (src->intr_handle.fd == event_fd)
				break;
		if (src == NULL) {
			rte_spinlock_unlock(&intr_lock);
			continue;
		}

		/* mark this interrupt source as active and release the lock. */
		src->active = 1;
		rte_spinlock_unlock(&intr_lock);

		/* set the length to be read dor different handle type */
		switch (src->intr_handle.type) {
		case RTE_INTR_HANDLE_ALARM:
			bytes_read = 0;
			call = true;
			break;
		case RTE_INTR_HANDLE_VDEV:
		case RTE_INTR_HANDLE_EXT:
			bytes_read = 0;
			call = true;
			break;
		case RTE_INTR_HANDLE_DEV_EVENT:
			bytes_read = 0;
			call = true;
			break;
		default:
			bytes_read = 1;
			break;
		}

		if (bytes_read > 0) {
			/**
			 * read out to clear the ready-to-be-read flag
			 * for epoll_wait.
			 */
			bytes_read = read(event_fd, &buf, bytes_read);
			if (bytes_read < 0) {
				if (errno == EINTR || errno == EWOULDBLOCK)
					continue;

				RTE_LOG(ERR, EAL, "Error reading from file "
					"descriptor %d: %s\n",
					event_fd,
					strerror(errno));
			} else if (bytes_read == 0)
				RTE_LOG(ERR, EAL, "Read nothing from file "
					"descriptor %d\n", event_fd);
			else
				call = true;
		}

		/* grab a lock, again to call callbacks and update status. */
		rte_spinlock_lock(&intr_lock);

		if (call) {
			/* Finally, call all callbacks. */
			TAILQ_FOREACH(cb, &src->callbacks, next) {

				/* make a copy and unlock. */
				active_cb = *cb;
				rte_spinlock_unlock(&intr_lock);

				/* call the actual callback */
				active_cb.cb_fn(active_cb.cb_arg);

				/*get the lock back. */
				rte_spinlock_lock(&intr_lock);
			}
		}

		/* we done with that interrupt source, release it. */
		src->active = 0;
		rte_spinlock_unlock(&intr_lock);
	}
}

static void *
eal_intr_thread_main(void *arg __rte_unused)
{
	struct kevent events[MAX_INTR_EVENTS];
	int nfds;

	/* host thread, never break out */
	for (;;) {
		/* do not change anything, just wait */
		nfds = kevent(kq, NULL, 0, events, MAX_INTR_EVENTS, NULL);

		/* kevent fail */
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			RTE_LOG(ERR, EAL,
				"kevent returns with fail\n");
			break;
		}
		/* kevent timeout, will never happen here */
		else if (nfds == 0)
			continue;

		/* kevent has at least one fd ready to read */
		eal_intr_process_interrupts(events, nfds);
	}
	close(kq);
	kq = -1;
	return NULL;
}

int
rte_eal_intr_init(void)
{
	int ret = 0;

	/* init the global interrupt source head */
	TAILQ_INIT(&intr_sources);

	kq = kqueue();
	if (kq < 0) {
		RTE_LOG(ERR, EAL, "Cannot create kqueue instance\n");
		return -1;
	}

	/* create the host thread to wait/handle the interrupt */
	ret = rte_ctrl_thread_create(&intr_thread, "eal-intr-thread", NULL,
			eal_intr_thread_main, NULL);
	if (ret != 0) {
		rte_errno = -ret;
		RTE_LOG(ERR, EAL,
			"Failed to create thread for interrupt handling\n");
	}

	return ret;
}

int
rte_intr_rx_ctl(struct rte_intr_handle *intr_handle,
		int epfd, int op, unsigned int vec, void *data)
{
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(epfd);
	RTE_SET_USED(op);
	RTE_SET_USED(vec);
	RTE_SET_USED(data);

	return -ENOTSUP;
}

int
rte_intr_efd_enable(struct rte_intr_handle *intr_handle, uint32_t nb_efd)
{
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(nb_efd);

	return 0;
}

void
rte_intr_efd_disable(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
}

int
rte_intr_dp_is_en(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	return 0;
}

int
rte_intr_allow_others(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	return 1;
}

int
rte_intr_cap_multiple(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	return 0;
}

int
rte_epoll_wait(int epfd, struct rte_epoll_event *events,
		int maxevents, int timeout)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(events);
	RTE_SET_USED(maxevents);
	RTE_SET_USED(timeout);

	return -ENOTSUP;
}

int
rte_epoll_ctl(int epfd, int op, int fd, struct rte_epoll_event *event)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(op);
	RTE_SET_USED(fd);
	RTE_SET_USED(event);

	return -ENOTSUP;
}

int
rte_intr_tls_epfd(void)
{
	return -ENOTSUP;
}

void
rte_intr_free_epoll_fd(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
}
