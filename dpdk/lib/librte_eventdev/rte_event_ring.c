/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#include <sys/queue.h>
#include <string.h>

#include <rte_tailq.h>
#include <rte_memzone.h>
#include <rte_rwlock.h>
#include <rte_eal_memconfig.h>
#include "rte_event_ring.h"

TAILQ_HEAD(rte_event_ring_list, rte_tailq_entry);

static struct rte_tailq_elem rte_event_ring_tailq = {
	.name = RTE_TAILQ_EVENT_RING_NAME,
};
EAL_REGISTER_TAILQ(rte_event_ring_tailq)

int
rte_event_ring_init(struct rte_event_ring *r, const char *name,
	unsigned int count, unsigned int flags)
{
	/* compilation-time checks */
	RTE_BUILD_BUG_ON((sizeof(struct rte_event_ring) &
			  RTE_CACHE_LINE_MASK) != 0);

	/* init the ring structure */
	return rte_ring_init(&r->r, name, count, flags);
}

/* create the ring */
struct rte_event_ring *
rte_event_ring_create(const char *name, unsigned int count, int socket_id,
		unsigned int flags)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct rte_event_ring *r;
	struct rte_tailq_entry *te;
	const struct rte_memzone *mz;
	ssize_t ring_size;
	int mz_flags = 0;
	struct rte_event_ring_list *ring_list = NULL;
	const unsigned int requested_count = count;
	int ret;

	ring_list = RTE_TAILQ_CAST(rte_event_ring_tailq.head,
		rte_event_ring_list);

	/* for an exact size ring, round up from count to a power of two */
	if (flags & RING_F_EXACT_SZ)
		count = rte_align32pow2(count + 1);
	else if (!rte_is_power_of_2(count)) {
		rte_errno = EINVAL;
		return NULL;
	}

	ring_size = sizeof(*r) + (count * sizeof(struct rte_event));

	ret = snprintf(mz_name, sizeof(mz_name), "%s%s",
		RTE_RING_MZ_PREFIX, name);
	if (ret < 0 || ret >= (int)sizeof(mz_name)) {
		rte_errno = ENAMETOOLONG;
		return NULL;
	}

	te = rte_zmalloc("RING_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		RTE_LOG(ERR, RING, "Cannot reserve memory for tailq\n");
		rte_errno = ENOMEM;
		return NULL;
	}

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/*
	 * reserve a memory zone for this ring. If we can't get rte_config or
	 * we are secondary process, the memzone_reserve function will set
	 * rte_errno for us appropriately - hence no check in this this function
	 */
	mz = rte_memzone_reserve(mz_name, ring_size, socket_id, mz_flags);
	if (mz != NULL) {
		r = mz->addr;
		/* Check return value in case rte_ring_init() fails on size */
		int err = rte_event_ring_init(r, name, requested_count, flags);
		if (err) {
			RTE_LOG(ERR, RING, "Ring init failed\n");
			if (rte_memzone_free(mz) != 0)
				RTE_LOG(ERR, RING, "Cannot free memzone\n");
			rte_free(te);
			rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
			return NULL;
		}

		te->data = (void *) r;
		r->r.memzone = mz;

		TAILQ_INSERT_TAIL(ring_list, te, next);
	} else {
		r = NULL;
		RTE_LOG(ERR, RING, "Cannot reserve memory\n");
		rte_free(te);
	}
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	return r;
}


struct rte_event_ring *
rte_event_ring_lookup(const char *name)
{
	struct rte_tailq_entry *te;
	struct rte_event_ring *r = NULL;
	struct rte_event_ring_list *ring_list;

	ring_list = RTE_TAILQ_CAST(rte_event_ring_tailq.head,
			rte_event_ring_list);

	rte_rwlock_read_lock(RTE_EAL_TAILQ_RWLOCK);

	TAILQ_FOREACH(te, ring_list, next) {
		r = (struct rte_event_ring *) te->data;
		if (strncmp(name, r->r.name, RTE_RING_NAMESIZE) == 0)
			break;
	}

	rte_rwlock_read_unlock(RTE_EAL_TAILQ_RWLOCK);

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}

	return r;
}

/* free the ring */
void
rte_event_ring_free(struct rte_event_ring *r)
{
	struct rte_event_ring_list *ring_list = NULL;
	struct rte_tailq_entry *te;

	if (r == NULL)
		return;

	/*
	 * Ring was not created with rte_event_ring_create,
	 * therefore, there is no memzone to free.
	 */
	if (r->r.memzone == NULL) {
		RTE_LOG(ERR, RING,
			"Cannot free ring (not created with rte_event_ring_create()");
		return;
	}

	if (rte_memzone_free(r->r.memzone) != 0) {
		RTE_LOG(ERR, RING, "Cannot free memory\n");
		return;
	}

	ring_list = RTE_TAILQ_CAST(rte_event_ring_tailq.head,
			rte_event_ring_list);
	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	TAILQ_FOREACH(te, ring_list, next) {
		if (te->data == (void *) r)
			break;
	}

	if (te == NULL) {
		rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
		return;
	}

	TAILQ_REMOVE(ring_list, te, next);

	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	rte_free(te);
}
