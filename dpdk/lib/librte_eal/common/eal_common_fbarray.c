/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2018 Intel Corporation
 */

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <sys/file.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include "eal_filesystem.h"
#include "eal_private.h"

#include "rte_fbarray.h"

#define MASK_SHIFT 6ULL
#define MASK_ALIGN (1ULL << MASK_SHIFT)
#define MASK_LEN_TO_IDX(x) ((x) >> MASK_SHIFT)
#define MASK_LEN_TO_MOD(x) ((x) - RTE_ALIGN_FLOOR(x, MASK_ALIGN))
#define MASK_GET_IDX(idx, mod) ((idx << MASK_SHIFT) + mod)

/*
 * This is a mask that is always stored at the end of array, to provide fast
 * way of finding free/used spots without looping through each element.
 */

struct used_mask {
	unsigned int n_masks;
	uint64_t data[];
};

static size_t
calc_mask_size(unsigned int len)
{
	/* mask must be multiple of MASK_ALIGN, even though length of array
	 * itself may not be aligned on that boundary.
	 */
	len = RTE_ALIGN_CEIL(len, MASK_ALIGN);
	return sizeof(struct used_mask) +
			sizeof(uint64_t) * MASK_LEN_TO_IDX(len);
}

static size_t
calc_data_size(size_t page_sz, unsigned int elt_sz, unsigned int len)
{
	size_t data_sz = elt_sz * len;
	size_t msk_sz = calc_mask_size(len);
	return RTE_ALIGN_CEIL(data_sz + msk_sz, page_sz);
}

static struct used_mask *
get_used_mask(void *data, unsigned int elt_sz, unsigned int len)
{
	return (struct used_mask *) RTE_PTR_ADD(data, elt_sz * len);
}

static int
resize_and_map(int fd, void *addr, size_t len)
{
	char path[PATH_MAX];
	void *map_addr;

	if (ftruncate(fd, len)) {
		RTE_LOG(ERR, EAL, "Cannot truncate %s\n", path);
		/* pass errno up the chain */
		rte_errno = errno;
		return -1;
	}

	map_addr = mmap(addr, len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_FIXED, fd, 0);
	if (map_addr != addr) {
		RTE_LOG(ERR, EAL, "mmap() failed: %s\n", strerror(errno));
		/* pass errno up the chain */
		rte_errno = errno;
		return -1;
	}
	return 0;
}

static int
find_next_n(const struct rte_fbarray *arr, unsigned int start, unsigned int n,
	    bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int msk_idx, lookahead_idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk, ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing ctz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	ignore_msk = ~((1ULL << first_mod) - 1);

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(-1ULL << last_mod);

	for (msk_idx = first; msk_idx < msk->n_masks; msk_idx++) {
		uint64_t cur_msk, lookahead_msk;
		unsigned int run_start, clz, left;
		bool found = false;
		/*
		 * The process of getting n consecutive bits for arbitrary n is
		 * a bit involved, but here it is in a nutshell:
		 *
		 *  1. let n be the number of consecutive bits we're looking for
		 *  2. check if n can fit in one mask, and if so, do n-1
		 *     rshift-ands to see if there is an appropriate run inside
		 *     our current mask
		 *    2a. if we found a run, bail out early
		 *    2b. if we didn't find a run, proceed
		 *  3. invert the mask and count leading zeroes (that is, count
		 *     how many consecutive set bits we had starting from the
		 *     end of current mask) as k
		 *    3a. if k is 0, continue to next mask
		 *    3b. if k is not 0, we have a potential run
		 *  4. to satisfy our requirements, next mask must have n-k
		 *     consecutive set bits right at the start, so we will do
		 *     (n-k-1) rshift-ands and check if first bit is set.
		 *
		 * Step 4 will need to be repeated if (n-k) > MASK_ALIGN until
		 * we either run out of masks, lose the run, or find what we
		 * were looking for.
		 */
		cur_msk = msk->data[msk_idx];
		left = n;

		/* if we're looking for free spaces, invert the mask */
		if (!used)
			cur_msk = ~cur_msk;

		/* combine current ignore mask with last index ignore mask */
		if (msk_idx == last)
			ignore_msk |= last_msk;

		/* if we have an ignore mask, ignore once */
		if (ignore_msk) {
			cur_msk &= ignore_msk;
			ignore_msk = 0;
		}

		/* if n can fit in within a single mask, do a search */
		if (n <= MASK_ALIGN) {
			uint64_t tmp_msk = cur_msk;
			unsigned int s_idx;
			for (s_idx = 0; s_idx < n - 1; s_idx++)
				tmp_msk &= tmp_msk >> 1ULL;
			/* we found what we were looking for */
			if (tmp_msk != 0) {
				run_start = __builtin_ctzll(tmp_msk);
				return MASK_GET_IDX(msk_idx, run_start);
			}
		}

		/*
		 * we didn't find our run within the mask, or n > MASK_ALIGN,
		 * so we're going for plan B.
		 */

		/* count leading zeroes on inverted mask */
		if (~cur_msk == 0)
			clz = sizeof(cur_msk) * 8;
		else
			clz = __builtin_clzll(~cur_msk);

		/* if there aren't any runs at the end either, just continue */
		if (clz == 0)
			continue;

		/* we have a partial run at the end, so try looking ahead */
		run_start = MASK_ALIGN - clz;
		left -= clz;

		for (lookahead_idx = msk_idx + 1; lookahead_idx < msk->n_masks;
				lookahead_idx++) {
			unsigned int s_idx, need;
			lookahead_msk = msk->data[lookahead_idx];

			/* if we're looking for free space, invert the mask */
			if (!used)
				lookahead_msk = ~lookahead_msk;

			/* figure out how many consecutive bits we need here */
			need = RTE_MIN(left, MASK_ALIGN);

			for (s_idx = 0; s_idx < need - 1; s_idx++)
				lookahead_msk &= lookahead_msk >> 1ULL;

			/* if first bit is not set, we've lost the run */
			if ((lookahead_msk & 1) == 0) {
				/*
				 * we've scanned this far, so we know there are
				 * no runs in the space we've lookahead-scanned
				 * as well, so skip that on next iteration.
				 */
				ignore_msk = ~((1ULL << need) - 1);
				msk_idx = lookahead_idx;
				break;
			}

			left -= need;

			/* check if we've found what we were looking for */
			if (left == 0) {
				found = true;
				break;
			}
		}

		/* we didn't find anything, so continue */
		if (!found)
			continue;

		return MASK_GET_IDX(msk_idx, run_start);
	}
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_next(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk, ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing ctz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	ignore_msk = ~((1ULL << first_mod) - 1ULL);

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(-(1ULL) << last_mod);

	for (idx = first; idx < msk->n_masks; idx++) {
		uint64_t cur = msk->data[idx];
		int found;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		if (idx == last)
			cur &= last_msk;

		/* ignore everything before start on first iteration */
		if (idx == first)
			cur &= ignore_msk;

		/* check if we have any entries */
		if (cur == 0)
			continue;

		/*
		 * find first set bit - that will correspond to whatever it is
		 * that we're looking for.
		 */
		found = __builtin_ctzll(cur);
		return MASK_GET_IDX(idx, found);
	}
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_contig(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int last, last_mod;
	uint64_t last_msk;
	unsigned int need_len, result = 0;

	/* array length may not be aligned, so calculate ignore mask for last
	 * mask index.
	 */
	last = MASK_LEN_TO_IDX(arr->len);
	last_mod = MASK_LEN_TO_MOD(arr->len);
	last_msk = ~(-(1ULL) << last_mod);

	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	for (idx = first; idx < msk->n_masks; idx++, result += need_len) {
		uint64_t cur = msk->data[idx];
		unsigned int run_len;

		need_len = MASK_ALIGN;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* if this is last mask, ignore everything after last bit */
		if (idx == last)
			cur &= last_msk;

		/* ignore everything before start on first iteration */
		if (idx == first) {
			cur >>= first_mod;
			/* at the start, we don't need the full mask len */
			need_len -= first_mod;
		}

		/* we will be looking for zeroes, so invert the mask */
		cur = ~cur;

		/* if mask is zero, we have a complete run */
		if (cur == 0)
			continue;

		/*
		 * see if current run ends before mask end.
		 */
		run_len = __builtin_ctzll(cur);

		/* add however many zeroes we've had in the last run and quit */
		if (run_len < need_len) {
			result += run_len;
			break;
		}
	}
	return result;
}

static int
find_prev_n(const struct rte_fbarray *arr, unsigned int start, unsigned int n,
		bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int msk_idx, lookbehind_idx, first, first_mod;
	uint64_t ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing ctz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	/* we're going backwards, so mask must start from the top */
	ignore_msk = first_mod == MASK_ALIGN - 1 ?
				-1ULL : /* prevent overflow */
				~(-1ULL << (first_mod + 1));

	/* go backwards, include zero */
	msk_idx = first;
	do {
		uint64_t cur_msk, lookbehind_msk;
		unsigned int run_start, run_end, ctz, left;
		bool found = false;
		/*
		 * The process of getting n consecutive bits from the top for
		 * arbitrary n is a bit involved, but here it is in a nutshell:
		 *
		 *  1. let n be the number of consecutive bits we're looking for
		 *  2. check if n can fit in one mask, and if so, do n-1
		 *     lshift-ands to see if there is an appropriate run inside
		 *     our current mask
		 *    2a. if we found a run, bail out early
		 *    2b. if we didn't find a run, proceed
		 *  3. invert the mask and count trailing zeroes (that is, count
		 *     how many consecutive set bits we had starting from the
		 *     start of current mask) as k
		 *    3a. if k is 0, continue to next mask
		 *    3b. if k is not 0, we have a potential run
		 *  4. to satisfy our requirements, next mask must have n-k
		 *     consecutive set bits at the end, so we will do (n-k-1)
		 *     lshift-ands and check if last bit is set.
		 *
		 * Step 4 will need to be repeated if (n-k) > MASK_ALIGN until
		 * we either run out of masks, lose the run, or find what we
		 * were looking for.
		 */
		cur_msk = msk->data[msk_idx];
		left = n;

		/* if we're looking for free spaces, invert the mask */
		if (!used)
			cur_msk = ~cur_msk;

		/* if we have an ignore mask, ignore once */
		if (ignore_msk) {
			cur_msk &= ignore_msk;
			ignore_msk = 0;
		}

		/* if n can fit in within a single mask, do a search */
		if (n <= MASK_ALIGN) {
			uint64_t tmp_msk = cur_msk;
			unsigned int s_idx;
			for (s_idx = 0; s_idx < n - 1; s_idx++)
				tmp_msk &= tmp_msk << 1ULL;
			/* we found what we were looking for */
			if (tmp_msk != 0) {
				/* clz will give us offset from end of mask, and
				 * we only get the end of our run, not start,
				 * so adjust result to point to where start
				 * would have been.
				 */
				run_start = MASK_ALIGN -
						__builtin_clzll(tmp_msk) - n;
				return MASK_GET_IDX(msk_idx, run_start);
			}
		}

		/*
		 * we didn't find our run within the mask, or n > MASK_ALIGN,
		 * so we're going for plan B.
		 */

		/* count trailing zeroes on inverted mask */
		if (~cur_msk == 0)
			ctz = sizeof(cur_msk) * 8;
		else
			ctz = __builtin_ctzll(~cur_msk);

		/* if there aren't any runs at the start either, just
		 * continue
		 */
		if (ctz == 0)
			continue;

		/* we have a partial run at the start, so try looking behind */
		run_end = MASK_GET_IDX(msk_idx, ctz);
		left -= ctz;

		/* go backwards, include zero */
		lookbehind_idx = msk_idx - 1;

		/* we can't lookbehind as we've run out of masks, so stop */
		if (msk_idx == 0)
			break;

		do {
			const uint64_t last_bit = 1ULL << (MASK_ALIGN - 1);
			unsigned int s_idx, need;

			lookbehind_msk = msk->data[lookbehind_idx];

			/* if we're looking for free space, invert the mask */
			if (!used)
				lookbehind_msk = ~lookbehind_msk;

			/* figure out how many consecutive bits we need here */
			need = RTE_MIN(left, MASK_ALIGN);

			for (s_idx = 0; s_idx < need - 1; s_idx++)
				lookbehind_msk &= lookbehind_msk << 1ULL;

			/* if last bit is not set, we've lost the run */
			if ((lookbehind_msk & last_bit) == 0) {
				/*
				 * we've scanned this far, so we know there are
				 * no runs in the space we've lookbehind-scanned
				 * as well, so skip that on next iteration.
				 */
				ignore_msk = -1ULL << need;
				msk_idx = lookbehind_idx;
				break;
			}

			left -= need;

			/* check if we've found what we were looking for */
			if (left == 0) {
				found = true;
				break;
			}
		} while ((lookbehind_idx--) != 0); /* decrement after check to
						    * include zero
						    */

		/* we didn't find anything, so continue */
		if (!found)
			continue;

		/* we've found what we were looking for, but we only know where
		 * the run ended, so calculate start position.
		 */
		return run_end - n;
	} while (msk_idx-- != 0); /* decrement after check to include zero */
	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_prev(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	uint64_t ignore_msk;

	/*
	 * mask only has granularity of MASK_ALIGN, but start may not be aligned
	 * on that boundary, so construct a special mask to exclude anything we
	 * don't want to see to avoid confusing clz.
	 */
	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);
	/* we're going backwards, so mask must start from the top */
	ignore_msk = first_mod == MASK_ALIGN - 1 ?
				-1ULL : /* prevent overflow */
				~(-1ULL << (first_mod + 1));

	/* go backwards, include zero */
	idx = first;
	do {
		uint64_t cur = msk->data[idx];
		int found;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* ignore everything before start on first iteration */
		if (idx == first)
			cur &= ignore_msk;

		/* check if we have any entries */
		if (cur == 0)
			continue;

		/*
		 * find last set bit - that will correspond to whatever it is
		 * that we're looking for. we're counting trailing zeroes, thus
		 * the value we get is counted from end of mask, so calculate
		 * position from start of mask.
		 */
		found = MASK_ALIGN - __builtin_clzll(cur) - 1;

		return MASK_GET_IDX(idx, found);
	} while (idx-- != 0); /* decrement after check  to include zero*/

	/* we didn't find anything */
	rte_errno = used ? ENOENT : ENOSPC;
	return -1;
}

static int
find_rev_contig(const struct rte_fbarray *arr, unsigned int start, bool used)
{
	const struct used_mask *msk = get_used_mask(arr->data, arr->elt_sz,
			arr->len);
	unsigned int idx, first, first_mod;
	unsigned int need_len, result = 0;

	first = MASK_LEN_TO_IDX(start);
	first_mod = MASK_LEN_TO_MOD(start);

	/* go backwards, include zero */
	idx = first;
	do {
		uint64_t cur = msk->data[idx];
		unsigned int run_len;

		need_len = MASK_ALIGN;

		/* if we're looking for free entries, invert mask */
		if (!used)
			cur = ~cur;

		/* ignore everything after start on first iteration */
		if (idx == first) {
			unsigned int end_len = MASK_ALIGN - first_mod - 1;
			cur <<= end_len;
			/* at the start, we don't need the full mask len */
			need_len -= end_len;
		}

		/* we will be looking for zeroes, so invert the mask */
		cur = ~cur;

		/* if mask is zero, we have a complete run */
		if (cur == 0)
			goto endloop;

		/*
		 * see where run ends, starting from the end.
		 */
		run_len = __builtin_clzll(cur);

		/* add however many zeroes we've had in the last run and quit */
		if (run_len < need_len) {
			result += run_len;
			break;
		}
endloop:
		result += need_len;
	} while (idx-- != 0); /* decrement after check to include zero */
	return result;
}

static int
set_used(struct rte_fbarray *arr, unsigned int idx, bool used)
{
	struct used_mask *msk;
	uint64_t msk_bit = 1ULL << MASK_LEN_TO_MOD(idx);
	unsigned int msk_idx = MASK_LEN_TO_IDX(idx);
	bool already_used;
	int ret = -1;

	if (arr == NULL || idx >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}
	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);
	ret = 0;

	/* prevent array from changing under us */
	rte_rwlock_write_lock(&arr->rwlock);

	already_used = (msk->data[msk_idx] & msk_bit) != 0;

	/* nothing to be done */
	if (used == already_used)
		goto out;

	if (used) {
		msk->data[msk_idx] |= msk_bit;
		arr->count++;
	} else {
		msk->data[msk_idx] &= ~msk_bit;
		arr->count--;
	}
out:
	rte_rwlock_write_unlock(&arr->rwlock);

	return ret;
}

static int
fully_validate(const char *name, unsigned int elt_sz, unsigned int len)
{
	if (name == NULL || elt_sz == 0 || len == 0 || len > INT_MAX) {
		rte_errno = EINVAL;
		return -1;
	}

	if (strnlen(name, RTE_FBARRAY_NAME_LEN) == RTE_FBARRAY_NAME_LEN) {
		rte_errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

int __rte_experimental
rte_fbarray_init(struct rte_fbarray *arr, const char *name, unsigned int len,
		unsigned int elt_sz)
{
	size_t page_sz, mmap_len;
	char path[PATH_MAX];
	struct used_mask *msk;
	void *data = NULL;
	int fd = -1;

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	if (fully_validate(name, elt_sz, len))
		return -1;

	page_sz = sysconf(_SC_PAGESIZE);
	if (page_sz == (size_t)-1)
		goto fail;

	/* calculate our memory limits */
	mmap_len = calc_data_size(page_sz, elt_sz, len);

	data = eal_get_virtual_area(NULL, &mmap_len, page_sz, 0, 0);
	if (data == NULL)
		goto fail;

	if (internal_config.no_shconf) {
		/* remap virtual area as writable */
		void *new_data = mmap(data, mmap_len, PROT_READ | PROT_WRITE,
				MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (new_data == MAP_FAILED) {
			RTE_LOG(DEBUG, EAL, "%s(): couldn't remap anonymous memory: %s\n",
					__func__, strerror(errno));
			goto fail;
		}
	} else {
		eal_get_fbarray_path(path, sizeof(path), name);

		/*
		 * Each fbarray is unique to process namespace, i.e. the
		 * filename depends on process prefix. Try to take out a lock
		 * and see if we succeed. If we don't, someone else is using it
		 * already.
		 */
		fd = open(path, O_CREAT | O_RDWR, 0600);
		if (fd < 0) {
			RTE_LOG(DEBUG, EAL, "%s(): couldn't open %s: %s\n",
					__func__, path, strerror(errno));
			rte_errno = errno;
			goto fail;
		} else if (flock(fd, LOCK_EX | LOCK_NB)) {
			RTE_LOG(DEBUG, EAL, "%s(): couldn't lock %s: %s\n",
					__func__, path, strerror(errno));
			rte_errno = EBUSY;
			goto fail;
		}

		/* take out a non-exclusive lock, so that other processes could
		 * still attach to it, but no other process could reinitialize
		 * it.
		 */
		if (flock(fd, LOCK_SH | LOCK_NB)) {
			rte_errno = errno;
			goto fail;
		}

		if (resize_and_map(fd, data, mmap_len))
			goto fail;

		/* we've mmap'ed the file, we can now close the fd */
		close(fd);
	}

	/* initialize the data */
	memset(data, 0, mmap_len);

	/* populate data structure */
	strlcpy(arr->name, name, sizeof(arr->name));
	arr->data = data;
	arr->len = len;
	arr->elt_sz = elt_sz;
	arr->count = 0;

	msk = get_used_mask(data, elt_sz, len);
	msk->n_masks = MASK_LEN_TO_IDX(RTE_ALIGN_CEIL(len, MASK_ALIGN));

	rte_rwlock_init(&arr->rwlock);

	return 0;
fail:
	if (data)
		munmap(data, mmap_len);
	if (fd >= 0)
		close(fd);
	return -1;
}

int __rte_experimental
rte_fbarray_attach(struct rte_fbarray *arr)
{
	size_t page_sz, mmap_len;
	char path[PATH_MAX];
	void *data = NULL;
	int fd = -1;

	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	/*
	 * we don't need to synchronize attach as two values we need (element
	 * size and array length) are constant for the duration of life of
	 * the array, so the parts we care about will not race.
	 */

	if (fully_validate(arr->name, arr->elt_sz, arr->len))
		return -1;

	page_sz = sysconf(_SC_PAGESIZE);
	if (page_sz == (size_t)-1)
		goto fail;

	mmap_len = calc_data_size(page_sz, arr->elt_sz, arr->len);

	data = eal_get_virtual_area(arr->data, &mmap_len, page_sz, 0, 0);
	if (data == NULL)
		goto fail;

	eal_get_fbarray_path(path, sizeof(path), arr->name);

	fd = open(path, O_RDWR);
	if (fd < 0) {
		rte_errno = errno;
		goto fail;
	}

	/* lock the file, to let others know we're using it */
	if (flock(fd, LOCK_SH | LOCK_NB)) {
		rte_errno = errno;
		goto fail;
	}

	if (resize_and_map(fd, data, mmap_len))
		goto fail;

	close(fd);

	/* we're done */

	return 0;
fail:
	if (data)
		munmap(data, mmap_len);
	if (fd >= 0)
		close(fd);
	return -1;
}

int __rte_experimental
rte_fbarray_detach(struct rte_fbarray *arr)
{
	if (arr == NULL) {
		rte_errno = EINVAL;
		return -1;
	}

	/*
	 * we don't need to synchronize detach as two values we need (element
	 * size and total capacity) are constant for the duration of life of
	 * the array, so the parts we care about will not race. if the user is
	 * detaching while doing something else in the same process, we can't
	 * really do anything about it, things will blow up either way.
	 */

	size_t page_sz = sysconf(_SC_PAGESIZE);

	if (page_sz == (size_t)-1)
		return -1;

	/* this may already be unmapped (e.g. repeated call from previously
	 * failed destroy(), but this is on user, we can't (easily) know if this
	 * is still mapped.
	 */
	munmap(arr->data, calc_data_size(page_sz, arr->elt_sz, arr->len));

	return 0;
}

int __rte_experimental
rte_fbarray_destroy(struct rte_fbarray *arr)
{
	int fd, ret;
	char path[PATH_MAX];

	ret = rte_fbarray_detach(arr);
	if (ret)
		return ret;

	/* with no shconf, there were never any files to begin with */
	if (internal_config.no_shconf)
		return 0;

	/* try deleting the file */
	eal_get_fbarray_path(path, sizeof(path), arr->name);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		RTE_LOG(ERR, EAL, "Could not open fbarray file: %s\n",
			strerror(errno));
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB)) {
		RTE_LOG(DEBUG, EAL, "Cannot destroy fbarray - another process is using it\n");
		rte_errno = EBUSY;
		ret = -1;
	} else {
		ret = 0;
		unlink(path);
		memset(arr, 0, sizeof(*arr));
	}
	close(fd);

	return ret;
}

void * __rte_experimental
rte_fbarray_get(const struct rte_fbarray *arr, unsigned int idx)
{
	void *ret = NULL;
	if (arr == NULL) {
		rte_errno = EINVAL;
		return NULL;
	}

	if (idx >= arr->len) {
		rte_errno = EINVAL;
		return NULL;
	}

	ret = RTE_PTR_ADD(arr->data, idx * arr->elt_sz);

	return ret;
}

int __rte_experimental
rte_fbarray_set_used(struct rte_fbarray *arr, unsigned int idx)
{
	return set_used(arr, idx, true);
}

int __rte_experimental
rte_fbarray_set_free(struct rte_fbarray *arr, unsigned int idx)
{
	return set_used(arr, idx, false);
}

int __rte_experimental
rte_fbarray_is_used(struct rte_fbarray *arr, unsigned int idx)
{
	struct used_mask *msk;
	int msk_idx;
	uint64_t msk_bit;
	int ret = -1;

	if (arr == NULL || idx >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);
	msk_idx = MASK_LEN_TO_IDX(idx);
	msk_bit = 1ULL << MASK_LEN_TO_MOD(idx);

	ret = (msk->data[msk_idx] & msk_bit) != 0;

	rte_rwlock_read_unlock(&arr->rwlock);

	return ret;
}

static int
fbarray_find(struct rte_fbarray *arr, unsigned int start, bool next, bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (!used) {
		if (arr->len == arr->count) {
			rte_errno = ENOSPC;
			goto out;
		}
		if (arr->count == 0) {
			ret = start;
			goto out;
		}
	} else {
		if (arr->count == 0) {
			rte_errno = ENOENT;
			goto out;
		}
		if (arr->len == arr->count) {
			ret = start;
			goto out;
		}
	}
	if (next)
		ret = find_next(arr, start, used);
	else
		ret = find_prev(arr, start, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

int __rte_experimental
rte_fbarray_find_next_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, true, false);
}

int __rte_experimental
rte_fbarray_find_next_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, true, true);
}

int __rte_experimental
rte_fbarray_find_prev_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, false, false);
}

int __rte_experimental
rte_fbarray_find_prev_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find(arr, start, false, true);
}

static int
fbarray_find_n(struct rte_fbarray *arr, unsigned int start, unsigned int n,
		bool next, bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len || n > arr->len || n == 0) {
		rte_errno = EINVAL;
		return -1;
	}
	if (next && (arr->len - start) < n) {
		rte_errno = used ? ENOENT : ENOSPC;
		return -1;
	}
	if (!next && start < (n - 1)) {
		rte_errno = used ? ENOENT : ENOSPC;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (!used) {
		if (arr->len == arr->count || arr->len - arr->count < n) {
			rte_errno = ENOSPC;
			goto out;
		}
		if (arr->count == 0) {
			ret = next ? start : start - n + 1;
			goto out;
		}
	} else {
		if (arr->count < n) {
			rte_errno = ENOENT;
			goto out;
		}
		if (arr->count == arr->len) {
			ret = next ? start : start - n + 1;
			goto out;
		}
	}

	if (next)
		ret = find_next_n(arr, start, n, used);
	else
		ret = find_prev_n(arr, start, n, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

int __rte_experimental
rte_fbarray_find_next_n_free(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, true, false);
}

int __rte_experimental
rte_fbarray_find_next_n_used(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, true, true);
}

int __rte_experimental
rte_fbarray_find_prev_n_free(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, false, false);
}

int __rte_experimental
rte_fbarray_find_prev_n_used(struct rte_fbarray *arr, unsigned int start,
		unsigned int n)
{
	return fbarray_find_n(arr, start, n, false, true);
}

static int
fbarray_find_contig(struct rte_fbarray *arr, unsigned int start, bool next,
		bool used)
{
	int ret = -1;

	if (arr == NULL || start >= arr->len) {
		rte_errno = EINVAL;
		return -1;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	/* cheap checks to prevent doing useless work */
	if (used) {
		if (arr->count == 0) {
			ret = 0;
			goto out;
		}
		if (next && arr->count == arr->len) {
			ret = arr->len - start;
			goto out;
		}
		if (!next && arr->count == arr->len) {
			ret = start + 1;
			goto out;
		}
	} else {
		if (arr->len == arr->count) {
			ret = 0;
			goto out;
		}
		if (next && arr->count == 0) {
			ret = arr->len - start;
			goto out;
		}
		if (!next && arr->count == 0) {
			ret = start + 1;
			goto out;
		}
	}

	if (next)
		ret = find_contig(arr, start, used);
	else
		ret = find_rev_contig(arr, start, used);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
	return ret;
}

int __rte_experimental
rte_fbarray_find_contig_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, true, false);
}

int __rte_experimental
rte_fbarray_find_contig_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, true, true);
}

int __rte_experimental
rte_fbarray_find_rev_contig_free(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, false, false);
}

int __rte_experimental
rte_fbarray_find_rev_contig_used(struct rte_fbarray *arr, unsigned int start)
{
	return fbarray_find_contig(arr, start, false, true);
}

int __rte_experimental
rte_fbarray_find_idx(const struct rte_fbarray *arr, const void *elt)
{
	void *end;
	int ret = -1;

	/*
	 * no need to synchronize as it doesn't matter if underlying data
	 * changes - we're doing pointer arithmetic here.
	 */

	if (arr == NULL || elt == NULL) {
		rte_errno = EINVAL;
		return -1;
	}
	end = RTE_PTR_ADD(arr->data, arr->elt_sz * arr->len);
	if (elt < arr->data || elt >= end) {
		rte_errno = EINVAL;
		return -1;
	}

	ret = RTE_PTR_DIFF(elt, arr->data) / arr->elt_sz;

	return ret;
}

void __rte_experimental
rte_fbarray_dump_metadata(struct rte_fbarray *arr, FILE *f)
{
	struct used_mask *msk;
	unsigned int i;

	if (arr == NULL || f == NULL) {
		rte_errno = EINVAL;
		return;
	}

	if (fully_validate(arr->name, arr->elt_sz, arr->len)) {
		fprintf(f, "Invalid file-backed array\n");
		goto out;
	}

	/* prevent array from changing under us */
	rte_rwlock_read_lock(&arr->rwlock);

	fprintf(f, "File-backed array: %s\n", arr->name);
	fprintf(f, "size: %i occupied: %i elt_sz: %i\n",
			arr->len, arr->count, arr->elt_sz);

	msk = get_used_mask(arr->data, arr->elt_sz, arr->len);

	for (i = 0; i < msk->n_masks; i++)
		fprintf(f, "msk idx %i: 0x%016" PRIx64 "\n", i, msk->data[i]);
out:
	rte_rwlock_read_unlock(&arr->rwlock);
}
