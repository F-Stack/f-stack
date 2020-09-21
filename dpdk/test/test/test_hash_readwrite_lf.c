/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Arm Limited
 */

#include <inttypes.h>
#include <locale.h>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_launch.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_spinlock.h>

#include "test.h"

#ifndef RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
#define RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF 0
#endif

#define BULK_LOOKUP_SIZE 32

#define RUN_WITH_HTM_DISABLED 0

#if (RUN_WITH_HTM_DISABLED)

#define TOTAL_ENTRY (5*1024)
#define TOTAL_INSERT (5*1024)

#else

#define TOTAL_ENTRY (4*1024*1024)
#define TOTAL_INSERT (4*1024*1024)

#endif

#define READ_FAIL 1
#define READ_PASS_NO_KEY_SHIFTS 2
#define READ_PASS_SHIFT_PATH 4
#define READ_PASS_NON_SHIFT_PATH 8
#define BULK_LOOKUP 16
#define NUM_TEST 3
unsigned int rwc_core_cnt[NUM_TEST] = {1, 2, 4};

struct rwc_perf {
	uint32_t w_no_ks_r_hit[2][NUM_TEST];
	uint32_t w_no_ks_r_miss[2][NUM_TEST];
	uint32_t w_ks_r_hit_nsp[2][NUM_TEST];
	uint32_t w_ks_r_hit_sp[2][NUM_TEST];
	uint32_t w_ks_r_miss[2][NUM_TEST];
	uint32_t multi_rw[NUM_TEST - 1][2][NUM_TEST];
};

static struct rwc_perf rwc_lf_results, rwc_non_lf_results;

struct {
	uint32_t *keys;
	uint32_t *keys_no_ks;
	uint32_t *keys_ks;
	uint32_t *keys_absent;
	uint32_t *keys_shift_path;
	uint32_t *keys_non_shift_path;
	uint32_t count_keys_no_ks;
	uint32_t count_keys_ks;
	uint32_t count_keys_absent;
	uint32_t count_keys_shift_path;
	uint32_t count_keys_non_shift_path;
	uint32_t single_insert;
	struct rte_hash *h;
} tbl_rwc_test_param;

static rte_atomic64_t gread_cycles;
static rte_atomic64_t greads;

static volatile uint8_t writer_done;

uint16_t enabled_core_ids[RTE_MAX_LCORE];

uint8_t *scanned_bkts;

static inline int
get_enabled_cores_list(void)
{
	uint32_t i = 0;
	uint16_t core_id;
	uint32_t max_cores = rte_lcore_count();
	RTE_LCORE_FOREACH(core_id) {
		enabled_core_ids[i] = core_id;
		i++;
	}

	if (i != max_cores) {
		printf("Number of enabled cores in list is different from "
			"number given by rte_lcore_count()\n");
		return -1;
	}
	return 0;
}

static inline int
check_bucket(uint32_t bkt_idx, uint32_t key)
{
	uint32_t iter;
	uint32_t prev_iter;
	uint32_t diff;
	uint32_t count = 0;
	const void *next_key;
	void *next_data;

	/* Temporary bucket to hold the keys */
	uint32_t keys_in_bkt[8];

	iter = bkt_idx * 8;
	prev_iter = iter;
	while (rte_hash_iterate(tbl_rwc_test_param.h,
			&next_key, &next_data, &iter) >= 0) {

		/* Check for duplicate entries */
		if (*(const uint32_t *)next_key == key)
			return 1;

		/* Identify if there is any free entry in the bucket */
		diff = iter - prev_iter;
		if (diff > 1)
			break;

		prev_iter = iter;
		keys_in_bkt[count] = *(const uint32_t *)next_key;
		count++;

		/* All entries in the bucket are occupied */
		if (count == 8) {

			/*
			 * Check if bucket was not scanned before, to avoid
			 * duplicate keys.
			 */
			if (scanned_bkts[bkt_idx] == 0) {
				/*
				 * Since this bucket (pointed to by bkt_idx) is
				 * full, it is likely that key(s) in this
				 * bucket will be on the shift path, when
				 * collision occurs. Thus, add it to
				 * keys_shift_path.
				 */
				memcpy(tbl_rwc_test_param.keys_shift_path +
					tbl_rwc_test_param.count_keys_shift_path
					, keys_in_bkt, 32);
				tbl_rwc_test_param.count_keys_shift_path += 8;
				scanned_bkts[bkt_idx] = 1;
			}
			return -1;
		}
	}
	return 0;
}

static int
generate_keys(void)
{
	uint32_t *keys = NULL;
	uint32_t *keys_no_ks = NULL;
	uint32_t *keys_ks = NULL;
	uint32_t *keys_absent = NULL;
	uint32_t *keys_non_shift_path = NULL;
	uint32_t *found = NULL;
	uint32_t count_keys_no_ks = 0;
	uint32_t count_keys_ks = 0;
	uint32_t i;

	/*
	 * keys will consist of a) keys whose addition to the hash table
	 * will result in shifting of the existing keys to their alternate
	 * locations b) keys whose addition to the hash table will not result
	 * in shifting of the existing keys.
	 */
	keys = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_INSERT, 0);
	if (keys == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/*
	 * keys_no_ks (no key-shifts): Subset of 'keys' - consists of keys  that
	 * will NOT result in shifting of the existing keys to their alternate
	 * locations. Roughly around 900K keys.
	 */
	keys_no_ks = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_INSERT, 0);
	if (keys_no_ks == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/*
	 * keys_ks (key-shifts): Subset of 'keys' - consists of keys that will
	 * result in shifting of the existing keys to their alternate locations.
	 * Roughly around 146K keys. There might be repeating keys. More code is
	 * required to filter out these keys which will complicate the test case
	 */
	keys_ks = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_INSERT, 0);
	if (keys_ks == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/* Used to identify keys not inserted in the hash table */
	found = rte_zmalloc(NULL, sizeof(uint32_t) * TOTAL_INSERT, 0);
	if (found == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/*
	 * This consist of keys not inserted to the hash table.
	 * Used to test perf of lookup on keys that do not exist in the table.
	 */
	keys_absent = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_INSERT, 0);
	if (keys_absent == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/*
	 * This consist of keys which are likely to be on the shift
	 * path (i.e. being moved to alternate location), when collision occurs
	 * on addition of a key to an already full primary bucket.
	 * Used to test perf of lookup on keys that are on the shift path.
	 */
	tbl_rwc_test_param.keys_shift_path = rte_malloc(NULL, sizeof(uint32_t) *
							TOTAL_INSERT, 0);
	if (tbl_rwc_test_param.keys_shift_path == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	/*
	 * This consist of keys which are never on the shift
	 * path (i.e. being moved to alternate location), when collision occurs
	 * on addition of a key to an already full primary bucket.
	 * Used to test perf of lookup on keys that are not on the shift path.
	 */
	keys_non_shift_path = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_INSERT,
					 0);
	if (keys_non_shift_path == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}


	hash_sig_t sig;
	uint32_t prim_bucket_idx;
	int ret;
	uint32_t num_buckets;
	uint32_t bucket_bitmask;
	num_buckets  = rte_align32pow2(TOTAL_ENTRY) / 8;
	bucket_bitmask = num_buckets - 1;

	/*
	 * Used to mark bkts in which at least one key was shifted to its
	 * alternate location
	 */
	scanned_bkts = rte_malloc(NULL, sizeof(uint8_t) * num_buckets, 0);
	if (scanned_bkts == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	tbl_rwc_test_param.keys = keys;
	tbl_rwc_test_param.keys_no_ks = keys_no_ks;
	tbl_rwc_test_param.keys_ks = keys_ks;
	tbl_rwc_test_param.keys_absent = keys_absent;
	tbl_rwc_test_param.keys_non_shift_path = keys_non_shift_path;
	/* Generate keys by adding previous two keys, neglect overflow */
	printf("Generating keys...\n");
	keys[0] = 0;
	keys[1] = 1;
	for (i = 2; i < TOTAL_INSERT; i++)
		keys[i] = keys[i-1] + keys[i-2];

	/* Segregate keys into keys_no_ks and keys_ks */
	for (i = 0; i < TOTAL_INSERT; i++) {
		/* Check if primary bucket has space.*/
		sig = rte_hash_hash(tbl_rwc_test_param.h,
					tbl_rwc_test_param.keys+i);
		prim_bucket_idx = sig & bucket_bitmask;
		ret = check_bucket(prim_bucket_idx, keys[i]);
		if (ret < 0) {
			/*
			 * Primary bucket is full, this key will result in
			 * shifting of the keys to their alternate locations.
			 */
			keys_ks[count_keys_ks] = keys[i];
			count_keys_ks++;
		} else if (ret == 0) {
			/*
			 * Primary bucket has space, this key will not result in
			 * shifting of the keys. Hence, add key to the table.
			 */
			ret = rte_hash_add_key_data(tbl_rwc_test_param.h,
							keys+i,
							(void *)((uintptr_t)i));
			if (ret < 0) {
				printf("writer failed %"PRIu32"\n", i);
				break;
			}
			keys_no_ks[count_keys_no_ks] = keys[i];
			count_keys_no_ks++;
		}
	}

	for (i = 0; i < count_keys_no_ks; i++) {
		/*
		 * Identify keys in keys_no_ks with value less than
		 * 4M (HTM enabled) OR 5K (HTM disabled)
		 */
		if (keys_no_ks[i] < TOTAL_INSERT)
			found[keys_no_ks[i]]++;
	}

	for (i = 0; i < count_keys_ks; i++) {
		/*
		 * Identify keys in keys_ks with value less than
		 * 4M (HTM enabled) OR 5K (HTM disabled)
		 */
		if (keys_ks[i] < TOTAL_INSERT)
			found[keys_ks[i]]++;
	}

	uint32_t count_keys_absent = 0;
	for (i = 0; i < TOTAL_INSERT; i++) {
		/*
		 * Identify missing keys between 0 and
		 * 4M (HTM enabled) OR 5K (HTM disabled)
		 */
		if (found[i] == 0)
			keys_absent[count_keys_absent++] = i;
	}

	/* Find keys that will not be on the shift path */
	uint32_t iter;
	const void *next_key;
	void *next_data;
	uint32_t count = 0;
	for (i = 0; i < num_buckets; i++) {
		/* Check bucket for no keys shifted to alternate locations */
		if (scanned_bkts[i] == 0) {
			iter = i * 8;
			while (rte_hash_iterate(tbl_rwc_test_param.h,
				&next_key, &next_data, &iter) >= 0) {

				/* Check if key belongs to the current bucket */
				if (i >= (iter-1)/8)
					keys_non_shift_path[count++]
						= *(const uint32_t *)next_key;
				else
					break;
			}
		}
	}

	tbl_rwc_test_param.count_keys_no_ks = count_keys_no_ks;
	tbl_rwc_test_param.count_keys_ks = count_keys_ks;
	tbl_rwc_test_param.count_keys_absent = count_keys_absent;
	tbl_rwc_test_param.count_keys_non_shift_path = count;

	printf("\nCount of keys NOT causing shifting of existing keys to "
	"alternate location: %d\n", tbl_rwc_test_param.count_keys_no_ks);
	printf("\nCount of keys causing shifting of existing keys to alternate "
		"locations: %d\n\n", tbl_rwc_test_param.count_keys_ks);
	printf("Count of absent keys that will never be added to the hash "
		"table: %d\n\n", tbl_rwc_test_param.count_keys_absent);
	printf("Count of keys likely to be on the shift path: %d\n\n",
	       tbl_rwc_test_param.count_keys_shift_path);
	printf("Count of keys not likely to be on the shift path: %d\n\n",
	       tbl_rwc_test_param.count_keys_non_shift_path);

	rte_free(found);
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_free(keys);
	rte_free(keys_no_ks);
	rte_free(keys_ks);
	rte_free(keys_absent);
	rte_free(found);
	rte_free(tbl_rwc_test_param.keys_shift_path);
	rte_free(scanned_bkts);
	return -1;
}

static int
init_params(int rwc_lf, int use_jhash, int htm)
{
	struct rte_hash *handle;

	struct rte_hash_parameters hash_params = {
		.entries = TOTAL_ENTRY,
		.key_len = sizeof(uint32_t),
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	if (use_jhash)
		hash_params.hash_func = rte_jhash;
	else
		hash_params.hash_func = rte_hash_crc;

	if (rwc_lf)
		hash_params.extra_flag =
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF |
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
	else if (htm)
		hash_params.extra_flag =
			RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
	else
		hash_params.extra_flag =
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;

	hash_params.name = "tests";

	handle = rte_hash_create(&hash_params);
	if (handle == NULL) {
		printf("hash creation failed");
		return -1;
	}

	tbl_rwc_test_param.h = handle;
	return 0;
}

static int
test_rwc_reader(__attribute__((unused)) void *arg)
{
	uint32_t i, j;
	int ret;
	uint64_t begin, cycles;
	uint32_t loop_cnt = 0;
	uint8_t read_type = (uint8_t)((uintptr_t)arg);
	uint32_t read_cnt;
	uint32_t *keys;
	uint32_t extra_keys;
	int32_t *pos;
	void *temp_a[BULK_LOOKUP_SIZE];

	/* Used to identify keys not inserted in the hash table */
	pos = rte_zmalloc(NULL, sizeof(uint32_t) * BULK_LOOKUP_SIZE, 0);
	if (pos == NULL) {
		printf("RTE_MALLOC failed\n");
		return -1;
	}

	if (read_type & READ_FAIL) {
		keys = tbl_rwc_test_param.keys_absent;
		read_cnt = tbl_rwc_test_param.count_keys_absent;
	} else if (read_type & READ_PASS_NO_KEY_SHIFTS) {
		keys = tbl_rwc_test_param.keys_no_ks;
		read_cnt = tbl_rwc_test_param.count_keys_no_ks;
	} else if (read_type & READ_PASS_SHIFT_PATH) {
		keys = tbl_rwc_test_param.keys_shift_path;
		read_cnt = tbl_rwc_test_param.count_keys_shift_path;
	} else {
		keys = tbl_rwc_test_param.keys_non_shift_path;
		read_cnt = tbl_rwc_test_param.count_keys_non_shift_path;
	}

	extra_keys = read_cnt & (BULK_LOOKUP_SIZE - 1);

	begin = rte_rdtsc_precise();
	do {
		if (read_type & BULK_LOOKUP) {
			for (i = 0; i < (read_cnt - extra_keys);
			     i += BULK_LOOKUP_SIZE) {
				/* Array of  pointer to the list of keys */
				for (j = 0; j < BULK_LOOKUP_SIZE; j++)
					temp_a[j] = keys + i + j;

				rte_hash_lookup_bulk(tbl_rwc_test_param.h,
						   (const void **)
						   ((uintptr_t)temp_a),
						   BULK_LOOKUP_SIZE, pos);
				/* Validate lookup result */
				for (j = 0; j < BULK_LOOKUP_SIZE; j++)
					if ((read_type & READ_FAIL &&
					     pos[j] != -ENOENT) ||
					    (!(read_type & READ_FAIL) &&
					     pos[j] == -ENOENT)) {
						printf("lookup failed!"
						       "%"PRIu32"\n",
						       keys[i + j]);
						return -1;
					}
			}
			for (j = 0; j < extra_keys; j++)
				temp_a[j] = keys + i + j;

			rte_hash_lookup_bulk(tbl_rwc_test_param.h,
					   (const void **)
					   ((uintptr_t)temp_a),
					   extra_keys, pos);
			for (j = 0; j < extra_keys; j++)
				if ((read_type & READ_FAIL &&
				     pos[j] != -ENOENT) ||
				    (!(read_type & READ_FAIL) &&
				     pos[j] == -ENOENT)) {
					printf("lookup failed! %"PRIu32"\n",
					       keys[i + j]);
					return -1;
				}
		} else {
			for (i = 0; i < read_cnt; i++) {
				ret = rte_hash_lookup
					(tbl_rwc_test_param.h, keys + i);
				if (((read_type & READ_FAIL) &&
				     (ret != -ENOENT)) ||
				    (!(read_type & READ_FAIL) &&
					ret == -ENOENT)) {
					printf("lookup failed! %"PRIu32"\n",
					       keys[i]);
					return -1;
				}
			}
		}
		loop_cnt++;
	} while (!writer_done);

	cycles = rte_rdtsc_precise() - begin;
	rte_atomic64_add(&gread_cycles, cycles);
	rte_atomic64_add(&greads, read_cnt*loop_cnt);
	return 0;
}

static int
write_keys(uint8_t key_shift)
{
	uint32_t i;
	int ret;
	uint32_t key_cnt;
	uint32_t *keys;
	if (key_shift) {
		key_cnt = tbl_rwc_test_param.count_keys_ks;
		keys = tbl_rwc_test_param.keys_ks;
	} else {
		key_cnt = tbl_rwc_test_param.count_keys_no_ks;
		keys = tbl_rwc_test_param.keys_no_ks;
	}
	for (i = 0; i < key_cnt; i++) {
		ret = rte_hash_add_key(tbl_rwc_test_param.h, keys + i);
		if (!key_shift && ret < 0) {
			printf("writer failed %"PRIu32"\n", i);
			return -1;
		}
	}
	return 0;
}

static int
test_rwc_multi_writer(__attribute__((unused)) void *arg)
{
	uint32_t i, offset;
	uint32_t pos_core = (uint32_t)((uintptr_t)arg);
	offset = pos_core * tbl_rwc_test_param.single_insert;
	for (i = offset; i < offset + tbl_rwc_test_param.single_insert; i++)
		rte_hash_add_key(tbl_rwc_test_param.h,
				 tbl_rwc_test_param.keys_ks + i);
	return 0;
}

/*
 * Test lookup perf:
 * Reader(s) lookup keys present in the table.
 */
static int
test_hash_add_no_ks_lookup_hit(struct rwc_perf *rwc_perf_results, int rwc_lf,
				int htm)
{
	unsigned int n, m;
	uint64_t i;
	int use_jhash = 0;
	uint8_t key_shift = 0;
	uint8_t read_type = READ_PASS_NO_KEY_SHIFTS;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Hash add - no key-shifts, read - hit\n");
	for (m = 0; m < 2; m++) {
		if (m == 1) {
			printf("\n** With bulk-lookup **\n");
			read_type |= BULK_LOOKUP;
		}
		for (n = 0; n < NUM_TEST; n++) {
			unsigned int tot_lcore = rte_lcore_count();
			if (tot_lcore < rwc_core_cnt[n] + 1)
				goto finish;

			printf("\nNumber of readers: %u\n", rwc_core_cnt[n]);

			rte_atomic64_clear(&greads);
			rte_atomic64_clear(&gread_cycles);

			rte_hash_reset(tbl_rwc_test_param.h);
			writer_done = 0;
			if (write_keys(key_shift) < 0)
				goto err;
			writer_done = 1;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
							enabled_core_ids[i]);

			for (i = 1; i <= rwc_core_cnt[n]; i++)
				if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
					goto err;

			unsigned long long cycles_per_lookup =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			rwc_perf_results->w_no_ks_r_hit[m][n]
						= cycles_per_lookup;
			printf("Cycles per lookup: %llu\n", cycles_per_lookup);
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

/*
 * Test lookup perf:
 * Reader(s) lookup keys absent in the table while
 * 'Main' thread adds with no key-shifts.
 */
static int
test_hash_add_no_ks_lookup_miss(struct rwc_perf *rwc_perf_results, int rwc_lf,
				int htm)
{
	unsigned int n, m;
	uint64_t i;
	int use_jhash = 0;
	uint8_t key_shift = 0;
	uint8_t read_type = READ_FAIL;
	int ret;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Hash add - no key-shifts, Hash lookup - miss\n");
	for (m = 0; m < 2; m++) {
		if (m == 1) {
			printf("\n** With bulk-lookup **\n");
			read_type |= BULK_LOOKUP;
		}
		for (n = 0; n < NUM_TEST; n++) {
			unsigned int tot_lcore = rte_lcore_count();
			if (tot_lcore < rwc_core_cnt[n] + 1)
				goto finish;

			printf("\nNumber of readers: %u\n", rwc_core_cnt[n]);

			rte_atomic64_clear(&greads);
			rte_atomic64_clear(&gread_cycles);

			rte_hash_reset(tbl_rwc_test_param.h);
			writer_done = 0;

			for (i = 1; i <= rwc_core_cnt[n]; i++)
				rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
							enabled_core_ids[i]);
			ret = write_keys(key_shift);
			writer_done = 1;

			if (ret < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
					goto err;

			unsigned long long cycles_per_lookup =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			rwc_perf_results->w_no_ks_r_miss[m][n]
						= cycles_per_lookup;
			printf("Cycles per lookup: %llu\n", cycles_per_lookup);
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

/*
 * Test lookup perf:
 * Reader(s) lookup keys present in the table and not likely to be on the
 * shift path  while 'Main' thread adds keys causing key-shifts.
 */
static int
test_hash_add_ks_lookup_hit_non_sp(struct rwc_perf *rwc_perf_results,
				    int rwc_lf, int htm)
{
	unsigned int n, m;
	uint64_t i;
	int use_jhash = 0;
	int ret;
	uint8_t key_shift;
	uint8_t read_type = READ_PASS_NON_SHIFT_PATH;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Hash add - key shift, Hash lookup - hit"
	       " (non-shift-path)\n");
	for (m = 0; m < 2; m++) {
		if (m == 1) {
			printf("\n** With bulk-lookup **\n");
			read_type |= BULK_LOOKUP;
		}
		for (n = 0; n < NUM_TEST; n++) {
			unsigned int tot_lcore = rte_lcore_count();
			if (tot_lcore < rwc_core_cnt[n] + 1)
				goto finish;

			printf("\nNumber of readers: %u\n", rwc_core_cnt[n]);

			rte_atomic64_clear(&greads);
			rte_atomic64_clear(&gread_cycles);

			rte_hash_reset(tbl_rwc_test_param.h);
			writer_done = 0;
			key_shift = 0;
			if (write_keys(key_shift) < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
							enabled_core_ids[i]);
			key_shift = 1;
			ret = write_keys(key_shift);
			writer_done = 1;

			if (ret < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
					goto err;

			unsigned long long cycles_per_lookup =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			rwc_perf_results->w_ks_r_hit_nsp[m][n]
						= cycles_per_lookup;
			printf("Cycles per lookup: %llu\n", cycles_per_lookup);
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

/*
 * Test lookup perf:
 * Reader(s) lookup keys present in the table and likely on the shift-path while
 * 'Main' thread adds keys causing key-shifts.
 */
static int
test_hash_add_ks_lookup_hit_sp(struct rwc_perf *rwc_perf_results, int rwc_lf,
				int htm)
{
	unsigned int n, m;
	uint64_t i;
	int use_jhash = 0;
	int ret;
	uint8_t key_shift;
	uint8_t read_type = READ_PASS_SHIFT_PATH;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Hash add - key shift, Hash lookup - hit (shift-path)"
	       "\n");

	for (m = 0; m < 2; m++) {
		if (m == 1) {
			printf("\n** With bulk-lookup **\n");
			read_type |= BULK_LOOKUP;
		}
		for (n = 0; n < NUM_TEST; n++) {
			unsigned int tot_lcore = rte_lcore_count();
			if (tot_lcore < rwc_core_cnt[n] + 1)
				goto finish;

			printf("\nNumber of readers: %u\n", rwc_core_cnt[n]);
			rte_atomic64_clear(&greads);
			rte_atomic64_clear(&gread_cycles);

			rte_hash_reset(tbl_rwc_test_param.h);
			writer_done = 0;
			key_shift = 0;
			if (write_keys(key_shift) < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
						enabled_core_ids[i]);
			key_shift = 1;
			ret = write_keys(key_shift);
			writer_done = 1;

			if (ret < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
					goto err;

			unsigned long long cycles_per_lookup =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			rwc_perf_results->w_ks_r_hit_sp[m][n]
						= cycles_per_lookup;
			printf("Cycles per lookup: %llu\n", cycles_per_lookup);
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

/*
 * Test lookup perf:
 * Reader(s) lookup keys absent in the table while
 * 'Main' thread adds keys causing key-shifts.
 */
static int
test_hash_add_ks_lookup_miss(struct rwc_perf *rwc_perf_results, int rwc_lf, int
			     htm)
{
	unsigned int n, m;
	uint64_t i;
	int use_jhash = 0;
	int ret;
	uint8_t key_shift;
	uint8_t read_type = READ_FAIL;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Hash add - key shift, Hash lookup - miss\n");
	for (m = 0; m < 2; m++) {
		if (m == 1) {
			printf("\n** With bulk-lookup **\n");
			read_type |= BULK_LOOKUP;
		}
		for (n = 0; n < NUM_TEST; n++) {
			unsigned int tot_lcore = rte_lcore_count();
			if (tot_lcore < rwc_core_cnt[n] + 1)
				goto finish;

			printf("\nNumber of readers: %u\n", rwc_core_cnt[n]);

			rte_atomic64_clear(&greads);
			rte_atomic64_clear(&gread_cycles);

			rte_hash_reset(tbl_rwc_test_param.h);
			writer_done = 0;
			key_shift = 0;
			if (write_keys(key_shift) < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
							enabled_core_ids[i]);
			key_shift = 1;
			ret = write_keys(key_shift);
			writer_done = 1;

			if (ret < 0)
				goto err;
			for (i = 1; i <= rwc_core_cnt[n]; i++)
				if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
					goto err;

			unsigned long long cycles_per_lookup =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			rwc_perf_results->w_ks_r_miss[m][n] = cycles_per_lookup;
			printf("Cycles per lookup: %llu\n", cycles_per_lookup);
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

/*
 * Test lookup perf for multi-writer:
 * Reader(s) lookup keys present in the table and likely on the shift-path while
 * Writers add keys causing key-shiftsi.
 * Writers are running in parallel, on different data plane cores.
 */
static int
test_hash_multi_add_lookup(struct rwc_perf *rwc_perf_results, int rwc_lf,
			   int htm)
{
	unsigned int n, m, k;
	uint64_t i;
	int use_jhash = 0;
	uint8_t key_shift;
	uint8_t read_type = READ_PASS_SHIFT_PATH;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gread_cycles);

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		goto err;
	printf("\nTest: Multi-add-lookup\n");
	uint8_t pos_core;
	for (m = 1; m < NUM_TEST; m++) {
		/* Calculate keys added by each writer */
		tbl_rwc_test_param.single_insert =
			tbl_rwc_test_param.count_keys_ks / rwc_core_cnt[m];
		for (k = 0; k < 2; k++) {
			if (k == 1) {
				printf("\n** With bulk-lookup **\n");
				read_type |= BULK_LOOKUP;
			}
			for (n = 0; n < NUM_TEST; n++) {
				unsigned int tot_lcore	= rte_lcore_count();
				if (tot_lcore < (rwc_core_cnt[n] +
				     rwc_core_cnt[m] + 1))
					goto finish;

				printf("\nNumber of writers: %u",
				       rwc_core_cnt[m]);
				printf("\nNumber of readers: %u\n",
				       rwc_core_cnt[n]);

				rte_atomic64_clear(&greads);
				rte_atomic64_clear(&gread_cycles);

				rte_hash_reset(tbl_rwc_test_param.h);
				writer_done = 0;
				key_shift = 0;
				if (write_keys(key_shift) < 0)
					goto err;

				/* Launch reader(s) */
				for (i = 1; i <= rwc_core_cnt[n]; i++)
					rte_eal_remote_launch(test_rwc_reader,
						(void *)(uintptr_t)read_type,
						enabled_core_ids[i]);
				key_shift = 1;
				pos_core = 0;

				/* Launch writers */
				for (; i <= rwc_core_cnt[m]
				     + rwc_core_cnt[n];	i++) {
					rte_eal_remote_launch
						(test_rwc_multi_writer,
						(void *)(uintptr_t)pos_core,
						enabled_core_ids[i]);
					pos_core++;
				}

				/* Wait for writers to complete */
				for (i = rwc_core_cnt[n] + 1;
				     i <= rwc_core_cnt[m] + rwc_core_cnt[n];
				     i++)
					rte_eal_wait_lcore(enabled_core_ids[i]);

				writer_done = 1;

				for (i = 1; i <= rwc_core_cnt[n]; i++)
					if (rte_eal_wait_lcore(enabled_core_ids[i]) < 0)
						goto err;

				unsigned long long cycles_per_lookup =
					rte_atomic64_read(&gread_cycles)
					/ rte_atomic64_read(&greads);
				rwc_perf_results->multi_rw[m][k][n]
					= cycles_per_lookup;
				printf("Cycles per lookup: %llu\n",
				       cycles_per_lookup);
			}
		}
	}

finish:
	rte_hash_free(tbl_rwc_test_param.h);
	return 0;

err:
	rte_eal_mp_wait_lcore();
	rte_hash_free(tbl_rwc_test_param.h);
	return -1;
}

static int
test_hash_readwrite_lf_main(void)
{
	/*
	 * Variables used to choose different tests.
	 * rwc_lf indicates if read-write concurrency lock-free support is
	 * enabled.
	 * htm indicates if Hardware transactional memory support is enabled.
	 */
	int rwc_lf = 0;
	int htm;
	int use_jhash = 0;
	if (rte_lcore_count() == 1) {
		printf("More than one lcore is required "
			"to do read write lock-free concurrency test\n");
		return -1;
	}

	setlocale(LC_NUMERIC, "");

	/* Reset tbl_rwc_test_param to discard values from previous run */
	memset(&tbl_rwc_test_param, 0, sizeof(tbl_rwc_test_param));

	if (rte_tm_supported())
		htm = 1;
	else
		htm = 0;

	if (init_params(rwc_lf, use_jhash, htm) != 0)
		return -1;
	if (generate_keys() != 0)
		return -1;
	if (get_enabled_cores_list() != 0)
		return -1;

	if (RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF) {
		rwc_lf = 1;
		printf("Test lookup with read-write concurrency lock free support"
		       " enabled\n");
		if (test_hash_add_no_ks_lookup_hit(&rwc_lf_results, rwc_lf,
							htm) < 0)
			return -1;
		if (test_hash_add_no_ks_lookup_miss(&rwc_lf_results, rwc_lf,
							htm) < 0)
			return -1;
		if (test_hash_add_ks_lookup_hit_non_sp(&rwc_lf_results, rwc_lf,
							htm) < 0)
			return -1;
		if (test_hash_add_ks_lookup_hit_sp(&rwc_lf_results, rwc_lf,
							htm) < 0)
			return -1;
		if (test_hash_add_ks_lookup_miss(&rwc_lf_results, rwc_lf, htm)
							< 0)
			return -1;
		if (test_hash_multi_add_lookup(&rwc_lf_results, rwc_lf, htm)
							< 0)
			return -1;
	}
	printf("\nTest lookup with read-write concurrency lock free support"
	       " disabled\n");
	rwc_lf = 0;
	if (!htm) {
		printf("With HTM Disabled\n");
		if (!RUN_WITH_HTM_DISABLED) {
			printf("Enable RUN_WITH_HTM_DISABLED to test with"
			       " lock-free disabled");
			goto results;
		}
	} else
		printf("With HTM Enabled\n");
	if (test_hash_add_no_ks_lookup_hit(&rwc_non_lf_results, rwc_lf, htm)
						< 0)
		return -1;
	if (test_hash_add_no_ks_lookup_miss(&rwc_non_lf_results, rwc_lf, htm)
						< 0)
		return -1;
	if (test_hash_add_ks_lookup_hit_non_sp(&rwc_non_lf_results, rwc_lf,
						htm) < 0)
		return -1;
	if (test_hash_add_ks_lookup_hit_sp(&rwc_non_lf_results, rwc_lf, htm)
						< 0)
		return -1;
	if (test_hash_add_ks_lookup_miss(&rwc_non_lf_results, rwc_lf, htm) < 0)
		return -1;
	if (test_hash_multi_add_lookup(&rwc_non_lf_results, rwc_lf, htm) < 0)
		return -1;
results:
	printf("\n\t\t\t\t\t\t********** Results summary **********\n\n");
	int i, j, k;
	for (j = 0; j < 2; j++) {
		if (j == 1)
			printf("\n\t\t\t\t\t#######********** Bulk Lookup "
			       "**********#######\n\n");
		printf("_______\t\t_______\t\t_________\t___\t\t_________\t\t"
			"\t\t\t\t_________________\n");
		printf("Writers\t\tReaders\t\tLock-free\tHTM\t\tTest-case\t\t\t"
		       "\t\t\tCycles per lookup\n");
		printf("_______\t\t_______\t\t_________\t___\t\t_________\t\t\t"
		       "\t\t\t_________________\n");
		for (i = 0; i < NUM_TEST; i++) {
			printf("%u\t\t%u\t\t", 1, rwc_core_cnt[i]);
			printf("Enabled\t\t");
			printf("N/A\t\t");
			printf("Hash add - no key-shifts, lookup - hit\t\t\t\t"
				"%u\n\t\t\t\t\t\t\t\t",
				rwc_lf_results.w_no_ks_r_hit[j][i]);
			printf("Hash add - no key-shifts, lookup - miss\t\t\t\t"
				"%u\n\t\t\t\t\t\t\t\t",
				rwc_lf_results.w_no_ks_r_miss[j][i]);
			printf("Hash add - key-shifts, lookup - hit"
			       "(non-shift-path)\t\t%u\n\t\t\t\t\t\t\t\t",
			       rwc_lf_results.w_ks_r_hit_nsp[j][i]);
			printf("Hash add - key-shifts, lookup - hit "
			       "(shift-path)\t\t%u\n\t\t\t\t\t\t\t\t",
			       rwc_lf_results.w_ks_r_hit_sp[j][i]);
			printf("Hash add - key-shifts, Hash lookup miss\t\t\t\t"
				"%u\n\n\t\t\t\t",
				rwc_lf_results.w_ks_r_miss[j][i]);

			printf("Disabled\t");
			if (htm)
				printf("Enabled\t\t");
			else
				printf("Disabled\t");
			printf("Hash add - no key-shifts, lookup - hit\t\t\t\t"
				"%u\n\t\t\t\t\t\t\t\t",
				rwc_non_lf_results.w_no_ks_r_hit[j][i]);
			printf("Hash add - no key-shifts, lookup - miss\t\t\t\t"
				"%u\n\t\t\t\t\t\t\t\t",
				rwc_non_lf_results.w_no_ks_r_miss[j][i]);
			printf("Hash add - key-shifts, lookup - hit "
			       "(non-shift-path)\t\t%u\n\t\t\t\t\t\t\t\t",
			       rwc_non_lf_results.w_ks_r_hit_nsp[j][i]);
			printf("Hash add - key-shifts, lookup - hit "
			       "(shift-path)\t\t%u\n\t\t\t\t\t\t\t\t",
			       rwc_non_lf_results.w_ks_r_hit_sp[j][i]);
			printf("Hash add - key-shifts, Hash lookup miss\t\t\t\t"
			       "%u\n", rwc_non_lf_results.w_ks_r_miss[j][i]);

			printf("_______\t\t_______\t\t_________\t___\t\t"
			       "_________\t\t\t\t\t\t_________________\n");
		}

		for (i = 1; i < NUM_TEST; i++) {
			for (k = 0; k < NUM_TEST; k++) {
				printf("%u", rwc_core_cnt[i]);
				printf("\t\t%u\t\t", rwc_core_cnt[k]);
				printf("Enabled\t\t");
				printf("N/A\t\t");
				printf("Multi-add-lookup\t\t\t\t\t\t%u\n\n\t\t"
				       "\t\t",
				       rwc_lf_results.multi_rw[i][j][k]);
				printf("Disabled\t");
				if (htm)
					printf("Enabled\t\t");
				else
					printf("Disabled\t");
				printf("Multi-add-lookup\t\t\t\t\t\t%u\n",
				       rwc_non_lf_results.multi_rw[i][j][k]);

				printf("_______\t\t_______\t\t_________\t___"
				       "\t\t_________\t\t\t\t\t\t"
				       "_________________\n");
			}
		}
	}
	rte_free(tbl_rwc_test_param.keys);
	rte_free(tbl_rwc_test_param.keys_no_ks);
	rte_free(tbl_rwc_test_param.keys_ks);
	rte_free(tbl_rwc_test_param.keys_absent);
	rte_free(tbl_rwc_test_param.keys_shift_path);
	rte_free(scanned_bkts);
	return 0;
}

REGISTER_TEST_COMMAND(hash_readwrite_lf_autotest, test_hash_readwrite_lf_main);
