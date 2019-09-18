/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
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

#define RTE_RWTEST_FAIL 0

#define TOTAL_ENTRY (5*1024*1024)
#define TOTAL_INSERT (4.5*1024*1024)
#define TOTAL_INSERT_EXT (5*1024*1024)

#define NUM_TEST 3
unsigned int core_cnt[NUM_TEST] = {2, 4, 8};

unsigned int slave_core_ids[RTE_MAX_LCORE];
struct perf {
	uint32_t single_read;
	uint32_t single_write;
	uint32_t read_only[NUM_TEST];
	uint32_t write_only[NUM_TEST];
	uint32_t read_write_r[NUM_TEST];
	uint32_t read_write_w[NUM_TEST];
};

static struct perf htm_results, non_htm_results;

struct {
	uint32_t *keys;
	uint8_t *found;
	uint32_t num_insert;
	uint32_t rounded_tot_insert;
	struct rte_hash *h;
} tbl_rw_test_param;

static rte_atomic64_t gcycles;
static rte_atomic64_t ginsertions;

static rte_atomic64_t gread_cycles;
static rte_atomic64_t gwrite_cycles;

static rte_atomic64_t greads;
static rte_atomic64_t gwrites;

static int
test_hash_readwrite_worker(__attribute__((unused)) void *arg)
{
	uint64_t i, offset;
	uint32_t lcore_id = rte_lcore_id();
	uint64_t begin, cycles;
	int *ret;

	ret = rte_malloc(NULL, sizeof(int) *
				tbl_rw_test_param.num_insert, 0);
	for (i = 0; i < rte_lcore_count(); i++) {
		if (slave_core_ids[i] == lcore_id)
			break;
	}
	offset = tbl_rw_test_param.num_insert * i;

	printf("Core #%d inserting and reading %d: %'"PRId64" - %'"PRId64"\n",
	       lcore_id, tbl_rw_test_param.num_insert,
	       offset, offset + tbl_rw_test_param.num_insert - 1);

	begin = rte_rdtsc_precise();

	for (i = offset; i < offset + tbl_rw_test_param.num_insert; i++) {

		if (rte_hash_lookup(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + i) > 0)
			break;

		ret[i - offset] = rte_hash_add_key(tbl_rw_test_param.h,
				     tbl_rw_test_param.keys + i);
		if (ret[i - offset] < 0)
			break;

		/* lookup a random key */
		uint32_t rand = rte_rand() % (i + 1 - offset);

		if (rte_hash_lookup(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + rand) != ret[rand])
			break;


		if (rte_hash_del_key(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + rand) != ret[rand])
			break;

		ret[rand] = rte_hash_add_key(tbl_rw_test_param.h,
					tbl_rw_test_param.keys + rand);
		if (ret[rand] < 0)
			break;

		if (rte_hash_lookup(tbl_rw_test_param.h,
			tbl_rw_test_param.keys + rand) != ret[rand])
			break;
	}

	cycles = rte_rdtsc_precise() - begin;
	rte_atomic64_add(&gcycles, cycles);
	rte_atomic64_add(&ginsertions, i - offset);

	for (; i < offset + tbl_rw_test_param.num_insert; i++)
		tbl_rw_test_param.keys[i] = RTE_RWTEST_FAIL;

	rte_free(ret);
	return 0;
}

static int
init_params(int use_ext, int use_htm, int use_jhash)
{
	unsigned int i;

	uint32_t *keys = NULL;
	uint8_t *found = NULL;
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

	if (use_htm)
		hash_params.extra_flag =
			RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT |
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
	else
		hash_params.extra_flag =
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY |
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;

	if (use_ext)
		hash_params.extra_flag |=
			RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	else
		hash_params.extra_flag &=
		       ~RTE_HASH_EXTRA_FLAGS_EXT_TABLE;

	hash_params.name = "tests";

	handle = rte_hash_create(&hash_params);
	if (handle == NULL) {
		printf("hash creation failed");
		return -1;
	}

	tbl_rw_test_param.h = handle;
	keys = rte_malloc(NULL, sizeof(uint32_t) * TOTAL_ENTRY, 0);

	if (keys == NULL) {
		printf("RTE_MALLOC failed\n");
		goto err;
	}

	found = rte_zmalloc(NULL, sizeof(uint8_t) * TOTAL_ENTRY, 0);
	if (found == NULL) {
		printf("RTE_ZMALLOC failed\n");
		goto err;
	}

	tbl_rw_test_param.keys = keys;
	tbl_rw_test_param.found = found;

	for (i = 0; i < TOTAL_ENTRY; i++)
		keys[i] = i;

	return 0;

err:
	rte_free(keys);
	rte_hash_free(handle);

	return -1;
}

static int
test_hash_readwrite_functional(int use_ext, int use_htm)
{
	unsigned int i;
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	uint32_t duplicated_keys = 0;
	uint32_t lost_keys = 0;
	int use_jhash = 1;
	int slave_cnt = rte_lcore_count() - 1;
	uint32_t tot_insert = 0;

	rte_atomic64_init(&gcycles);
	rte_atomic64_clear(&gcycles);

	rte_atomic64_init(&ginsertions);
	rte_atomic64_clear(&ginsertions);

	if (init_params(use_ext, use_htm, use_jhash) != 0)
		goto err;

	if (use_ext)
		tot_insert = TOTAL_INSERT_EXT;
	else
		tot_insert = TOTAL_INSERT;

	tbl_rw_test_param.num_insert =
		tot_insert / slave_cnt;

	tbl_rw_test_param.rounded_tot_insert =
		tbl_rw_test_param.num_insert
		* slave_cnt;

	printf("++++++++Start function tests:+++++++++\n");

	/* Fire all threads. */
	rte_eal_mp_remote_launch(test_hash_readwrite_worker,
				 NULL, SKIP_MASTER);
	rte_eal_mp_wait_lcore();

	while (rte_hash_iterate(tbl_rw_test_param.h, &next_key,
			&next_data, &iter) >= 0) {
		/* Search for the key in the list of keys added .*/
		i = *(const uint32_t *)next_key;
		tbl_rw_test_param.found[i]++;
	}

	for (i = 0; i < tbl_rw_test_param.rounded_tot_insert; i++) {
		if (tbl_rw_test_param.keys[i] != RTE_RWTEST_FAIL) {
			if (tbl_rw_test_param.found[i] > 1) {
				duplicated_keys++;
				break;
			}
			if (tbl_rw_test_param.found[i] == 0) {
				lost_keys++;
				printf("key %d is lost\n", i);
				break;
			}
		}
	}

	if (duplicated_keys > 0) {
		printf("%d key duplicated\n", duplicated_keys);
		goto err_free;
	}

	if (lost_keys > 0) {
		printf("%d key lost\n", lost_keys);
		goto err_free;
	}

	printf("No key corrupted during read-write test.\n");

	unsigned long long int cycles_per_insertion =
		rte_atomic64_read(&gcycles) /
		rte_atomic64_read(&ginsertions);

	printf("cycles per insertion and lookup: %llu\n", cycles_per_insertion);

	rte_free(tbl_rw_test_param.found);
	rte_free(tbl_rw_test_param.keys);
	rte_hash_free(tbl_rw_test_param.h);
	printf("+++++++++Complete function tests+++++++++\n");
	return 0;

err_free:
	rte_free(tbl_rw_test_param.found);
	rte_free(tbl_rw_test_param.keys);
	rte_hash_free(tbl_rw_test_param.h);
err:
	return -1;
}

static int
test_rw_reader(void *arg)
{
	uint64_t i;
	uint64_t begin, cycles;
	uint64_t read_cnt = (uint64_t)((uintptr_t)arg);

	begin = rte_rdtsc_precise();
	for (i = 0; i < read_cnt; i++) {
		void *data;
		rte_hash_lookup_data(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + i,
				&data);
		if (i != (uint64_t)(uintptr_t)data) {
			printf("lookup find wrong value %"PRIu64","
				"%"PRIu64"\n", i,
				(uint64_t)(uintptr_t)data);
			break;
		}
	}

	cycles = rte_rdtsc_precise() - begin;
	rte_atomic64_add(&gread_cycles, cycles);
	rte_atomic64_add(&greads, i);
	return 0;
}

static int
test_rw_writer(void *arg)
{
	uint64_t i;
	uint32_t lcore_id = rte_lcore_id();
	uint64_t begin, cycles;
	int ret;
	uint64_t start_coreid = (uint64_t)(uintptr_t)arg;
	uint64_t offset;

	for (i = 0; i < rte_lcore_count(); i++) {
		if (slave_core_ids[i] == lcore_id)
			break;
	}

	offset = TOTAL_INSERT / 2 + (i - (start_coreid)) *
				tbl_rw_test_param.num_insert;
	begin = rte_rdtsc_precise();
	for (i = offset; i < offset + tbl_rw_test_param.num_insert; i++) {
		ret = rte_hash_add_key_data(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + i,
				(void *)((uintptr_t)i));
		if (ret < 0) {
			printf("writer failed %"PRIu64"\n", i);
			break;
		}
	}

	cycles = rte_rdtsc_precise() - begin;
	rte_atomic64_add(&gwrite_cycles, cycles);
	rte_atomic64_add(&gwrites, tbl_rw_test_param.num_insert);
	return 0;
}

static int
test_hash_readwrite_perf(struct perf *perf_results, int use_htm,
							int reader_faster)
{
	unsigned int n;
	int ret;
	int start_coreid;
	uint64_t i, read_cnt;

	const void *next_key;
	void *next_data;
	uint32_t iter;
	int use_jhash = 0;

	uint32_t duplicated_keys = 0;
	uint32_t lost_keys = 0;

	uint64_t start = 0, end = 0;

	rte_atomic64_init(&greads);
	rte_atomic64_init(&gwrites);
	rte_atomic64_clear(&gwrites);
	rte_atomic64_clear(&greads);

	rte_atomic64_init(&gread_cycles);
	rte_atomic64_clear(&gread_cycles);
	rte_atomic64_init(&gwrite_cycles);
	rte_atomic64_clear(&gwrite_cycles);

	if (init_params(0, use_htm, use_jhash) != 0)
		goto err;

	/*
	 * Do a readers finish faster or writers finish faster test.
	 * When readers finish faster, we timing the readers, and when writers
	 * finish faster, we timing the writers.
	 * Divided by 10 or 2 is just experimental values to vary the workload
	 * of readers.
	 */
	if (reader_faster) {
		printf("++++++Start perf test: reader++++++++\n");
		read_cnt = TOTAL_INSERT / 10;
	} else {
		printf("++++++Start perf test: writer++++++++\n");
		read_cnt = TOTAL_INSERT / 2;
	}

	/* We first test single thread performance */
	start = rte_rdtsc_precise();
	/* Insert half of the keys */
	for (i = 0; i < TOTAL_INSERT / 2; i++) {
		ret = rte_hash_add_key_data(tbl_rw_test_param.h,
				     tbl_rw_test_param.keys + i,
					(void *)((uintptr_t)i));
		if (ret < 0) {
			printf("Failed to insert half of keys\n");
			goto err_free;
		}
	}
	end = rte_rdtsc_precise() - start;
	perf_results->single_write = end / i;

	start = rte_rdtsc_precise();

	for (i = 0; i < read_cnt; i++) {
		void *data;
		rte_hash_lookup_data(tbl_rw_test_param.h,
				tbl_rw_test_param.keys + i,
				&data);
		if (i != (uint64_t)(uintptr_t)data) {
			printf("lookup find wrong value"
					" %"PRIu64",%"PRIu64"\n", i,
					(uint64_t)(uintptr_t)data);
			break;
		}
	}
	end = rte_rdtsc_precise() - start;
	perf_results->single_read = end / i;

	for (n = 0; n < NUM_TEST; n++) {
		unsigned int tot_slave_lcore = rte_lcore_count() - 1;
		if (tot_slave_lcore < core_cnt[n] * 2)
			goto finish;

		rte_atomic64_clear(&greads);
		rte_atomic64_clear(&gread_cycles);
		rte_atomic64_clear(&gwrites);
		rte_atomic64_clear(&gwrite_cycles);

		rte_hash_reset(tbl_rw_test_param.h);

		tbl_rw_test_param.num_insert = TOTAL_INSERT / 2 / core_cnt[n];
		tbl_rw_test_param.rounded_tot_insert = TOTAL_INSERT / 2 +
						tbl_rw_test_param.num_insert *
						core_cnt[n];

		for (i = 0; i < TOTAL_INSERT / 2; i++) {
			ret = rte_hash_add_key_data(tbl_rw_test_param.h,
					tbl_rw_test_param.keys + i,
					(void *)((uintptr_t)i));
			if (ret < 0) {
				printf("Failed to insert half of keys\n");
				goto err_free;
			}
		}

		/* Then test multiple thread case but only all reads or
		 * all writes
		 */

		/* Test only reader cases */
		for (i = 0; i < core_cnt[n]; i++)
			rte_eal_remote_launch(test_rw_reader,
					(void *)(uintptr_t)read_cnt,
					slave_core_ids[i]);

		rte_eal_mp_wait_lcore();

		start_coreid = i;
		/* Test only writer cases */
		for (; i < core_cnt[n] * 2; i++)
			rte_eal_remote_launch(test_rw_writer,
					(void *)((uintptr_t)start_coreid),
					slave_core_ids[i]);

		rte_eal_mp_wait_lcore();

		if (reader_faster) {
			unsigned long long int cycles_per_insertion =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			perf_results->read_only[n] = cycles_per_insertion;
			printf("Reader only: cycles per lookup: %llu\n",
							cycles_per_insertion);
		}

		else {
			unsigned long long int cycles_per_insertion =
				rte_atomic64_read(&gwrite_cycles) /
				rte_atomic64_read(&gwrites);
			perf_results->write_only[n] = cycles_per_insertion;
			printf("Writer only: cycles per writes: %llu\n",
							cycles_per_insertion);
		}

		rte_atomic64_clear(&greads);
		rte_atomic64_clear(&gread_cycles);
		rte_atomic64_clear(&gwrites);
		rte_atomic64_clear(&gwrite_cycles);

		rte_hash_reset(tbl_rw_test_param.h);

		for (i = 0; i < TOTAL_INSERT / 2; i++) {
			ret = rte_hash_add_key_data(tbl_rw_test_param.h,
					tbl_rw_test_param.keys + i,
					(void *)((uintptr_t)i));
			if (ret < 0) {
				printf("Failed to insert half of keys\n");
				goto err_free;
			}
		}

		start_coreid = core_cnt[n];

		if (reader_faster) {
			for (i = core_cnt[n]; i < core_cnt[n] * 2; i++)
				rte_eal_remote_launch(test_rw_writer,
					(void *)((uintptr_t)start_coreid),
					slave_core_ids[i]);
			for (i = 0; i < core_cnt[n]; i++)
				rte_eal_remote_launch(test_rw_reader,
					(void *)(uintptr_t)read_cnt,
					slave_core_ids[i]);
		} else {
			for (i = 0; i < core_cnt[n]; i++)
				rte_eal_remote_launch(test_rw_reader,
					(void *)(uintptr_t)read_cnt,
					slave_core_ids[i]);
			for (; i < core_cnt[n] * 2; i++)
				rte_eal_remote_launch(test_rw_writer,
					(void *)((uintptr_t)start_coreid),
					slave_core_ids[i]);
		}

		rte_eal_mp_wait_lcore();

		iter = 0;
		memset(tbl_rw_test_param.found, 0, TOTAL_ENTRY);
		while (rte_hash_iterate(tbl_rw_test_param.h,
				&next_key, &next_data, &iter) >= 0) {
			/* Search for the key in the list of keys added .*/
			i = *(const uint32_t *)next_key;
			tbl_rw_test_param.found[i]++;
		}

		for (i = 0; i < tbl_rw_test_param.rounded_tot_insert; i++) {
			if (tbl_rw_test_param.keys[i] != RTE_RWTEST_FAIL) {
				if (tbl_rw_test_param.found[i] > 1) {
					duplicated_keys++;
					break;
				}
				if (tbl_rw_test_param.found[i] == 0) {
					lost_keys++;
					printf("key %"PRIu64" is lost\n", i);
					break;
				}
			}
		}

		if (duplicated_keys > 0) {
			printf("%d key duplicated\n", duplicated_keys);
			goto err_free;
		}

		if (lost_keys > 0) {
			printf("%d key lost\n", lost_keys);
			goto err_free;
		}

		printf("No key corrupted during read-write test.\n");

		if (reader_faster) {
			unsigned long long int cycles_per_insertion =
				rte_atomic64_read(&gread_cycles) /
				rte_atomic64_read(&greads);
			perf_results->read_write_r[n] = cycles_per_insertion;
			printf("Read-write cycles per lookup: %llu\n",
							cycles_per_insertion);
		}

		else {
			unsigned long long int cycles_per_insertion =
				rte_atomic64_read(&gwrite_cycles) /
				rte_atomic64_read(&gwrites);
			perf_results->read_write_w[n] = cycles_per_insertion;
			printf("Read-write cycles per writes: %llu\n",
							cycles_per_insertion);
		}
	}

finish:
	rte_free(tbl_rw_test_param.found);
	rte_free(tbl_rw_test_param.keys);
	rte_hash_free(tbl_rw_test_param.h);
	return 0;

err_free:
	rte_free(tbl_rw_test_param.found);
	rte_free(tbl_rw_test_param.keys);
	rte_hash_free(tbl_rw_test_param.h);

err:
	return -1;
}

static int
test_hash_readwrite_main(void)
{
	/*
	 * Variables used to choose different tests.
	 * use_htm indicates if hardware transactional memory should be used.
	 * reader_faster indicates if the reader threads should finish earlier
	 * than writer threads. This is to timing either reader threads or
	 * writer threads for performance numbers.
	 */
	int use_htm, use_ext,  reader_faster;
	unsigned int i = 0, core_id = 0;

	if (rte_lcore_count() <= 2) {
		printf("More than two lcores are required "
			"to do read write test\n");
		return -1;
	}

	RTE_LCORE_FOREACH_SLAVE(core_id) {
		slave_core_ids[i] = core_id;
		i++;
	}

	setlocale(LC_NUMERIC, "");

	if (rte_tm_supported()) {
		printf("Hardware transactional memory (lock elision) "
			"is supported\n");

		printf("Test read-write with Hardware transactional memory\n");

		use_htm = 1;
		use_ext = 0;

		if (test_hash_readwrite_functional(use_ext, use_htm) < 0)
			return -1;

		use_ext = 1;
		if (test_hash_readwrite_functional(use_ext, use_htm) < 0)
			return -1;

		reader_faster = 1;
		if (test_hash_readwrite_perf(&htm_results, use_htm,
							reader_faster) < 0)
			return -1;

		reader_faster = 0;
		if (test_hash_readwrite_perf(&htm_results, use_htm,
							reader_faster) < 0)
			return -1;
	} else {
		printf("Hardware transactional memory (lock elision) "
			"is NOT supported\n");
	}

	printf("Test read-write without Hardware transactional memory\n");
	use_htm = 0;
	use_ext = 0;
	if (test_hash_readwrite_functional(use_ext, use_htm) < 0)
		return -1;

	use_ext = 1;
	if (test_hash_readwrite_functional(use_ext, use_htm) < 0)
		return -1;

	reader_faster = 1;
	if (test_hash_readwrite_perf(&non_htm_results, use_htm,
							reader_faster) < 0)
		return -1;
	reader_faster = 0;
	if (test_hash_readwrite_perf(&non_htm_results, use_htm,
							reader_faster) < 0)
		return -1;

	printf("================\n");
	printf("Results summary:\n");
	printf("================\n");

	printf("single read: %u\n", htm_results.single_read);
	printf("single write: %u\n", htm_results.single_write);
	for (i = 0; i < NUM_TEST; i++) {
		printf("+++ core_cnt: %u +++\n", core_cnt[i]);
		printf("HTM:\n");
		printf("  read only: %u\n", htm_results.read_only[i]);
		printf("  write only: %u\n", htm_results.write_only[i]);
		printf("  read-write read: %u\n", htm_results.read_write_r[i]);
		printf("  read-write write: %u\n", htm_results.read_write_w[i]);

		printf("non HTM:\n");
		printf("  read only: %u\n", non_htm_results.read_only[i]);
		printf("  write only: %u\n", non_htm_results.write_only[i]);
		printf("  read-write read: %u\n",
			non_htm_results.read_write_r[i]);
		printf("  read-write write: %u\n",
			non_htm_results.read_write_w[i]);
	}

	return 0;
}

REGISTER_TEST_COMMAND(hash_readwrite_autotest, test_hash_readwrite_main);
