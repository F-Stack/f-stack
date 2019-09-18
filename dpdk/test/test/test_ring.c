/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_random.h>
#include <rte_errno.h>
#include <rte_hexdump.h>

#include "test.h"

/*
 * Ring
 * ====
 *
 * #. Basic tests: done on one core:
 *
 *    - Using single producer/single consumer functions:
 *
 *      - Enqueue one object, two objects, MAX_BULK objects
 *      - Dequeue one object, two objects, MAX_BULK objects
 *      - Check that dequeued pointers are correct
 *
 *    - Using multi producers/multi consumers functions:
 *
 *      - Enqueue one object, two objects, MAX_BULK objects
 *      - Dequeue one object, two objects, MAX_BULK objects
 *      - Check that dequeued pointers are correct
 *
 * #. Performance tests.
 *
 * Tests done in test_ring_perf.c
 */

#define RING_SIZE 4096
#define MAX_BULK 32

static rte_atomic32_t synchro;

#define	TEST_RING_VERIFY(exp)						\
	if (!(exp)) {							\
		printf("error at %s:%d\tcondition " #exp " failed\n",	\
		    __func__, __LINE__);				\
		rte_ring_dump(stdout, r);				\
		return -1;						\
	}

#define	TEST_RING_FULL_EMTPY_ITER	8

/*
 * helper routine for test_ring_basic
 */
static int
test_ring_basic_full_empty(struct rte_ring *r, void * const src[], void *dst[])
{
	unsigned i, rand;
	const unsigned rsz = RING_SIZE - 1;

	printf("Basic full/empty test\n");

	for (i = 0; TEST_RING_FULL_EMTPY_ITER != i; i++) {

		/* random shift in the ring */
		rand = RTE_MAX(rte_rand() % RING_SIZE, 1UL);
		printf("%s: iteration %u, random shift: %u;\n",
		    __func__, i, rand);
		TEST_RING_VERIFY(rte_ring_enqueue_bulk(r, src, rand,
				NULL) != 0);
		TEST_RING_VERIFY(rte_ring_dequeue_bulk(r, dst, rand,
				NULL) == rand);

		/* fill the ring */
		TEST_RING_VERIFY(rte_ring_enqueue_bulk(r, src, rsz, NULL) != 0);
		TEST_RING_VERIFY(0 == rte_ring_free_count(r));
		TEST_RING_VERIFY(rsz == rte_ring_count(r));
		TEST_RING_VERIFY(rte_ring_full(r));
		TEST_RING_VERIFY(0 == rte_ring_empty(r));

		/* empty the ring */
		TEST_RING_VERIFY(rte_ring_dequeue_bulk(r, dst, rsz,
				NULL) == rsz);
		TEST_RING_VERIFY(rsz == rte_ring_free_count(r));
		TEST_RING_VERIFY(0 == rte_ring_count(r));
		TEST_RING_VERIFY(0 == rte_ring_full(r));
		TEST_RING_VERIFY(rte_ring_empty(r));

		/* check data */
		TEST_RING_VERIFY(0 == memcmp(src, dst, rsz));
		rte_ring_dump(stdout, r);
	}
	return 0;
}

static int
test_ring_basic(struct rte_ring *r)
{
	void **src = NULL, **cur_src = NULL, **dst = NULL, **cur_dst = NULL;
	int ret;
	unsigned i, num_elems;

	/* alloc dummy object pointers */
	src = malloc(RING_SIZE*2*sizeof(void *));
	if (src == NULL)
		goto fail;

	for (i = 0; i < RING_SIZE*2 ; i++) {
		src[i] = (void *)(unsigned long)i;
	}
	cur_src = src;

	/* alloc some room for copied objects */
	dst = malloc(RING_SIZE*2*sizeof(void *));
	if (dst == NULL)
		goto fail;

	memset(dst, 0, RING_SIZE*2*sizeof(void *));
	cur_dst = dst;

	printf("enqueue 1 obj\n");
	ret = rte_ring_sp_enqueue_bulk(r, cur_src, 1, NULL);
	cur_src += 1;
	if (ret == 0)
		goto fail;

	printf("enqueue 2 objs\n");
	ret = rte_ring_sp_enqueue_bulk(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret == 0)
		goto fail;

	printf("enqueue MAX_BULK objs\n");
	ret = rte_ring_sp_enqueue_bulk(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK;
	if (ret == 0)
		goto fail;

	printf("dequeue 1 obj\n");
	ret = rte_ring_sc_dequeue_bulk(r, cur_dst, 1, NULL);
	cur_dst += 1;
	if (ret == 0)
		goto fail;

	printf("dequeue 2 objs\n");
	ret = rte_ring_sc_dequeue_bulk(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret == 0)
		goto fail;

	printf("dequeue MAX_BULK objs\n");
	ret = rte_ring_sc_dequeue_bulk(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK;
	if (ret == 0)
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}
	cur_src = src;
	cur_dst = dst;

	printf("enqueue 1 obj\n");
	ret = rte_ring_mp_enqueue_bulk(r, cur_src, 1, NULL);
	cur_src += 1;
	if (ret == 0)
		goto fail;

	printf("enqueue 2 objs\n");
	ret = rte_ring_mp_enqueue_bulk(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret == 0)
		goto fail;

	printf("enqueue MAX_BULK objs\n");
	ret = rte_ring_mp_enqueue_bulk(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK;
	if (ret == 0)
		goto fail;

	printf("dequeue 1 obj\n");
	ret = rte_ring_mc_dequeue_bulk(r, cur_dst, 1, NULL);
	cur_dst += 1;
	if (ret == 0)
		goto fail;

	printf("dequeue 2 objs\n");
	ret = rte_ring_mc_dequeue_bulk(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret == 0)
		goto fail;

	printf("dequeue MAX_BULK objs\n");
	ret = rte_ring_mc_dequeue_bulk(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK;
	if (ret == 0)
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}
	cur_src = src;
	cur_dst = dst;

	printf("fill and empty the ring\n");
	for (i = 0; i<RING_SIZE/MAX_BULK; i++) {
		ret = rte_ring_mp_enqueue_bulk(r, cur_src, MAX_BULK, NULL);
		cur_src += MAX_BULK;
		if (ret == 0)
			goto fail;
		ret = rte_ring_mc_dequeue_bulk(r, cur_dst, MAX_BULK, NULL);
		cur_dst += MAX_BULK;
		if (ret == 0)
			goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	if (test_ring_basic_full_empty(r, src, dst) != 0)
		goto fail;

	cur_src = src;
	cur_dst = dst;

	printf("test default bulk enqueue / dequeue\n");
	num_elems = 16;

	cur_src = src;
	cur_dst = dst;

	ret = rte_ring_enqueue_bulk(r, cur_src, num_elems, NULL);
	cur_src += num_elems;
	if (ret == 0) {
		printf("Cannot enqueue\n");
		goto fail;
	}
	ret = rte_ring_enqueue_bulk(r, cur_src, num_elems, NULL);
	cur_src += num_elems;
	if (ret == 0) {
		printf("Cannot enqueue\n");
		goto fail;
	}
	ret = rte_ring_dequeue_bulk(r, cur_dst, num_elems, NULL);
	cur_dst += num_elems;
	if (ret == 0) {
		printf("Cannot dequeue\n");
		goto fail;
	}
	ret = rte_ring_dequeue_bulk(r, cur_dst, num_elems, NULL);
	cur_dst += num_elems;
	if (ret == 0) {
		printf("Cannot dequeue2\n");
		goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	ret = rte_ring_mp_enqueue(r, cur_src);
	if (ret != 0)
		goto fail;

	ret = rte_ring_mc_dequeue(r, cur_dst);
	if (ret != 0)
		goto fail;

	free(src);
	free(dst);
	return 0;

 fail:
	free(src);
	free(dst);
	return -1;
}

static int
test_ring_burst_basic(struct rte_ring *r)
{
	void **src = NULL, **cur_src = NULL, **dst = NULL, **cur_dst = NULL;
	int ret;
	unsigned i;

	/* alloc dummy object pointers */
	src = malloc(RING_SIZE*2*sizeof(void *));
	if (src == NULL)
		goto fail;

	for (i = 0; i < RING_SIZE*2 ; i++) {
		src[i] = (void *)(unsigned long)i;
	}
	cur_src = src;

	/* alloc some room for copied objects */
	dst = malloc(RING_SIZE*2*sizeof(void *));
	if (dst == NULL)
		goto fail;

	memset(dst, 0, RING_SIZE*2*sizeof(void *));
	cur_dst = dst;

	printf("Test SP & SC basic functions \n");
	printf("enqueue 1 obj\n");
	ret = rte_ring_sp_enqueue_burst(r, cur_src, 1, NULL);
	cur_src += 1;
	if (ret != 1)
		goto fail;

	printf("enqueue 2 objs\n");
	ret = rte_ring_sp_enqueue_burst(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret != 2)
		goto fail;

	printf("enqueue MAX_BULK objs\n");
	ret = rte_ring_sp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK;
	if (ret != MAX_BULK)
		goto fail;

	printf("dequeue 1 obj\n");
	ret = rte_ring_sc_dequeue_burst(r, cur_dst, 1, NULL);
	cur_dst += 1;
	if (ret != 1)
		goto fail;

	printf("dequeue 2 objs\n");
	ret = rte_ring_sc_dequeue_burst(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret != 2)
		goto fail;

	printf("dequeue MAX_BULK objs\n");
	ret = rte_ring_sc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK;
	if (ret != MAX_BULK)
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("Test enqueue without enough memory space \n");
	for (i = 0; i< (RING_SIZE/MAX_BULK - 1); i++) {
		ret = rte_ring_sp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
		cur_src += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
	}

	printf("Enqueue 2 objects, free entries = MAX_BULK - 2  \n");
	ret = rte_ring_sp_enqueue_burst(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret != 2)
		goto fail;

	printf("Enqueue the remaining entries = MAX_BULK - 2  \n");
	/* Always one free entry left */
	ret = rte_ring_sp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK - 3;
	if (ret != MAX_BULK - 3)
		goto fail;

	printf("Test if ring is full  \n");
	if (rte_ring_full(r) != 1)
		goto fail;

	printf("Test enqueue for a full entry  \n");
	ret = rte_ring_sp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
	if (ret != 0)
		goto fail;

	printf("Test dequeue without enough objects \n");
	for (i = 0; i<RING_SIZE/MAX_BULK - 1; i++) {
		ret = rte_ring_sc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
		cur_dst += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
	}

	/* Available memory space for the exact MAX_BULK entries */
	ret = rte_ring_sc_dequeue_burst(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret != 2)
		goto fail;

	ret = rte_ring_sc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK - 3;
	if (ret != MAX_BULK - 3)
		goto fail;

	printf("Test if ring is empty \n");
	/* Check if ring is empty */
	if (1 != rte_ring_empty(r))
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("Test MP & MC basic functions \n");

	printf("enqueue 1 obj\n");
	ret = rte_ring_mp_enqueue_burst(r, cur_src, 1, NULL);
	cur_src += 1;
	if (ret != 1)
		goto fail;

	printf("enqueue 2 objs\n");
	ret = rte_ring_mp_enqueue_burst(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret != 2)
		goto fail;

	printf("enqueue MAX_BULK objs\n");
	ret = rte_ring_mp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK;
	if (ret != MAX_BULK)
		goto fail;

	printf("dequeue 1 obj\n");
	ret = rte_ring_mc_dequeue_burst(r, cur_dst, 1, NULL);
	cur_dst += 1;
	if (ret != 1)
		goto fail;

	printf("dequeue 2 objs\n");
	ret = rte_ring_mc_dequeue_burst(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret != 2)
		goto fail;

	printf("dequeue MAX_BULK objs\n");
	ret = rte_ring_mc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK;
	if (ret != MAX_BULK)
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("fill and empty the ring\n");
	for (i = 0; i<RING_SIZE/MAX_BULK; i++) {
		ret = rte_ring_mp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
		cur_src += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
		ret = rte_ring_mc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
		cur_dst += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
	}

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("Test enqueue without enough memory space \n");
	for (i = 0; i<RING_SIZE/MAX_BULK - 1; i++) {
		ret = rte_ring_mp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
		cur_src += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
	}

	/* Available memory space for the exact MAX_BULK objects */
	ret = rte_ring_mp_enqueue_burst(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret != 2)
		goto fail;

	ret = rte_ring_mp_enqueue_burst(r, cur_src, MAX_BULK, NULL);
	cur_src += MAX_BULK - 3;
	if (ret != MAX_BULK - 3)
		goto fail;


	printf("Test dequeue without enough objects \n");
	for (i = 0; i<RING_SIZE/MAX_BULK - 1; i++) {
		ret = rte_ring_mc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
		cur_dst += MAX_BULK;
		if (ret != MAX_BULK)
			goto fail;
	}

	/* Available objects - the exact MAX_BULK */
	ret = rte_ring_mc_dequeue_burst(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret != 2)
		goto fail;

	ret = rte_ring_mc_dequeue_burst(r, cur_dst, MAX_BULK, NULL);
	cur_dst += MAX_BULK - 3;
	if (ret != MAX_BULK - 3)
		goto fail;

	/* check data */
	if (memcmp(src, dst, cur_dst - dst)) {
		rte_hexdump(stdout, "src", src, cur_src - src);
		rte_hexdump(stdout, "dst", dst, cur_dst - dst);
		printf("data after dequeue is not the same\n");
		goto fail;
	}

	cur_src = src;
	cur_dst = dst;

	printf("Covering rte_ring_enqueue_burst functions \n");

	ret = rte_ring_enqueue_burst(r, cur_src, 2, NULL);
	cur_src += 2;
	if (ret != 2)
		goto fail;

	ret = rte_ring_dequeue_burst(r, cur_dst, 2, NULL);
	cur_dst += 2;
	if (ret != 2)
		goto fail;

	/* Free memory before test completed */
	free(src);
	free(dst);
	return 0;

 fail:
	free(src);
	free(dst);
	return -1;
}

/*
 * it will always fail to create ring with a wrong ring size number in this function
 */
static int
test_ring_creation_with_wrong_size(void)
{
	struct rte_ring * rp = NULL;

	/* Test if ring size is not power of 2 */
	rp = rte_ring_create("test_bad_ring_size", RING_SIZE + 1, SOCKET_ID_ANY, 0);
	if (NULL != rp) {
		return -1;
	}

	/* Test if ring size is exceeding the limit */
	rp = rte_ring_create("test_bad_ring_size", (RTE_RING_SZ_MASK + 1), SOCKET_ID_ANY, 0);
	if (NULL != rp) {
		return -1;
	}
	return 0;
}

/*
 * it tests if it would always fail to create ring with an used ring name
 */
static int
test_ring_creation_with_an_used_name(void)
{
	struct rte_ring * rp;

	rp = rte_ring_create("test", RING_SIZE, SOCKET_ID_ANY, 0);
	if (NULL != rp)
		return -1;

	return 0;
}

/*
 * Test to if a non-power of 2 count causes the create
 * function to fail correctly
 */
static int
test_create_count_odd(void)
{
	struct rte_ring *r = rte_ring_create("test_ring_count",
			4097, SOCKET_ID_ANY, 0 );
	if(r != NULL){
		return -1;
	}
	return 0;
}

static int
test_lookup_null(void)
{
	struct rte_ring *rlp = rte_ring_lookup("ring_not_found");
	if (rlp ==NULL)
	if (rte_errno != ENOENT){
		printf( "test failed to returnn error on null pointer\n");
		return -1;
	}
	return 0;
}

/*
 * it tests some more basic ring operations
 */
static int
test_ring_basic_ex(void)
{
	int ret = -1;
	unsigned i;
	struct rte_ring *rp = NULL;
	void **obj = NULL;

	obj = rte_calloc("test_ring_basic_ex_malloc", RING_SIZE, sizeof(void *), 0);
	if (obj == NULL) {
		printf("test_ring_basic_ex fail to rte_malloc\n");
		goto fail_test;
	}

	rp = rte_ring_create("test_ring_basic_ex", RING_SIZE, SOCKET_ID_ANY,
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rp == NULL) {
		printf("test_ring_basic_ex fail to create ring\n");
		goto fail_test;
	}

	if (rte_ring_lookup("test_ring_basic_ex") != rp) {
		goto fail_test;
	}

	if (rte_ring_empty(rp) != 1) {
		printf("test_ring_basic_ex ring is not empty but it should be\n");
		goto fail_test;
	}

	printf("%u ring entries are now free\n", rte_ring_free_count(rp));

	for (i = 0; i < RING_SIZE; i ++) {
		rte_ring_enqueue(rp, obj[i]);
	}

	if (rte_ring_full(rp) != 1) {
		printf("test_ring_basic_ex ring is not full but it should be\n");
		goto fail_test;
	}

	for (i = 0; i < RING_SIZE; i ++) {
		rte_ring_dequeue(rp, &obj[i]);
	}

	if (rte_ring_empty(rp) != 1) {
		printf("test_ring_basic_ex ring is not empty but it should be\n");
		goto fail_test;
	}

	/* Covering the ring burst operation */
	ret = rte_ring_enqueue_burst(rp, obj, 2, NULL);
	if (ret != 2) {
		printf("test_ring_basic_ex: rte_ring_enqueue_burst fails \n");
		goto fail_test;
	}

	ret = rte_ring_dequeue_burst(rp, obj, 2, NULL);
	if (ret != 2) {
		printf("test_ring_basic_ex: rte_ring_dequeue_burst fails \n");
		goto fail_test;
	}

	ret = 0;
fail_test:
	rte_ring_free(rp);
	if (obj != NULL)
		rte_free(obj);

	return ret;
}

static int
test_ring_with_exact_size(void)
{
	struct rte_ring *std_ring = NULL, *exact_sz_ring = NULL;
	void *ptr_array[16];
	static const unsigned int ring_sz = RTE_DIM(ptr_array);
	unsigned int i;
	int ret = -1;

	std_ring = rte_ring_create("std", ring_sz, rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (std_ring == NULL) {
		printf("%s: error, can't create std ring\n", __func__);
		goto end;
	}
	exact_sz_ring = rte_ring_create("exact sz", ring_sz, rte_socket_id(),
			RING_F_SP_ENQ | RING_F_SC_DEQ | RING_F_EXACT_SZ);
	if (exact_sz_ring == NULL) {
		printf("%s: error, can't create exact size ring\n", __func__);
		goto end;
	}

	/*
	 * Check that the exact size ring is bigger than the standard ring
	 */
	if (rte_ring_get_size(std_ring) >= rte_ring_get_size(exact_sz_ring)) {
		printf("%s: error, std ring (size: %u) is not smaller than exact size one (size %u)\n",
				__func__,
				rte_ring_get_size(std_ring),
				rte_ring_get_size(exact_sz_ring));
		goto end;
	}
	/*
	 * check that the exact_sz_ring can hold one more element than the
	 * standard ring. (16 vs 15 elements)
	 */
	for (i = 0; i < ring_sz - 1; i++) {
		rte_ring_enqueue(std_ring, NULL);
		rte_ring_enqueue(exact_sz_ring, NULL);
	}
	if (rte_ring_enqueue(std_ring, NULL) != -ENOBUFS) {
		printf("%s: error, unexpected successful enqueue\n", __func__);
		goto end;
	}
	if (rte_ring_enqueue(exact_sz_ring, NULL) == -ENOBUFS) {
		printf("%s: error, enqueue failed\n", __func__);
		goto end;
	}

	/* check that dequeue returns the expected number of elements */
	if (rte_ring_dequeue_burst(exact_sz_ring, ptr_array,
			RTE_DIM(ptr_array), NULL) != ring_sz) {
		printf("%s: error, failed to dequeue expected nb of elements\n",
				__func__);
		goto end;
	}

	/* check that the capacity function returns expected value */
	if (rte_ring_get_capacity(exact_sz_ring) != ring_sz) {
		printf("%s: error, incorrect ring capacity reported\n",
				__func__);
		goto end;
	}

	ret = 0; /* all ok if we get here */
end:
	rte_ring_free(std_ring);
	rte_ring_free(exact_sz_ring);
	return ret;
}

static int
test_ring(void)
{
	struct rte_ring *r = NULL;

	/* some more basic operations */
	if (test_ring_basic_ex() < 0)
		goto test_fail;

	rte_atomic32_init(&synchro);

	r = rte_ring_create("test", RING_SIZE, SOCKET_ID_ANY, 0);
	if (r == NULL)
		goto test_fail;

	/* retrieve the ring from its name */
	if (rte_ring_lookup("test") != r) {
		printf("Cannot lookup ring from its name\n");
		goto test_fail;
	}

	/* burst operations */
	if (test_ring_burst_basic(r) < 0)
		goto test_fail;

	/* basic operations */
	if (test_ring_basic(r) < 0)
		goto test_fail;

	/* basic operations */
	if ( test_create_count_odd() < 0){
		printf("Test failed to detect odd count\n");
		goto test_fail;
	} else
		printf("Test detected odd count\n");

	if ( test_lookup_null() < 0){
		printf("Test failed to detect NULL ring lookup\n");
		goto test_fail;
	} else
		printf("Test detected NULL ring lookup\n");

	/* test of creating ring with wrong size */
	if (test_ring_creation_with_wrong_size() < 0)
		goto test_fail;

	/* test of creation ring with an used name */
	if (test_ring_creation_with_an_used_name() < 0)
		goto test_fail;

	if (test_ring_with_exact_size() < 0)
		goto test_fail;

	/* dump the ring status */
	rte_ring_list_dump(stdout);

	rte_ring_free(r);

	return 0;

test_fail:
	rte_ring_free(r);

	return -1;
}

REGISTER_TEST_COMMAND(ring_autotest, test_ring);
