/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 NXP
 */

#include <stdlib.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <dev_driver.h>
#include <rte_rawdev.h>
#include <bus_vdev_driver.h>
#include <rte_test.h>

/* Using relative path as skeleton_rawdev is not part of exported headers */
#include "skeleton_rawdev.h"

#define TEST_DEV_NAME "rawdev_skeleton"

#define SKELDEV_LOGS(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, skeleton_pmd_logtype, fmt "\n", \
		##args)

#define SKELDEV_TEST_INFO(fmt, args...) \
	SKELDEV_LOGS(INFO, fmt, ## args)
#define SKELDEV_TEST_DEBUG(fmt, args...) \
	SKELDEV_LOGS(DEBUG, fmt, ## args)

#define SKELDEV_TEST_RUN(setup, teardown, test) \
	skeldev_test_run(setup, teardown, test, #test)

#define TEST_SUCCESS 0
#define TEST_FAILED  -1

static int total;
static int passed;
static int failed;
static int unsupported;

static uint16_t test_dev_id;

static int
testsuite_setup(void)
{
	uint8_t count;

	total = 0;
	passed = 0;
	failed = 0;
	unsupported = 0;

	count = rte_rawdev_count();
	if (!count) {
		SKELDEV_TEST_INFO("\tNo existing rawdev; "
				  "Creating 'skeldev_rawdev'");
		return rte_vdev_init(TEST_DEV_NAME, NULL);
	}

	return TEST_SUCCESS;
}

static void local_teardown(void);

static void
testsuite_teardown(void)
{
	local_teardown();
}

static void
local_teardown(void)
{
	rte_vdev_uninit(TEST_DEV_NAME);
}

static int
test_rawdev_count(void)
{
	uint8_t count;
	count = rte_rawdev_count();
	RTE_TEST_ASSERT(count > 0, "Invalid rawdev count %" PRIu8, count);
	return TEST_SUCCESS;
}

static int
test_rawdev_get_dev_id(void)
{
	int ret;
	ret = rte_rawdev_get_dev_id("invalid_rawdev_device");
	RTE_TEST_ASSERT_FAIL(ret, "Expected <0 for invalid dev name ret=%d",
			     ret);
	return TEST_SUCCESS;
}

static int
test_rawdev_socket_id(void)
{
	int socket_id;
	socket_id = rte_rawdev_socket_id(test_dev_id);
	RTE_TEST_ASSERT(socket_id != -EINVAL,
			"Failed to get socket_id %d", socket_id);
	socket_id = rte_rawdev_socket_id(RTE_RAWDEV_MAX_DEVS);
	RTE_TEST_ASSERT(socket_id == -EINVAL,
			"Expected -EINVAL %d", socket_id);

	return TEST_SUCCESS;
}

static int
test_rawdev_info_get(void)
{
	int ret;
	struct rte_rawdev_info rdev_info = {0};
	struct skeleton_rawdev_conf skel_conf = {0};

	ret = rte_rawdev_info_get(test_dev_id, NULL, 0);
	RTE_TEST_ASSERT(ret == -EINVAL, "Expected -EINVAL, %d", ret);

	rdev_info.dev_private = &skel_conf;

	ret = rte_rawdev_info_get(test_dev_id, &rdev_info, sizeof(skel_conf));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to get raw dev info");

	return TEST_SUCCESS;
}

static int
test_rawdev_configure(void)
{
	int ret;
	struct rte_rawdev_info rdev_info = {0};
	struct skeleton_rawdev_conf rdev_conf_set = {0};
	struct skeleton_rawdev_conf rdev_conf_get = {0};

	/* Check invalid configuration */
	ret = rte_rawdev_configure(test_dev_id, NULL, 0);
	RTE_TEST_ASSERT(ret == -EINVAL,
			"Null configure; Expected -EINVAL, got %d", ret);

	/* Valid configuration test */
	rdev_conf_set.num_queues = 1;
	rdev_conf_set.capabilities = SKELETON_CAPA_FW_LOAD |
				     SKELETON_CAPA_FW_RESET;

	rdev_info.dev_private = &rdev_conf_set;
	ret = rte_rawdev_configure(test_dev_id,
				   (rte_rawdev_obj_t)&rdev_info,
				   sizeof(rdev_conf_set));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to configure rawdev (%d)", ret);

	rdev_info.dev_private = &rdev_conf_get;
	ret = rte_rawdev_info_get(test_dev_id,
				  (rte_rawdev_obj_t)&rdev_info,
				  sizeof(rdev_conf_get));
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to obtain rawdev configuration (%d)",
				ret);

	RTE_TEST_ASSERT_EQUAL(rdev_conf_set.num_queues,
			      rdev_conf_get.num_queues,
			      "Configuration test failed; num_queues (%d)(%d)",
			      rdev_conf_set.num_queues,
			      rdev_conf_get.num_queues);
	RTE_TEST_ASSERT_EQUAL(rdev_conf_set.capabilities,
			  rdev_conf_get.capabilities,
			  "Configuration test failed; capabilities");

	return TEST_SUCCESS;
}

static int
test_rawdev_queue_default_conf_get(void)
{
	int ret, i;
	struct rte_rawdev_info rdev_info = {0};
	struct skeleton_rawdev_conf rdev_conf_get = {0};
	struct skeleton_rawdev_queue q = {0};

	/* Get the current configuration */
	rdev_info.dev_private = &rdev_conf_get;
	ret = rte_rawdev_info_get(test_dev_id,
				  (rte_rawdev_obj_t)&rdev_info,
				  sizeof(rdev_conf_get));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to obtain rawdev configuration (%d)",
				ret);

	/* call to test_rawdev_configure would have set the num_queues = 1 */
	RTE_TEST_ASSERT_SUCCESS(!(rdev_conf_get.num_queues > 0),
				"Invalid number of queues (%d). Expected 1",
				rdev_conf_get.num_queues);
	/* All queues by default should have state = DETACH and
	 * depth = DEF_DEPTH
	 */
	for (i = 0; i < rdev_conf_get.num_queues; i++) {
		rte_rawdev_queue_conf_get(test_dev_id, i, &q, sizeof(q));
		RTE_TEST_ASSERT_EQUAL(q.depth, SKELETON_QUEUE_DEF_DEPTH,
				      "Invalid default depth of queue (%d)",
				      q.depth);
		RTE_TEST_ASSERT_EQUAL(q.state, SKELETON_QUEUE_DETACH,
				      "Invalid default state of queue (%d)",
				      q.state);
	}

	return TEST_SUCCESS;
}

static int
test_rawdev_queue_count(void)
{
	unsigned int q_count;

	/* Get the current configuration */
	q_count = rte_rawdev_queue_count(test_dev_id);
	RTE_TEST_ASSERT_EQUAL(q_count, 1, "Invalid queue count (%d)", q_count);

	return TEST_SUCCESS;
}

static int
test_rawdev_queue_setup(void)
{
	int ret;
	struct rte_rawdev_info rdev_info = {0};
	struct skeleton_rawdev_conf rdev_conf_get = {0};
	struct skeleton_rawdev_queue qset = {0};
	struct skeleton_rawdev_queue qget = {0};

	/* Get the current configuration */
	rdev_info.dev_private = &rdev_conf_get;
	ret = rte_rawdev_info_get(test_dev_id,
				  (rte_rawdev_obj_t)&rdev_info,
				  sizeof(rdev_conf_get));
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to obtain rawdev configuration (%d)",
				ret);

	/* call to test_rawdev_configure would have set the num_queues = 1 */
	RTE_TEST_ASSERT_SUCCESS(!(rdev_conf_get.num_queues > 0),
				"Invalid number of queues (%d). Expected 1",
				rdev_conf_get.num_queues);

	/* Modify the queue depth for Queue 0 and attach it */
	qset.depth = 15;
	qset.state = SKELETON_QUEUE_ATTACH;
	ret = rte_rawdev_queue_setup(test_dev_id, 0, &qset, sizeof(qset));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to setup queue (%d)", ret);

	/* Now, fetching the queue 0 should show depth as 15 */
	ret = rte_rawdev_queue_conf_get(test_dev_id, 0, &qget, sizeof(qget));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to get queue config (%d)", ret);

	RTE_TEST_ASSERT_EQUAL(qset.depth, qget.depth,
			      "Failed to set queue depth: Need(%d), has(%d)",
			      qset.depth, qget.depth);

	return TEST_SUCCESS;
}

/* After executing test_rawdev_queue_setup, queue_id=0 would have depth as 15.
 * Releasing should set it back to default. state would set to DETACH
 */
static int
test_rawdev_queue_release(void)
{
	int ret;
	struct skeleton_rawdev_queue qget = {0};

	/* Now, fetching the queue 0 should show depth as 100 */
	ret = rte_rawdev_queue_release(test_dev_id, 0);
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to release queue 0; (%d)", ret);

	/* Now, fetching the queue 0 should show depth as default */
	ret = rte_rawdev_queue_conf_get(test_dev_id, 0, &qget, sizeof(qget));
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to get queue config (%d)", ret);

	RTE_TEST_ASSERT_EQUAL(qget.depth, SKELETON_QUEUE_DEF_DEPTH,
			      "Release of Queue 0 failed; (depth)");

	RTE_TEST_ASSERT_EQUAL(qget.state, SKELETON_QUEUE_DETACH,
			      "Release of Queue 0 failed; (state)");

	return TEST_SUCCESS;
}

static int
test_rawdev_attr_set_get(void)
{
	int ret;
	int *dummy_value, set_value;
	uint64_t ret_value;

	/* Set an attribute and fetch it */
	ret = rte_rawdev_set_attr(test_dev_id, "Test1", 100);
	RTE_TEST_ASSERT(!ret, "Unable to set an attribute (Test1)");

	dummy_value = &set_value;
	*dummy_value = 200;
	ret = rte_rawdev_set_attr(test_dev_id, "Test2", (uintptr_t)dummy_value);
	RTE_TEST_ASSERT(!ret, "Unable to set an attribute (Test2)");

	/* Check if attributes have been set */
	ret = rte_rawdev_get_attr(test_dev_id, "Test1", &ret_value);
	RTE_TEST_ASSERT_EQUAL(ret_value, 100,
			      "Attribute (Test1) not set correctly (%" PRIu64 ")",
			      ret_value);

	ret_value = 0;
	ret = rte_rawdev_get_attr(test_dev_id, "Test2", &ret_value);
	RTE_TEST_ASSERT_EQUAL(*((int *)(uintptr_t)ret_value), set_value,
			      "Attribute (Test2) not set correctly (%" PRIu64 ")",
			      ret_value);

	return TEST_SUCCESS;
}

static int
test_rawdev_start_stop(void)
{
	int ret;
	struct rte_rawdev_info rdev_info = {0};
	struct skeleton_rawdev_conf rdev_conf_get = {0};
	char *dummy_firmware = NULL;

	/* Get the current configuration */
	rdev_info.dev_private = &rdev_conf_get;

	/* Load a firmware using a dummy address area */
	dummy_firmware = rte_zmalloc("RAWDEV SKELETON", sizeof(int) * 10, 0);
	RTE_TEST_ASSERT(dummy_firmware != NULL,
			"Failed to create firmware memory backing");

	ret = rte_rawdev_firmware_load(test_dev_id, dummy_firmware);
	RTE_TEST_ASSERT_SUCCESS(ret, "Firmware loading failed (%d)", ret);

	/* Skeleton doesn't do anything with the firmware area - that is dummy
	 * and can be removed.
	 */
	rte_free(dummy_firmware);
	dummy_firmware = NULL;

	rte_rawdev_start(test_dev_id);
	ret = rte_rawdev_info_get(test_dev_id, (rte_rawdev_obj_t)&rdev_info,
			sizeof(rdev_conf_get));
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to obtain rawdev configuration (%d)",
				ret);
	RTE_TEST_ASSERT_EQUAL(rdev_conf_get.device_state, SKELETON_DEV_RUNNING,
			      "Device start failed. State is (%d)",
			      rdev_conf_get.device_state);

	rte_rawdev_stop(test_dev_id);
	ret = rte_rawdev_info_get(test_dev_id, (rte_rawdev_obj_t)&rdev_info,
			sizeof(rdev_conf_get));
	RTE_TEST_ASSERT_SUCCESS(ret,
				"Failed to obtain rawdev configuration (%d)",
				ret);
	RTE_TEST_ASSERT_EQUAL(rdev_conf_get.device_state, SKELETON_DEV_STOPPED,
			      "Device stop failed. State is (%d)",
			      rdev_conf_get.device_state);

	/* Unloading the firmware once device is stopped */
	ret = rte_rawdev_firmware_unload(test_dev_id);
	RTE_TEST_ASSERT_SUCCESS(ret, "Failed to unload firmware (%d)", ret);

	return TEST_SUCCESS;
}

static int
test_rawdev_enqdeq(void)
{
	int ret;
	uint16_t queue_id = 0;
	struct rte_rawdev_buf buffer;
	struct rte_rawdev_buf *buffers[1];
	struct rte_rawdev_buf deq_buffer;
	struct rte_rawdev_buf *deq_buffers[1];

	buffers[0] = &buffer;
	buffer.buf_addr = malloc(strlen(TEST_DEV_NAME) + 3);
	if (!buffer.buf_addr)
		return TEST_FAILED;
	snprintf(buffer.buf_addr, strlen(TEST_DEV_NAME) + 2, "%s%d",
		 TEST_DEV_NAME, 0);

	ret = rte_rawdev_enqueue_buffers(test_dev_id, buffers,
					 RTE_DIM(buffers), &queue_id);
	RTE_TEST_ASSERT_EQUAL((unsigned int)ret, RTE_DIM(buffers),
			      "Unable to enqueue buffers");

	deq_buffers[0] = &deq_buffer;
	ret = rte_rawdev_dequeue_buffers(test_dev_id, deq_buffers,
					RTE_DIM(deq_buffers), &queue_id);
	RTE_TEST_ASSERT_EQUAL((unsigned int)ret, RTE_DIM(buffers),
			      "Unable to dequeue buffers");
	RTE_TEST_ASSERT_EQUAL(deq_buffers[0]->buf_addr, buffers[0]->buf_addr,
			      "Did not retrieve expected object");

	free(buffer.buf_addr);
	return TEST_SUCCESS;
}

static void skeldev_test_run(int (*setup)(void),
			     void (*teardown)(void),
			     int (*test)(void),
			     const char *name)
{
	int ret = 0;

	if (setup) {
		ret = setup();
		if (ret < 0) {
			SKELDEV_TEST_INFO("Error setting up test %s", name);
			unsupported++;
		}
	}

	if (test) {
		ret = test();
		if (ret < 0) {
			failed++;
			SKELDEV_TEST_INFO("%s Failed", name);
		} else {
			passed++;
			SKELDEV_TEST_DEBUG("%s Passed", name);
		}
	}

	if (teardown)
		teardown();

	total++;
}

int
test_rawdev_skeldev(uint16_t dev_id)
{
	test_dev_id = dev_id;
	testsuite_setup();

	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_count);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_get_dev_id);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_socket_id);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_info_get);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_configure);
	SKELDEV_TEST_RUN(test_rawdev_configure, NULL,
			 test_rawdev_queue_default_conf_get);
	SKELDEV_TEST_RUN(test_rawdev_configure, NULL, test_rawdev_queue_setup);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_queue_count);
	SKELDEV_TEST_RUN(test_rawdev_queue_setup, NULL,
			 test_rawdev_queue_release);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_attr_set_get);
	SKELDEV_TEST_RUN(NULL, NULL, test_rawdev_start_stop);
	SKELDEV_TEST_RUN(test_rawdev_queue_setup, NULL, test_rawdev_enqdeq);

	testsuite_teardown();

	SKELDEV_TEST_INFO("Total tests   : %d", total);
	SKELDEV_TEST_INFO("Passed        : %d", passed);
	SKELDEV_TEST_INFO("Failed        : %d", failed);
	SKELDEV_TEST_INFO("Not supported : %d", unsupported);

	if (failed)
		return -1;

	return 0;
};
