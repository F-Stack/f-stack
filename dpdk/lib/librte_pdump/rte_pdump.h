/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation
 */

#ifndef _RTE_PDUMP_H_
#define _RTE_PDUMP_H_

/**
 * @file
 * RTE pdump
 *
 * packet dump library to provide packet capturing support on dpdk.
 */

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_PDUMP_ALL_QUEUES UINT16_MAX

enum {
	RTE_PDUMP_FLAG_RX = 1,  /* receive direction */
	RTE_PDUMP_FLAG_TX = 2,  /* transmit direction */
	/* both receive and transmit directions */
	RTE_PDUMP_FLAG_RXTX = (RTE_PDUMP_FLAG_RX|RTE_PDUMP_FLAG_TX)
};

enum rte_pdump_socktype {
	RTE_PDUMP_SOCKET_SERVER = 1,
	RTE_PDUMP_SOCKET_CLIENT = 2
};

/**
 * Initialize packet capturing handling
 *
 * Register the IPC action for communication with target (primary) process.
 *
 * @param path
 * This parameter is going to be deprecated; it was used for specifying the
 * directory path for server socket.
 *
 * @return
 *    0 on success, -1 on error
 */
int
rte_pdump_init(const char *path);

/**
 * Un initialize packet capturing handling
 *
 * Unregister the IPC action for communication with target (primary) process.
 *
 * @return
 *    0 on success, -1 on error
 */
int
rte_pdump_uninit(void);

/**
 * Enables packet capturing on given port and queue.
 *
 * @param port
 *  port on which packet capturing should be enabled.
 * @param queue
 *  queue of a given port on which packet capturing should be enabled.
 *  users should pass on value UINT16_MAX to enable packet capturing on all
 *  queues of a given port.
 * @param flags
 *  flags specifies RTE_PDUMP_FLAG_RX/RTE_PDUMP_FLAG_TX/RTE_PDUMP_FLAG_RXTX
 *  on which packet capturing should be enabled for a given port and queue.
 * @param ring
 *  ring on which captured packets will be enqueued for user.
 * @param mp
 *  mempool on to which original packets will be mirrored or duplicated.
 * @param filter
 *  place holder for packet filtering.
 *
 * @return
 *    0 on success, -1 on error, rte_errno is set accordingly.
 */

int
rte_pdump_enable(uint16_t port, uint16_t queue, uint32_t flags,
		struct rte_ring *ring,
		struct rte_mempool *mp,
		void *filter);

/**
 * Disables packet capturing on given port and queue.
 *
 * @param port
 *  port on which packet capturing should be disabled.
 * @param queue
 *  queue of a given port on which packet capturing should be disabled.
 *  users should pass on value UINT16_MAX to disable packet capturing on all
 *  queues of a given port.
 * @param flags
 *  flags specifies RTE_PDUMP_FLAG_RX/RTE_PDUMP_FLAG_TX/RTE_PDUMP_FLAG_RXTX
 *  on which packet capturing should be enabled for a given port and queue.
 *
 * @return
 *    0 on success, -1 on error, rte_errno is set accordingly.
 */

int
rte_pdump_disable(uint16_t port, uint16_t queue, uint32_t flags);

/**
 * Enables packet capturing on given device id and queue.
 * device_id can be name or pci address of device.
 *
 * @param device_id
 *  device id on which packet capturing should be enabled.
 * @param queue
 *  queue of a given device id on which packet capturing should be enabled.
 *  users should pass on value UINT16_MAX to enable packet capturing on all
 *  queues of a given device id.
 * @param flags
 *  flags specifies RTE_PDUMP_FLAG_RX/RTE_PDUMP_FLAG_TX/RTE_PDUMP_FLAG_RXTX
 *  on which packet capturing should be enabled for a given port and queue.
 * @param ring
 *  ring on which captured packets will be enqueued for user.
 * @param mp
 *  mempool on to which original packets will be mirrored or duplicated.
 * @param filter
 *  place holder for packet filtering.
 *
 * @return
 *    0 on success, -1 on error, rte_errno is set accordingly.
 */

int
rte_pdump_enable_by_deviceid(char *device_id, uint16_t queue,
				uint32_t flags,
				struct rte_ring *ring,
				struct rte_mempool *mp,
				void *filter);

/**
 * Disables packet capturing on given device_id and queue.
 * device_id can be name or pci address of device.
 *
 * @param device_id
 *  pci address or name of the device on which packet capturing
 *  should be disabled.
 * @param queue
 *  queue of a given device on which packet capturing should be disabled.
 *  users should pass on value UINT16_MAX to disable packet capturing on all
 *  queues of a given device id.
 * @param flags
 *  flags specifies RTE_PDUMP_FLAG_RX/RTE_PDUMP_FLAG_TX/RTE_PDUMP_FLAG_RXTX
 *  on which packet capturing should be enabled for a given port and queue.
 *
 * @return
 *    0 on success, -1 on error, rte_errno is set accordingly.
 */
int
rte_pdump_disable_by_deviceid(char *device_id, uint16_t queue,
				uint32_t flags);

/**
 * @deprecated
 * Allows applications to set server and client socket paths.
 * If specified path is null default path will be selected, i.e.
 *"/var/run/" for root user and "$HOME" for non root user.
 * Clients also need to call this API to set their server path if the
 * server path is different from default path.
 * This API is not thread-safe.
 *
 * @param path
 * directory path for server or client socket.
 * @param type
 * specifies RTE_PDUMP_SOCKET_SERVER if socket path is for server.
 * (or)
 * specifies RTE_PDUMP_SOCKET_CLIENT if socket path is for client.
 *
 * @return
 * 0 on success, -EINVAL on error
 *
 */
__rte_deprecated int
rte_pdump_set_socket_dir(const char *path, enum rte_pdump_socktype type);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PDUMP_H_ */
