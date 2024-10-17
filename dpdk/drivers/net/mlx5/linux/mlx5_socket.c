/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "rte_eal.h"
#include "mlx5_utils.h"
#include "mlx5.h"

/* PMD socket service for tools. */

#define MLX5_SOCKET_PATH "/var/tmp/dpdk_net_mlx5_%d"

int server_socket = -1; /* Unix socket for primary process. */
struct rte_intr_handle *server_intr_handle; /* Interrupt handler. */

/**
 * Handle server pmd socket interrupts.
 */
static void
mlx5_pmd_socket_handle(void *cb __rte_unused)
{
	int conn_sock;
	int ret;
	struct cmsghdr *cmsg = NULL;
	uint32_t data[MLX5_SENDMSG_MAX / sizeof(uint32_t)];
	uint64_t flow_ptr = 0;
	uint8_t  buf[CMSG_SPACE(sizeof(int))] = { 0 };
	struct iovec io = {
		.iov_base = data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_iov = &io,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};

	uint32_t port_id;
	int fd;
	FILE *file = NULL;
	struct rte_eth_dev *dev;
	struct rte_flow_error err;
	struct mlx5_flow_dump_req  *dump_req;
	struct mlx5_flow_dump_ack  *dump_ack;

	memset(data, 0, sizeof(data));
	/* Accept the connection from the client. */
	conn_sock = accept(server_socket, NULL, NULL);
	if (conn_sock < 0) {
		DRV_LOG(WARNING, "connection failed: %s", strerror(errno));
		return;
	}
	ret = recvmsg(conn_sock, &msg, MSG_WAITALL);
	if (ret != sizeof(struct mlx5_flow_dump_req)) {
		DRV_LOG(WARNING, "wrong message received: %s",
			strerror(errno));
		goto error;
	}

	/* Receive file descriptor. */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_type != SCM_RIGHTS ||
	    cmsg->cmsg_len < sizeof(int)) {
		DRV_LOG(WARNING, "invalid file descriptor message");
		goto error;
	}
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	file = fdopen(fd, "w");
	if (!file) {
		DRV_LOG(WARNING, "Failed to open file");
		goto error;
	}
	/* Receive port number. */
	if (msg.msg_iovlen != 1 || msg.msg_iov->iov_len < sizeof(uint16_t)) {
		DRV_LOG(WARNING, "wrong port number message");
		goto error;
	}

	dump_req = (struct mlx5_flow_dump_req *)msg.msg_iov->iov_base;
	if (dump_req) {
		port_id = dump_req->port_id;
		flow_ptr = dump_req->flow_id;
	} else {
		DRV_LOG(WARNING, "Invalid message");
		goto error;
	}

	if (!rte_eth_dev_is_valid_port(port_id)) {
		DRV_LOG(WARNING, "Invalid port %u", port_id);
		goto error;
	}

	/* Dump flow. */
	dev = &rte_eth_devices[port_id];
	if (flow_ptr == 0)
		ret = mlx5_flow_dev_dump(dev, NULL, file, NULL);
	else
		ret = mlx5_flow_dev_dump(dev,
			(struct rte_flow *)((uintptr_t)flow_ptr), file, &err);

	/* Set-up the ancillary data and reply. */
	msg.msg_controllen = 0;
	msg.msg_control = NULL;
	msg.msg_iovlen = 1;
	msg.msg_iov = &io;
	dump_ack = (struct mlx5_flow_dump_ack *)data;
	dump_ack->rc = -ret;
	io.iov_len = sizeof(struct mlx5_flow_dump_ack);
	io.iov_base = dump_ack;
	do {
		ret = sendmsg(conn_sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0)
		DRV_LOG(WARNING, "failed to send response %s",
			strerror(errno));
error:
	if (conn_sock >= 0)
		close(conn_sock);
	if (file)
		fclose(file);
}

/**
 * Initialise the socket to communicate with external tools.
 *
 * @return
 *   0 on success, a negative value otherwise.
 */
int
mlx5_pmd_socket_init(void)
{
	struct sockaddr_un sun = {
		.sun_family = AF_UNIX,
	};
	int ret;
	int flags;

	MLX5_ASSERT(rte_eal_process_type() == RTE_PROC_PRIMARY);
	if (server_socket != -1)
		return 0;
	ret = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret < 0) {
		DRV_LOG(WARNING, "Failed to open mlx5 socket: %s",
			strerror(errno));
		goto error;
	}
	server_socket = ret;
	flags = fcntl(server_socket, F_GETFL, 0);
	if (flags == -1)
		goto close;
	ret = fcntl(server_socket, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		goto close;
	snprintf(sun.sun_path, sizeof(sun.sun_path), MLX5_SOCKET_PATH,
		 getpid());
	remove(sun.sun_path);
	ret = bind(server_socket, (const struct sockaddr *)&sun, sizeof(sun));
	if (ret < 0) {
		DRV_LOG(WARNING,
			"cannot bind mlx5 socket: %s", strerror(errno));
		goto remove;
	}
	ret = listen(server_socket, 0);
	if (ret < 0) {
		DRV_LOG(WARNING, "cannot listen on mlx5 socket: %s",
			strerror(errno));
		goto remove;
	}
	server_intr_handle = mlx5_os_interrupt_handler_create
		(RTE_INTR_INSTANCE_F_PRIVATE, false,
		 server_socket, mlx5_pmd_socket_handle, NULL);
	if (server_intr_handle == NULL) {
		DRV_LOG(WARNING, "cannot register interrupt handler for mlx5 socket: %s",
			strerror(errno));
		goto remove;
	}
	return 0;
remove:
	remove(sun.sun_path);
close:
	claim_zero(close(server_socket));
	server_socket = -1;
error:
	DRV_LOG(ERR, "Cannot initialize socket: %s", strerror(errno));
	return -errno;
}

/**
 * Un-Initialize the pmd socket
 */
void
mlx5_pmd_socket_uninit(void)
{
	if (server_socket == -1)
		return;
	mlx5_os_interrupt_handler_destroy(server_intr_handle,
					  mlx5_pmd_socket_handle, NULL);
	claim_zero(close(server_socket));
	server_socket = -1;
	MKSTR(path, MLX5_SOCKET_PATH, getpid());
	claim_zero(remove(path));
}
