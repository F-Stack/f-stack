/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 6WIND S.A.
 * Copyright 2017 Mellanox Technologies, Ltd
 */

#include <inttypes.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <string.h>

#include <rte_log.h>
#include <tap_tcmsgs.h>
#include "tap_log.h"

struct qdisc {
	uint32_t handle;
	uint32_t parent;
};

struct list_args {
	int nlsk_fd;
	uint16_t ifindex;
	void *custom_arg;
};

struct qdisc_custom_arg {
	uint32_t handle;
	uint32_t parent;
	uint8_t exists;
};

/**
 * Initialize a netlink message with a TC header.
 *
 * @param[in, out] msg
 *   The netlink message to fill.
 * @param[in] ifindex
 *   The netdevice ifindex where the rule will be applied.
 * @param[in] type
 *   The type of TC message to create (RTM_NEWTFILTER, RTM_NEWQDISC, etc.).
 * @param[in] flags
 *   Overrides the default netlink flags for this msg with those specified.
 */
void
tc_init_msg(struct nlmsg *msg, uint16_t ifindex, uint16_t type, uint16_t flags)
{
	struct nlmsghdr *n = &msg->nh;

	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	n->nlmsg_type = type;
	if (flags)
		n->nlmsg_flags = flags;
	else
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	msg->t.tcm_family = AF_UNSPEC;
	msg->t.tcm_ifindex = ifindex;
}

/**
 * Delete a specific QDISC identified by its iface, and it's handle and parent.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex on whom the deletion will happen.
 * @param[in] qinfo
 *   Additional info to identify the QDISC (handle and parent).
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
static int
qdisc_del(int nlsk_fd, uint16_t ifindex, struct qdisc *qinfo)
{
	struct nlmsg msg;
	int fd = 0;

	tc_init_msg(&msg, ifindex, RTM_DELQDISC, 0);
	msg.t.tcm_handle = qinfo->handle;
	msg.t.tcm_parent = qinfo->parent;
	/* if no netlink socket is provided, create one */
	if (!nlsk_fd) {
		fd = tap_nl_init(0);
		if (fd < 0) {
			TAP_LOG(ERR,
				"Could not delete QDISC: null netlink socket");
			return -1;
		}
	} else {
		fd = nlsk_fd;
	}
	if (tap_nl_send(fd, &msg.nh) < 0)
		goto error;
	if (tap_nl_recv_ack(fd) < 0)
		goto error;
	if (!nlsk_fd)
		return tap_nl_final(fd);
	return 0;
error:
	if (!nlsk_fd)
		tap_nl_final(fd);
	return -1;
}

/**
 * Add the multiqueue QDISC with MULTIQ_MAJOR_HANDLE handle.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where to add the multiqueue QDISC.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int
qdisc_add_multiq(int nlsk_fd, uint16_t ifindex)
{
	struct tc_multiq_qopt opt = {0};
	struct nlmsg msg;

	tc_init_msg(&msg, ifindex, RTM_NEWQDISC,
		    NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
	msg.t.tcm_handle = TC_H_MAKE(MULTIQ_MAJOR_HANDLE, 0);
	msg.t.tcm_parent = TC_H_ROOT;
	tap_nlattr_add(&msg.nh, TCA_KIND, sizeof("multiq"), "multiq");
	tap_nlattr_add(&msg.nh, TCA_OPTIONS, sizeof(opt), &opt);
	if (tap_nl_send(nlsk_fd, &msg.nh) < 0)
		return -1;
	if (tap_nl_recv_ack(nlsk_fd) < 0)
		return -1;
	return 0;
}

/**
 * Add the ingress QDISC with default ffff: handle.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where the QDISC will be added.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int
qdisc_add_ingress(int nlsk_fd, uint16_t ifindex)
{
	struct nlmsg msg;

	tc_init_msg(&msg, ifindex, RTM_NEWQDISC,
		    NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
	msg.t.tcm_handle = TC_H_MAKE(TC_H_INGRESS, 0);
	msg.t.tcm_parent = TC_H_INGRESS;
	tap_nlattr_add(&msg.nh, TCA_KIND, sizeof("ingress"), "ingress");
	if (tap_nl_send(nlsk_fd, &msg.nh) < 0)
		return -1;
	if (tap_nl_recv_ack(nlsk_fd) < 0)
		return -1;
	return 0;
}

/**
 * Callback function to delete a QDISC.
 *
 * @param[in] nh
 *   The netlink message to parse, received from the kernel.
 * @param[in] arg
 *   Custom arguments for the callback.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
static int
qdisc_del_cb(struct nlmsghdr *nh, void *arg)
{
	struct tcmsg *t = NLMSG_DATA(nh);
	struct list_args *args = arg;

	struct qdisc qinfo = {
		.handle = t->tcm_handle,
		.parent = t->tcm_parent,
	};

	/* filter out other ifaces' qdiscs */
	if (args->ifindex != (unsigned int)t->tcm_ifindex)
		return 0;
	/*
	 * Use another nlsk_fd (0) to avoid tampering with the current list
	 * iteration.
	 */
	return qdisc_del(0, args->ifindex, &qinfo);
}

/**
 * Iterate over all QDISC, and call the callback() function for each.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where to find QDISCs.
 * @param[in] callback
 *   The function to call for each QDISC.
 * @param[in, out] arg
 *   The arguments to provide the callback function with.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
static int
qdisc_iterate(int nlsk_fd, uint16_t ifindex,
	      int (*callback)(struct nlmsghdr *, void *), void *arg)
{
	struct nlmsg msg;
	struct list_args args = {
		.nlsk_fd = nlsk_fd,
		.ifindex = ifindex,
		.custom_arg = arg,
	};

	tc_init_msg(&msg, ifindex, RTM_GETQDISC, NLM_F_REQUEST | NLM_F_DUMP);
	if (tap_nl_send(nlsk_fd, &msg.nh) < 0)
		return -1;
	if (tap_nl_recv(nlsk_fd, callback, &args) < 0)
		return -1;
	return 0;
}

/**
 * Delete all QDISCs for a given netdevice.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where to find QDISCs.
 *
 * @return
 *   0 on success, -1 otherwise with errno set.
 */
int
qdisc_flush(int nlsk_fd, uint16_t ifindex)
{
	return qdisc_iterate(nlsk_fd, ifindex, qdisc_del_cb, NULL);
}

/**
 * Create the multiqueue QDISC, only if it does not exist already.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where to add the multiqueue QDISC.
 *
 * @return
 *   0 if the qdisc exists or if has been successfully added.
 *   Return -1 otherwise.
 */
int
qdisc_create_multiq(int nlsk_fd, uint16_t ifindex)
{
	int err = 0;

	err = qdisc_add_multiq(nlsk_fd, ifindex);
	if (err < 0 && errno != -EEXIST) {
		TAP_LOG(ERR, "Could not add multiq qdisc (%d): %s",
			errno, strerror(errno));
		return -1;
	}
	return 0;
}

/**
 * Create the ingress QDISC, only if it does not exist already.
 *
 * @param[in] nlsk_fd
 *   The netlink socket file descriptor used for communication.
 * @param[in] ifindex
 *   The netdevice ifindex where to add the ingress QDISC.
 *
 * @return
 *   0 if the qdisc exists or if has been successfully added.
 *   Return -1 otherwise.
 */
int
qdisc_create_ingress(int nlsk_fd, uint16_t ifindex)
{
	int err = 0;

	err = qdisc_add_ingress(nlsk_fd, ifindex);
	if (err < 0 && errno != -EEXIST) {
		TAP_LOG(ERR, "Could not add ingress qdisc (%d): %s",
			errno, strerror(errno));
		return -1;
	}
	return 0;
}
