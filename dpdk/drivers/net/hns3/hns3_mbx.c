/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2021 HiSilicon Limited.
 */

#include <ethdev_driver.h>
#include <rte_io.h>

#include "hns3_common.h"
#include "hns3_regs.h"
#include "hns3_logs.h"
#include "hns3_intr.h"
#include "hns3_rxtx.h"

static const struct errno_respcode_map err_code_map[] = {
	{0, 0},
	{1, -EPERM},
	{2, -ENOENT},
	{5, -EIO},
	{11, -EAGAIN},
	{12, -ENOMEM},
	{16, -EBUSY},
	{22, -EINVAL},
	{28, -ENOSPC},
	{95, -EOPNOTSUPP},
};

void
hns3vf_mbx_setup(struct hns3_vf_to_pf_msg *req, uint8_t code, uint8_t subcode)
{
	memset(req, 0, sizeof(struct hns3_vf_to_pf_msg));
	req->code = code;
	req->subcode = subcode;
}

static int
hns3_resp_to_errno(uint16_t resp_code)
{
	uint32_t i, num;

	num = sizeof(err_code_map) / sizeof(struct errno_respcode_map);
	for (i = 0; i < num; i++) {
		if (err_code_map[i].resp_code == resp_code)
			return err_code_map[i].err_no;
	}

	return -EIO;
}

static int
hns3_get_mbx_resp(struct hns3_hw *hw, uint16_t code, uint16_t subcode,
		  uint8_t *resp_data, uint16_t resp_len)
{
#define HNS3_WAIT_RESP_US	100
#define US_PER_MS		1000
	uint32_t mbx_time_limit;
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_mbx_resp_status *mbx_resp;
	uint32_t wait_time = 0;

	if (resp_len > HNS3_MBX_MAX_RESP_DATA_SIZE) {
		hns3_err(hw, "VF mbx response len(=%u) exceeds maximum(=%d)",
			 resp_len, HNS3_MBX_MAX_RESP_DATA_SIZE);
		return -EINVAL;
	}

	mbx_time_limit = (uint32_t)hns->mbx_time_limit_ms * US_PER_MS;
	while (wait_time < mbx_time_limit) {
		if (__atomic_load_n(&hw->reset.disable_cmd, __ATOMIC_RELAXED)) {
			hns3_err(hw, "Don't wait for mbx response because of "
				 "disable_cmd");
			return -EBUSY;
		}

		if (is_reset_pending(hns)) {
			hw->mbx_resp.req_msg_data = 0;
			hns3_err(hw, "Don't wait for mbx response because of "
				 "reset pending");
			return -EIO;
		}

		hns3vf_handle_mbx_msg(hw);
		rte_delay_us(HNS3_WAIT_RESP_US);

		if (hw->mbx_resp.received_match_resp)
			break;

		wait_time += HNS3_WAIT_RESP_US;
	}
	hw->mbx_resp.req_msg_data = 0;
	if (wait_time >= mbx_time_limit) {
		hns3_err(hw, "VF could not get mbx(%u,%u) from PF", code, subcode);
		return -ETIME;
	}
	rte_io_rmb();
	mbx_resp = &hw->mbx_resp;

	if (mbx_resp->resp_status)
		return mbx_resp->resp_status;

	if (resp_data)
		memcpy(resp_data, &mbx_resp->additional_info[0], resp_len);

	return 0;
}

static void
hns3_mbx_prepare_resp(struct hns3_hw *hw, uint16_t code, uint16_t subcode)
{
	/*
	 * Init both matching scheme fields because we may not know the exact
	 * scheme will be used when in the initial phase.
	 *
	 * Also, there are OK to init both matching scheme fields even though
	 * we get the exact scheme which is used.
	 */
	hw->mbx_resp.req_msg_data = (uint32_t)code << 16 | subcode;

	/* Update match_id and ensure the value of match_id is not zero */
	hw->mbx_resp.match_id++;
	if (hw->mbx_resp.match_id == 0)
		hw->mbx_resp.match_id = 1;
	hw->mbx_resp.received_match_resp = false;

	hw->mbx_resp.resp_status = 0;
	memset(hw->mbx_resp.additional_info, 0, HNS3_MBX_MAX_RESP_DATA_SIZE);
}

int
hns3vf_mbx_send(struct hns3_hw *hw,
		struct hns3_vf_to_pf_msg *req, bool need_resp,
		uint8_t *resp_data, uint16_t resp_len)
{
	struct hns3_mbx_vf_to_pf_cmd *cmd;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MBX_VF_TO_PF, false);
	cmd = (struct hns3_mbx_vf_to_pf_cmd *)desc.data;
	cmd->msg = *req;

	/* synchronous send */
	if (need_resp) {
		cmd->mbx_need_resp |= HNS3_MBX_NEED_RESP_BIT;
		rte_spinlock_lock(&hw->mbx_resp.lock);
		hns3_mbx_prepare_resp(hw, req->code, req->subcode);
		cmd->match_id = hw->mbx_resp.match_id;
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			rte_spinlock_unlock(&hw->mbx_resp.lock);
			hns3_err(hw, "VF failed(=%d) to send mbx message to PF",
				 ret);
			return ret;
		}

		ret = hns3_get_mbx_resp(hw, req->code, req->subcode,
					resp_data, resp_len);
		rte_spinlock_unlock(&hw->mbx_resp.lock);
	} else {
		/* asynchronous send */
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			hns3_err(hw, "VF failed(=%d) to send mbx message to PF",
				 ret);
			return ret;
		}
	}

	return ret;
}

static bool
hns3_cmd_crq_empty(struct hns3_hw *hw)
{
	uint32_t tail = hns3_read_dev(hw, HNS3_CMDQ_RX_TAIL_REG);

	return tail == hw->cmq.crq.next_to_use;
}

static void
hns3vf_handle_link_change_event(struct hns3_hw *hw,
				struct hns3_mbx_pf_to_vf_cmd *req)
{
	struct hns3_mbx_link_status *link_info =
		(struct hns3_mbx_link_status *)req->msg.msg_data;
	uint8_t link_status, link_duplex;
	uint8_t support_push_lsc;
	uint32_t link_speed;

	link_status = (uint8_t)rte_le_to_cpu_16(link_info->link_status);
	link_speed = rte_le_to_cpu_32(link_info->speed);
	link_duplex = (uint8_t)rte_le_to_cpu_16(link_info->duplex);
	hns3vf_update_link_status(hw, link_status, link_speed, link_duplex);
	support_push_lsc = (link_info->flag) & 1u;
	hns3vf_update_push_lsc_cap(hw, support_push_lsc);
}

static void
hns3_handle_asserting_reset(struct hns3_hw *hw,
			    struct hns3_mbx_pf_to_vf_cmd *req)
{
	enum hns3_reset_level reset_level;

	/*
	 * PF has asserted reset hence VF should go in pending
	 * state and poll for the hardware reset status till it
	 * has been completely reset. After this stack should
	 * eventually be re-initialized.
	 */
	reset_level = rte_le_to_cpu_16(req->msg.reset_level);
	hns3_atomic_set_bit(reset_level, &hw->reset.pending);

	hns3_warn(hw, "PF inform reset level %d", reset_level);
	hw->reset.stats.request_cnt++;
	hns3_schedule_reset(HNS3_DEV_HW_TO_ADAPTER(hw));
}

static void
hns3_handle_mbx_response(struct hns3_hw *hw, struct hns3_mbx_pf_to_vf_cmd *req)
{
#define HNS3_MBX_RESP_CODE_OFFSET 16
	struct hns3_mbx_resp_status *resp = &hw->mbx_resp;
	uint32_t msg_data;

	if (req->match_id != 0) {
		/*
		 * If match_id is not zero, it means PF support copy request's
		 * match_id to its response. So VF could use the match_id
		 * to match the request.
		 */
		if (req->match_id == resp->match_id) {
			resp->resp_status =
				hns3_resp_to_errno(req->msg.resp_status);
			memcpy(resp->additional_info, &req->msg.resp_data,
			       HNS3_MBX_MAX_RESP_DATA_SIZE);
			rte_io_wmb();
			resp->received_match_resp = true;
		}
		return;
	}

	/*
	 * If the below instructions can be executed, it means PF does not
	 * support copy request's match_id to its response. So VF follows the
	 * original scheme to process.
	 */
	msg_data = (uint32_t)req->msg.vf_mbx_msg_code <<
			HNS3_MBX_RESP_CODE_OFFSET | req->msg.vf_mbx_msg_subcode;
	if (resp->req_msg_data != msg_data) {
		hns3_warn(hw,
			"received response tag (%u) is mismatched with requested tag (%u)",
			msg_data, resp->req_msg_data);
		return;
	}

	resp->resp_status = hns3_resp_to_errno(req->msg.resp_status);
	memcpy(resp->additional_info, &req->msg.resp_data,
	       HNS3_MBX_MAX_RESP_DATA_SIZE);
	rte_io_wmb();
	resp->received_match_resp = true;
}

static void
hns3_link_fail_parse(struct hns3_hw *hw, uint8_t link_fail_code)
{
	switch (link_fail_code) {
	case HNS3_MBX_LF_NORMAL:
		break;
	case HNS3_MBX_LF_REF_CLOCK_LOST:
		hns3_warn(hw, "Reference clock lost!");
		break;
	case HNS3_MBX_LF_XSFP_TX_DISABLE:
		hns3_warn(hw, "SFP tx is disabled!");
		break;
	case HNS3_MBX_LF_XSFP_ABSENT:
		hns3_warn(hw, "SFP is absent!");
		break;
	default:
		hns3_warn(hw, "Unknown fail code:%u!", link_fail_code);
		break;
	}
}

static void
hns3pf_handle_link_change_event(struct hns3_hw *hw,
				struct hns3_mbx_vf_to_pf_cmd *req)
{
	if (!req->msg.link_status)
		hns3_link_fail_parse(hw, req->msg.link_fail_code);

	hns3_update_linkstatus_and_event(hw, true);
}

static void
hns3_update_port_base_vlan_info(struct hns3_hw *hw,
				struct hns3_mbx_pf_to_vf_cmd *req)
{
	uint16_t new_pvid_state = req->msg.pvid_state ?
		HNS3_PORT_BASE_VLAN_ENABLE : HNS3_PORT_BASE_VLAN_DISABLE;
	/*
	 * Currently, hardware doesn't support more than two layers VLAN offload
	 * based on hns3 network engine, which would cause packets loss or wrong
	 * packets for these types of packets. If the hns3 PF kernel ethdev
	 * driver sets the PVID for VF device after initialization of the
	 * related VF device, the PF driver will notify VF driver to update the
	 * PVID configuration state. The VF driver will update the PVID
	 * configuration state immediately to ensure that the VLAN process in Tx
	 * and Rx is correct. But in the window period of this state transition,
	 * packets loss or packets with wrong VLAN may occur.
	 */
	if (hw->port_base_vlan_cfg.state != new_pvid_state) {
		hw->port_base_vlan_cfg.state = new_pvid_state;
		hns3_update_all_queues_pvid_proc_en(hw);
	}
}

static void
hns3_handle_promisc_info(struct hns3_hw *hw, uint16_t promisc_en)
{
	if (!promisc_en) {
		/*
		 * When promisc/allmulti mode is closed by the hns3 PF kernel
		 * ethdev driver for untrusted, modify VF's related status.
		 */
		hns3_warn(hw, "Promisc mode will be closed by host for being "
			      "untrusted.");
		hw->data->promiscuous = 0;
		hw->data->all_multicast = 0;
	}
}

static void
hns3_handle_mbx_msg_out_intr(struct hns3_hw *hw)
{
	struct hns3_cmq_ring *crq = &hw->cmq.crq;
	struct hns3_mbx_pf_to_vf_cmd *req;
	struct hns3_cmd_desc *desc;
	uint32_t tail, next_to_use;
	uint8_t opcode;
	uint16_t flag;

	tail = hns3_read_dev(hw, HNS3_CMDQ_RX_TAIL_REG);
	next_to_use = crq->next_to_use;
	while (next_to_use != tail) {
		desc = &crq->desc[next_to_use];
		req = (struct hns3_mbx_pf_to_vf_cmd *)desc->data;
		opcode = req->msg.code & 0xff;

		flag = rte_le_to_cpu_16(crq->desc[next_to_use].flag);
		if (!hns3_get_bit(flag, HNS3_CMDQ_RX_OUTVLD_B))
			goto scan_next;

		if (crq->desc[next_to_use].opcode == 0)
			goto scan_next;

		if (opcode == HNS3_MBX_PF_VF_RESP) {
			hns3_handle_mbx_response(hw, req);
			/*
			 * Clear opcode to inform intr thread don't process
			 * again.
			 */
			crq->desc[next_to_use].opcode = 0;
		}

scan_next:
		next_to_use = (next_to_use + 1) % hw->cmq.crq.desc_num;
	}

	/*
	 * Note: the crq->next_to_use field should not updated, otherwise,
	 * mailbox messages may be discarded.
	 */
}

void
hns3pf_handle_mbx_msg(struct hns3_hw *hw)
{
	struct hns3_cmq_ring *crq = &hw->cmq.crq;
	struct hns3_mbx_vf_to_pf_cmd *req;
	struct hns3_cmd_desc *desc;
	uint16_t flag;

	rte_spinlock_lock(&hw->cmq.crq.lock);

	while (!hns3_cmd_crq_empty(hw)) {
		if (__atomic_load_n(&hw->reset.disable_cmd, __ATOMIC_RELAXED)) {
			rte_spinlock_unlock(&hw->cmq.crq.lock);
			return;
		}
		desc = &crq->desc[crq->next_to_use];
		req = (struct hns3_mbx_vf_to_pf_cmd *)desc->data;

		flag = rte_le_to_cpu_16(crq->desc[crq->next_to_use].flag);
		if (unlikely(!hns3_get_bit(flag, HNS3_CMDQ_RX_OUTVLD_B))) {
			hns3_warn(hw,
				  "dropped invalid mailbox message, code = %u",
				  req->msg.code);

			/* dropping/not processing this invalid message */
			crq->desc[crq->next_to_use].flag = 0;
			hns3_mbx_ring_ptr_move_crq(crq);
			continue;
		}

		switch (req->msg.code) {
		case HNS3_MBX_PUSH_LINK_STATUS:
			hns3pf_handle_link_change_event(hw, req);
			break;
		default:
			hns3_err(hw, "received unsupported(%u) mbx msg",
				 req->msg.code);
			break;
		}
		crq->desc[crq->next_to_use].flag = 0;
		hns3_mbx_ring_ptr_move_crq(crq);
	}

	/* Write back CMDQ_RQ header pointer, IMP need this pointer */
	hns3_write_dev(hw, HNS3_CMDQ_RX_HEAD_REG, crq->next_to_use);

	rte_spinlock_unlock(&hw->cmq.crq.lock);
}

void
hns3vf_handle_mbx_msg(struct hns3_hw *hw)
{
	struct hns3_cmq_ring *crq = &hw->cmq.crq;
	struct hns3_mbx_pf_to_vf_cmd *req;
	struct hns3_cmd_desc *desc;
	bool handle_out;
	uint8_t opcode;
	uint16_t flag;

	rte_spinlock_lock(&hw->cmq.crq.lock);

	handle_out = (rte_eal_process_type() != RTE_PROC_PRIMARY ||
		      !rte_thread_is_intr());
	if (handle_out) {
		/*
		 * Currently, any threads in the primary and secondary processes
		 * could send mailbox sync request, so it will need to process
		 * the crq message (which is the HNS3_MBX_PF_VF_RESP) in there
		 * own thread context. It may also process other messages
		 * because it uses the policy of processing all pending messages
		 * at once.
		 * But some messages such as HNS3_MBX_PUSH_LINK_STATUS could
		 * only process within the intr thread in primary process,
		 * otherwise it may lead to report lsc event in secondary
		 * process.
		 * So the threads other than intr thread in primary process
		 * could only process HNS3_MBX_PF_VF_RESP message, if the
		 * message processed, its opcode will rewrite with zero, then
		 * the intr thread in primary process will not process again.
		 */
		hns3_handle_mbx_msg_out_intr(hw);
		rte_spinlock_unlock(&hw->cmq.crq.lock);
		return;
	}

	while (!hns3_cmd_crq_empty(hw)) {
		if (__atomic_load_n(&hw->reset.disable_cmd, __ATOMIC_RELAXED)) {
			rte_spinlock_unlock(&hw->cmq.crq.lock);
			return;
		}

		desc = &crq->desc[crq->next_to_use];
		req = (struct hns3_mbx_pf_to_vf_cmd *)desc->data;
		opcode = req->msg.code & 0xff;

		flag = rte_le_to_cpu_16(crq->desc[crq->next_to_use].flag);
		if (unlikely(!hns3_get_bit(flag, HNS3_CMDQ_RX_OUTVLD_B))) {
			hns3_warn(hw,
				  "dropped invalid mailbox message, code = %u",
				  opcode);

			/* dropping/not processing this invalid message */
			crq->desc[crq->next_to_use].flag = 0;
			hns3_mbx_ring_ptr_move_crq(crq);
			continue;
		}

		if (desc->opcode == 0) {
			/* Message already processed by other thread */
			crq->desc[crq->next_to_use].flag = 0;
			hns3_mbx_ring_ptr_move_crq(crq);
			continue;
		}

		switch (opcode) {
		case HNS3_MBX_PF_VF_RESP:
			hns3_handle_mbx_response(hw, req);
			break;
		case HNS3_MBX_LINK_STAT_CHANGE:
			hns3vf_handle_link_change_event(hw, req);
			break;
		case HNS3_MBX_ASSERTING_RESET:
			hns3_handle_asserting_reset(hw, req);
			break;
		case HNS3_MBX_PUSH_VLAN_INFO:
			/*
			 * When the PVID configuration status of VF device is
			 * changed by the hns3 PF kernel driver, VF driver will
			 * receive this mailbox message from PF driver.
			 */
			hns3_update_port_base_vlan_info(hw, req);
			break;
		case HNS3_MBX_PUSH_PROMISC_INFO:
			/*
			 * When the trust status of VF device changed by the
			 * hns3 PF kernel driver, VF driver will receive this
			 * mailbox message from PF driver.
			 */
			hns3_handle_promisc_info(hw, req->msg.promisc_en);
			break;
		default:
			hns3_err(hw, "received unsupported(%u) mbx msg",
				 opcode);
			break;
		}

		crq->desc[crq->next_to_use].flag = 0;
		hns3_mbx_ring_ptr_move_crq(crq);
	}

	/* Write back CMDQ_RQ header pointer, IMP need this pointer */
	hns3_write_dev(hw, HNS3_CMDQ_RX_HEAD_REG, crq->next_to_use);

	rte_spinlock_unlock(&hw->cmq.crq.lock);
}
