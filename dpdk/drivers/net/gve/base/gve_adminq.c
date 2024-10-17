/* SPDX-License-Identifier: MIT
 * Google Virtual Ethernet (gve) driver
 * Copyright (C) 2015-2022 Google, Inc.
 */

#include "../gve_ethdev.h"
#include "gve_adminq.h"
#include "gve_register.h"

#define GVE_MAX_ADMINQ_RELEASE_CHECK	500
#define GVE_ADMINQ_SLEEP_LEN		20
#define GVE_MAX_ADMINQ_EVENT_COUNTER_CHECK	100

#define GVE_DEVICE_OPTION_ERROR_FMT "%s option error:\n Expected: length=%d, feature_mask=%x.\n Actual: length=%d, feature_mask=%x."

#define GVE_DEVICE_OPTION_TOO_BIG_FMT "Length of %s option larger than expected. Possible older version of guest driver."

static
struct gve_device_option *gve_get_next_option(struct gve_device_descriptor *descriptor,
					      struct gve_device_option *option)
{
	uintptr_t option_end, descriptor_end;

	option_end = (uintptr_t)option + sizeof(*option) + be16_to_cpu(option->option_length);
	descriptor_end = (uintptr_t)descriptor + be16_to_cpu(descriptor->total_length);

	return option_end > descriptor_end ? NULL : (struct gve_device_option *)option_end;
}

static
void gve_parse_device_option(struct gve_priv *priv,
			     struct gve_device_option *option,
			     struct gve_device_option_gqi_rda **dev_op_gqi_rda,
			     struct gve_device_option_gqi_qpl **dev_op_gqi_qpl,
			     struct gve_device_option_dqo_rda **dev_op_dqo_rda,
			     struct gve_device_option_jumbo_frames **dev_op_jumbo_frames)
{
	u32 req_feat_mask = be32_to_cpu(option->required_features_mask);
	u16 option_length = be16_to_cpu(option->option_length);
	u16 option_id = be16_to_cpu(option->option_id);

	/* If the length or feature mask doesn't match, continue without
	 * enabling the feature.
	 */
	switch (option_id) {
	case GVE_DEV_OPT_ID_GQI_RAW_ADDRESSING:
		if (option_length != GVE_DEV_OPT_LEN_GQI_RAW_ADDRESSING ||
		    req_feat_mask != GVE_DEV_OPT_REQ_FEAT_MASK_GQI_RAW_ADDRESSING) {
			PMD_DRV_LOG(WARNING, GVE_DEVICE_OPTION_ERROR_FMT,
				    "Raw Addressing",
				    GVE_DEV_OPT_LEN_GQI_RAW_ADDRESSING,
				    GVE_DEV_OPT_REQ_FEAT_MASK_GQI_RAW_ADDRESSING,
				    option_length, req_feat_mask);
			break;
		}

		PMD_DRV_LOG(INFO, "Gqi raw addressing device option enabled.");
		priv->queue_format = GVE_GQI_RDA_FORMAT;
		break;
	case GVE_DEV_OPT_ID_GQI_RDA:
		if (option_length < sizeof(**dev_op_gqi_rda) ||
		    req_feat_mask != GVE_DEV_OPT_REQ_FEAT_MASK_GQI_RDA) {
			PMD_DRV_LOG(WARNING, GVE_DEVICE_OPTION_ERROR_FMT,
				    "GQI RDA", (int)sizeof(**dev_op_gqi_rda),
				    GVE_DEV_OPT_REQ_FEAT_MASK_GQI_RDA,
				    option_length, req_feat_mask);
			break;
		}

		if (option_length > sizeof(**dev_op_gqi_rda)) {
			PMD_DRV_LOG(WARNING,
				    GVE_DEVICE_OPTION_TOO_BIG_FMT, "GQI RDA");
		}
		*dev_op_gqi_rda = RTE_PTR_ADD(option, sizeof(*option));
		break;
	case GVE_DEV_OPT_ID_GQI_QPL:
		if (option_length < sizeof(**dev_op_gqi_qpl) ||
		    req_feat_mask != GVE_DEV_OPT_REQ_FEAT_MASK_GQI_QPL) {
			PMD_DRV_LOG(WARNING, GVE_DEVICE_OPTION_ERROR_FMT,
				    "GQI QPL", (int)sizeof(**dev_op_gqi_qpl),
				    GVE_DEV_OPT_REQ_FEAT_MASK_GQI_QPL,
				    option_length, req_feat_mask);
			break;
		}

		if (option_length > sizeof(**dev_op_gqi_qpl)) {
			PMD_DRV_LOG(WARNING,
				    GVE_DEVICE_OPTION_TOO_BIG_FMT, "GQI QPL");
		}
		*dev_op_gqi_qpl = RTE_PTR_ADD(option, sizeof(*option));
		break;
	case GVE_DEV_OPT_ID_DQO_RDA:
		if (option_length < sizeof(**dev_op_dqo_rda) ||
		    req_feat_mask != GVE_DEV_OPT_REQ_FEAT_MASK_DQO_RDA) {
			PMD_DRV_LOG(WARNING, GVE_DEVICE_OPTION_ERROR_FMT,
				    "DQO RDA", (int)sizeof(**dev_op_dqo_rda),
				    GVE_DEV_OPT_REQ_FEAT_MASK_DQO_RDA,
				    option_length, req_feat_mask);
			break;
		}

		if (option_length > sizeof(**dev_op_dqo_rda)) {
			PMD_DRV_LOG(WARNING,
				    GVE_DEVICE_OPTION_TOO_BIG_FMT, "DQO RDA");
		}
		*dev_op_dqo_rda = RTE_PTR_ADD(option, sizeof(*option));
		break;
	case GVE_DEV_OPT_ID_JUMBO_FRAMES:
		if (option_length < sizeof(**dev_op_jumbo_frames) ||
		    req_feat_mask != GVE_DEV_OPT_REQ_FEAT_MASK_JUMBO_FRAMES) {
			PMD_DRV_LOG(WARNING, GVE_DEVICE_OPTION_ERROR_FMT,
				    "Jumbo Frames",
				    (int)sizeof(**dev_op_jumbo_frames),
				    GVE_DEV_OPT_REQ_FEAT_MASK_JUMBO_FRAMES,
				    option_length, req_feat_mask);
			break;
		}

		if (option_length > sizeof(**dev_op_jumbo_frames)) {
			PMD_DRV_LOG(WARNING,
				    GVE_DEVICE_OPTION_TOO_BIG_FMT,
				    "Jumbo Frames");
		}
		*dev_op_jumbo_frames = RTE_PTR_ADD(option, sizeof(*option));
		break;
	default:
		/* If we don't recognize the option just continue
		 * without doing anything.
		 */
		PMD_DRV_LOG(DEBUG, "Unrecognized device option 0x%hx not enabled.",
			    option_id);
	}
}

/* Process all device options for a given describe device call. */
static int
gve_process_device_options(struct gve_priv *priv,
			   struct gve_device_descriptor *descriptor,
			   struct gve_device_option_gqi_rda **dev_op_gqi_rda,
			   struct gve_device_option_gqi_qpl **dev_op_gqi_qpl,
			   struct gve_device_option_dqo_rda **dev_op_dqo_rda,
			   struct gve_device_option_jumbo_frames **dev_op_jumbo_frames)
{
	const int num_options = be16_to_cpu(descriptor->num_device_options);
	struct gve_device_option *dev_opt;
	int i;

	/* The options struct directly follows the device descriptor. */
	dev_opt = RTE_PTR_ADD(descriptor, sizeof(*descriptor));
	for (i = 0; i < num_options; i++) {
		struct gve_device_option *next_opt;

		next_opt = gve_get_next_option(descriptor, dev_opt);
		if (!next_opt) {
			PMD_DRV_LOG(ERR,
				    "options exceed device_descriptor's total length.");
			return -EINVAL;
		}

		gve_parse_device_option(priv, dev_opt,
					dev_op_gqi_rda, dev_op_gqi_qpl,
					dev_op_dqo_rda, dev_op_jumbo_frames);
		dev_opt = next_opt;
	}

	return 0;
}

int gve_adminq_alloc(struct gve_priv *priv)
{
	priv->adminq = gve_alloc_dma_mem(&priv->adminq_dma_mem, PAGE_SIZE);
	if (unlikely(!priv->adminq))
		return -ENOMEM;

	priv->adminq_mask = (PAGE_SIZE / sizeof(union gve_adminq_command)) - 1;
	priv->adminq_prod_cnt = 0;
	priv->adminq_cmd_fail = 0;
	priv->adminq_timeouts = 0;
	priv->adminq_describe_device_cnt = 0;
	priv->adminq_cfg_device_resources_cnt = 0;
	priv->adminq_register_page_list_cnt = 0;
	priv->adminq_unregister_page_list_cnt = 0;
	priv->adminq_create_tx_queue_cnt = 0;
	priv->adminq_create_rx_queue_cnt = 0;
	priv->adminq_destroy_tx_queue_cnt = 0;
	priv->adminq_destroy_rx_queue_cnt = 0;
	priv->adminq_dcfg_device_resources_cnt = 0;
	priv->adminq_set_driver_parameter_cnt = 0;
	priv->adminq_report_stats_cnt = 0;
	priv->adminq_report_link_speed_cnt = 0;
	priv->adminq_get_ptype_map_cnt = 0;

	/* Setup Admin queue with the device */
	iowrite32be(priv->adminq_dma_mem.pa / PAGE_SIZE,
		    &priv->reg_bar0->adminq_pfn);

	gve_set_admin_queue_ok(priv);
	return 0;
}

void gve_adminq_release(struct gve_priv *priv)
{
	int i = 0;

	/* Tell the device the adminq is leaving */
	iowrite32be(0x0, &priv->reg_bar0->adminq_pfn);
	while (ioread32be(&priv->reg_bar0->adminq_pfn)) {
		/* If this is reached the device is unrecoverable and still
		 * holding memory. Continue looping to avoid memory corruption,
		 * but WARN so it is visible what is going on.
		 */
		if (i == GVE_MAX_ADMINQ_RELEASE_CHECK)
			PMD_DRV_LOG(WARNING, "Unrecoverable platform error!");
		i++;
		msleep(GVE_ADMINQ_SLEEP_LEN);
	}
	gve_clear_device_rings_ok(priv);
	gve_clear_device_resources_ok(priv);
	gve_clear_admin_queue_ok(priv);
}

void gve_adminq_free(struct gve_priv *priv)
{
	if (!gve_get_admin_queue_ok(priv))
		return;
	gve_adminq_release(priv);
	gve_free_dma_mem(&priv->adminq_dma_mem);
	gve_clear_admin_queue_ok(priv);
}

static void gve_adminq_kick_cmd(struct gve_priv *priv, u32 prod_cnt)
{
	iowrite32be(prod_cnt, &priv->reg_bar0->adminq_doorbell);
}

static bool gve_adminq_wait_for_cmd(struct gve_priv *priv, u32 prod_cnt)
{
	int i;

	for (i = 0; i < GVE_MAX_ADMINQ_EVENT_COUNTER_CHECK; i++) {
		if (ioread32be(&priv->reg_bar0->adminq_event_counter)
		    == prod_cnt)
			return true;
		msleep(GVE_ADMINQ_SLEEP_LEN);
	}

	return false;
}

static int gve_adminq_parse_err(struct gve_priv *priv, u32 status)
{
	if (status != GVE_ADMINQ_COMMAND_PASSED &&
	    status != GVE_ADMINQ_COMMAND_UNSET) {
		PMD_DRV_LOG(ERR, "AQ command failed with status %d", status);
		priv->adminq_cmd_fail++;
	}
	switch (status) {
	case GVE_ADMINQ_COMMAND_PASSED:
		return 0;
	case GVE_ADMINQ_COMMAND_UNSET:
		PMD_DRV_LOG(ERR, "parse_aq_err: err and status both unset, this should not be possible.");
		return -EINVAL;
	case GVE_ADMINQ_COMMAND_ERROR_ABORTED:
	case GVE_ADMINQ_COMMAND_ERROR_CANCELLED:
	case GVE_ADMINQ_COMMAND_ERROR_DATALOSS:
	case GVE_ADMINQ_COMMAND_ERROR_FAILED_PRECONDITION:
	case GVE_ADMINQ_COMMAND_ERROR_UNAVAILABLE:
		return -EAGAIN;
	case GVE_ADMINQ_COMMAND_ERROR_ALREADY_EXISTS:
	case GVE_ADMINQ_COMMAND_ERROR_INTERNAL_ERROR:
	case GVE_ADMINQ_COMMAND_ERROR_INVALID_ARGUMENT:
	case GVE_ADMINQ_COMMAND_ERROR_NOT_FOUND:
	case GVE_ADMINQ_COMMAND_ERROR_OUT_OF_RANGE:
	case GVE_ADMINQ_COMMAND_ERROR_UNKNOWN_ERROR:
		return -EINVAL;
	case GVE_ADMINQ_COMMAND_ERROR_DEADLINE_EXCEEDED:
		return -ETIMEDOUT;
	case GVE_ADMINQ_COMMAND_ERROR_PERMISSION_DENIED:
	case GVE_ADMINQ_COMMAND_ERROR_UNAUTHENTICATED:
		return -EACCES;
	case GVE_ADMINQ_COMMAND_ERROR_RESOURCE_EXHAUSTED:
		return -ENOMEM;
	case GVE_ADMINQ_COMMAND_ERROR_UNIMPLEMENTED:
		return -ENOTSUP;
	default:
		PMD_DRV_LOG(ERR, "parse_aq_err: unknown status code %d",
			    status);
		return -EINVAL;
	}
}

/* Flushes all AQ commands currently queued and waits for them to complete.
 * If there are failures, it will return the first error.
 */
static int gve_adminq_kick_and_wait(struct gve_priv *priv)
{
	u32 tail, head;
	u32 i;

	tail = ioread32be(&priv->reg_bar0->adminq_event_counter);
	head = priv->adminq_prod_cnt;

	gve_adminq_kick_cmd(priv, head);
	if (!gve_adminq_wait_for_cmd(priv, head)) {
		PMD_DRV_LOG(ERR, "AQ commands timed out, need to reset AQ");
		priv->adminq_timeouts++;
		return -ENOTRECOVERABLE;
	}

	for (i = tail; i < head; i++) {
		union gve_adminq_command *cmd;
		u32 status, err;

		cmd = &priv->adminq[i & priv->adminq_mask];
		status = be32_to_cpu(READ_ONCE32(cmd->status));
		err = gve_adminq_parse_err(priv, status);
		if (err)
			/* Return the first error if we failed. */
			return err;
	}

	return 0;
}

/* This function is not threadsafe - the caller is responsible for any
 * necessary locks.
 */
static int gve_adminq_issue_cmd(struct gve_priv *priv,
				union gve_adminq_command *cmd_orig)
{
	union gve_adminq_command *cmd;
	u32 opcode;
	u32 tail;

	tail = ioread32be(&priv->reg_bar0->adminq_event_counter);

	/* Check if next command will overflow the buffer. */
	if (((priv->adminq_prod_cnt + 1) & priv->adminq_mask) ==
	    (tail & priv->adminq_mask)) {
		int err;

		/* Flush existing commands to make room. */
		err = gve_adminq_kick_and_wait(priv);
		if (err)
			return err;

		/* Retry. */
		tail = ioread32be(&priv->reg_bar0->adminq_event_counter);
		if (((priv->adminq_prod_cnt + 1) & priv->adminq_mask) ==
		    (tail & priv->adminq_mask)) {
			/* This should never happen. We just flushed the
			 * command queue so there should be enough space.
			 */
			return -ENOMEM;
		}
	}

	cmd = &priv->adminq[priv->adminq_prod_cnt & priv->adminq_mask];
	priv->adminq_prod_cnt++;

	memcpy(cmd, cmd_orig, sizeof(*cmd_orig));
	opcode = be32_to_cpu(READ_ONCE32(cmd->opcode));

	switch (opcode) {
	case GVE_ADMINQ_DESCRIBE_DEVICE:
		priv->adminq_describe_device_cnt++;
		break;
	case GVE_ADMINQ_CONFIGURE_DEVICE_RESOURCES:
		priv->adminq_cfg_device_resources_cnt++;
		break;
	case GVE_ADMINQ_REGISTER_PAGE_LIST:
		priv->adminq_register_page_list_cnt++;
		break;
	case GVE_ADMINQ_UNREGISTER_PAGE_LIST:
		priv->adminq_unregister_page_list_cnt++;
		break;
	case GVE_ADMINQ_CREATE_TX_QUEUE:
		priv->adminq_create_tx_queue_cnt++;
		break;
	case GVE_ADMINQ_CREATE_RX_QUEUE:
		priv->adminq_create_rx_queue_cnt++;
		break;
	case GVE_ADMINQ_DESTROY_TX_QUEUE:
		priv->adminq_destroy_tx_queue_cnt++;
		break;
	case GVE_ADMINQ_DESTROY_RX_QUEUE:
		priv->adminq_destroy_rx_queue_cnt++;
		break;
	case GVE_ADMINQ_DECONFIGURE_DEVICE_RESOURCES:
		priv->adminq_dcfg_device_resources_cnt++;
		break;
	case GVE_ADMINQ_SET_DRIVER_PARAMETER:
		priv->adminq_set_driver_parameter_cnt++;
		break;
	case GVE_ADMINQ_REPORT_STATS:
		priv->adminq_report_stats_cnt++;
		break;
	case GVE_ADMINQ_REPORT_LINK_SPEED:
		priv->adminq_report_link_speed_cnt++;
		break;
	case GVE_ADMINQ_GET_PTYPE_MAP:
		priv->adminq_get_ptype_map_cnt++;
		break;
	default:
		PMD_DRV_LOG(ERR, "unknown AQ command opcode %d", opcode);
	}

	return 0;
}

/* This function is not threadsafe - the caller is responsible for any
 * necessary locks.
 * The caller is also responsible for making sure there are no commands
 * waiting to be executed.
 */
static int gve_adminq_execute_cmd(struct gve_priv *priv,
				  union gve_adminq_command *cmd_orig)
{
	u32 tail, head;
	int err;

	tail = ioread32be(&priv->reg_bar0->adminq_event_counter);
	head = priv->adminq_prod_cnt;
	if (tail != head)
		/* This is not a valid path */
		return -EINVAL;

	err = gve_adminq_issue_cmd(priv, cmd_orig);
	if (err)
		return err;

	return gve_adminq_kick_and_wait(priv);
}

/* The device specifies that the management vector can either be the first irq
 * or the last irq. ntfy_blk_msix_base_idx indicates the first irq assigned to
 * the ntfy blks. It if is 0 then the management vector is last, if it is 1 then
 * the management vector is first.
 *
 * gve arranges the msix vectors so that the management vector is last.
 */
#define GVE_NTFY_BLK_BASE_MSIX_IDX	0
int gve_adminq_configure_device_resources(struct gve_priv *priv,
					  dma_addr_t counter_array_bus_addr,
					  u32 num_counters,
					  dma_addr_t db_array_bus_addr,
					  u32 num_ntfy_blks)
{
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_CONFIGURE_DEVICE_RESOURCES);
	cmd.configure_device_resources =
		(struct gve_adminq_configure_device_resources) {
		.counter_array = cpu_to_be64(counter_array_bus_addr),
		.num_counters = cpu_to_be32(num_counters),
		.irq_db_addr = cpu_to_be64(db_array_bus_addr),
		.num_irq_dbs = cpu_to_be32(num_ntfy_blks),
		.irq_db_stride = cpu_to_be32(sizeof(*priv->irq_dbs)),
		.ntfy_blk_msix_base_idx =
					cpu_to_be32(GVE_NTFY_BLK_BASE_MSIX_IDX),
		.queue_format = priv->queue_format,
	};

	return gve_adminq_execute_cmd(priv, &cmd);
}

int gve_adminq_deconfigure_device_resources(struct gve_priv *priv)
{
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_DECONFIGURE_DEVICE_RESOURCES);

	return gve_adminq_execute_cmd(priv, &cmd);
}

static int gve_adminq_create_tx_queue(struct gve_priv *priv, u32 queue_index)
{
	struct gve_tx_queue *txq = priv->txqs[queue_index];
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_CREATE_TX_QUEUE);
	cmd.create_tx_queue = (struct gve_adminq_create_tx_queue) {
		.queue_id = cpu_to_be32(queue_index),
		.queue_resources_addr =
			cpu_to_be64(txq->qres_mz->iova),
		.tx_ring_addr = cpu_to_be64(txq->tx_ring_phys_addr),
		.ntfy_id = cpu_to_be32(txq->ntfy_id),
	};

	if (gve_is_gqi(priv)) {
		u32 qpl_id = priv->queue_format == GVE_GQI_RDA_FORMAT ?
			GVE_RAW_ADDRESSING_QPL_ID : txq->qpl->id;

		cmd.create_tx_queue.queue_page_list_id = cpu_to_be32(qpl_id);
	} else {
		cmd.create_tx_queue.tx_ring_size =
			cpu_to_be16(txq->nb_tx_desc);
		cmd.create_tx_queue.tx_comp_ring_addr =
			cpu_to_be64(txq->complq->tx_ring_phys_addr);
		cmd.create_tx_queue.tx_comp_ring_size =
			cpu_to_be16(priv->tx_compq_size);
	}

	return gve_adminq_issue_cmd(priv, &cmd);
}

int gve_adminq_create_tx_queues(struct gve_priv *priv, u32 num_queues)
{
	int err;
	u32 i;

	for (i = 0; i < num_queues; i++) {
		err = gve_adminq_create_tx_queue(priv, i);
		if (err)
			return err;
	}

	return gve_adminq_kick_and_wait(priv);
}

static int gve_adminq_create_rx_queue(struct gve_priv *priv, u32 queue_index)
{
	struct gve_rx_queue *rxq = priv->rxqs[queue_index];
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_CREATE_RX_QUEUE);
	cmd.create_rx_queue = (struct gve_adminq_create_rx_queue) {
		.queue_id = cpu_to_be32(queue_index),
		.ntfy_id = cpu_to_be32(rxq->ntfy_id),
		.queue_resources_addr = cpu_to_be64(rxq->qres_mz->iova),
	};

	if (gve_is_gqi(priv)) {
		u32 qpl_id = priv->queue_format == GVE_GQI_RDA_FORMAT ?
			GVE_RAW_ADDRESSING_QPL_ID : rxq->qpl->id;

		cmd.create_rx_queue.rx_desc_ring_addr =
			cpu_to_be64(rxq->mz->iova),
		cmd.create_rx_queue.rx_data_ring_addr =
			cpu_to_be64(rxq->data_mz->iova),
		cmd.create_rx_queue.index = cpu_to_be32(queue_index);
		cmd.create_rx_queue.queue_page_list_id = cpu_to_be32(qpl_id);
		cmd.create_rx_queue.packet_buffer_size = cpu_to_be16(rxq->rx_buf_len);
	} else {
		cmd.create_rx_queue.rx_ring_size =
			cpu_to_be16(priv->rx_desc_cnt);
		cmd.create_rx_queue.rx_desc_ring_addr =
			cpu_to_be64(rxq->rx_ring_phys_addr);
		cmd.create_rx_queue.rx_data_ring_addr =
			cpu_to_be64(rxq->bufq->rx_ring_phys_addr);
		cmd.create_rx_queue.packet_buffer_size =
			cpu_to_be16(rxq->rx_buf_len);
		cmd.create_rx_queue.rx_buff_ring_size =
			cpu_to_be16(priv->rx_bufq_size);
		cmd.create_rx_queue.enable_rsc = !!(priv->enable_rsc);
	}

	return gve_adminq_issue_cmd(priv, &cmd);
}

int gve_adminq_create_rx_queues(struct gve_priv *priv, u32 num_queues)
{
	int err;
	u32 i;

	for (i = 0; i < num_queues; i++) {
		err = gve_adminq_create_rx_queue(priv, i);
		if (err)
			return err;
	}

	return gve_adminq_kick_and_wait(priv);
}

static int gve_adminq_destroy_tx_queue(struct gve_priv *priv, u32 queue_index)
{
	union gve_adminq_command cmd;
	int err;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_DESTROY_TX_QUEUE);
	cmd.destroy_tx_queue = (struct gve_adminq_destroy_tx_queue) {
		.queue_id = cpu_to_be32(queue_index),
	};

	err = gve_adminq_issue_cmd(priv, &cmd);
	if (err)
		return err;

	return 0;
}

int gve_adminq_destroy_tx_queues(struct gve_priv *priv, u32 num_queues)
{
	int err;
	u32 i;

	for (i = 0; i < num_queues; i++) {
		err = gve_adminq_destroy_tx_queue(priv, i);
		if (err)
			return err;
	}

	return gve_adminq_kick_and_wait(priv);
}

static int gve_adminq_destroy_rx_queue(struct gve_priv *priv, u32 queue_index)
{
	union gve_adminq_command cmd;
	int err;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_DESTROY_RX_QUEUE);
	cmd.destroy_rx_queue = (struct gve_adminq_destroy_rx_queue) {
		.queue_id = cpu_to_be32(queue_index),
	};

	err = gve_adminq_issue_cmd(priv, &cmd);
	if (err)
		return err;

	return 0;
}

int gve_adminq_destroy_rx_queues(struct gve_priv *priv, u32 num_queues)
{
	int err;
	u32 i;

	for (i = 0; i < num_queues; i++) {
		err = gve_adminq_destroy_rx_queue(priv, i);
		if (err)
			return err;
	}

	return gve_adminq_kick_and_wait(priv);
}

static int gve_set_desc_cnt(struct gve_priv *priv,
			    struct gve_device_descriptor *descriptor)
{
	priv->tx_desc_cnt = be16_to_cpu(descriptor->tx_queue_entries);
	if (priv->tx_desc_cnt * sizeof(priv->txqs[0]->tx_desc_ring[0])
	    < PAGE_SIZE) {
		PMD_DRV_LOG(ERR, "Tx desc count %d too low", priv->tx_desc_cnt);
		return -EINVAL;
	}
	priv->rx_desc_cnt = be16_to_cpu(descriptor->rx_queue_entries);
	if (priv->rx_desc_cnt * sizeof(priv->rxqs[0]->rx_desc_ring[0])
	    < PAGE_SIZE) {
		PMD_DRV_LOG(ERR, "Rx desc count %d too low", priv->rx_desc_cnt);
		return -EINVAL;
	}
	return 0;
}

static int
gve_set_desc_cnt_dqo(struct gve_priv *priv,
		     const struct gve_device_descriptor *descriptor,
		     const struct gve_device_option_dqo_rda *dev_op_dqo_rda)
{
	priv->tx_desc_cnt = be16_to_cpu(descriptor->tx_queue_entries);
	priv->tx_compq_size = be16_to_cpu(dev_op_dqo_rda->tx_comp_ring_entries);
	priv->rx_desc_cnt = be16_to_cpu(descriptor->rx_queue_entries);
	priv->rx_bufq_size = be16_to_cpu(dev_op_dqo_rda->rx_buff_ring_entries);

	return 0;
}

static void gve_enable_supported_features(struct gve_priv *priv,
					  u32 supported_features_mask,
					  const struct gve_device_option_jumbo_frames
						  *dev_op_jumbo_frames)
{
	/* Before control reaches this point, the page-size-capped max MTU from
	 * the gve_device_descriptor field has already been stored in
	 * priv->dev->max_mtu. We overwrite it with the true max MTU below.
	 */
	if (dev_op_jumbo_frames &&
	    (supported_features_mask & GVE_SUP_JUMBO_FRAMES_MASK)) {
		PMD_DRV_LOG(INFO, "JUMBO FRAMES device option enabled.");
		priv->max_mtu = be16_to_cpu(dev_op_jumbo_frames->max_mtu);
	}
}

int gve_adminq_describe_device(struct gve_priv *priv)
{
	struct gve_device_option_jumbo_frames *dev_op_jumbo_frames = NULL;
	struct gve_device_option_gqi_rda *dev_op_gqi_rda = NULL;
	struct gve_device_option_gqi_qpl *dev_op_gqi_qpl = NULL;
	struct gve_device_option_dqo_rda *dev_op_dqo_rda = NULL;
	struct gve_device_descriptor *descriptor;
	struct gve_dma_mem descriptor_dma_mem;
	u32 supported_features_mask = 0;
	union gve_adminq_command cmd;
	int err = 0;
	u16 mtu;

	memset(&cmd, 0, sizeof(cmd));
	descriptor = gve_alloc_dma_mem(&descriptor_dma_mem, PAGE_SIZE);
	if (!descriptor)
		return -ENOMEM;
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_DESCRIBE_DEVICE);
	cmd.describe_device.device_descriptor_addr =
					cpu_to_be64(descriptor_dma_mem.pa);
	cmd.describe_device.device_descriptor_version =
			cpu_to_be32(GVE_ADMINQ_DEVICE_DESCRIPTOR_VERSION);
	cmd.describe_device.available_length = cpu_to_be32(PAGE_SIZE);

	err = gve_adminq_execute_cmd(priv, &cmd);
	if (err)
		goto free_device_descriptor;

	err = gve_process_device_options(priv, descriptor, &dev_op_gqi_rda,
					 &dev_op_gqi_qpl, &dev_op_dqo_rda,
					 &dev_op_jumbo_frames);
	if (err)
		goto free_device_descriptor;

	/* If the GQI_RAW_ADDRESSING option is not enabled and the queue format
	 * is not set to GqiRda, choose the queue format in a priority order:
	 * DqoRda, GqiRda, GqiQpl. Use GqiQpl as default.
	 */
	if (dev_op_dqo_rda) {
		priv->queue_format = GVE_DQO_RDA_FORMAT;
		PMD_DRV_LOG(INFO, "Driver is running with DQO RDA queue format.");
		supported_features_mask =
			be32_to_cpu(dev_op_dqo_rda->supported_features_mask);
	} else if (dev_op_gqi_rda) {
		priv->queue_format = GVE_GQI_RDA_FORMAT;
		PMD_DRV_LOG(INFO, "Driver is running with GQI RDA queue format.");
		supported_features_mask =
			be32_to_cpu(dev_op_gqi_rda->supported_features_mask);
	} else if (priv->queue_format == GVE_GQI_RDA_FORMAT) {
		PMD_DRV_LOG(INFO, "Driver is running with GQI RDA queue format.");
	} else {
		priv->queue_format = GVE_GQI_QPL_FORMAT;
		if (dev_op_gqi_qpl)
			supported_features_mask =
				be32_to_cpu(dev_op_gqi_qpl->supported_features_mask);
		PMD_DRV_LOG(INFO, "Driver is running with GQI QPL queue format.");
	}
	if (gve_is_gqi(priv)) {
		err = gve_set_desc_cnt(priv, descriptor);
	} else {
		/* DQO supports LRO. */
		err = gve_set_desc_cnt_dqo(priv, descriptor, dev_op_dqo_rda);
	}
	if (err)
		goto free_device_descriptor;

	priv->max_registered_pages =
				be64_to_cpu(descriptor->max_registered_pages);
	mtu = be16_to_cpu(descriptor->mtu);
	if (mtu < ETH_MIN_MTU) {
		PMD_DRV_LOG(ERR, "MTU %d below minimum MTU", mtu);
		err = -EINVAL;
		goto free_device_descriptor;
	}
	priv->max_mtu = mtu;
	priv->num_event_counters = be16_to_cpu(descriptor->counters);
	rte_memcpy(priv->dev_addr.addr_bytes, descriptor->mac, ETH_ALEN);
	PMD_DRV_LOG(INFO, "MAC addr: " RTE_ETHER_ADDR_PRT_FMT,
		    RTE_ETHER_ADDR_BYTES(&priv->dev_addr));
	priv->tx_pages_per_qpl = be16_to_cpu(descriptor->tx_pages_per_qpl);
	priv->rx_data_slot_cnt = be16_to_cpu(descriptor->rx_pages_per_qpl);

	if (gve_is_gqi(priv) && priv->rx_data_slot_cnt < priv->rx_desc_cnt) {
		PMD_DRV_LOG(ERR,
			    "rx_data_slot_cnt cannot be smaller than rx_desc_cnt, setting rx_desc_cnt down to %d",
			    priv->rx_data_slot_cnt);
		priv->rx_desc_cnt = priv->rx_data_slot_cnt;
	}
	priv->default_num_queues = be16_to_cpu(descriptor->default_num_queues);

	gve_enable_supported_features(priv, supported_features_mask,
				      dev_op_jumbo_frames);

free_device_descriptor:
	gve_free_dma_mem(&descriptor_dma_mem);
	return err;
}

int gve_adminq_register_page_list(struct gve_priv *priv,
				  struct gve_queue_page_list *qpl)
{
	struct gve_dma_mem page_list_dma_mem;
	u32 num_entries = qpl->num_entries;
	u32 size = num_entries * sizeof(qpl->page_buses[0]);
	union gve_adminq_command cmd;
	__be64 *page_list;
	int err;
	u32 i;

	memset(&cmd, 0, sizeof(cmd));
	page_list = gve_alloc_dma_mem(&page_list_dma_mem, size);
	if (!page_list)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++)
		page_list[i] = cpu_to_be64(qpl->page_buses[i]);

	cmd.opcode = cpu_to_be32(GVE_ADMINQ_REGISTER_PAGE_LIST);
	cmd.reg_page_list = (struct gve_adminq_register_page_list) {
		.page_list_id = cpu_to_be32(qpl->id),
		.num_pages = cpu_to_be32(num_entries),
		.page_address_list_addr = cpu_to_be64(page_list_dma_mem.pa),
	};

	err = gve_adminq_execute_cmd(priv, &cmd);
	gve_free_dma_mem(&page_list_dma_mem);
	return err;
}

int gve_adminq_unregister_page_list(struct gve_priv *priv, u32 page_list_id)
{
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_UNREGISTER_PAGE_LIST);
	cmd.unreg_page_list = (struct gve_adminq_unregister_page_list) {
		.page_list_id = cpu_to_be32(page_list_id),
	};

	return gve_adminq_execute_cmd(priv, &cmd);
}

int gve_adminq_set_mtu(struct gve_priv *priv, u64 mtu)
{
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_SET_DRIVER_PARAMETER);
	cmd.set_driver_param = (struct gve_adminq_set_driver_parameter) {
		.parameter_type = cpu_to_be32(GVE_SET_PARAM_MTU),
		.parameter_value = cpu_to_be64(mtu),
	};

	return gve_adminq_execute_cmd(priv, &cmd);
}

int gve_adminq_report_stats(struct gve_priv *priv, u64 stats_report_len,
			    dma_addr_t stats_report_addr, u64 interval)
{
	union gve_adminq_command cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = cpu_to_be32(GVE_ADMINQ_REPORT_STATS);
	cmd.report_stats = (struct gve_adminq_report_stats) {
		.stats_report_len = cpu_to_be64(stats_report_len),
		.stats_report_addr = cpu_to_be64(stats_report_addr),
		.interval = cpu_to_be64(interval),
	};

	return gve_adminq_execute_cmd(priv, &cmd);
}

int gve_adminq_report_link_speed(struct gve_priv *priv)
{
	struct gve_dma_mem link_speed_region_dma_mem;
	union gve_adminq_command gvnic_cmd;
	u64 *link_speed_region;
	int err;

	link_speed_region = gve_alloc_dma_mem(&link_speed_region_dma_mem,
					      sizeof(*link_speed_region));

	if (!link_speed_region)
		return -ENOMEM;

	memset(&gvnic_cmd, 0, sizeof(gvnic_cmd));
	gvnic_cmd.opcode = cpu_to_be32(GVE_ADMINQ_REPORT_LINK_SPEED);
	gvnic_cmd.report_link_speed.link_speed_address =
		cpu_to_be64(link_speed_region_dma_mem.pa);

	err = gve_adminq_execute_cmd(priv, &gvnic_cmd);

	priv->link_speed = be64_to_cpu(*link_speed_region);
	gve_free_dma_mem(&link_speed_region_dma_mem);
	return err;
}

int gve_adminq_get_ptype_map_dqo(struct gve_priv *priv,
				 struct gve_ptype_lut *ptype_lut)
{
	struct gve_dma_mem ptype_map_dma_mem;
	struct gve_ptype_map *ptype_map;
	union gve_adminq_command cmd;
	int err = 0;
	int i;

	memset(&cmd, 0, sizeof(cmd));
	ptype_map = gve_alloc_dma_mem(&ptype_map_dma_mem, sizeof(*ptype_map));
	if (!ptype_map)
		return -ENOMEM;

	cmd.opcode = cpu_to_be32(GVE_ADMINQ_GET_PTYPE_MAP);
	cmd.get_ptype_map = (struct gve_adminq_get_ptype_map) {
		.ptype_map_len = cpu_to_be64(sizeof(*ptype_map)),
		.ptype_map_addr = cpu_to_be64(ptype_map_dma_mem.pa),
	};

	err = gve_adminq_execute_cmd(priv, &cmd);
	if (err)
		goto err;

	/* Populate ptype_lut. */
	for (i = 0; i < GVE_NUM_PTYPES; i++) {
		ptype_lut->ptypes[i].l3_type =
			ptype_map->ptypes[i].l3_type;
		ptype_lut->ptypes[i].l4_type =
			ptype_map->ptypes[i].l4_type;
	}
err:
	gve_free_dma_mem(&ptype_map_dma_mem);
	return err;
}
