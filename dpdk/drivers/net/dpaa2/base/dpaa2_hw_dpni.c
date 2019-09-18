/* SPDX-License-Identifier: BSD-3-Clause
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *   Copyright 2016 NXP
 *
 */

#include <time.h>
#include <net/if.h>

#include <rte_mbuf.h>
#include <rte_ethdev_driver.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_kvargs.h>
#include <rte_dev.h>

#include <dpaa2_pmd_logs.h>
#include <dpaa2_hw_pvt.h>
#include <dpaa2_hw_mempool.h>

#include "../dpaa2_ethdev.h"

static int
dpaa2_distset_to_dpkg_profile_cfg(
		uint64_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg);

int
dpaa2_setup_flow_dist(struct rte_eth_dev *eth_dev,
		      uint64_t req_dist_set)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret, tc_index = 0;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		DPAA2_PMD_ERR("Unable to allocate flow-dist parameters");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	ret = dpaa2_distset_to_dpkg_profile_cfg(req_dist_set, &kg_cfg);
	if (ret) {
		DPAA2_PMD_ERR("Given RSS Hash (%" PRIx64 ") not supported",
			      req_dist_set);
		rte_free(p_params);
		return ret;
	}
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = eth_dev->data->nb_rx_queues;
	tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;

	ret = dpkg_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		DPAA2_PMD_ERR("Unable to prepare extract parameters");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret) {
		DPAA2_PMD_ERR(
			     "Setting distribution for Rx failed with err: %d",
			     ret);
		return ret;
	}

	return 0;
}

int dpaa2_remove_flow_dist(
	struct rte_eth_dev *eth_dev,
	uint8_t tc_index)
{
	struct dpaa2_dev_priv *priv = eth_dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	void *p_params;
	int ret;

	p_params = rte_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, RTE_CACHE_LINE_SIZE);
	if (!p_params) {
		DPAA2_PMD_ERR("Unable to allocate flow-dist parameters");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));
	kg_cfg.num_extracts = 0;
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = 0;
	tc_cfg.dist_mode = DPNI_DIST_MODE_NONE;

	ret = dpkg_prepare_key_cfg(&kg_cfg, p_params);
	if (ret) {
		DPAA2_PMD_ERR("Unable to prepare extract parameters");
		rte_free(p_params);
		return ret;
	}

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, priv->token, tc_index,
				  &tc_cfg);
	rte_free(p_params);
	if (ret)
		DPAA2_PMD_ERR(
			     "Setting distribution for Rx failed with err: %d",
			     ret);
	return ret;
}

static int
dpaa2_distset_to_dpkg_profile_cfg(
		uint64_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg)
{
	uint32_t loop = 0, i = 0, dist_field = 0;
	int l2_configured = 0, l3_configured = 0;
	int l4_configured = 0, sctp_configured = 0;

	memset(kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	while (req_dist_set) {
		if (req_dist_set % 2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case ETH_RSS_L2_PAYLOAD:

				if (l2_configured)
					break;
				l2_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_ETH;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_ETH_TYPE;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
			break;

			case ETH_RSS_IPV4:
			case ETH_RSS_FRAG_IPV4:
			case ETH_RSS_NONFRAG_IPV4_OTHER:
			case ETH_RSS_IPV6:
			case ETH_RSS_FRAG_IPV6:
			case ETH_RSS_NONFRAG_IPV6_OTHER:
			case ETH_RSS_IPV6_EX:

				if (l3_configured)
					break;
				l3_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_SRC;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_DST;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_PROTO;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				kg_cfg->num_extracts++;
				i++;
			break;

			case ETH_RSS_NONFRAG_IPV4_TCP:
			case ETH_RSS_NONFRAG_IPV6_TCP:
			case ETH_RSS_NONFRAG_IPV4_UDP:
			case ETH_RSS_NONFRAG_IPV6_UDP:
			case ETH_RSS_IPV6_TCP_EX:
			case ETH_RSS_IPV6_UDP_EX:

				if (l4_configured)
					break;
				l4_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			case ETH_RSS_NONFRAG_IPV4_SCTP:
			case ETH_RSS_NONFRAG_IPV6_SCTP:

				if (sctp_configured)
					break;
				sctp_configured = 1;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_SRC;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;

				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_SCTP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_SCTP_PORT_DST;
				kg_cfg->extracts[i].type =
					DPKG_EXTRACT_FROM_HDR;
				kg_cfg->extracts[i].extract.from_hdr.type =
					DPKG_FULL_FIELD;
				i++;
				break;

			default:
				DPAA2_PMD_WARN(
					     "Unsupported flow dist option %x",
					     dist_field);
				return -EINVAL;
			}
		}
		req_dist_set = req_dist_set >> 1;
		loop++;
	}
	kg_cfg->num_extracts = i;
	return 0;
}

int
dpaa2_attach_bp_list(struct dpaa2_dev_priv *priv,
		     void *blist)
{
	/* Function to attach a DPNI with a buffer pool list. Buffer pool list
	 * handle is passed in blist.
	 */
	int32_t retcode;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_pools_cfg bpool_cfg;
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)blist;
	struct dpni_buffer_layout layout;
	int tot_size;

	/* ... rx buffer layout .
	 * Check alignment for buffer layouts first
	 */

	/* ... rx buffer layout ... */
	tot_size = RTE_PKTMBUF_HEADROOM;
	tot_size = RTE_ALIGN_CEIL(tot_size, DPAA2_PACKET_LAYOUT_ALIGN);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM |
			 DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
			 DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
			 DPNI_BUF_LAYOUT_OPT_DATA_ALIGN |
			 DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;

	layout.pass_frame_status = 1;
	layout.private_data_size = DPAA2_FD_PTA_SIZE;
	layout.pass_parser_result = 1;
	layout.data_align = DPAA2_PACKET_LAYOUT_ALIGN;
	layout.data_head_room = tot_size - DPAA2_FD_PTA_SIZE -
				DPAA2_MBUF_HW_ANNOTATION;
	retcode = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, priv->token,
					 DPNI_QUEUE_RX, &layout);
	if (retcode) {
		DPAA2_PMD_ERR("Error configuring buffer pool Rx layout (%d)",
			     retcode);
		return retcode;
	}

	/*Attach buffer pool to the network interface as described by the user*/
	bpool_cfg.num_dpbp = 1;
	bpool_cfg.pools[0].dpbp_id = bp_list->buf_pool.dpbp_node->dpbp_id;
	bpool_cfg.pools[0].backup_pool = 0;
	bpool_cfg.pools[0].buffer_size = RTE_ALIGN_CEIL(bp_list->buf_pool.size,
						DPAA2_PACKET_LAYOUT_ALIGN);
	bpool_cfg.pools[0].priority_mask = 0;

	retcode = dpni_set_pools(dpni, CMD_PRI_LOW, priv->token, &bpool_cfg);
	if (retcode != 0) {
		DPAA2_PMD_ERR("Error configuring buffer pool on interface."
			      " bpid = %d error code = %d",
			      bpool_cfg.pools[0].dpbp_id, retcode);
		return retcode;
	}

	priv->bp_list = bp_list;
	return 0;
}
