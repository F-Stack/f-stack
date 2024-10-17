/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_FLOW_H_
#define RTE_PMD_MLX5_FLOW_H_

#include <stdalign.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_alarm.h>
#include <rte_mtr.h>

#include <mlx5_glue.h>
#include <mlx5_prm.h>

#include "mlx5.h"
#include "hws/mlx5dr.h"

/* E-Switch Manager port, used for rte_flow_item_port_id. */
#define MLX5_PORT_ESW_MGR UINT32_MAX

/* E-Switch Manager port, used for rte_flow_item_ethdev. */
#define MLX5_REPRESENTED_PORT_ESW_MGR UINT16_MAX

/* Private rte flow items. */
enum mlx5_rte_flow_item_type {
	MLX5_RTE_FLOW_ITEM_TYPE_END = INT_MIN,
	MLX5_RTE_FLOW_ITEM_TYPE_TAG,
	MLX5_RTE_FLOW_ITEM_TYPE_SQ,
	MLX5_RTE_FLOW_ITEM_TYPE_VLAN,
	MLX5_RTE_FLOW_ITEM_TYPE_TUNNEL,
};

/* Private (internal) rte flow actions. */
enum mlx5_rte_flow_action_type {
	MLX5_RTE_FLOW_ACTION_TYPE_END = INT_MIN,
	MLX5_RTE_FLOW_ACTION_TYPE_TAG,
	MLX5_RTE_FLOW_ACTION_TYPE_MARK,
	MLX5_RTE_FLOW_ACTION_TYPE_COPY_MREG,
	MLX5_RTE_FLOW_ACTION_TYPE_DEFAULT_MISS,
	MLX5_RTE_FLOW_ACTION_TYPE_TUNNEL_SET,
	MLX5_RTE_FLOW_ACTION_TYPE_AGE,
	MLX5_RTE_FLOW_ACTION_TYPE_COUNT,
	MLX5_RTE_FLOW_ACTION_TYPE_JUMP,
	MLX5_RTE_FLOW_ACTION_TYPE_RSS,
	MLX5_RTE_FLOW_ACTION_TYPE_METER_MARK,
};

/* Private (internal) Field IDs for MODIFY_FIELD action. */
enum mlx5_rte_flow_field_id {
		MLX5_RTE_FLOW_FIELD_END = INT_MIN,
			MLX5_RTE_FLOW_FIELD_META_REG,
};

#define MLX5_INDIRECT_ACTION_TYPE_OFFSET 29

#define MLX5_INDIRECT_ACTION_TYPE_GET(handle) \
	(((uint32_t)(uintptr_t)(handle)) >> MLX5_INDIRECT_ACTION_TYPE_OFFSET)

#define MLX5_INDIRECT_ACTION_IDX_GET(handle) \
	(((uint32_t)(uintptr_t)(handle)) & \
	 ((1u << MLX5_INDIRECT_ACTION_TYPE_OFFSET) - 1))

enum {
	MLX5_INDIRECT_ACTION_TYPE_RSS,
	MLX5_INDIRECT_ACTION_TYPE_AGE,
	MLX5_INDIRECT_ACTION_TYPE_COUNT,
	MLX5_INDIRECT_ACTION_TYPE_CT,
	MLX5_INDIRECT_ACTION_TYPE_METER_MARK,
};

/* Now, the maximal ports will be supported is 16, action number is 32M. */
#define MLX5_INDIRECT_ACT_CT_MAX_PORT 0x10

#define MLX5_INDIRECT_ACT_CT_OWNER_SHIFT 25
#define MLX5_INDIRECT_ACT_CT_OWNER_MASK (MLX5_INDIRECT_ACT_CT_MAX_PORT - 1)

/* 29-31: type, 25-28: owner port, 0-24: index */
#define MLX5_INDIRECT_ACT_CT_GEN_IDX(owner, index) \
	((MLX5_INDIRECT_ACTION_TYPE_CT << MLX5_INDIRECT_ACTION_TYPE_OFFSET) | \
	 (((owner) & MLX5_INDIRECT_ACT_CT_OWNER_MASK) << \
	  MLX5_INDIRECT_ACT_CT_OWNER_SHIFT) | (index))

#define MLX5_INDIRECT_ACT_CT_GET_OWNER(index) \
	(((index) >> MLX5_INDIRECT_ACT_CT_OWNER_SHIFT) & \
	 MLX5_INDIRECT_ACT_CT_OWNER_MASK)

#define MLX5_INDIRECT_ACT_CT_GET_IDX(index) \
	((index) & ((1 << MLX5_INDIRECT_ACT_CT_OWNER_SHIFT) - 1))

#define MLX5_ACTION_CTX_CT_GET_IDX  MLX5_INDIRECT_ACT_CT_GET_IDX
#define MLX5_ACTION_CTX_CT_GET_OWNER MLX5_INDIRECT_ACT_CT_GET_OWNER
#define MLX5_ACTION_CTX_CT_GEN_IDX MLX5_INDIRECT_ACT_CT_GEN_IDX

/* Matches on selected register. */
struct mlx5_rte_flow_item_tag {
	enum modify_reg id;
	uint32_t data;
};

/* Modify selected register. */
struct mlx5_rte_flow_action_set_tag {
	enum modify_reg id;
	uint8_t offset;
	uint8_t length;
	uint32_t data;
};

struct mlx5_flow_action_copy_mreg {
	enum modify_reg dst;
	enum modify_reg src;
};

/* Matches on source queue. */
struct mlx5_rte_flow_item_sq {
	uint32_t queue; /* DevX SQ number */
};

/* Feature name to allocate metadata register. */
enum mlx5_feature_name {
	MLX5_HAIRPIN_RX,
	MLX5_HAIRPIN_TX,
	MLX5_METADATA_RX,
	MLX5_METADATA_TX,
	MLX5_METADATA_FDB,
	MLX5_FLOW_MARK,
	MLX5_APP_TAG,
	MLX5_COPY_MARK,
	MLX5_MTR_COLOR,
	MLX5_MTR_ID,
	MLX5_ASO_FLOW_HIT,
	MLX5_ASO_CONNTRACK,
	MLX5_SAMPLE_ID,
};

/* Default queue number. */
#define MLX5_RSSQ_DEFAULT_NUM 16

#define MLX5_FLOW_LAYER_OUTER_L2 (1u << 0)
#define MLX5_FLOW_LAYER_OUTER_L3_IPV4 (1u << 1)
#define MLX5_FLOW_LAYER_OUTER_L3_IPV6 (1u << 2)
#define MLX5_FLOW_LAYER_OUTER_L4_UDP (1u << 3)
#define MLX5_FLOW_LAYER_OUTER_L4_TCP (1u << 4)
#define MLX5_FLOW_LAYER_OUTER_VLAN (1u << 5)

/* Pattern inner Layer bits. */
#define MLX5_FLOW_LAYER_INNER_L2 (1u << 6)
#define MLX5_FLOW_LAYER_INNER_L3_IPV4 (1u << 7)
#define MLX5_FLOW_LAYER_INNER_L3_IPV6 (1u << 8)
#define MLX5_FLOW_LAYER_INNER_L4_UDP (1u << 9)
#define MLX5_FLOW_LAYER_INNER_L4_TCP (1u << 10)
#define MLX5_FLOW_LAYER_INNER_VLAN (1u << 11)

/* Pattern tunnel Layer bits. */
#define MLX5_FLOW_LAYER_VXLAN (1u << 12)
#define MLX5_FLOW_LAYER_VXLAN_GPE (1u << 13)
#define MLX5_FLOW_LAYER_GRE (1u << 14)
#define MLX5_FLOW_LAYER_MPLS (1u << 15)
/* List of tunnel Layer bits continued below. */

/* General pattern items bits. */
#define MLX5_FLOW_ITEM_METADATA (1u << 16)
#define MLX5_FLOW_ITEM_PORT_ID (1u << 17)
#define MLX5_FLOW_ITEM_TAG (1u << 18)
#define MLX5_FLOW_ITEM_MARK (1u << 19)

/* Pattern MISC bits. */
#define MLX5_FLOW_LAYER_ICMP (1u << 20)
#define MLX5_FLOW_LAYER_ICMP6 (1u << 21)
#define MLX5_FLOW_LAYER_GRE_KEY (1u << 22)

/* Pattern tunnel Layer bits (continued). */
#define MLX5_FLOW_LAYER_IPIP (1u << 23)
#define MLX5_FLOW_LAYER_IPV6_ENCAP (1u << 24)
#define MLX5_FLOW_LAYER_NVGRE (1u << 25)
#define MLX5_FLOW_LAYER_GENEVE (1u << 26)

/* Queue items. */
#define MLX5_FLOW_ITEM_SQ (1u << 27)

/* Pattern tunnel Layer bits (continued). */
#define MLX5_FLOW_LAYER_GTP (1u << 28)

/* Pattern eCPRI Layer bit. */
#define MLX5_FLOW_LAYER_ECPRI (UINT64_C(1) << 29)

/* IPv6 Fragment Extension Header bit. */
#define MLX5_FLOW_LAYER_OUTER_L3_IPV6_FRAG_EXT (1u << 30)
#define MLX5_FLOW_LAYER_INNER_L3_IPV6_FRAG_EXT (1u << 31)

/* Pattern tunnel Layer bits (continued). */
#define MLX5_FLOW_LAYER_GENEVE_OPT (UINT64_C(1) << 32)
#define MLX5_FLOW_LAYER_GTP_PSC (UINT64_C(1) << 33)

/* INTEGRITY item bits */
#define MLX5_FLOW_ITEM_OUTER_INTEGRITY (UINT64_C(1) << 34)
#define MLX5_FLOW_ITEM_INNER_INTEGRITY (UINT64_C(1) << 35)
#define MLX5_FLOW_ITEM_INTEGRITY \
	(MLX5_FLOW_ITEM_OUTER_INTEGRITY | MLX5_FLOW_ITEM_INNER_INTEGRITY)

/* Conntrack item. */
#define MLX5_FLOW_LAYER_ASO_CT (UINT64_C(1) << 36)

/* Flex item */
#define MLX5_FLOW_ITEM_OUTER_FLEX (UINT64_C(1) << 37)
#define MLX5_FLOW_ITEM_INNER_FLEX (UINT64_C(1) << 38)
#define MLX5_FLOW_ITEM_FLEX_TUNNEL (UINT64_C(1) << 39)

/* ESP item */
#define MLX5_FLOW_ITEM_ESP (UINT64_C(1) << 40)

/* Port Representor/Represented Port item */
#define MLX5_FLOW_ITEM_PORT_REPRESENTOR (UINT64_C(1) << 41)
#define MLX5_FLOW_ITEM_REPRESENTED_PORT (UINT64_C(1) << 42)

/* Meter color item */
#define MLX5_FLOW_ITEM_METER_COLOR (UINT64_C(1) << 44)

/* Outer Masks. */
#define MLX5_FLOW_LAYER_OUTER_L3 \
	(MLX5_FLOW_LAYER_OUTER_L3_IPV4 | MLX5_FLOW_LAYER_OUTER_L3_IPV6)
#define MLX5_FLOW_LAYER_OUTER_L4 \
	(MLX5_FLOW_LAYER_OUTER_L4_UDP | MLX5_FLOW_LAYER_OUTER_L4_TCP)
#define MLX5_FLOW_LAYER_OUTER \
	(MLX5_FLOW_LAYER_OUTER_L2 | MLX5_FLOW_LAYER_OUTER_L3 | \
	 MLX5_FLOW_LAYER_OUTER_L4)

/* Tunnel Masks. */
#define MLX5_FLOW_LAYER_TUNNEL \
	(MLX5_FLOW_LAYER_VXLAN | MLX5_FLOW_LAYER_VXLAN_GPE | \
	 MLX5_FLOW_LAYER_GRE | MLX5_FLOW_LAYER_NVGRE | MLX5_FLOW_LAYER_MPLS | \
	 MLX5_FLOW_LAYER_IPIP | MLX5_FLOW_LAYER_IPV6_ENCAP | \
	 MLX5_FLOW_LAYER_GENEVE | MLX5_FLOW_LAYER_GTP | \
	 MLX5_FLOW_ITEM_FLEX_TUNNEL)

/* Inner Masks. */
#define MLX5_FLOW_LAYER_INNER_L3 \
	(MLX5_FLOW_LAYER_INNER_L3_IPV4 | MLX5_FLOW_LAYER_INNER_L3_IPV6)
#define MLX5_FLOW_LAYER_INNER_L4 \
	(MLX5_FLOW_LAYER_INNER_L4_UDP | MLX5_FLOW_LAYER_INNER_L4_TCP)
#define MLX5_FLOW_LAYER_INNER \
	(MLX5_FLOW_LAYER_INNER_L2 | MLX5_FLOW_LAYER_INNER_L3 | \
	 MLX5_FLOW_LAYER_INNER_L4)

/* Layer Masks. */
#define MLX5_FLOW_LAYER_L2 \
	(MLX5_FLOW_LAYER_OUTER_L2 | MLX5_FLOW_LAYER_INNER_L2)
#define MLX5_FLOW_LAYER_L3_IPV4 \
	(MLX5_FLOW_LAYER_OUTER_L3_IPV4 | MLX5_FLOW_LAYER_INNER_L3_IPV4)
#define MLX5_FLOW_LAYER_L3_IPV6 \
	(MLX5_FLOW_LAYER_OUTER_L3_IPV6 | MLX5_FLOW_LAYER_INNER_L3_IPV6)
#define MLX5_FLOW_LAYER_L3 \
	(MLX5_FLOW_LAYER_L3_IPV4 | MLX5_FLOW_LAYER_L3_IPV6)
#define MLX5_FLOW_LAYER_L4 \
	(MLX5_FLOW_LAYER_OUTER_L4 | MLX5_FLOW_LAYER_INNER_L4)

/* Actions */
#define MLX5_FLOW_ACTION_DROP (1ull << 0)
#define MLX5_FLOW_ACTION_QUEUE (1ull << 1)
#define MLX5_FLOW_ACTION_RSS (1ull << 2)
#define MLX5_FLOW_ACTION_FLAG (1ull << 3)
#define MLX5_FLOW_ACTION_MARK (1ull << 4)
#define MLX5_FLOW_ACTION_COUNT (1ull << 5)
#define MLX5_FLOW_ACTION_PORT_ID (1ull << 6)
#define MLX5_FLOW_ACTION_OF_POP_VLAN (1ull << 7)
#define MLX5_FLOW_ACTION_OF_PUSH_VLAN (1ull << 8)
#define MLX5_FLOW_ACTION_OF_SET_VLAN_VID (1ull << 9)
#define MLX5_FLOW_ACTION_OF_SET_VLAN_PCP (1ull << 10)
#define MLX5_FLOW_ACTION_SET_IPV4_SRC (1ull << 11)
#define MLX5_FLOW_ACTION_SET_IPV4_DST (1ull << 12)
#define MLX5_FLOW_ACTION_SET_IPV6_SRC (1ull << 13)
#define MLX5_FLOW_ACTION_SET_IPV6_DST (1ull << 14)
#define MLX5_FLOW_ACTION_SET_TP_SRC (1ull << 15)
#define MLX5_FLOW_ACTION_SET_TP_DST (1ull << 16)
#define MLX5_FLOW_ACTION_JUMP (1ull << 17)
#define MLX5_FLOW_ACTION_SET_TTL (1ull << 18)
#define MLX5_FLOW_ACTION_DEC_TTL (1ull << 19)
#define MLX5_FLOW_ACTION_SET_MAC_SRC (1ull << 20)
#define MLX5_FLOW_ACTION_SET_MAC_DST (1ull << 21)
#define MLX5_FLOW_ACTION_ENCAP (1ull << 22)
#define MLX5_FLOW_ACTION_DECAP (1ull << 23)
#define MLX5_FLOW_ACTION_INC_TCP_SEQ (1ull << 24)
#define MLX5_FLOW_ACTION_DEC_TCP_SEQ (1ull << 25)
#define MLX5_FLOW_ACTION_INC_TCP_ACK (1ull << 26)
#define MLX5_FLOW_ACTION_DEC_TCP_ACK (1ull << 27)
#define MLX5_FLOW_ACTION_SET_TAG (1ull << 28)
#define MLX5_FLOW_ACTION_MARK_EXT (1ull << 29)
#define MLX5_FLOW_ACTION_SET_META (1ull << 30)
#define MLX5_FLOW_ACTION_METER (1ull << 31)
#define MLX5_FLOW_ACTION_SET_IPV4_DSCP (1ull << 32)
#define MLX5_FLOW_ACTION_SET_IPV6_DSCP (1ull << 33)
#define MLX5_FLOW_ACTION_AGE (1ull << 34)
#define MLX5_FLOW_ACTION_DEFAULT_MISS (1ull << 35)
#define MLX5_FLOW_ACTION_SAMPLE (1ull << 36)
#define MLX5_FLOW_ACTION_TUNNEL_SET (1ull << 37)
#define MLX5_FLOW_ACTION_TUNNEL_MATCH (1ull << 38)
#define MLX5_FLOW_ACTION_MODIFY_FIELD (1ull << 39)
#define MLX5_FLOW_ACTION_METER_WITH_TERMINATED_POLICY (1ull << 40)
#define MLX5_FLOW_ACTION_CT (1ull << 41)
#define MLX5_FLOW_ACTION_SEND_TO_KERNEL (1ull << 42)
#define MLX5_FLOW_ACTION_INDIRECT_COUNT (1ull << 43)
#define MLX5_FLOW_ACTION_INDIRECT_AGE (1ull << 44)

#define MLX5_FLOW_DROP_INCLUSIVE_ACTIONS \
	(MLX5_FLOW_ACTION_COUNT | MLX5_FLOW_ACTION_SAMPLE | MLX5_FLOW_ACTION_AGE)

#define MLX5_FLOW_FATE_ACTIONS \
	(MLX5_FLOW_ACTION_DROP | MLX5_FLOW_ACTION_QUEUE | \
	 MLX5_FLOW_ACTION_RSS | MLX5_FLOW_ACTION_JUMP | \
	 MLX5_FLOW_ACTION_DEFAULT_MISS | \
	 MLX5_FLOW_ACTION_METER_WITH_TERMINATED_POLICY | \
	 MLX5_FLOW_ACTION_SEND_TO_KERNEL)

#define MLX5_FLOW_FATE_ESWITCH_ACTIONS \
	(MLX5_FLOW_ACTION_DROP | MLX5_FLOW_ACTION_PORT_ID | \
	 MLX5_FLOW_ACTION_JUMP | MLX5_FLOW_ACTION_METER_WITH_TERMINATED_POLICY)

#define MLX5_FLOW_MODIFY_HDR_ACTIONS (MLX5_FLOW_ACTION_SET_IPV4_SRC | \
				      MLX5_FLOW_ACTION_SET_IPV4_DST | \
				      MLX5_FLOW_ACTION_SET_IPV6_SRC | \
				      MLX5_FLOW_ACTION_SET_IPV6_DST | \
				      MLX5_FLOW_ACTION_SET_TP_SRC | \
				      MLX5_FLOW_ACTION_SET_TP_DST | \
				      MLX5_FLOW_ACTION_SET_TTL | \
				      MLX5_FLOW_ACTION_DEC_TTL | \
				      MLX5_FLOW_ACTION_SET_MAC_SRC | \
				      MLX5_FLOW_ACTION_SET_MAC_DST | \
				      MLX5_FLOW_ACTION_INC_TCP_SEQ | \
				      MLX5_FLOW_ACTION_DEC_TCP_SEQ | \
				      MLX5_FLOW_ACTION_INC_TCP_ACK | \
				      MLX5_FLOW_ACTION_DEC_TCP_ACK | \
				      MLX5_FLOW_ACTION_OF_SET_VLAN_VID | \
				      MLX5_FLOW_ACTION_SET_TAG | \
				      MLX5_FLOW_ACTION_MARK_EXT | \
				      MLX5_FLOW_ACTION_SET_META | \
				      MLX5_FLOW_ACTION_SET_IPV4_DSCP | \
				      MLX5_FLOW_ACTION_SET_IPV6_DSCP | \
				      MLX5_FLOW_ACTION_MODIFY_FIELD)

#define MLX5_FLOW_VLAN_ACTIONS (MLX5_FLOW_ACTION_OF_POP_VLAN | \
				MLX5_FLOW_ACTION_OF_PUSH_VLAN)

#define MLX5_FLOW_XCAP_ACTIONS (MLX5_FLOW_ACTION_ENCAP | MLX5_FLOW_ACTION_DECAP)

#ifndef IPPROTO_MPLS
#define IPPROTO_MPLS 137
#endif

/* UDP port number for MPLS */
#define MLX5_UDP_PORT_MPLS 6635

/* UDP port numbers for VxLAN. */
#define MLX5_UDP_PORT_VXLAN 4789
#define MLX5_UDP_PORT_VXLAN_GPE 4790

/* UDP port numbers for GENEVE. */
#define MLX5_UDP_PORT_GENEVE 6081

/* Lowest priority indicator. */
#define MLX5_FLOW_LOWEST_PRIO_INDICATOR ((uint32_t)-1)

/*
 * Max priority for ingress\egress flow groups
 * greater than 0 and for any transfer flow group.
 * From user configation: 0 - 21843.
 */
#define MLX5_NON_ROOT_FLOW_MAX_PRIO	(21843 + 1)

/*
 * Number of sub priorities.
 * For each kind of pattern matching i.e. L2, L3, L4 to have a correct
 * matching on the NIC (firmware dependent) L4 most have the higher priority
 * followed by L3 and ending with L2.
 */
#define MLX5_PRIORITY_MAP_L2 2
#define MLX5_PRIORITY_MAP_L3 1
#define MLX5_PRIORITY_MAP_L4 0
#define MLX5_PRIORITY_MAP_MAX 3

/* Valid layer type for IPV4 RSS. */
#define MLX5_IPV4_LAYER_TYPES \
	(RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 | \
	 RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP | \
	 RTE_ETH_RSS_NONFRAG_IPV4_OTHER)

/* IBV hash source bits  for IPV4. */
#define MLX5_IPV4_IBV_RX_HASH (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4)

/* Valid layer type for IPV6 RSS. */
#define MLX5_IPV6_LAYER_TYPES \
	(RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_TCP | \
	 RTE_ETH_RSS_NONFRAG_IPV6_UDP | RTE_ETH_RSS_IPV6_EX  | RTE_ETH_RSS_IPV6_TCP_EX | \
	 RTE_ETH_RSS_IPV6_UDP_EX | RTE_ETH_RSS_NONFRAG_IPV6_OTHER)

/* IBV hash source bits  for IPV6. */
#define MLX5_IPV6_IBV_RX_HASH (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6)

/* IBV hash bits for L3 SRC. */
#define MLX5_L3_SRC_IBV_RX_HASH (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_SRC_IPV6)

/* IBV hash bits for L3 DST. */
#define MLX5_L3_DST_IBV_RX_HASH (IBV_RX_HASH_DST_IPV4 | IBV_RX_HASH_DST_IPV6)

/* IBV hash bits for TCP. */
#define MLX5_TCP_IBV_RX_HASH (IBV_RX_HASH_SRC_PORT_TCP | \
			      IBV_RX_HASH_DST_PORT_TCP)

/* IBV hash bits for UDP. */
#define MLX5_UDP_IBV_RX_HASH (IBV_RX_HASH_SRC_PORT_UDP | \
			      IBV_RX_HASH_DST_PORT_UDP)

/* IBV hash bits for L4 SRC. */
#define MLX5_L4_SRC_IBV_RX_HASH (IBV_RX_HASH_SRC_PORT_TCP | \
				 IBV_RX_HASH_SRC_PORT_UDP)

/* IBV hash bits for L4 DST. */
#define MLX5_L4_DST_IBV_RX_HASH (IBV_RX_HASH_DST_PORT_TCP | \
				 IBV_RX_HASH_DST_PORT_UDP)

/* Geneve header first 16Bit */
#define MLX5_GENEVE_VER_MASK 0x3
#define MLX5_GENEVE_VER_SHIFT 14
#define MLX5_GENEVE_VER_VAL(a) \
		(((a) >> (MLX5_GENEVE_VER_SHIFT)) & (MLX5_GENEVE_VER_MASK))
#define MLX5_GENEVE_OPTLEN_MASK 0x3F
#define MLX5_GENEVE_OPTLEN_SHIFT 8
#define MLX5_GENEVE_OPTLEN_VAL(a) \
	    (((a) >> (MLX5_GENEVE_OPTLEN_SHIFT)) & (MLX5_GENEVE_OPTLEN_MASK))
#define MLX5_GENEVE_OAMF_MASK 0x1
#define MLX5_GENEVE_OAMF_SHIFT 7
#define MLX5_GENEVE_OAMF_VAL(a) \
		(((a) >> (MLX5_GENEVE_OAMF_SHIFT)) & (MLX5_GENEVE_OAMF_MASK))
#define MLX5_GENEVE_CRITO_MASK 0x1
#define MLX5_GENEVE_CRITO_SHIFT 6
#define MLX5_GENEVE_CRITO_VAL(a) \
		(((a) >> (MLX5_GENEVE_CRITO_SHIFT)) & (MLX5_GENEVE_CRITO_MASK))
#define MLX5_GENEVE_RSVD_MASK 0x3F
#define MLX5_GENEVE_RSVD_VAL(a) ((a) & (MLX5_GENEVE_RSVD_MASK))
/*
 * The length of the Geneve options fields, expressed in four byte multiples,
 * not including the eight byte fixed tunnel.
 */
#define MLX5_GENEVE_OPT_LEN_0 14
#define MLX5_GENEVE_OPT_LEN_1 63

#define MLX5_ENCAPSULATION_DECISION_SIZE (sizeof(struct rte_ether_hdr) + \
					  sizeof(struct rte_ipv4_hdr))
/* GTP extension header flag. */
#define MLX5_GTP_EXT_HEADER_FLAG 4

/* GTP extension header PDU type shift. */
#define MLX5_GTP_PDU_TYPE_SHIFT(a) ((a) << 4)

/* IPv4 fragment_offset field contains relevant data in bits 2 to 15. */
#define MLX5_IPV4_FRAG_OFFSET_MASK \
		(RTE_IPV4_HDR_OFFSET_MASK | RTE_IPV4_HDR_MF_FLAG)

/* Specific item's fields can accept a range of values (using spec and last). */
#define MLX5_ITEM_RANGE_NOT_ACCEPTED	false
#define MLX5_ITEM_RANGE_ACCEPTED	true

/* Software header modify action numbers of a flow. */
#define MLX5_ACT_NUM_MDF_IPV4		1
#define MLX5_ACT_NUM_MDF_IPV6		4
#define MLX5_ACT_NUM_MDF_MAC		2
#define MLX5_ACT_NUM_MDF_VID		1
#define MLX5_ACT_NUM_MDF_PORT		1
#define MLX5_ACT_NUM_MDF_TTL		1
#define MLX5_ACT_NUM_DEC_TTL		MLX5_ACT_NUM_MDF_TTL
#define MLX5_ACT_NUM_MDF_TCPSEQ		1
#define MLX5_ACT_NUM_MDF_TCPACK		1
#define MLX5_ACT_NUM_SET_REG		1
#define MLX5_ACT_NUM_SET_TAG		1
#define MLX5_ACT_NUM_CPY_MREG		MLX5_ACT_NUM_SET_TAG
#define MLX5_ACT_NUM_SET_MARK		MLX5_ACT_NUM_SET_TAG
#define MLX5_ACT_NUM_SET_META		MLX5_ACT_NUM_SET_TAG
#define MLX5_ACT_NUM_SET_DSCP		1

/* Maximum number of fields to modify in MODIFY_FIELD */
#define MLX5_ACT_MAX_MOD_FIELDS 5

/* Syndrome bits definition for connection tracking. */
#define MLX5_CT_SYNDROME_VALID		(0x0 << 6)
#define MLX5_CT_SYNDROME_INVALID	(0x1 << 6)
#define MLX5_CT_SYNDROME_TRAP		(0x2 << 6)
#define MLX5_CT_SYNDROME_STATE_CHANGE	(0x1 << 1)
#define MLX5_CT_SYNDROME_BAD_PACKET	(0x1 << 0)

enum mlx5_flow_drv_type {
	MLX5_FLOW_TYPE_MIN,
	MLX5_FLOW_TYPE_DV,
	MLX5_FLOW_TYPE_VERBS,
	MLX5_FLOW_TYPE_HW,
	MLX5_FLOW_TYPE_MAX,
};

/* Fate action type. */
enum mlx5_flow_fate_type {
	MLX5_FLOW_FATE_NONE, /* Egress flow. */
	MLX5_FLOW_FATE_QUEUE,
	MLX5_FLOW_FATE_JUMP,
	MLX5_FLOW_FATE_PORT_ID,
	MLX5_FLOW_FATE_DROP,
	MLX5_FLOW_FATE_DEFAULT_MISS,
	MLX5_FLOW_FATE_SHARED_RSS,
	MLX5_FLOW_FATE_MTR,
	MLX5_FLOW_FATE_SEND_TO_KERNEL,
	MLX5_FLOW_FATE_MAX,
};

/* Matcher PRM representation */
struct mlx5_flow_dv_match_params {
	size_t size;
	/**< Size of match value. Do NOT split size and key! */
	uint32_t buf[MLX5_ST_SZ_DW(fte_match_param)];
	/**< Matcher value. This value is used as the mask or as a key. */
};

/* Matcher structure. */
struct mlx5_flow_dv_matcher {
	struct mlx5_list_entry entry; /**< Pointer to the next element. */
	struct mlx5_flow_tbl_resource *tbl;
	/**< Pointer to the table(group) the matcher associated with. */
	void *matcher_object; /**< Pointer to DV matcher */
	uint16_t crc; /**< CRC of key. */
	uint16_t priority; /**< Priority of matcher. */
	struct mlx5_flow_dv_match_params mask; /**< Matcher mask. */
};

#define MLX5_ENCAP_MAX_LEN 132

/* Encap/decap resource structure. */
struct mlx5_flow_dv_encap_decap_resource {
	struct mlx5_list_entry entry;
	/* Pointer to next element. */
	uint32_t refcnt; /**< Reference counter. */
	void *action;
	/**< Encap/decap action object. */
	uint8_t buf[MLX5_ENCAP_MAX_LEN];
	size_t size;
	uint8_t reformat_type;
	uint8_t ft_type;
	uint64_t flags; /**< Flags for RDMA API. */
	uint32_t idx; /**< Index for the index memory pool. */
};

/* Tag resource structure. */
struct mlx5_flow_dv_tag_resource {
	struct mlx5_list_entry entry;
	/**< hash list entry for tag resource, tag value as the key. */
	void *action;
	/**< Tag action object. */
	uint32_t refcnt; /**< Reference counter. */
	uint32_t idx; /**< Index for the index memory pool. */
	uint32_t tag_id; /**< Tag ID. */
};

/* Modify resource structure */
struct mlx5_flow_dv_modify_hdr_resource {
	struct mlx5_list_entry entry;
	void *action; /**< Modify header action object. */
	uint32_t idx;
	/* Key area for hash list matching: */
	uint8_t ft_type; /**< Flow table type, Rx or Tx. */
	uint8_t actions_num; /**< Number of modification actions. */
	bool root; /**< Whether action is in root table. */
	struct mlx5_modification_cmd actions[];
	/**< Modification actions. */
} __rte_packed;

/* Modify resource key of the hash organization. */
union mlx5_flow_modify_hdr_key {
	struct {
		uint32_t ft_type:8;	/**< Flow table type, Rx or Tx. */
		uint32_t actions_num:5;	/**< Number of modification actions. */
		uint32_t group:19;	/**< Flow group id. */
		uint32_t cksum;		/**< Actions check sum. */
	};
	uint64_t v64;			/**< full 64bits value of key */
};

/* Jump action resource structure. */
struct mlx5_flow_dv_jump_tbl_resource {
	void *action; /**< Pointer to the rdma core action. */
};

/* Port ID resource structure. */
struct mlx5_flow_dv_port_id_action_resource {
	struct mlx5_list_entry entry;
	void *action; /**< Action object. */
	uint32_t port_id; /**< Port ID value. */
	uint32_t idx; /**< Indexed pool memory index. */
};

/* Push VLAN action resource structure */
struct mlx5_flow_dv_push_vlan_action_resource {
	struct mlx5_list_entry entry; /* Cache entry. */
	void *action; /**< Action object. */
	uint8_t ft_type; /**< Flow table type, Rx, Tx or FDB. */
	rte_be32_t vlan_tag; /**< VLAN tag value. */
	uint32_t idx; /**< Indexed pool memory index. */
};

/* Metadata register copy table entry. */
struct mlx5_flow_mreg_copy_resource {
	/*
	 * Hash list entry for copy table.
	 *  - Key is 32/64-bit MARK action ID.
	 *  - MUST be the first entry.
	 */
	struct mlx5_list_entry hlist_ent;
	LIST_ENTRY(mlx5_flow_mreg_copy_resource) next;
	/* List entry for device flows. */
	uint32_t idx;
	uint32_t rix_flow; /* Built flow for copy. */
	uint32_t mark_id;
};

/* Table tunnel parameter. */
struct mlx5_flow_tbl_tunnel_prm {
	const struct mlx5_flow_tunnel *tunnel;
	uint32_t group_id;
	bool external;
};

/* Table data structure of the hash organization. */
struct mlx5_flow_tbl_data_entry {
	struct mlx5_list_entry entry;
	/**< hash list entry, 64-bits key inside. */
	struct mlx5_flow_tbl_resource tbl;
	/**< flow table resource. */
	struct mlx5_list *matchers;
	/**< matchers' header associated with the flow table. */
	struct mlx5_flow_dv_jump_tbl_resource jump;
	/**< jump resource, at most one for each table created. */
	uint32_t idx; /**< index for the indexed mempool. */
	/**< tunnel offload */
	const struct mlx5_flow_tunnel *tunnel;
	uint32_t group_id;
	uint32_t external:1;
	uint32_t tunnel_offload:1; /* Tunnel offload table or not. */
	uint32_t is_egress:1; /**< Egress table. */
	uint32_t is_transfer:1; /**< Transfer table. */
	uint32_t dummy:1; /**<  DR table. */
	uint32_t id:22; /**< Table ID. */
	uint32_t reserve:5; /**< Reserved to future using. */
	uint32_t level; /**< Table level. */
};

/* Sub rdma-core actions list. */
struct mlx5_flow_sub_actions_list {
	uint32_t actions_num; /**< Number of sample actions. */
	uint64_t action_flags;
	void *dr_queue_action;
	void *dr_tag_action;
	void *dr_cnt_action;
	void *dr_port_id_action;
	void *dr_encap_action;
	void *dr_jump_action;
};

/* Sample sub-actions resource list. */
struct mlx5_flow_sub_actions_idx {
	uint32_t rix_hrxq; /**< Hash Rx queue object index. */
	uint32_t rix_tag; /**< Index to the tag action. */
	uint32_t rix_port_id_action; /**< Index to port ID action resource. */
	uint32_t rix_encap_decap; /**< Index to encap/decap resource. */
	uint32_t rix_jump; /**< Index to the jump action resource. */
};

/* Sample action resource structure. */
struct mlx5_flow_dv_sample_resource {
	struct mlx5_list_entry entry; /**< Cache entry. */
	union {
		void *verbs_action; /**< Verbs sample action object. */
		void **sub_actions; /**< Sample sub-action array. */
	};
	struct rte_eth_dev *dev; /**< Device registers the action. */
	uint32_t idx; /** Sample object index. */
	uint8_t ft_type; /** Flow Table Type */
	uint32_t ft_id; /** Flow Table Level */
	uint32_t ratio;   /** Sample Ratio */
	uint64_t set_action; /** Restore reg_c0 value */
	void *normal_path_tbl; /** Flow Table pointer */
	struct mlx5_flow_sub_actions_idx sample_idx;
	/**< Action index resources. */
	struct mlx5_flow_sub_actions_list sample_act;
	/**< Action resources. */
};

#define MLX5_MAX_DEST_NUM	2

/* Destination array action resource structure. */
struct mlx5_flow_dv_dest_array_resource {
	struct mlx5_list_entry entry; /**< Cache entry. */
	uint32_t idx; /** Destination array action object index. */
	uint8_t ft_type; /** Flow Table Type */
	uint8_t num_of_dest; /**< Number of destination actions. */
	struct rte_eth_dev *dev; /**< Device registers the action. */
	void *action; /**< Pointer to the rdma core action. */
	struct mlx5_flow_sub_actions_idx sample_idx[MLX5_MAX_DEST_NUM];
	/**< Action index resources. */
	struct mlx5_flow_sub_actions_list sample_act[MLX5_MAX_DEST_NUM];
	/**< Action resources. */
};

/* PMD flow priority for tunnel */
#define MLX5_TUNNEL_PRIO_GET(rss_desc) \
	((rss_desc)->level >= 2 ? MLX5_PRIORITY_MAP_L2 : MLX5_PRIORITY_MAP_L4)


/** Device flow handle structure for DV mode only. */
struct mlx5_flow_handle_dv {
	/* Flow DV api: */
	struct mlx5_flow_dv_matcher *matcher; /**< Cache to matcher. */
	struct mlx5_flow_dv_modify_hdr_resource *modify_hdr;
	/**< Pointer to modify header resource in cache. */
	uint32_t rix_encap_decap;
	/**< Index to encap/decap resource in cache. */
	uint32_t rix_push_vlan;
	/**< Index to push VLAN action resource in cache. */
	uint32_t rix_tag;
	/**< Index to the tag action. */
	uint32_t rix_sample;
	/**< Index to sample action resource in cache. */
	uint32_t rix_dest_array;
	/**< Index to destination array resource in cache. */
} __rte_packed;

/** Device flow handle structure: used both for creating & destroying. */
struct mlx5_flow_handle {
	SILIST_ENTRY(uint32_t)next;
	struct mlx5_vf_vlan vf_vlan; /**< Structure for VF VLAN workaround. */
	/**< Index to next device flow handle. */
	uint64_t layers;
	/**< Bit-fields of present layers, see MLX5_FLOW_LAYER_*. */
	void *drv_flow; /**< pointer to driver flow object. */
	uint32_t split_flow_id:27; /**< Sub flow unique match flow id. */
	uint32_t is_meter_flow_id:1; /**< Indicate if flow_id is for meter. */
	uint32_t fate_action:4; /**< Fate action type. */
	union {
		uint32_t rix_hrxq; /**< Hash Rx queue object index. */
		uint32_t rix_jump; /**< Index to the jump action resource. */
		uint32_t rix_port_id_action;
		/**< Index to port ID action resource. */
		uint32_t rix_fate;
		/**< Generic value indicates the fate action. */
		uint32_t rix_default_fate;
		/**< Indicates default miss fate action. */
		uint32_t rix_srss;
		/**< Indicates shared RSS fate action. */
	};
#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)
	struct mlx5_flow_handle_dv dvh;
#endif
	uint8_t flex_item; /**< referenced Flex Item bitmask. */
} __rte_packed;

/*
 * Size for Verbs device flow handle structure only. Do not use the DV only
 * structure in Verbs. No DV flows attributes will be accessed.
 * Macro offsetof() could also be used here.
 */
#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)
#define MLX5_FLOW_HANDLE_VERBS_SIZE \
	(sizeof(struct mlx5_flow_handle) - sizeof(struct mlx5_flow_handle_dv))
#else
#define MLX5_FLOW_HANDLE_VERBS_SIZE (sizeof(struct mlx5_flow_handle))
#endif

/** Device flow structure only for DV flow creation. */
struct mlx5_flow_dv_workspace {
	uint32_t group; /**< The group index. */
	uint32_t table_id; /**< Flow table identifier. */
	uint8_t transfer; /**< 1 if the flow is E-Switch flow. */
	int actions_n; /**< number of actions. */
	void *actions[MLX5_DV_MAX_NUMBER_OF_ACTIONS]; /**< Action list. */
	struct mlx5_flow_dv_encap_decap_resource *encap_decap;
	/**< Pointer to encap/decap resource in cache. */
	struct mlx5_flow_dv_push_vlan_action_resource *push_vlan_res;
	/**< Pointer to push VLAN action resource in cache. */
	struct mlx5_flow_dv_tag_resource *tag_resource;
	/**< pointer to the tag action. */
	struct mlx5_flow_dv_port_id_action_resource *port_id_action;
	/**< Pointer to port ID action resource. */
	struct mlx5_flow_dv_jump_tbl_resource *jump;
	/**< Pointer to the jump action resource. */
	struct mlx5_flow_dv_match_params value;
	/**< Holds the value that the packet is compared to. */
	struct mlx5_flow_dv_sample_resource *sample_res;
	/**< Pointer to the sample action resource. */
	struct mlx5_flow_dv_dest_array_resource *dest_array_res;
	/**< Pointer to the destination array resource. */
};

#ifdef HAVE_INFINIBAND_VERBS_H
/*
 * Maximal Verbs flow specifications & actions size.
 * Some elements are mutually exclusive, but enough space should be allocated.
 * Tunnel cases: 1. Max 2 Ethernet + IP(v6 len > v4 len) + TCP/UDP headers.
 *               2. One tunnel header (exception: GRE + MPLS),
 *                  SPEC length: GRE == tunnel.
 * Actions: 1. 1 Mark OR Flag.
 *          2. 1 Drop (if any).
 *          3. No limitation for counters, but it makes no sense to support too
 *             many counters in a single device flow.
 */
#ifdef HAVE_IBV_DEVICE_MPLS_SUPPORT
#define MLX5_VERBS_MAX_SPEC_SIZE \
		( \
			(2 * (sizeof(struct ibv_flow_spec_eth) + \
			      sizeof(struct ibv_flow_spec_ipv6) + \
			      sizeof(struct ibv_flow_spec_tcp_udp)) + \
			sizeof(struct ibv_flow_spec_gre) + \
			sizeof(struct ibv_flow_spec_mpls)) \
		)
#else
#define MLX5_VERBS_MAX_SPEC_SIZE \
		( \
			(2 * (sizeof(struct ibv_flow_spec_eth) + \
			      sizeof(struct ibv_flow_spec_ipv6) + \
			      sizeof(struct ibv_flow_spec_tcp_udp)) + \
			sizeof(struct ibv_flow_spec_tunnel)) \
		)
#endif

#if defined(HAVE_IBV_DEVICE_COUNTERS_SET_V42) || \
	defined(HAVE_IBV_DEVICE_COUNTERS_SET_V45)
#define MLX5_VERBS_MAX_ACT_SIZE \
		( \
			sizeof(struct ibv_flow_spec_action_tag) + \
			sizeof(struct ibv_flow_spec_action_drop) + \
			sizeof(struct ibv_flow_spec_counter_action) * 4 \
		)
#else
#define MLX5_VERBS_MAX_ACT_SIZE \
		( \
			sizeof(struct ibv_flow_spec_action_tag) + \
			sizeof(struct ibv_flow_spec_action_drop) \
		)
#endif

#define MLX5_VERBS_MAX_SPEC_ACT_SIZE \
		(MLX5_VERBS_MAX_SPEC_SIZE + MLX5_VERBS_MAX_ACT_SIZE)

/** Device flow structure only for Verbs flow creation. */
struct mlx5_flow_verbs_workspace {
	unsigned int size; /**< Size of the attribute. */
	struct ibv_flow_attr attr; /**< Verbs flow attribute buffer. */
	uint8_t specs[MLX5_VERBS_MAX_SPEC_ACT_SIZE];
	/**< Specifications & actions buffer of verbs flow. */
};
#endif /* HAVE_INFINIBAND_VERBS_H */

#define MLX5_SCALE_FLOW_GROUP_BIT 0
#define MLX5_SCALE_JUMP_FLOW_GROUP_BIT 1

/** Maximal number of device sub-flows supported. */
#define MLX5_NUM_MAX_DEV_FLOWS 32

/**
 * tunnel offload rules type
 */
enum mlx5_tof_rule_type {
	MLX5_TUNNEL_OFFLOAD_NONE = 0,
	MLX5_TUNNEL_OFFLOAD_SET_RULE,
	MLX5_TUNNEL_OFFLOAD_MATCH_RULE,
	MLX5_TUNNEL_OFFLOAD_MISS_RULE,
};

/** Device flow structure. */
__extension__
struct mlx5_flow {
	struct rte_flow *flow; /**< Pointer to the main flow. */
	uint32_t flow_idx; /**< The memory pool index to the main flow. */
	uint64_t hash_fields; /**< Hash Rx queue hash fields. */
	uint64_t act_flags;
	/**< Bit-fields of detected actions, see MLX5_FLOW_ACTION_*. */
	bool external; /**< true if the flow is created external to PMD. */
	uint8_t ingress:1; /**< 1 if the flow is ingress. */
	uint8_t skip_scale:2;
	/**
	 * Each Bit be set to 1 if Skip the scale the flow group with factor.
	 * If bit0 be set to 1, then skip the scale the original flow group;
	 * If bit1 be set to 1, then skip the scale the jump flow group if
	 * having jump action.
	 * 00: Enable scale in a flow, default value.
	 * 01: Skip scale the flow group with factor, enable scale the group
	 * of jump action.
	 * 10: Enable scale the group with factor, skip scale the group of
	 * jump action.
	 * 11: Skip scale the table with factor both for flow group and jump
	 * group.
	 */
	union {
#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)
		struct mlx5_flow_dv_workspace dv;
#endif
#ifdef HAVE_INFINIBAND_VERBS_H
		struct mlx5_flow_verbs_workspace verbs;
#endif
	};
	struct mlx5_flow_handle *handle;
	uint32_t handle_idx; /* Index of the mlx5 flow handle memory. */
	const struct mlx5_flow_tunnel *tunnel;
	enum mlx5_tof_rule_type tof_type;
};

/* Flow meter state. */
#define MLX5_FLOW_METER_DISABLE 0
#define MLX5_FLOW_METER_ENABLE 1

#define MLX5_ASO_WQE_CQE_RESPONSE_DELAY 10u
#define MLX5_MTR_POLL_WQE_CQE_TIMES 100000u

#define MLX5_CT_POLL_WQE_CQE_TIMES MLX5_MTR_POLL_WQE_CQE_TIMES

#define MLX5_MAN_WIDTH 8
/* Legacy Meter parameter structure. */
struct mlx5_legacy_flow_meter {
	struct mlx5_flow_meter_info fm;
	/* Must be the first in struct. */
	TAILQ_ENTRY(mlx5_legacy_flow_meter) next;
	/**< Pointer to the next flow meter structure. */
	uint32_t idx;
	/* Index to meter object. */
};

#define MLX5_MAX_TUNNELS 256
#define MLX5_TNL_MISS_RULE_PRIORITY 3
#define MLX5_TNL_MISS_FDB_JUMP_GRP  0x1234faac

/*
 * When tunnel offload is active, all JUMP group ids are converted
 * using the same method. That conversion is applied both to tunnel and
 * regular rule types.
 * Group ids used in tunnel rules are relative to it's tunnel (!).
 * Application can create number of steer rules, using the same
 * tunnel, with different group id in each rule.
 * Each tunnel stores its groups internally in PMD tunnel object.
 * Groups used in regular rules do not belong to any tunnel and are stored
 * in tunnel hub.
 */

struct mlx5_flow_tunnel {
	LIST_ENTRY(mlx5_flow_tunnel) chain;
	struct rte_flow_tunnel app_tunnel;	/** app tunnel copy */
	uint32_t tunnel_id;			/** unique tunnel ID */
	uint32_t refctn;
	struct rte_flow_action action;
	struct rte_flow_item item;
	struct mlx5_hlist *groups;		/** tunnel groups */
};

/** PMD tunnel related context */
struct mlx5_flow_tunnel_hub {
	/* Tunnels list
	 * Access to the list MUST be MT protected
	 */
	LIST_HEAD(, mlx5_flow_tunnel) tunnels;
	 /* protect access to the tunnels list */
	rte_spinlock_t sl;
	struct mlx5_hlist *groups;		/** non tunnel groups */
};

/* convert jump group to flow table ID in tunnel rules */
struct tunnel_tbl_entry {
	struct mlx5_list_entry hash;
	uint32_t flow_table;
	uint32_t tunnel_id;
	uint32_t group;
};

static inline uint32_t
tunnel_id_to_flow_tbl(uint32_t id)
{
	return id | (1u << 16);
}

static inline uint32_t
tunnel_flow_tbl_to_id(uint32_t flow_tbl)
{
	return flow_tbl & ~(1u << 16);
}

union tunnel_tbl_key {
	uint64_t val;
	struct {
		uint32_t tunnel_id;
		uint32_t group;
	};
};

static inline struct mlx5_flow_tunnel_hub *
mlx5_tunnel_hub(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	return priv->sh->tunnel_hub;
}

static inline bool
is_tunnel_offload_active(const struct rte_eth_dev *dev)
{
#ifdef HAVE_IBV_FLOW_DV_SUPPORT
	const struct mlx5_priv *priv = dev->data->dev_private;
	return !!priv->sh->config.dv_miss_info;
#else
	RTE_SET_USED(dev);
	return false;
#endif
}

static inline bool
is_flow_tunnel_match_rule(enum mlx5_tof_rule_type tof_rule_type)
{
	return tof_rule_type == MLX5_TUNNEL_OFFLOAD_MATCH_RULE;
}

static inline bool
is_flow_tunnel_steer_rule(enum mlx5_tof_rule_type tof_rule_type)
{
	return tof_rule_type == MLX5_TUNNEL_OFFLOAD_SET_RULE;
}

static inline const struct mlx5_flow_tunnel *
flow_actions_to_tunnel(const struct rte_flow_action actions[])
{
	return actions[0].conf;
}

static inline const struct mlx5_flow_tunnel *
flow_items_to_tunnel(const struct rte_flow_item items[])
{
	return items[0].spec;
}

/**
 * Fetch 1, 2, 3 or 4 byte field from the byte array
 * and return as unsigned integer in host-endian format.
 *
 * @param[in] data
 *   Pointer to data array.
 * @param[in] size
 *   Size of field to extract.
 *
 * @return
 *   converted field in host endian format.
 */
static inline uint32_t
flow_dv_fetch_field(const uint8_t *data, uint32_t size)
{
	uint32_t ret;

	switch (size) {
	case 1:
		ret = *data;
		break;
	case 2:
		ret = rte_be_to_cpu_16(*(const unaligned_uint16_t *)data);
		break;
	case 3:
		ret = rte_be_to_cpu_16(*(const unaligned_uint16_t *)data);
		ret = (ret << 8) | *(data + sizeof(uint16_t));
		break;
	case 4:
		ret = rte_be_to_cpu_32(*(const unaligned_uint32_t *)data);
		break;
	default:
		MLX5_ASSERT(false);
		ret = 0;
		break;
	}
	return ret;
}

struct field_modify_info {
	uint32_t size; /* Size of field in protocol header, in bytes. */
	uint32_t offset; /* Offset of field in protocol header, in bytes. */
	enum mlx5_modification_field id;
};

/* HW steering flow attributes. */
struct mlx5_flow_attr {
	uint32_t port_id; /* Port index. */
	uint32_t group; /* Flow group. */
	uint32_t priority; /* Original Priority. */
	/* rss level, used by priority adjustment. */
	uint32_t rss_level;
	/* Action flags, used by priority adjustment. */
	uint32_t act_flags;
	uint32_t tbl_type; /* Flow table type. */
};

/* Flow structure. */
struct rte_flow {
	uint32_t dev_handles;
	/**< Device flow handles that are part of the flow. */
	uint32_t type:2;
	uint32_t drv_type:2; /**< Driver type. */
	uint32_t tunnel:1;
	uint32_t meter:24; /**< Holds flow meter id. */
	uint32_t indirect_type:2; /**< Indirect action type. */
	uint32_t rix_mreg_copy;
	/**< Index to metadata register copy table resource. */
	uint32_t counter; /**< Holds flow counter. */
	uint32_t tunnel_id;  /**< Tunnel id */
	union {
		uint32_t age; /**< Holds ASO age bit index. */
		uint32_t ct; /**< Holds ASO CT index. */
	};
	uint32_t geneve_tlv_option; /**< Holds Geneve TLV option id. > */
} __rte_packed;

/*
 * HWS COUNTER ID's layout
 *       3                   2                   1                   0
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |  T  |     | D |                                               |
 *    ~  Y  |     | C |                    IDX                        ~
 *    |  P  |     | S |                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    Bit 31:29 = TYPE = MLX5_INDIRECT_ACTION_TYPE_COUNT = b'10
 *    Bit 25:24 = DCS index
 *    Bit 23:00 = IDX in this counter belonged DCS bulk.
 */
typedef uint32_t cnt_id_t;

#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)

#ifdef PEDANTIC
#pragma GCC diagnostic ignored "-Wpedantic"
#endif

/* HWS flow struct. */
struct rte_flow_hw {
	uint32_t idx; /* Flow index from indexed pool. */
	uint32_t fate_type; /* Fate action type. */
	union {
		/* Jump action. */
		struct mlx5_hw_jump_action *jump;
		struct mlx5_hrxq *hrxq; /* TIR action. */
	};
	struct rte_flow_template_table *table; /* The table flow allcated from. */
	uint32_t age_idx;
	cnt_id_t cnt_id;
	uint32_t mtr_id;
	uint8_t rule[0]; /* HWS layer data struct. */
} __rte_packed;

#ifdef PEDANTIC
#pragma GCC diagnostic error "-Wpedantic"
#endif

/* rte flow action translate to DR action struct. */
struct mlx5_action_construct_data {
	LIST_ENTRY(mlx5_action_construct_data) next;
	/* Ensure the action types are matched. */
	int type;
	uint32_t idx;  /* Data index. */
	uint16_t action_src; /* rte_flow_action src offset. */
	uint16_t action_dst; /* mlx5dr_rule_action dst offset. */
	union {
		struct {
			/* encap data len. */
			uint16_t len;
		} encap;
		struct {
			/* Modify header action offset in pattern. */
			uint16_t mhdr_cmds_off;
			/* Offset in pattern after modify header actions. */
			uint16_t mhdr_cmds_end;
			/*
			 * True if this action is masked and does not need to
			 * be generated.
			 */
			bool shared;
			/*
			 * Modified field definitions in dst field (SET, ADD)
			 * or src field (COPY).
			 */
			struct field_modify_info field[MLX5_ACT_MAX_MOD_FIELDS];
			/* Modified field definitions in dst field (COPY). */
			struct field_modify_info dcopy[MLX5_ACT_MAX_MOD_FIELDS];
			/*
			 * Masks applied to field values to generate
			 * PRM actions.
			 */
			uint32_t mask[MLX5_ACT_MAX_MOD_FIELDS];
		} modify_header;
		struct {
			uint64_t types; /* RSS hash types. */
			uint32_t level; /* RSS level. */
			uint32_t idx; /* Shared action index. */
		} shared_rss;
		struct {
			cnt_id_t id;
		} shared_counter;
		struct {
			uint32_t id;
		} shared_meter;
	};
};

/* Flow item template struct. */
struct rte_flow_pattern_template {
	LIST_ENTRY(rte_flow_pattern_template) next;
	/* Template attributes. */
	struct rte_flow_pattern_template_attr attr;
	struct mlx5dr_match_template *mt; /* mlx5 match template. */
	uint64_t item_flags; /* Item layer flags. */
	uint64_t orig_item_nb; /* Number of pattern items provided by the user (with END item). */
	uint32_t refcnt;  /* Reference counter. */
	/*
	 * If true, then rule pattern should be prepended with
	 * represented_port pattern item.
	 */
	bool implicit_port;
	/*
	 * If true, then rule pattern should be prepended with
	 * tag pattern item for representor matching.
	 */
	bool implicit_tag;
};

/* Flow action template struct. */
struct rte_flow_actions_template {
	LIST_ENTRY(rte_flow_actions_template) next;
	/* Template attributes. */
	struct rte_flow_actions_template_attr attr;
	struct rte_flow_action *actions; /* Cached flow actions. */
	struct rte_flow_action *masks; /* Cached action masks.*/
	struct mlx5dr_action_template *tmpl; /* mlx5dr action template. */
	uint64_t action_flags; /* Bit-map of all valid action in template. */
	uint16_t dr_actions_num; /* Amount of DR rules actions. */
	uint16_t actions_num; /* Amount of flow actions */
	uint16_t *actions_off; /* DR action offset for given rte action offset. */
	uint16_t reformat_off; /* Offset of DR reformat action. */
	uint16_t mhdr_off; /* Offset of DR modify header action. */
	uint32_t refcnt; /* Reference counter. */
	uint16_t rx_cpy_pos; /* Action position of Rx metadata to be copied. */
};

/* Jump action struct. */
struct mlx5_hw_jump_action {
	/* Action jump from root. */
	struct mlx5dr_action *root_action;
	/* HW steering jump action. */
	struct mlx5dr_action *hws_action;
};

/* Encap decap action struct. */
struct mlx5_hw_encap_decap_action {
	struct mlx5dr_action *action; /* Action object. */
	/* Is header_reformat action shared across flows in table. */
	bool shared;
	size_t data_size; /* Action metadata size. */
	uint8_t data[]; /* Action data. */
};

#define MLX5_MHDR_MAX_CMD ((MLX5_MAX_MODIFY_NUM) * 2 + 1)

/* Modify field action struct. */
struct mlx5_hw_modify_header_action {
	/* Reference to DR action */
	struct mlx5dr_action *action;
	/* Modify header action position in action rule table. */
	uint16_t pos;
	/* Is MODIFY_HEADER action shared across flows in table. */
	bool shared;
	/* Amount of modification commands stored in the precompiled buffer. */
	uint32_t mhdr_cmds_num;
	/* Precompiled modification commands. */
	struct mlx5_modification_cmd mhdr_cmds[MLX5_MHDR_MAX_CMD];
};

/* The maximum actions support in the flow. */
#define MLX5_HW_MAX_ACTS 16

/* DR action set struct. */
struct mlx5_hw_actions {
	/* Dynamic action list. */
	LIST_HEAD(act_list, mlx5_action_construct_data) act_list;
	struct mlx5_hw_jump_action *jump; /* Jump action. */
	struct mlx5_hrxq *tir; /* TIR action. */
	struct mlx5_hw_modify_header_action *mhdr; /* Modify header action. */
	/* Encap/Decap action. */
	struct mlx5_hw_encap_decap_action *encap_decap;
	uint16_t encap_decap_pos; /* Encap/Decap action position. */
	uint32_t mark:1; /* Indicate the mark action. */
	cnt_id_t cnt_id; /* Counter id. */
	uint32_t mtr_id; /* Meter id. */
	/* Translated DR action array from action template. */
	struct mlx5dr_rule_action rule_acts[MLX5_HW_MAX_ACTS];
};

/* mlx5 action template struct. */
struct mlx5_hw_action_template {
	/* Action template pointer. */
	struct rte_flow_actions_template *action_template;
	struct mlx5_hw_actions acts; /* Template actions. */
};

/* mlx5 flow group struct. */
struct mlx5_flow_group {
	struct mlx5_list_entry entry;
	struct rte_eth_dev *dev; /* Reference to corresponding device. */
	struct mlx5dr_table *tbl; /* HWS table object. */
	struct mlx5_hw_jump_action jump; /* Jump action. */
	enum mlx5dr_table_type type; /* Table type. */
	uint32_t group_id; /* Group id. */
	uint32_t idx; /* Group memory index. */
};


#define MLX5_HW_TBL_MAX_ITEM_TEMPLATE 2
#define MLX5_HW_TBL_MAX_ACTION_TEMPLATE 32

struct mlx5_flow_template_table_cfg {
	struct rte_flow_template_table_attr attr; /* Table attributes passed through flow API. */
	bool external; /* True if created by flow API, false if table is internal to PMD. */
};

struct rte_flow_template_table {
	LIST_ENTRY(rte_flow_template_table) next;
	struct mlx5_flow_group *grp; /* The group rte_flow_template_table uses. */
	struct mlx5dr_matcher *matcher; /* Template matcher. */
	/* Item templates bind to the table. */
	struct rte_flow_pattern_template *its[MLX5_HW_TBL_MAX_ITEM_TEMPLATE];
	/* Action templates bind to the table. */
	struct mlx5_hw_action_template ats[MLX5_HW_TBL_MAX_ACTION_TEMPLATE];
	struct mlx5_indexed_pool *flow; /* The table's flow ipool. */
	struct mlx5_flow_template_table_cfg cfg;
	uint32_t type; /* Flow table type RX/TX/FDB. */
	uint8_t nb_item_templates; /* Item template number. */
	uint8_t nb_action_templates; /* Action template number. */
	uint32_t refcnt; /* Table reference counter. */
};

#endif

/*
 * Define list of valid combinations of RX Hash fields
 * (see enum ibv_rx_hash_fields).
 */
#define MLX5_RSS_HASH_IPV4 (IBV_RX_HASH_SRC_IPV4 | IBV_RX_HASH_DST_IPV4)
#define MLX5_RSS_HASH_IPV4_TCP \
	(MLX5_RSS_HASH_IPV4 | \
	 IBV_RX_HASH_SRC_PORT_TCP | IBV_RX_HASH_DST_PORT_TCP)
#define MLX5_RSS_HASH_IPV4_UDP \
	(MLX5_RSS_HASH_IPV4 | \
	 IBV_RX_HASH_SRC_PORT_UDP | IBV_RX_HASH_DST_PORT_UDP)
#define MLX5_RSS_HASH_IPV6 (IBV_RX_HASH_SRC_IPV6 | IBV_RX_HASH_DST_IPV6)
#define MLX5_RSS_HASH_IPV6_TCP \
	(MLX5_RSS_HASH_IPV6 | \
	 IBV_RX_HASH_SRC_PORT_TCP | IBV_RX_HASH_DST_PORT_TCP)
#define MLX5_RSS_HASH_IPV6_UDP \
	(MLX5_RSS_HASH_IPV6 | \
	 IBV_RX_HASH_SRC_PORT_UDP | IBV_RX_HASH_DST_PORT_UDP)
#define MLX5_RSS_HASH_IPV4_SRC_ONLY IBV_RX_HASH_SRC_IPV4
#define MLX5_RSS_HASH_IPV4_DST_ONLY IBV_RX_HASH_DST_IPV4
#define MLX5_RSS_HASH_IPV6_SRC_ONLY IBV_RX_HASH_SRC_IPV6
#define MLX5_RSS_HASH_IPV6_DST_ONLY IBV_RX_HASH_DST_IPV6
#define MLX5_RSS_HASH_IPV4_UDP_SRC_ONLY \
	(MLX5_RSS_HASH_IPV4 | IBV_RX_HASH_SRC_PORT_UDP)
#define MLX5_RSS_HASH_IPV4_UDP_DST_ONLY \
	(MLX5_RSS_HASH_IPV4 | IBV_RX_HASH_DST_PORT_UDP)
#define MLX5_RSS_HASH_IPV6_UDP_SRC_ONLY \
	(MLX5_RSS_HASH_IPV6 | IBV_RX_HASH_SRC_PORT_UDP)
#define MLX5_RSS_HASH_IPV6_UDP_DST_ONLY \
	(MLX5_RSS_HASH_IPV6 | IBV_RX_HASH_DST_PORT_UDP)
#define MLX5_RSS_HASH_IPV4_TCP_SRC_ONLY \
	(MLX5_RSS_HASH_IPV4 | IBV_RX_HASH_SRC_PORT_TCP)
#define MLX5_RSS_HASH_IPV4_TCP_DST_ONLY \
	(MLX5_RSS_HASH_IPV4 | IBV_RX_HASH_DST_PORT_TCP)
#define MLX5_RSS_HASH_IPV6_TCP_SRC_ONLY \
	(MLX5_RSS_HASH_IPV6 | IBV_RX_HASH_SRC_PORT_TCP)
#define MLX5_RSS_HASH_IPV6_TCP_DST_ONLY \
	(MLX5_RSS_HASH_IPV6 | IBV_RX_HASH_DST_PORT_TCP)

#ifndef HAVE_IBV_RX_HASH_IPSEC_SPI
#define IBV_RX_HASH_IPSEC_SPI (1U << 8)
#endif

#define MLX5_RSS_HASH_ESP_SPI IBV_RX_HASH_IPSEC_SPI
#define MLX5_RSS_HASH_IPV4_ESP (MLX5_RSS_HASH_IPV4 | \
				MLX5_RSS_HASH_ESP_SPI)
#define MLX5_RSS_HASH_IPV6_ESP (MLX5_RSS_HASH_IPV6 | \
				MLX5_RSS_HASH_ESP_SPI)
#define MLX5_RSS_HASH_NONE 0ULL


/* extract next protocol type from Ethernet & VLAN headers */
#define MLX5_ETHER_TYPE_FROM_HEADER(_s, _m, _itm, _prt) do { \
	(_prt) = ((const struct _s *)(_itm)->mask)->_m;       \
	(_prt) &= ((const struct _s *)(_itm)->spec)->_m;      \
	(_prt) = rte_be_to_cpu_16((_prt));                    \
} while (0)

/* array of valid combinations of RX Hash fields for RSS */
static const uint64_t mlx5_rss_hash_fields[] = {
	MLX5_RSS_HASH_IPV4,
	MLX5_RSS_HASH_IPV4_TCP,
	MLX5_RSS_HASH_IPV4_UDP,
	MLX5_RSS_HASH_IPV4_ESP,
	MLX5_RSS_HASH_IPV6,
	MLX5_RSS_HASH_IPV6_TCP,
	MLX5_RSS_HASH_IPV6_UDP,
	MLX5_RSS_HASH_IPV6_ESP,
	MLX5_RSS_HASH_ESP_SPI,
	MLX5_RSS_HASH_NONE,
};

/* Shared RSS action structure */
struct mlx5_shared_action_rss {
	ILIST_ENTRY(uint32_t)next; /**< Index to the next RSS structure. */
	uint32_t refcnt; /**< Atomically accessed refcnt. */
	struct rte_flow_action_rss origin; /**< Original rte RSS action. */
	uint8_t key[MLX5_RSS_HASH_KEY_LEN]; /**< RSS hash key. */
	struct mlx5_ind_table_obj *ind_tbl;
	/**< Hash RX queues (hrxq, hrxq_tunnel fields) indirection table. */
	uint32_t hrxq[MLX5_RSS_HASH_FIELDS_LEN];
	/**< Hash RX queue indexes mapped to mlx5_rss_hash_fields */
	rte_spinlock_t action_rss_sl; /**< Shared RSS action spinlock. */
};

struct rte_flow_action_handle {
	uint32_t id;
};

/* Thread specific flow workspace intermediate data. */
struct mlx5_flow_workspace {
	/* If creating another flow in same thread, push new as stack. */
	struct mlx5_flow_workspace *prev;
	struct mlx5_flow_workspace *next;
	struct mlx5_flow_workspace *gc;
	uint32_t inuse; /* can't create new flow with current. */
	struct mlx5_flow flows[MLX5_NUM_MAX_DEV_FLOWS];
	struct mlx5_flow_rss_desc rss_desc;
	uint32_t flow_idx; /* Intermediate device flow index. */
	struct mlx5_flow_meter_info *fm; /* Pointer to the meter in flow. */
	struct mlx5_flow_meter_policy *policy;
	/* The meter policy used by meter in flow. */
	struct mlx5_flow_meter_policy *final_policy;
	/* The final policy when meter policy is hierarchy. */
	uint32_t skip_matcher_reg:1;
	/* Indicates if need to skip matcher register in translate. */
	uint32_t mark:1; /* Indicates if flow contains mark action. */
	uint32_t vport_meta_tag; /* Used for vport index match. */
};

/* Matcher translate type. */
enum MLX5_SET_MATCHER {
	MLX5_SET_MATCHER_SW_V = 1 << 0,
	MLX5_SET_MATCHER_SW_M = 1 << 1,
	MLX5_SET_MATCHER_HS_V = 1 << 2,
	MLX5_SET_MATCHER_HS_M = 1 << 3,
};

#define MLX5_SET_MATCHER_SW (MLX5_SET_MATCHER_SW_V | MLX5_SET_MATCHER_SW_M)
#define MLX5_SET_MATCHER_HS (MLX5_SET_MATCHER_HS_V | MLX5_SET_MATCHER_HS_M)
#define MLX5_SET_MATCHER_V (MLX5_SET_MATCHER_SW_V | MLX5_SET_MATCHER_HS_V)
#define MLX5_SET_MATCHER_M (MLX5_SET_MATCHER_SW_M | MLX5_SET_MATCHER_HS_M)

/* Flow matcher workspace intermediate data. */
struct mlx5_dv_matcher_workspace {
	uint8_t priority; /* Flow priority. */
	uint64_t last_item; /* Last item in pattern. */
	uint64_t item_flags; /* Flow item pattern flags. */
	uint64_t action_flags; /* Flow action flags. */
	bool external; /* External flow or not. */
	uint32_t vlan_tag:12; /* Flow item VLAN tag. */
	uint8_t next_protocol; /* Tunnel next protocol */
	uint32_t geneve_tlv_option; /* Flow item Geneve TLV option. */
	uint32_t group; /* Flow group. */
	uint16_t udp_dport; /* Flow item UDP port. */
	const struct rte_flow_attr *attr; /* Flow attribute. */
	struct mlx5_flow_rss_desc *rss_desc; /* RSS descriptor. */
	const struct rte_flow_item *tunnel_item; /* Flow tunnel item. */
	const struct rte_flow_item *gre_item; /* Flow GRE item. */
	const struct rte_flow_item *integrity_items[2];
};

struct mlx5_flow_split_info {
	uint32_t external:1;
	/**< True if flow is created by request external to PMD. */
	uint32_t prefix_mark:1; /**< Prefix subflow mark flag. */
	uint32_t skip_scale:8; /**< Skip the scale the table with factor. */
	uint32_t flow_idx; /**< This memory pool index to the flow. */
	uint32_t table_id; /**< Flow table identifier. */
	uint64_t prefix_layers; /**< Prefix subflow layers. */
};

struct flow_hw_port_info {
	uint32_t regc_mask;
	uint32_t regc_value;
	uint32_t is_wire:1;
};

extern struct flow_hw_port_info mlx5_flow_hw_port_infos[RTE_MAX_ETHPORTS];

#define MLX5_FLOW_HW_TAGS_MAX 8
extern uint32_t mlx5_flow_hw_avl_tags_init_cnt;
extern enum modify_reg mlx5_flow_hw_avl_tags[];
extern enum modify_reg mlx5_flow_hw_aso_tag;

/*
 * Get metadata match tag and mask for given rte_eth_dev port.
 * Used in HWS rule creation.
 */
static __rte_always_inline const struct flow_hw_port_info *
flow_hw_conv_port_id(const uint16_t port_id)
{
	struct flow_hw_port_info *port_info;

	if (port_id >= RTE_MAX_ETHPORTS)
		return NULL;
	port_info = &mlx5_flow_hw_port_infos[port_id];
	return !!port_info->regc_mask ? port_info : NULL;
}

#ifdef HAVE_IBV_FLOW_DV_SUPPORT
/*
 * Get metadata match tag and mask for the uplink port represented
 * by given IB context. Used in HWS context creation.
 */
static __rte_always_inline const struct flow_hw_port_info *
flow_hw_get_wire_port(struct ibv_context *ibctx)
{
	struct ibv_device *ibdev = ibctx->device;
	uint16_t port_id;

	MLX5_ETH_FOREACH_DEV(port_id, NULL) {
		const struct mlx5_priv *priv =
				rte_eth_devices[port_id].data->dev_private;

		if (priv && priv->master) {
			struct ibv_context *port_ibctx = priv->sh->cdev->ctx;

			if (port_ibctx->device == ibdev)
				return flow_hw_conv_port_id(port_id);
		}
	}
	return NULL;
}
#endif

extern uint32_t mlx5_flow_hw_flow_metadata_config_refcnt;
extern uint8_t mlx5_flow_hw_flow_metadata_esw_en;
extern uint8_t mlx5_flow_hw_flow_metadata_xmeta_en;

void flow_hw_init_flow_metadata_config(struct rte_eth_dev *dev);
void flow_hw_clear_flow_metadata_config(void);

/*
 * Convert metadata or tag to the actual register.
 * META: Can only be used to match in the FDB in this stage, fixed C_1.
 * TAG: C_x expect meter color reg and the reserved ones.
 * TODO: Per port / device, FDB or NIC for Meta matching.
 */
static __rte_always_inline int
flow_hw_get_reg_id(enum rte_flow_item_type type, uint32_t id)
{
	switch (type) {
	case RTE_FLOW_ITEM_TYPE_META:
#ifdef HAVE_MLX5_HWS_SUPPORT
		if (mlx5_flow_hw_flow_metadata_esw_en &&
		    mlx5_flow_hw_flow_metadata_xmeta_en == MLX5_XMETA_MODE_META32_HWS) {
			return REG_C_1;
		}
#endif
		/*
		 * On root table - PMD allows only egress META matching, thus
		 * REG_A matching is sufficient.
		 *
		 * On non-root tables - REG_A corresponds to general_purpose_lookup_field,
		 * which translates to REG_A in NIC TX and to REG_B in NIC RX.
		 * However, current FW does not implement REG_B case right now, so
		 * REG_B case should be rejected on pattern template validation.
		 */
		return REG_A;
	case RTE_FLOW_ITEM_TYPE_CONNTRACK:
	case RTE_FLOW_ITEM_TYPE_METER_COLOR:
		return mlx5_flow_hw_aso_tag;
	case RTE_FLOW_ITEM_TYPE_TAG:
		MLX5_ASSERT(id < MLX5_FLOW_HW_TAGS_MAX);
		return mlx5_flow_hw_avl_tags[id];
	default:
		return REG_NON;
	}
}

static __rte_always_inline int
flow_hw_get_port_id_from_ctx(void *dr_ctx, uint32_t *port_val)
{
#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)
	uint32_t port;

	MLX5_ETH_FOREACH_DEV(port, NULL) {
		struct mlx5_priv *priv;
		priv = rte_eth_devices[port].data->dev_private;

		if (priv->dr_ctx == dr_ctx) {
			*port_val = port;
			return 0;
		}
	}
#else
	RTE_SET_USED(dr_ctx);
	RTE_SET_USED(port_val);
#endif
	return -EINVAL;
}

void flow_hw_set_port_info(struct rte_eth_dev *dev);
void flow_hw_clear_port_info(struct rte_eth_dev *dev);

void flow_hw_init_tags_set(struct rte_eth_dev *dev);
void flow_hw_clear_tags_set(struct rte_eth_dev *dev);

int flow_hw_create_vport_action(struct rte_eth_dev *dev);
void flow_hw_destroy_vport_action(struct rte_eth_dev *dev);

typedef int (*mlx5_flow_validate_t)(struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    const struct rte_flow_item items[],
				    const struct rte_flow_action actions[],
				    bool external,
				    int hairpin,
				    struct rte_flow_error *error);
typedef struct mlx5_flow *(*mlx5_flow_prepare_t)
	(struct rte_eth_dev *dev, const struct rte_flow_attr *attr,
	 const struct rte_flow_item items[],
	 const struct rte_flow_action actions[], struct rte_flow_error *error);
typedef int (*mlx5_flow_translate_t)(struct rte_eth_dev *dev,
				     struct mlx5_flow *dev_flow,
				     const struct rte_flow_attr *attr,
				     const struct rte_flow_item items[],
				     const struct rte_flow_action actions[],
				     struct rte_flow_error *error);
typedef int (*mlx5_flow_apply_t)(struct rte_eth_dev *dev, struct rte_flow *flow,
				 struct rte_flow_error *error);
typedef void (*mlx5_flow_remove_t)(struct rte_eth_dev *dev,
				   struct rte_flow *flow);
typedef void (*mlx5_flow_destroy_t)(struct rte_eth_dev *dev,
				    struct rte_flow *flow);
typedef int (*mlx5_flow_query_t)(struct rte_eth_dev *dev,
				 struct rte_flow *flow,
				 const struct rte_flow_action *actions,
				 void *data,
				 struct rte_flow_error *error);
typedef int (*mlx5_flow_create_mtr_tbls_t)(struct rte_eth_dev *dev,
					struct mlx5_flow_meter_info *fm,
					uint32_t mtr_idx,
					uint8_t domain_bitmap);
typedef void (*mlx5_flow_destroy_mtr_tbls_t)(struct rte_eth_dev *dev,
				struct mlx5_flow_meter_info *fm);
typedef void (*mlx5_flow_destroy_mtr_drop_tbls_t)(struct rte_eth_dev *dev);
typedef struct mlx5_flow_meter_sub_policy *
	(*mlx5_flow_meter_sub_policy_rss_prepare_t)
		(struct rte_eth_dev *dev,
		struct mlx5_flow_meter_policy *mtr_policy,
		struct mlx5_flow_rss_desc *rss_desc[MLX5_MTR_RTE_COLORS]);
typedef int (*mlx5_flow_meter_hierarchy_rule_create_t)
		(struct rte_eth_dev *dev,
		struct mlx5_flow_meter_info *fm,
		int32_t src_port,
		const struct rte_flow_item *item,
		struct rte_flow_error *error);
typedef void (*mlx5_flow_destroy_sub_policy_with_rxq_t)
	(struct rte_eth_dev *dev,
	struct mlx5_flow_meter_policy *mtr_policy);
typedef uint32_t (*mlx5_flow_mtr_alloc_t)
					    (struct rte_eth_dev *dev);
typedef void (*mlx5_flow_mtr_free_t)(struct rte_eth_dev *dev,
						uint32_t mtr_idx);
typedef uint32_t (*mlx5_flow_counter_alloc_t)
				   (struct rte_eth_dev *dev);
typedef void (*mlx5_flow_counter_free_t)(struct rte_eth_dev *dev,
					 uint32_t cnt);
typedef int (*mlx5_flow_counter_query_t)(struct rte_eth_dev *dev,
					 uint32_t cnt,
					 bool clear, uint64_t *pkts,
					 uint64_t *bytes, void **action);
typedef int (*mlx5_flow_get_aged_flows_t)
					(struct rte_eth_dev *dev,
					 void **context,
					 uint32_t nb_contexts,
					 struct rte_flow_error *error);
typedef int (*mlx5_flow_get_q_aged_flows_t)
					(struct rte_eth_dev *dev,
					 uint32_t queue_id,
					 void **context,
					 uint32_t nb_contexts,
					 struct rte_flow_error *error);
typedef int (*mlx5_flow_action_validate_t)
				(struct rte_eth_dev *dev,
				 const struct rte_flow_indir_action_conf *conf,
				 const struct rte_flow_action *action,
				 struct rte_flow_error *error);
typedef struct rte_flow_action_handle *(*mlx5_flow_action_create_t)
				(struct rte_eth_dev *dev,
				 const struct rte_flow_indir_action_conf *conf,
				 const struct rte_flow_action *action,
				 struct rte_flow_error *error);
typedef int (*mlx5_flow_action_destroy_t)
				(struct rte_eth_dev *dev,
				 struct rte_flow_action_handle *action,
				 struct rte_flow_error *error);
typedef int (*mlx5_flow_action_update_t)
			(struct rte_eth_dev *dev,
			 struct rte_flow_action_handle *action,
			 const void *update,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_action_query_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_action_handle *action,
			 void *data,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_sync_domain_t)
			(struct rte_eth_dev *dev,
			 uint32_t domains,
			 uint32_t flags);
typedef int (*mlx5_flow_validate_mtr_acts_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_action *actions[RTE_COLORS],
			 struct rte_flow_attr *attr,
			 bool *is_rss,
			 uint8_t *domain_bitmap,
			 uint8_t *policy_mode,
			 struct rte_mtr_error *error);
typedef int (*mlx5_flow_create_mtr_acts_t)
			(struct rte_eth_dev *dev,
		      struct mlx5_flow_meter_policy *mtr_policy,
		      const struct rte_flow_action *actions[RTE_COLORS],
		      struct rte_flow_attr *attr,
		      struct rte_mtr_error *error);
typedef void (*mlx5_flow_destroy_mtr_acts_t)
			(struct rte_eth_dev *dev,
		      struct mlx5_flow_meter_policy *mtr_policy);
typedef int (*mlx5_flow_create_policy_rules_t)
			(struct rte_eth_dev *dev,
			  struct mlx5_flow_meter_policy *mtr_policy);
typedef void (*mlx5_flow_destroy_policy_rules_t)
			(struct rte_eth_dev *dev,
			  struct mlx5_flow_meter_policy *mtr_policy);
typedef int (*mlx5_flow_create_def_policy_t)
			(struct rte_eth_dev *dev);
typedef void (*mlx5_flow_destroy_def_policy_t)
			(struct rte_eth_dev *dev);
typedef int (*mlx5_flow_discover_priorities_t)
			(struct rte_eth_dev *dev,
			 const uint16_t *vprio, int vprio_n);
typedef struct rte_flow_item_flex_handle *(*mlx5_flow_item_create_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_item_flex_conf *conf,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_item_release_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_item_flex_handle *handle,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_item_update_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_item_flex_handle *handle,
			 const struct rte_flow_item_flex_conf *conf,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_info_get_t)
			(struct rte_eth_dev *dev,
			 struct rte_flow_port_info *port_info,
			 struct rte_flow_queue_info *queue_info,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_port_configure_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_port_attr *port_attr,
			 uint16_t nb_queue,
			 const struct rte_flow_queue_attr *queue_attr[],
			 struct rte_flow_error *err);
typedef int (*mlx5_flow_pattern_validate_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_pattern_template_attr *attr,
			 const struct rte_flow_item items[],
			 struct rte_flow_error *error);
typedef struct rte_flow_pattern_template *(*mlx5_flow_pattern_template_create_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_pattern_template_attr *attr,
			 const struct rte_flow_item items[],
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_pattern_template_destroy_t)
			(struct rte_eth_dev *dev,
			 struct rte_flow_pattern_template *template,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_actions_validate_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_actions_template_attr *attr,
			 const struct rte_flow_action actions[],
			 const struct rte_flow_action masks[],
			 struct rte_flow_error *error);
typedef struct rte_flow_actions_template *(*mlx5_flow_actions_template_create_t)
			(struct rte_eth_dev *dev,
			 const struct rte_flow_actions_template_attr *attr,
			 const struct rte_flow_action actions[],
			 const struct rte_flow_action masks[],
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_actions_template_destroy_t)
			(struct rte_eth_dev *dev,
			 struct rte_flow_actions_template *template,
			 struct rte_flow_error *error);
typedef struct rte_flow_template_table *(*mlx5_flow_table_create_t)
		(struct rte_eth_dev *dev,
		 const struct rte_flow_template_table_attr *attr,
		 struct rte_flow_pattern_template *item_templates[],
		 uint8_t nb_item_templates,
		 struct rte_flow_actions_template *action_templates[],
		 uint8_t nb_action_templates,
		 struct rte_flow_error *error);
typedef int (*mlx5_flow_table_destroy_t)
			(struct rte_eth_dev *dev,
			 struct rte_flow_template_table *table,
			 struct rte_flow_error *error);
typedef struct rte_flow *(*mlx5_flow_async_flow_create_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 struct rte_flow_template_table *table,
			 const struct rte_flow_item items[],
			 uint8_t pattern_template_index,
			 const struct rte_flow_action actions[],
			 uint8_t action_template_index,
			 void *user_data,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_async_flow_destroy_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 struct rte_flow *flow,
			 void *user_data,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_pull_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 struct rte_flow_op_result res[],
			 uint16_t n_res,
			 struct rte_flow_error *error);
typedef int (*mlx5_flow_push_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 struct rte_flow_error *error);

typedef struct rte_flow_action_handle *(*mlx5_flow_async_action_handle_create_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 const struct rte_flow_indir_action_conf *conf,
			 const struct rte_flow_action *action,
			 void *user_data,
			 struct rte_flow_error *error);

typedef int (*mlx5_flow_async_action_handle_update_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 struct rte_flow_action_handle *handle,
			 const void *update,
			 void *user_data,
			 struct rte_flow_error *error);

typedef int (*mlx5_flow_async_action_handle_query_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 const struct rte_flow_action_handle *handle,
			 void *data,
			 void *user_data,
			 struct rte_flow_error *error);

typedef int (*mlx5_flow_async_action_handle_destroy_t)
			(struct rte_eth_dev *dev,
			 uint32_t queue,
			 const struct rte_flow_op_attr *attr,
			 struct rte_flow_action_handle *handle,
			 void *user_data,
			 struct rte_flow_error *error);

struct mlx5_flow_driver_ops {
	mlx5_flow_validate_t validate;
	mlx5_flow_prepare_t prepare;
	mlx5_flow_translate_t translate;
	mlx5_flow_apply_t apply;
	mlx5_flow_remove_t remove;
	mlx5_flow_destroy_t destroy;
	mlx5_flow_query_t query;
	mlx5_flow_create_mtr_tbls_t create_mtr_tbls;
	mlx5_flow_destroy_mtr_tbls_t destroy_mtr_tbls;
	mlx5_flow_destroy_mtr_drop_tbls_t destroy_mtr_drop_tbls;
	mlx5_flow_mtr_alloc_t create_meter;
	mlx5_flow_mtr_free_t free_meter;
	mlx5_flow_validate_mtr_acts_t validate_mtr_acts;
	mlx5_flow_create_mtr_acts_t create_mtr_acts;
	mlx5_flow_destroy_mtr_acts_t destroy_mtr_acts;
	mlx5_flow_create_policy_rules_t create_policy_rules;
	mlx5_flow_destroy_policy_rules_t destroy_policy_rules;
	mlx5_flow_create_def_policy_t create_def_policy;
	mlx5_flow_destroy_def_policy_t destroy_def_policy;
	mlx5_flow_meter_sub_policy_rss_prepare_t meter_sub_policy_rss_prepare;
	mlx5_flow_meter_hierarchy_rule_create_t meter_hierarchy_rule_create;
	mlx5_flow_destroy_sub_policy_with_rxq_t destroy_sub_policy_with_rxq;
	mlx5_flow_counter_alloc_t counter_alloc;
	mlx5_flow_counter_free_t counter_free;
	mlx5_flow_counter_query_t counter_query;
	mlx5_flow_get_aged_flows_t get_aged_flows;
	mlx5_flow_get_q_aged_flows_t get_q_aged_flows;
	mlx5_flow_action_validate_t action_validate;
	mlx5_flow_action_create_t action_create;
	mlx5_flow_action_destroy_t action_destroy;
	mlx5_flow_action_update_t action_update;
	mlx5_flow_action_query_t action_query;
	mlx5_flow_sync_domain_t sync_domain;
	mlx5_flow_discover_priorities_t discover_priorities;
	mlx5_flow_item_create_t item_create;
	mlx5_flow_item_release_t item_release;
	mlx5_flow_item_update_t item_update;
	mlx5_flow_info_get_t info_get;
	mlx5_flow_port_configure_t configure;
	mlx5_flow_pattern_validate_t pattern_validate;
	mlx5_flow_pattern_template_create_t pattern_template_create;
	mlx5_flow_pattern_template_destroy_t pattern_template_destroy;
	mlx5_flow_actions_validate_t actions_validate;
	mlx5_flow_actions_template_create_t actions_template_create;
	mlx5_flow_actions_template_destroy_t actions_template_destroy;
	mlx5_flow_table_create_t template_table_create;
	mlx5_flow_table_destroy_t template_table_destroy;
	mlx5_flow_async_flow_create_t async_flow_create;
	mlx5_flow_async_flow_destroy_t async_flow_destroy;
	mlx5_flow_pull_t pull;
	mlx5_flow_push_t push;
	mlx5_flow_async_action_handle_create_t async_action_create;
	mlx5_flow_async_action_handle_update_t async_action_update;
	mlx5_flow_async_action_handle_query_t async_action_query;
	mlx5_flow_async_action_handle_destroy_t async_action_destroy;
};

/* mlx5_flow.c */

struct mlx5_flow_workspace *mlx5_flow_push_thread_workspace(void);
void mlx5_flow_pop_thread_workspace(void);
struct mlx5_flow_workspace *mlx5_flow_get_thread_workspace(void);

__extension__
struct flow_grp_info {
	uint64_t external:1;
	uint64_t transfer:1;
	uint64_t fdb_def_rule:1;
	/* force standard group translation */
	uint64_t std_tbl_fix:1;
	uint64_t skip_scale:2;
};

static inline bool
tunnel_use_standard_attr_group_translate
		    (const struct rte_eth_dev *dev,
		     const struct rte_flow_attr *attr,
		     const struct mlx5_flow_tunnel *tunnel,
		     enum mlx5_tof_rule_type tof_rule_type)
{
	bool verdict;

	if (!is_tunnel_offload_active(dev))
		/* no tunnel offload API */
		verdict = true;
	else if (tunnel) {
		/*
		 * OvS will use jump to group 0 in tunnel steer rule.
		 * If tunnel steer rule starts from group 0 (attr.group == 0)
		 * that 0 group must be translated with standard method.
		 * attr.group == 0 in tunnel match rule translated with tunnel
		 * method
		 */
		verdict = !attr->group &&
			  is_flow_tunnel_steer_rule(tof_rule_type);
	} else {
		/*
		 * non-tunnel group translation uses standard method for
		 * root group only: attr.group == 0
		 */
		verdict = !attr->group;
	}

	return verdict;
}

/**
 * Get DV flow aso meter by index.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] idx
 *   mlx5 flow aso meter index in the container.
 * @param[out] ppool
 *   mlx5 flow aso meter pool in the container,
 *
 * @return
 *   Pointer to the aso meter, NULL otherwise.
 */
static inline struct mlx5_aso_mtr *
mlx5_aso_meter_by_idx(struct mlx5_priv *priv, uint32_t idx)
{
	struct mlx5_aso_mtr_pool *pool;
	struct mlx5_aso_mtr_pools_mng *pools_mng =
				&priv->sh->mtrmng->pools_mng;

	if (priv->mtr_bulk.aso)
		return priv->mtr_bulk.aso + idx;
	/* Decrease to original index. */
	idx--;
	MLX5_ASSERT(idx / MLX5_ASO_MTRS_PER_POOL < pools_mng->n);
	rte_rwlock_read_lock(&pools_mng->resize_mtrwl);
	pool = pools_mng->pools[idx / MLX5_ASO_MTRS_PER_POOL];
	rte_rwlock_read_unlock(&pools_mng->resize_mtrwl);
	return &pool->mtrs[idx % MLX5_ASO_MTRS_PER_POOL];
}

static __rte_always_inline const struct rte_flow_item *
mlx5_find_end_item(const struct rte_flow_item *item)
{
	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++);
	return item;
}

static __rte_always_inline bool
mlx5_validate_integrity_item(const struct rte_flow_item_integrity *item)
{
	struct rte_flow_item_integrity test = *item;
	test.l3_ok = 0;
	test.l4_ok = 0;
	test.ipv4_csum_ok = 0;
	test.l4_csum_ok = 0;
	return (test.value == 0);
}

/*
 * Get ASO CT action by device and index.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] idx
 *   Index to the ASO CT action.
 *
 * @return
 *   The specified ASO CT action pointer.
 */
static inline struct mlx5_aso_ct_action *
flow_aso_ct_get_by_dev_idx(struct rte_eth_dev *dev, uint32_t idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_aso_ct_pools_mng *mng = priv->sh->ct_mng;
	struct mlx5_aso_ct_pool *pool;

	idx--;
	MLX5_ASSERT((idx / MLX5_ASO_CT_ACTIONS_PER_POOL) < mng->n);
	/* Bit operation AND could be used. */
	rte_rwlock_read_lock(&mng->resize_rwl);
	pool = mng->pools[idx / MLX5_ASO_CT_ACTIONS_PER_POOL];
	rte_rwlock_read_unlock(&mng->resize_rwl);
	return &pool->actions[idx % MLX5_ASO_CT_ACTIONS_PER_POOL];
}

/*
 * Get ASO CT action by owner & index.
 *
 * @param[in] dev
 *   Pointer to the Ethernet device structure.
 * @param[in] idx
 *   Index to the ASO CT action and owner port combination.
 *
 * @return
 *   The specified ASO CT action pointer.
 */
static inline struct mlx5_aso_ct_action *
flow_aso_ct_get_by_idx(struct rte_eth_dev *dev, uint32_t own_idx)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_aso_ct_action *ct;
	uint16_t owner = (uint16_t)MLX5_INDIRECT_ACT_CT_GET_OWNER(own_idx);
	uint32_t idx = MLX5_INDIRECT_ACT_CT_GET_IDX(own_idx);

	if (owner == PORT_ID(priv)) {
		ct = flow_aso_ct_get_by_dev_idx(dev, idx);
	} else {
		struct rte_eth_dev *owndev = &rte_eth_devices[owner];

		MLX5_ASSERT(owner < RTE_MAX_ETHPORTS);
		if (dev->data->dev_started != 1)
			return NULL;
		ct = flow_aso_ct_get_by_dev_idx(owndev, idx);
		if (ct->peer != PORT_ID(priv))
			return NULL;
	}
	return ct;
}

static inline uint16_t
mlx5_translate_tunnel_etypes(uint64_t pattern_flags)
{
	if (pattern_flags & MLX5_FLOW_LAYER_INNER_L2)
		return RTE_ETHER_TYPE_TEB;
	else if (pattern_flags & MLX5_FLOW_LAYER_INNER_L3_IPV4)
		return RTE_ETHER_TYPE_IPV4;
	else if (pattern_flags & MLX5_FLOW_LAYER_INNER_L3_IPV6)
		return RTE_ETHER_TYPE_IPV6;
	else if (pattern_flags & MLX5_FLOW_LAYER_MPLS)
		return RTE_ETHER_TYPE_MPLS;
	return 0;
}

int flow_hw_q_flow_flush(struct rte_eth_dev *dev,
			 struct rte_flow_error *error);

/*
 * Convert rte_mtr_color to mlx5 color.
 *
 * @param[in] rcol
 *   rte_mtr_color.
 *
 * @return
 *   mlx5 color.
 */
static inline int
rte_col_2_mlx5_col(enum rte_color rcol)
{
	switch (rcol) {
	case RTE_COLOR_GREEN:
		return MLX5_FLOW_COLOR_GREEN;
	case RTE_COLOR_YELLOW:
		return MLX5_FLOW_COLOR_YELLOW;
	case RTE_COLOR_RED:
		return MLX5_FLOW_COLOR_RED;
	default:
		break;
	}
	return MLX5_FLOW_COLOR_UNDEFINED;
}

/**
 * Indicates whether flow source vport is representor port.
 *
 * @param[in] priv
 *   Pointer to device private context structure.
 * @param[in] act_priv
 *   Pointer to actual device private context structure if have.
 *
 * @return
 *   True when the flow source vport is representor port, false otherwise.
 */
static inline bool
flow_source_vport_representor(struct mlx5_priv *priv, struct mlx5_priv *act_priv)
{
	MLX5_ASSERT(priv);
	return (!act_priv ? (priv->representor_id != UINT16_MAX) :
		 (act_priv->representor_id != UINT16_MAX));
}

/* All types of Ethernet patterns used in control flow rules. */
enum mlx5_flow_ctrl_rx_eth_pattern_type {
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_ALL = 0,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_ALL_MCAST,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_BCAST,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_BCAST_VLAN,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_IPV4_MCAST,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_IPV4_MCAST_VLAN,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_IPV6_MCAST,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_IPV6_MCAST_VLAN,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_DMAC,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_DMAC_VLAN,
	MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_MAX,
};

/* All types of RSS actions used in control flow rules. */
enum mlx5_flow_ctrl_rx_expanded_rss_type {
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_NON_IP = 0,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV4,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV4_UDP,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV4_TCP,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV6,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV6_UDP,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_IPV6_TCP,
	MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_MAX,
};

/**
 * Contains pattern template, template table and its attributes for a single
 * combination of Ethernet pattern and RSS action. Used to create control flow rules
 * with HWS.
 */
struct mlx5_flow_hw_ctrl_rx_table {
	struct rte_flow_template_table_attr attr;
	struct rte_flow_pattern_template *pt;
	struct rte_flow_template_table *tbl;
};

/* Contains all templates required to create control flow rules with HWS. */
struct mlx5_flow_hw_ctrl_rx {
	struct rte_flow_actions_template *rss[MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_MAX];
	struct mlx5_flow_hw_ctrl_rx_table tables[MLX5_FLOW_HW_CTRL_RX_ETH_PATTERN_MAX]
						[MLX5_FLOW_HW_CTRL_RX_EXPANDED_RSS_MAX];
};

/* Contains all templates required for control flow rules in FDB with HWS. */
struct mlx5_flow_hw_ctrl_fdb {
	struct rte_flow_pattern_template *esw_mgr_items_tmpl;
	struct rte_flow_actions_template *regc_jump_actions_tmpl;
	struct rte_flow_template_table *hw_esw_sq_miss_root_tbl;
	struct rte_flow_pattern_template *regc_sq_items_tmpl;
	struct rte_flow_actions_template *port_actions_tmpl;
	struct rte_flow_template_table *hw_esw_sq_miss_tbl;
	struct rte_flow_pattern_template *port_items_tmpl;
	struct rte_flow_actions_template *jump_one_actions_tmpl;
	struct rte_flow_template_table *hw_esw_zero_tbl;
	struct rte_flow_pattern_template *tx_meta_items_tmpl;
	struct rte_flow_actions_template *tx_meta_actions_tmpl;
	struct rte_flow_template_table *hw_tx_meta_cpy_tbl;
	struct rte_flow_pattern_template *lacp_rx_items_tmpl;
	struct rte_flow_actions_template *lacp_rx_actions_tmpl;
	struct rte_flow_template_table *hw_lacp_rx_tbl;
};

#define MLX5_CTRL_PROMISCUOUS    (RTE_BIT32(0))
#define MLX5_CTRL_ALL_MULTICAST  (RTE_BIT32(1))
#define MLX5_CTRL_BROADCAST      (RTE_BIT32(2))
#define MLX5_CTRL_IPV4_MULTICAST (RTE_BIT32(3))
#define MLX5_CTRL_IPV6_MULTICAST (RTE_BIT32(4))
#define MLX5_CTRL_DMAC           (RTE_BIT32(5))
#define MLX5_CTRL_VLAN_FILTER    (RTE_BIT32(6))

int mlx5_flow_hw_ctrl_flows(struct rte_eth_dev *dev, uint32_t flags);
void mlx5_flow_hw_cleanup_ctrl_rx_templates(struct rte_eth_dev *dev);

int mlx5_flow_group_to_table(struct rte_eth_dev *dev,
			     const struct mlx5_flow_tunnel *tunnel,
			     uint32_t group, uint32_t *table,
			     const struct flow_grp_info *flags,
			     struct rte_flow_error *error);
uint64_t mlx5_flow_hashfields_adjust(struct mlx5_flow_rss_desc *rss_desc,
				     int tunnel, uint64_t layer_types,
				     uint64_t hash_fields);
int mlx5_flow_discover_priorities(struct rte_eth_dev *dev);
uint32_t mlx5_flow_adjust_priority(struct rte_eth_dev *dev, int32_t priority,
				   uint32_t subpriority);
uint32_t mlx5_get_lowest_priority(struct rte_eth_dev *dev,
					const struct rte_flow_attr *attr);
uint16_t mlx5_get_matcher_priority(struct rte_eth_dev *dev,
				   const struct rte_flow_attr *attr,
				   uint32_t subpriority, bool external);
uint32_t mlx5_get_send_to_kernel_priority(struct rte_eth_dev *dev);
int mlx5_flow_get_reg_id(struct rte_eth_dev *dev,
				     enum mlx5_feature_name feature,
				     uint32_t id,
				     struct rte_flow_error *error);
const struct rte_flow_action *mlx5_flow_find_action
					(const struct rte_flow_action *actions,
					 enum rte_flow_action_type action);
int mlx5_validate_action_rss(struct rte_eth_dev *dev,
			     const struct rte_flow_action *action,
			     struct rte_flow_error *error);
int mlx5_flow_validate_action_count(struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    struct rte_flow_error *error);
int mlx5_flow_validate_action_drop(struct rte_eth_dev *dev,
				   bool is_root,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_flag(uint64_t action_flags,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_mark(const struct rte_flow_action *action,
				   uint64_t action_flags,
				   const struct rte_flow_attr *attr,
				   struct rte_flow_error *error);
int mlx5_flow_validate_action_queue(const struct rte_flow_action *action,
				    uint64_t action_flags,
				    struct rte_eth_dev *dev,
				    const struct rte_flow_attr *attr,
				    struct rte_flow_error *error);
int mlx5_flow_validate_action_rss(const struct rte_flow_action *action,
				  uint64_t action_flags,
				  struct rte_eth_dev *dev,
				  const struct rte_flow_attr *attr,
				  uint64_t item_flags,
				  struct rte_flow_error *error);
int mlx5_flow_validate_action_default_miss(uint64_t action_flags,
				const struct rte_flow_attr *attr,
				struct rte_flow_error *error);
int mlx5_flow_item_acceptable(const struct rte_flow_item *item,
			      const uint8_t *mask,
			      const uint8_t *nic_mask,
			      unsigned int size,
			      bool range_accepted,
			      struct rte_flow_error *error);
int mlx5_flow_validate_item_eth(const struct rte_flow_item *item,
				uint64_t item_flags, bool ext_vlan_sup,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_gre(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_gre_key(const struct rte_flow_item *item,
				    uint64_t item_flags,
				    const struct rte_flow_item *gre_item,
				    struct rte_flow_error *error);
int mlx5_flow_validate_item_gre_option(struct rte_eth_dev *dev,
				       const struct rte_flow_item *item,
				       uint64_t item_flags,
				       const struct rte_flow_attr *attr,
				       const struct rte_flow_item *gre_item,
				       struct rte_flow_error *error);
int mlx5_flow_validate_item_ipv4(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint64_t last_item,
				 uint16_t ether_type,
				 const struct rte_flow_item_ipv4 *acc_mask,
				 bool range_accepted,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_ipv6(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint64_t last_item,
				 uint16_t ether_type,
				 const struct rte_flow_item_ipv6 *acc_mask,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_mpls(struct rte_eth_dev *dev,
				 const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint64_t prev_layer,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_tcp(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				const struct rte_flow_item_tcp *flow_mask,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_udp(const struct rte_flow_item *item,
				uint64_t item_flags,
				uint8_t target_protocol,
				struct rte_flow_error *error);
int mlx5_flow_validate_item_vlan(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 struct rte_eth_dev *dev,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_vxlan(struct rte_eth_dev *dev,
				  uint16_t udp_dport,
				  const struct rte_flow_item *item,
				  uint64_t item_flags,
				  bool root,
				  struct rte_flow_error *error);
int mlx5_flow_validate_item_vxlan_gpe(const struct rte_flow_item *item,
				      uint64_t item_flags,
				      struct rte_eth_dev *dev,
				      struct rte_flow_error *error);
int mlx5_flow_validate_item_icmp(const struct rte_flow_item *item,
				 uint64_t item_flags,
				 uint8_t target_protocol,
				 struct rte_flow_error *error);
int mlx5_flow_validate_item_icmp6(const struct rte_flow_item *item,
				   uint64_t item_flags,
				   uint8_t target_protocol,
				   struct rte_flow_error *error);
int mlx5_flow_validate_item_nvgre(const struct rte_flow_item *item,
				  uint64_t item_flags,
				  uint8_t target_protocol,
				  struct rte_flow_error *error);
int mlx5_flow_validate_item_geneve(const struct rte_flow_item *item,
				   uint64_t item_flags,
				   struct rte_eth_dev *dev,
				   struct rte_flow_error *error);
int mlx5_flow_validate_item_geneve_opt(const struct rte_flow_item *item,
				   uint64_t last_item,
				   const struct rte_flow_item *geneve_item,
				   struct rte_eth_dev *dev,
				   struct rte_flow_error *error);
int mlx5_flow_validate_item_ecpri(const struct rte_flow_item *item,
				  uint64_t item_flags,
				  uint64_t last_item,
				  uint16_t ether_type,
				  const struct rte_flow_item_ecpri *acc_mask,
				  struct rte_flow_error *error);
int mlx5_flow_create_mtr_tbls(struct rte_eth_dev *dev,
			      struct mlx5_flow_meter_info *fm,
			      uint32_t mtr_idx,
			      uint8_t domain_bitmap);
void mlx5_flow_destroy_mtr_tbls(struct rte_eth_dev *dev,
			       struct mlx5_flow_meter_info *fm);
void mlx5_flow_destroy_mtr_drop_tbls(struct rte_eth_dev *dev);
struct mlx5_flow_meter_sub_policy *mlx5_flow_meter_sub_policy_rss_prepare
		(struct rte_eth_dev *dev,
		struct mlx5_flow_meter_policy *mtr_policy,
		struct mlx5_flow_rss_desc *rss_desc[MLX5_MTR_RTE_COLORS]);
void mlx5_flow_destroy_sub_policy_with_rxq(struct rte_eth_dev *dev,
		struct mlx5_flow_meter_policy *mtr_policy);
int mlx5_flow_dv_discover_counter_offset_support(struct rte_eth_dev *dev);
int mlx5_flow_discover_dr_action_support(struct rte_eth_dev *dev);
int mlx5_action_handle_attach(struct rte_eth_dev *dev);
int mlx5_action_handle_detach(struct rte_eth_dev *dev);
int mlx5_action_handle_flush(struct rte_eth_dev *dev);
void mlx5_release_tunnel_hub(struct mlx5_dev_ctx_shared *sh, uint16_t port_id);
int mlx5_alloc_tunnel_hub(struct mlx5_dev_ctx_shared *sh);

struct mlx5_list_entry *flow_dv_tbl_create_cb(void *tool_ctx, void *entry_ctx);
int flow_dv_tbl_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			 void *cb_ctx);
void flow_dv_tbl_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_tbl_clone_cb(void *tool_ctx,
					     struct mlx5_list_entry *oentry,
					     void *entry_ctx);
void flow_dv_tbl_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_flow_tbl_resource *flow_dv_tbl_resource_get(struct rte_eth_dev *dev,
		uint32_t table_level, uint8_t egress, uint8_t transfer,
		bool external, const struct mlx5_flow_tunnel *tunnel,
		uint32_t group_id, uint8_t dummy,
		uint32_t table_id, struct rte_flow_error *error);
int flow_dv_tbl_resource_release(struct mlx5_dev_ctx_shared *sh,
				 struct mlx5_flow_tbl_resource *tbl);

struct mlx5_list_entry *flow_dv_tag_create_cb(void *tool_ctx, void *cb_ctx);
int flow_dv_tag_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			 void *cb_ctx);
void flow_dv_tag_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_tag_clone_cb(void *tool_ctx,
					     struct mlx5_list_entry *oentry,
					     void *cb_ctx);
void flow_dv_tag_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry);

int flow_dv_modify_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			    void *cb_ctx);
struct mlx5_list_entry *flow_dv_modify_create_cb(void *tool_ctx, void *ctx);
void flow_dv_modify_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_modify_clone_cb(void *tool_ctx,
						struct mlx5_list_entry *oentry,
						void *ctx);
void flow_dv_modify_clone_free_cb(void *tool_ctx,
				  struct mlx5_list_entry *entry);

struct mlx5_list_entry *flow_dv_mreg_create_cb(void *tool_ctx, void *ctx);
int flow_dv_mreg_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			  void *cb_ctx);
void flow_dv_mreg_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_mreg_clone_cb(void *tool_ctx,
					      struct mlx5_list_entry *entry,
					      void *ctx);
void flow_dv_mreg_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry);

int flow_dv_encap_decap_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
				 void *cb_ctx);
struct mlx5_list_entry *flow_dv_encap_decap_create_cb(void *tool_ctx,
						      void *cb_ctx);
void flow_dv_encap_decap_remove_cb(void *tool_ctx,
				   struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_encap_decap_clone_cb(void *tool_ctx,
						  struct mlx5_list_entry *entry,
						  void *cb_ctx);
void flow_dv_encap_decap_clone_free_cb(void *tool_ctx,
				       struct mlx5_list_entry *entry);

int flow_dv_matcher_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			     void *ctx);
struct mlx5_list_entry *flow_dv_matcher_create_cb(void *tool_ctx, void *ctx);
void flow_dv_matcher_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);

int flow_dv_port_id_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			     void *cb_ctx);
struct mlx5_list_entry *flow_dv_port_id_create_cb(void *tool_ctx, void *cb_ctx);
void flow_dv_port_id_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_port_id_clone_cb(void *tool_ctx,
				struct mlx5_list_entry *entry, void *cb_ctx);
void flow_dv_port_id_clone_free_cb(void *tool_ctx,
				   struct mlx5_list_entry *entry);

int flow_dv_push_vlan_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			       void *cb_ctx);
struct mlx5_list_entry *flow_dv_push_vlan_create_cb(void *tool_ctx,
						    void *cb_ctx);
void flow_dv_push_vlan_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_push_vlan_clone_cb(void *tool_ctx,
				 struct mlx5_list_entry *entry, void *cb_ctx);
void flow_dv_push_vlan_clone_free_cb(void *tool_ctx,
				     struct mlx5_list_entry *entry);

int flow_dv_sample_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
			    void *cb_ctx);
struct mlx5_list_entry *flow_dv_sample_create_cb(void *tool_ctx, void *cb_ctx);
void flow_dv_sample_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_sample_clone_cb(void *tool_ctx,
				 struct mlx5_list_entry *entry, void *cb_ctx);
void flow_dv_sample_clone_free_cb(void *tool_ctx,
				  struct mlx5_list_entry *entry);

int flow_dv_dest_array_match_cb(void *tool_ctx, struct mlx5_list_entry *entry,
				void *cb_ctx);
struct mlx5_list_entry *flow_dv_dest_array_create_cb(void *tool_ctx,
						     void *cb_ctx);
void flow_dv_dest_array_remove_cb(void *tool_ctx,
				  struct mlx5_list_entry *entry);
struct mlx5_list_entry *flow_dv_dest_array_clone_cb(void *tool_ctx,
				   struct mlx5_list_entry *entry, void *cb_ctx);
void flow_dv_dest_array_clone_free_cb(void *tool_ctx,
				      struct mlx5_list_entry *entry);
void flow_dv_hashfields_set(uint64_t item_flags,
			    struct mlx5_flow_rss_desc *rss_desc,
			    uint64_t *hash_fields);
void flow_dv_action_rss_l34_hash_adjust(uint64_t rss_types,
					uint64_t *hash_field);
uint32_t flow_dv_action_rss_hrxq_lookup(struct rte_eth_dev *dev, uint32_t idx,
					const uint64_t hash_fields);

struct mlx5_list_entry *flow_hw_grp_create_cb(void *tool_ctx, void *cb_ctx);
void flow_hw_grp_remove_cb(void *tool_ctx, struct mlx5_list_entry *entry);
int flow_hw_grp_match_cb(void *tool_ctx,
			 struct mlx5_list_entry *entry,
			 void *cb_ctx);
struct mlx5_list_entry *flow_hw_grp_clone_cb(void *tool_ctx,
					     struct mlx5_list_entry *oentry,
					     void *cb_ctx);
void flow_hw_grp_clone_free_cb(void *tool_ctx, struct mlx5_list_entry *entry);

struct mlx5_aso_age_action *flow_aso_age_get_by_idx(struct rte_eth_dev *dev,
						    uint32_t age_idx);
int flow_dev_geneve_tlv_option_resource_register(struct rte_eth_dev *dev,
					     const struct rte_flow_item *item,
					     struct rte_flow_error *error);
void flow_dev_geneve_tlv_option_resource_release(struct mlx5_dev_ctx_shared *sh);

void flow_release_workspace(void *data);
int mlx5_flow_os_init_workspace_once(void);
void *mlx5_flow_os_get_specific_workspace(void);
int mlx5_flow_os_set_specific_workspace(struct mlx5_flow_workspace *data);
void mlx5_flow_os_release_workspace(void);
uint32_t mlx5_flow_mtr_alloc(struct rte_eth_dev *dev);
void mlx5_flow_mtr_free(struct rte_eth_dev *dev, uint32_t mtr_idx);
int mlx5_flow_validate_mtr_acts(struct rte_eth_dev *dev,
			const struct rte_flow_action *actions[RTE_COLORS],
			struct rte_flow_attr *attr,
			bool *is_rss,
			uint8_t *domain_bitmap,
			uint8_t *policy_mode,
			struct rte_mtr_error *error);
void mlx5_flow_destroy_mtr_acts(struct rte_eth_dev *dev,
		      struct mlx5_flow_meter_policy *mtr_policy);
int mlx5_flow_create_mtr_acts(struct rte_eth_dev *dev,
		      struct mlx5_flow_meter_policy *mtr_policy,
		      const struct rte_flow_action *actions[RTE_COLORS],
		      struct rte_flow_attr *attr,
		      struct rte_mtr_error *error);
int mlx5_flow_create_policy_rules(struct rte_eth_dev *dev,
			     struct mlx5_flow_meter_policy *mtr_policy);
void mlx5_flow_destroy_policy_rules(struct rte_eth_dev *dev,
			     struct mlx5_flow_meter_policy *mtr_policy);
int mlx5_flow_create_def_policy(struct rte_eth_dev *dev);
void mlx5_flow_destroy_def_policy(struct rte_eth_dev *dev);
void flow_drv_rxq_flags_set(struct rte_eth_dev *dev,
		       struct mlx5_flow_handle *dev_handle);
const struct mlx5_flow_tunnel *
mlx5_get_tof(const struct rte_flow_item *items,
	     const struct rte_flow_action *actions,
	     enum mlx5_tof_rule_type *rule_type);
void
flow_hw_resource_release(struct rte_eth_dev *dev);
void
flow_hw_rxq_flag_set(struct rte_eth_dev *dev, bool enable);
int flow_dv_action_validate(struct rte_eth_dev *dev,
			    const struct rte_flow_indir_action_conf *conf,
			    const struct rte_flow_action *action,
			    struct rte_flow_error *err);
struct rte_flow_action_handle *flow_dv_action_create(struct rte_eth_dev *dev,
		      const struct rte_flow_indir_action_conf *conf,
		      const struct rte_flow_action *action,
		      struct rte_flow_error *err);
int flow_dv_action_destroy(struct rte_eth_dev *dev,
			   struct rte_flow_action_handle *handle,
			   struct rte_flow_error *error);
int flow_dv_action_update(struct rte_eth_dev *dev,
			  struct rte_flow_action_handle *handle,
			  const void *update,
			  struct rte_flow_error *err);
int flow_dv_action_query(struct rte_eth_dev *dev,
			 const struct rte_flow_action_handle *handle,
			 void *data,
			 struct rte_flow_error *error);
size_t flow_dv_get_item_hdr_len(const enum rte_flow_item_type item_type);
int flow_dv_convert_encap_data(const struct rte_flow_item *items, uint8_t *buf,
			   size_t *size, struct rte_flow_error *error);
void mlx5_flow_field_id_to_modify_info
		(const struct rte_flow_action_modify_data *data,
		 struct field_modify_info *info, uint32_t *mask,
		 uint32_t width, struct rte_eth_dev *dev,
		 const struct rte_flow_attr *attr, struct rte_flow_error *error);
int flow_dv_convert_modify_action(struct rte_flow_item *item,
			      struct field_modify_info *field,
			      struct field_modify_info *dcopy,
			      struct mlx5_flow_dv_modify_hdr_resource *resource,
			      uint32_t type, struct rte_flow_error *error);

#define MLX5_PF_VPORT_ID 0
#define MLX5_ECPF_VPORT_ID 0xFFFE

int16_t mlx5_flow_get_esw_manager_vport_id(struct rte_eth_dev *dev);
int mlx5_flow_get_item_vport_id(struct rte_eth_dev *dev,
				const struct rte_flow_item *item,
				uint16_t *vport_id,
				bool *all_ports,
				struct rte_flow_error *error);

int flow_dv_translate_items_hws(const struct rte_flow_item *items,
				struct mlx5_flow_attr *attr, void *key,
				uint32_t key_type, uint64_t *item_flags,
				uint8_t *match_criteria,
				struct rte_flow_error *error);

int mlx5_flow_pick_transfer_proxy(struct rte_eth_dev *dev,
				  uint16_t *proxy_port_id,
				  struct rte_flow_error *error);

int mlx5_flow_hw_flush_ctrl_flows(struct rte_eth_dev *dev);

int mlx5_flow_hw_esw_create_sq_miss_flow(struct rte_eth_dev *dev,
					 uint32_t sqn, bool external);
int mlx5_flow_hw_esw_destroy_sq_miss_flow(struct rte_eth_dev *dev,
					  uint32_t sqn);
int mlx5_flow_hw_esw_create_default_jump_flow(struct rte_eth_dev *dev);
int mlx5_flow_hw_create_tx_default_mreg_copy_flow(struct rte_eth_dev *dev);
int mlx5_flow_hw_tx_repr_matching_flow(struct rte_eth_dev *dev, uint32_t sqn, bool external);
int mlx5_flow_hw_lacp_rx_flow(struct rte_eth_dev *dev);
int mlx5_flow_actions_validate(struct rte_eth_dev *dev,
		const struct rte_flow_actions_template_attr *attr,
		const struct rte_flow_action actions[],
		const struct rte_flow_action masks[],
		struct rte_flow_error *error);
int mlx5_flow_pattern_validate(struct rte_eth_dev *dev,
		const struct rte_flow_pattern_template_attr *attr,
		const struct rte_flow_item items[],
		struct rte_flow_error *error);
int flow_hw_table_update(struct rte_eth_dev *dev,
			 struct rte_flow_error *error);
int mlx5_flow_item_field_width(struct rte_eth_dev *dev,
			   enum rte_flow_field_id field, int inherit,
			   const struct rte_flow_attr *attr,
			   struct rte_flow_error *error);
#endif /* RTE_PMD_MLX5_FLOW_H_ */
