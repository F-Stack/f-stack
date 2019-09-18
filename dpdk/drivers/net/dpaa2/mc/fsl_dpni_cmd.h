/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright 2013-2016 Freescale Semiconductor Inc.
 * Copyright 2016-2017 NXP
 *
 */
#ifndef _FSL_DPNI_CMD_H
#define _FSL_DPNI_CMD_H

/* DPNI Version */
#define DPNI_VER_MAJOR				7
#define DPNI_VER_MINOR				8

#define DPNI_CMD_BASE_VERSION			1
#define DPNI_CMD_VERSION_2			2
#define DPNI_CMD_VERSION_3			3
#define DPNI_CMD_ID_OFFSET			4

#define DPNI_CMD(id)	(((id) << DPNI_CMD_ID_OFFSET) | DPNI_CMD_BASE_VERSION)
#define DPNI_CMD_V2(id)	(((id) << DPNI_CMD_ID_OFFSET) | DPNI_CMD_VERSION_2)
#define DPNI_CMD_V3(id)	(((id) << DPNI_CMD_ID_OFFSET) | DPNI_CMD_VERSION_3)

/* Command IDs */
#define DPNI_CMDID_OPEN				DPNI_CMD(0x801)
#define DPNI_CMDID_CLOSE			DPNI_CMD(0x800)
#define DPNI_CMDID_CREATE			DPNI_CMD_V2(0x901)
#define DPNI_CMDID_DESTROY			DPNI_CMD(0x981)
#define DPNI_CMDID_GET_API_VERSION		DPNI_CMD(0xa01)

#define DPNI_CMDID_ENABLE			DPNI_CMD(0x002)
#define DPNI_CMDID_DISABLE			DPNI_CMD(0x003)
#define DPNI_CMDID_GET_ATTR			DPNI_CMD_V2(0x004)
#define DPNI_CMDID_RESET			DPNI_CMD(0x005)
#define DPNI_CMDID_IS_ENABLED			DPNI_CMD(0x006)

#define DPNI_CMDID_SET_IRQ_ENABLE		DPNI_CMD(0x012)
#define DPNI_CMDID_GET_IRQ_ENABLE		DPNI_CMD(0x013)
#define DPNI_CMDID_SET_IRQ_MASK			DPNI_CMD(0x014)
#define DPNI_CMDID_GET_IRQ_MASK			DPNI_CMD(0x015)
#define DPNI_CMDID_GET_IRQ_STATUS		DPNI_CMD(0x016)
#define DPNI_CMDID_CLEAR_IRQ_STATUS		DPNI_CMD(0x017)

#define DPNI_CMDID_SET_POOLS			DPNI_CMD_V2(0x200)
#define DPNI_CMDID_SET_ERRORS_BEHAVIOR		DPNI_CMD(0x20B)

#define DPNI_CMDID_GET_QDID			DPNI_CMD(0x210)
#define DPNI_CMDID_GET_SP_INFO			DPNI_CMD(0x211)
#define DPNI_CMDID_GET_TX_DATA_OFFSET		DPNI_CMD(0x212)
#define DPNI_CMDID_GET_LINK_STATE		DPNI_CMD_V2(0x215)
#define DPNI_CMDID_SET_MAX_FRAME_LENGTH		DPNI_CMD(0x216)
#define DPNI_CMDID_GET_MAX_FRAME_LENGTH		DPNI_CMD(0x217)
#define DPNI_CMDID_SET_LINK_CFG			DPNI_CMD_V2(0x21A)
#define DPNI_CMDID_SET_TX_SHAPING		DPNI_CMD_V2(0x21B)

#define DPNI_CMDID_SET_MCAST_PROMISC		DPNI_CMD(0x220)
#define DPNI_CMDID_GET_MCAST_PROMISC		DPNI_CMD(0x221)
#define DPNI_CMDID_SET_UNICAST_PROMISC		DPNI_CMD(0x222)
#define DPNI_CMDID_GET_UNICAST_PROMISC		DPNI_CMD(0x223)
#define DPNI_CMDID_SET_PRIM_MAC			DPNI_CMD(0x224)
#define DPNI_CMDID_GET_PRIM_MAC			DPNI_CMD(0x225)
#define DPNI_CMDID_ADD_MAC_ADDR			DPNI_CMD(0x226)
#define DPNI_CMDID_REMOVE_MAC_ADDR		DPNI_CMD(0x227)
#define DPNI_CMDID_CLR_MAC_FILTERS		DPNI_CMD(0x228)

#define DPNI_CMDID_ENABLE_VLAN_FILTER		DPNI_CMD(0x230)
#define DPNI_CMDID_ADD_VLAN_ID			DPNI_CMD(0x231)
#define DPNI_CMDID_REMOVE_VLAN_ID		DPNI_CMD(0x232)
#define DPNI_CMDID_CLR_VLAN_FILTERS		DPNI_CMD(0x233)

#define DPNI_CMDID_SET_RX_TC_DIST		DPNI_CMD_V3(0x235)

#define DPNI_CMDID_GET_STATISTICS		DPNI_CMD_V2(0x25D)
#define DPNI_CMDID_RESET_STATISTICS		DPNI_CMD(0x25E)
#define DPNI_CMDID_GET_QUEUE			DPNI_CMD(0x25F)
#define DPNI_CMDID_SET_QUEUE			DPNI_CMD(0x260)
#define DPNI_CMDID_GET_TAILDROP			DPNI_CMD_V2(0x261)
#define DPNI_CMDID_SET_TAILDROP			DPNI_CMD_V2(0x262)

#define DPNI_CMDID_GET_PORT_MAC_ADDR		DPNI_CMD(0x263)

#define DPNI_CMDID_GET_BUFFER_LAYOUT		DPNI_CMD_V2(0x264)
#define DPNI_CMDID_SET_BUFFER_LAYOUT		DPNI_CMD_V2(0x265)

#define DPNI_CMDID_SET_CONGESTION_NOTIFICATION	DPNI_CMD(0x267)
#define DPNI_CMDID_GET_CONGESTION_NOTIFICATION	DPNI_CMD(0x268)
#define DPNI_CMDID_SET_EARLY_DROP		DPNI_CMD_V2(0x269)
#define DPNI_CMDID_GET_EARLY_DROP		DPNI_CMD_V2(0x26A)
#define DPNI_CMDID_GET_OFFLOAD			DPNI_CMD(0x26B)
#define DPNI_CMDID_SET_OFFLOAD			DPNI_CMD(0x26C)
#define DPNI_CMDID_SET_TX_CONFIRMATION_MODE	DPNI_CMD(0x266)
#define DPNI_CMDID_GET_TX_CONFIRMATION_MODE	DPNI_CMD(0x26D)
#define DPNI_CMDID_SET_OPR			DPNI_CMD(0x26e)
#define DPNI_CMDID_GET_OPR			DPNI_CMD(0x26f)

/* Macros for accessing command fields smaller than 1byte */
#define DPNI_MASK(field)	\
	GENMASK(DPNI_##field##_SHIFT + DPNI_##field##_SIZE - 1, \
		DPNI_##field##_SHIFT)
#define dpni_set_field(var, field, val)	\
	((var) |= (((val) << DPNI_##field##_SHIFT) & DPNI_MASK(field)))
#define dpni_get_field(var, field)	\
	(((var) & DPNI_MASK(field)) >> DPNI_##field##_SHIFT)

#pragma pack(push, 1)
struct dpni_cmd_open {
	uint32_t dpni_id;
};

struct dpni_cmd_create {
	uint32_t options;
	uint8_t num_queues;
	uint8_t num_tcs;
	uint8_t mac_filter_entries;
	uint8_t pad1;
	uint8_t vlan_filter_entries;
	uint8_t pad2;
	uint8_t qos_entries;
	uint8_t pad3;
	uint16_t fs_entries;
	uint8_t num_rx_tcs;
};

struct dpni_cmd_destroy {
	uint32_t dpsw_id;
};

#define DPNI_BACKUP_POOL(val, order)	(((val) & 0x1) << (order))

struct dpni_cmd_pool {
	uint16_t dpbp_id;
	uint8_t priority_mask;
	uint8_t pad;
};

struct dpni_cmd_set_pools {
	uint8_t num_dpbp;
	uint8_t backup_pool_mask;
	uint16_t pad;
	struct dpni_cmd_pool pool[8];
	uint16_t buffer_size[8];
};

/* The enable indication is always the least significant bit */
#define DPNI_ENABLE_SHIFT		0
#define DPNI_ENABLE_SIZE		1

struct dpni_rsp_is_enabled {
	uint8_t enabled;
};

struct dpni_cmd_set_irq_enable {
	uint8_t enable;
	uint8_t pad[3];
	uint8_t irq_index;
};

struct dpni_cmd_get_irq_enable {
	uint32_t pad;
	uint8_t irq_index;
};

struct dpni_rsp_get_irq_enable {
	uint8_t enabled;
};

struct dpni_cmd_set_irq_mask {
	uint32_t mask;
	uint8_t irq_index;
};

struct dpni_cmd_get_irq_mask {
	uint32_t pad;
	uint8_t irq_index;
};

struct dpni_rsp_get_irq_mask {
	uint32_t mask;
};

struct dpni_cmd_get_irq_status {
	uint32_t status;
	uint8_t irq_index;
};

struct dpni_rsp_get_irq_status {
	uint32_t status;
};

struct dpni_cmd_clear_irq_status {
	uint32_t status;
	uint8_t irq_index;
};

struct dpni_rsp_get_attr {
	/* response word 0 */
	uint32_t options;
	uint8_t num_queues;
	uint8_t num_rx_tcs;
	uint8_t mac_filter_entries;
	uint8_t num_tx_tcs;
	/* response word 1 */
	uint8_t vlan_filter_entries;
	uint8_t pad1;
	uint8_t qos_entries;
	uint8_t pad2;
	uint16_t fs_entries;
	uint16_t pad3;
	/* response word 2 */
	uint8_t qos_key_size;
	uint8_t fs_key_size;
	uint16_t wriop_version;
};

#define DPNI_ERROR_ACTION_SHIFT		0
#define DPNI_ERROR_ACTION_SIZE		4
#define DPNI_FRAME_ANN_SHIFT		4
#define DPNI_FRAME_ANN_SIZE		1

struct dpni_cmd_set_errors_behavior {
	uint32_t errors;
	/* from least significant bit: error_action:4, set_frame_annotation:1 */
	uint8_t flags;
};

/* There are 3 separate commands for configuring Rx, Tx and Tx confirmation
 * buffer layouts, but they all share the same parameters.
 * If one of the functions changes, below structure needs to be split.
 */

#define DPNI_PASS_TS_SHIFT		0
#define DPNI_PASS_TS_SIZE		1
#define DPNI_PASS_PR_SHIFT		1
#define DPNI_PASS_PR_SIZE		1
#define DPNI_PASS_FS_SHIFT		2
#define DPNI_PASS_FS_SIZE		1
#define DPNI_PASS_SWO_SHIFT		3
#define DPNI_PASS_SWO_SIZE		1

struct dpni_cmd_get_buffer_layout {
	uint8_t qtype;
};

struct dpni_rsp_get_buffer_layout {
	/* response word 0 */
	uint8_t pad0[6];
	/* from LSB: pass_timestamp:1, parser_result:1, frame_status:1 */
	uint8_t flags;
	uint8_t pad1;
	/* response word 1 */
	uint16_t private_data_size;
	uint16_t data_align;
	uint16_t head_room;
	uint16_t tail_room;
};

struct dpni_cmd_set_buffer_layout {
	/* cmd word 0 */
	uint8_t qtype;
	uint8_t pad0[3];
	uint16_t options;
	/* from LSB: pass_timestamp:1, parser_result:1, frame_status:1 */
	uint8_t flags;
	uint8_t pad1;
	/* cmd word 1 */
	uint16_t private_data_size;
	uint16_t data_align;
	uint16_t head_room;
	uint16_t tail_room;
};

struct dpni_cmd_set_offload {
	uint8_t pad[3];
	uint8_t dpni_offload;
	uint32_t config;
};

struct dpni_cmd_get_offload {
	uint8_t pad[3];
	uint8_t dpni_offload;
};

struct dpni_rsp_get_offload {
	uint32_t pad;
	uint32_t config;
};

struct dpni_cmd_get_qdid {
	uint8_t qtype;
};

struct dpni_rsp_get_qdid {
	uint16_t qdid;
};

struct dpni_rsp_get_sp_info {
	uint16_t spids[2];
};

struct dpni_rsp_get_tx_data_offset {
	uint16_t data_offset;
};

struct dpni_cmd_get_statistics {
	uint8_t page_number;
	uint8_t param;
};

struct dpni_rsp_get_statistics {
	uint64_t counter[7];
};

struct dpni_cmd_set_link_cfg {
	uint64_t pad0;
	uint32_t rate;
	uint32_t pad1;
	uint64_t options;
	uint64_t advertising;
};

#define DPNI_LINK_STATE_SHIFT		0
#define DPNI_LINK_STATE_SIZE		1
#define DPNI_STATE_VALID_SHIFT		1
#define DPNI_STATE_VALID_SIZE		1

struct dpni_rsp_get_link_state {
	uint32_t pad0;
	/* from LSB: up:1 */
	uint8_t flags;
	uint8_t pad1[3];
	uint32_t rate;
	uint32_t pad2;
	uint64_t options;
	uint64_t supported;
	uint64_t advertising;
};

struct dpni_cmd_set_max_frame_length {
	uint16_t max_frame_length;
};

struct dpni_rsp_get_max_frame_length {
	uint16_t max_frame_length;
};

struct dpni_cmd_set_multicast_promisc {
	uint8_t enable;
};

struct dpni_rsp_get_multicast_promisc {
	uint8_t enabled;
};

struct dpni_cmd_set_unicast_promisc {
	uint8_t enable;
};

struct dpni_rsp_get_unicast_promisc {
	uint8_t enabled;
};

struct dpni_cmd_set_primary_mac_addr {
	uint16_t pad;
	uint8_t mac_addr[6];
};

struct dpni_rsp_get_primary_mac_addr {
	uint16_t pad;
	uint8_t mac_addr[6];
};

struct dpni_rsp_get_port_mac_addr {
	uint16_t pad;
	uint8_t mac_addr[6];
};

struct dpni_cmd_add_mac_addr {
	uint16_t pad;
	uint8_t mac_addr[6];
};

struct dpni_cmd_remove_mac_addr {
	uint16_t pad;
	uint8_t mac_addr[6];
};

#define DPNI_UNICAST_FILTERS_SHIFT	0
#define DPNI_UNICAST_FILTERS_SIZE	1
#define DPNI_MULTICAST_FILTERS_SHIFT	1
#define DPNI_MULTICAST_FILTERS_SIZE	1

struct dpni_cmd_clear_mac_filters {
	/* from LSB: unicast:1, multicast:1 */
	uint8_t flags;
};

struct dpni_cmd_enable_vlan_filter {
	/* only the LSB */
	uint8_t en;
};

struct dpni_cmd_vlan_id {
	uint32_t pad;
	uint16_t vlan_id;
};

#define DPNI_SEPARATE_GRP_SHIFT 0
#define DPNI_SEPARATE_GRP_SIZE  1
#define DPNI_MODE_1_SHIFT		0
#define DPNI_MODE_1_SIZE		4
#define DPNI_MODE_2_SHIFT		4
#define DPNI_MODE_2_SIZE		4

struct dpni_cmd_set_tx_priorities {
	uint16_t flags;
	uint8_t prio_group_A;
	uint8_t prio_group_B;
	uint32_t pad0;
	uint8_t modes[4];
	uint32_t pad1;
	uint64_t pad2;
	uint16_t delta_bandwidth[8];
};

#define DPNI_DIST_MODE_SHIFT		0
#define DPNI_DIST_MODE_SIZE		4
#define DPNI_MISS_ACTION_SHIFT		4
#define DPNI_MISS_ACTION_SIZE		4
#define DPNI_KEEP_HASH_KEY_SHIFT	7
#define DPNI_KEEP_HASH_KEY_SIZE		1
#define DPNI_KEEP_ENTRIES_SHIFT		6
#define DPNI_KEEP_ENTRIES_SIZE		1

struct dpni_cmd_set_rx_tc_dist {
	uint16_t dist_size;
	uint8_t tc_id;
	/* from LSB: dist_mode:4, miss_action:4 */
	uint8_t flags;
	uint8_t pad0;
	/* only the LSB */
	uint8_t keep_hash_key;
	uint16_t default_flow_id;
	uint64_t pad1[5];
	uint64_t key_cfg_iova;
};

struct dpni_cmd_get_queue {
	uint8_t qtype;
	uint8_t tc;
	uint8_t index;
};

#define DPNI_DEST_TYPE_SHIFT		0
#define DPNI_DEST_TYPE_SIZE		4
#define DPNI_STASH_CTRL_SHIFT		6
#define DPNI_STASH_CTRL_SIZE		1
#define DPNI_HOLD_ACTIVE_SHIFT		7
#define DPNI_HOLD_ACTIVE_SIZE		1

struct dpni_rsp_get_queue {
	/* response word 0 */
	uint64_t pad0;
	/* response word 1 */
	uint32_t dest_id;
	uint16_t pad1;
	uint8_t dest_prio;
	/* From LSB: dest_type:4, pad:2, flc_stash_ctrl:1, hold_active:1 */
	uint8_t flags;
	/* response word 2 */
	uint64_t flc;
	/* response word 3 */
	uint64_t user_context;
	/* response word 4 */
	uint32_t fqid;
	uint16_t qdbin;
};

struct dpni_cmd_set_queue {
	/* cmd word 0 */
	uint8_t qtype;
	uint8_t tc;
	uint8_t index;
	uint8_t options;
	uint32_t pad0;
	/* cmd word 1 */
	uint32_t dest_id;
	uint16_t pad1;
	uint8_t dest_prio;
	uint8_t flags;
	/* cmd word 2 */
	uint64_t flc;
	/* cmd word 3 */
	uint64_t user_context;
};

#define DPNI_DROP_ENABLE_SHIFT	0
#define DPNI_DROP_ENABLE_SIZE	1
#define DPNI_DROP_UNITS_SHIFT	2
#define DPNI_DROP_UNITS_SIZE	2

struct dpni_early_drop {
	/* from LSB: enable:1 units:2 */
	uint8_t flags;
	uint8_t pad0[3];
	uint32_t pad1;
	uint8_t green_drop_probability;
	uint8_t pad2[7];
	uint64_t green_max_threshold;
	uint64_t green_min_threshold;
	uint64_t pad3;
	uint8_t yellow_drop_probability;
	uint8_t pad4[7];
	uint64_t yellow_max_threshold;
	uint64_t yellow_min_threshold;
	uint64_t pad5;
	uint8_t red_drop_probability;
	uint8_t pad6[7];
	uint64_t red_max_threshold;
	uint64_t red_min_threshold;
};

struct dpni_cmd_early_drop {
	uint8_t qtype;
	uint8_t tc;
	uint8_t pad[6];
	uint64_t early_drop_iova;
};

struct dpni_rsp_get_api_version {
	uint16_t major;
	uint16_t minor;
};

struct dpni_cmd_get_taildrop {
	uint8_t congestion_point;
	uint8_t qtype;
	uint8_t tc;
	uint8_t index;
};

struct dpni_rsp_get_taildrop {
	/* cmd word 0 */
	uint64_t pad0;
	/* cmd word 1 */
	/* from LSB: enable:1 oal_lo:7 */
	uint8_t enable_oal_lo;
	/* from LSB: oal_hi:5 */
	uint8_t oal_hi;
	uint8_t units;
	uint8_t pad2;
	uint32_t threshold;
};

#define DPNI_OAL_LO_SHIFT	1
#define DPNI_OAL_LO_SIZE	7
#define DPNI_OAL_HI_SHIFT	0
#define DPNI_OAL_HI_SIZE	5

struct dpni_cmd_set_taildrop {
	/* cmd word 0 */
	uint8_t congestion_point;
	uint8_t qtype;
	uint8_t tc;
	uint8_t index;
	uint32_t pad0;
	/* cmd word 1 */
	/* from LSB: enable:1 oal_lo:7 */
	uint8_t enable_oal_lo;
	/* from LSB: oal_hi:5 */
	uint8_t oal_hi;
	uint8_t units;
	uint8_t pad2;
	uint32_t threshold;
};

struct dpni_tx_confirmation_mode {
	uint32_t pad;
	uint8_t confirmation_mode;
};

#define DPNI_DEST_TYPE_SHIFT		0
#define DPNI_DEST_TYPE_SIZE		4
#define DPNI_CONG_UNITS_SHIFT		4
#define DPNI_CONG_UNITS_SIZE		2

struct dpni_cmd_set_congestion_notification {
	uint8_t qtype;
	uint8_t tc;
	uint8_t pad[6];
	uint32_t dest_id;
	uint16_t notification_mode;
	uint8_t dest_priority;
	/* from LSB: dest_type: 4 units:2 */
	uint8_t type_units;
	uint64_t message_iova;
	uint64_t message_ctx;
	uint32_t threshold_entry;
	uint32_t threshold_exit;
};

struct dpni_cmd_get_congestion_notification {
	uint8_t qtype;
	uint8_t tc;
};

struct dpni_rsp_get_congestion_notification {
	uint64_t pad;
	uint32_t dest_id;
	uint16_t notification_mode;
	uint8_t dest_priority;
	/* from LSB: dest_type: 4 units:2 */
	uint8_t type_units;
	uint64_t message_iova;
	uint64_t message_ctx;
	uint32_t threshold_entry;
	uint32_t threshold_exit;
};

struct dpni_cmd_set_opr {
	uint8_t pad0;
	uint8_t tc_id;
	uint8_t index;
	uint8_t options;
	uint8_t pad1[7];
	uint8_t oloe;
	uint8_t oeane;
	uint8_t olws;
	uint8_t oa;
	uint8_t oprrws;
};

struct dpni_cmd_get_opr {
	uint8_t pad;
	uint8_t tc_id;
	uint8_t index;
};

#define DPNI_RIP_SHIFT	0
#define DPNI_RIP_SIZE		1
#define DPNI_OPR_ENABLE_SHIFT	1
#define DPNI_OPR_ENABLE_SIZE	1
#define DPNI_TSEQ_NLIS_SHIFT	0
#define DPNI_TSEQ_NLIS_SIZE	1
#define DPNI_HSEQ_NLIS_SHIFT	0
#define DPNI_HSEQ_NLIS_SIZE	1

struct dpni_rsp_get_opr {
	uint64_t pad0;
	/* from LSB: rip:1 enable:1 */
	uint8_t flags;
	uint16_t pad1;
	uint8_t oloe;
	uint8_t oeane;
	uint8_t olws;
	uint8_t oa;
	uint8_t oprrws;
	uint16_t nesn;
	uint16_t pad8;
	uint16_t ndsn;
	uint16_t pad2;
	uint16_t ea_tseq;
	/* only the LSB */
	uint8_t tseq_nlis;
	uint8_t pad3;
	uint16_t ea_hseq;
	/* only the LSB */
	uint8_t hseq_nlis;
	uint8_t pad4;
	uint16_t ea_hptr;
	uint16_t pad5;
	uint16_t ea_tptr;
	uint16_t pad6;
	uint16_t opr_vid;
	uint16_t pad7;
	uint16_t opr_id;
};

#pragma pack(pop)
#endif /* _FSL_DPNI_CMD_H */
