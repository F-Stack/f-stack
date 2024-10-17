/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <ethdev_driver.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eth_ctrl.h>
#include <rte_tailq.h>
#include <rte_flow_driver.h>
#include <rte_flow.h>
#include "base/ice_type.h"
#include "base/ice_switch.h"
#include "ice_logs.h"
#include "ice_ethdev.h"
#include "ice_generic_flow.h"
#include "ice_dcf_ethdev.h"


#define MAX_QGRP_NUM_TYPE	7
#define MAX_INPUT_SET_BYTE	32
#define ICE_PPP_IPV4_PROTO	0x0021
#define ICE_PPP_IPV6_PROTO	0x0057
#define ICE_IPV4_PROTO_NVGRE	0x002F
#define ICE_SW_PRI_BASE 6

#define ICE_SW_INSET_ETHER ( \
	ICE_INSET_DMAC | ICE_INSET_SMAC | ICE_INSET_ETHERTYPE)
#define ICE_SW_INSET_MAC_VLAN ( \
	ICE_SW_INSET_ETHER | ICE_INSET_VLAN_INNER)
#define ICE_SW_INSET_MAC_QINQ  ( \
	ICE_INSET_DMAC | ICE_INSET_SMAC | ICE_INSET_VLAN_INNER | \
	ICE_INSET_VLAN_OUTER)
#define ICE_SW_INSET_MAC_IPV4 ( \
	ICE_INSET_DMAC | ICE_INSET_IPV4_DST | ICE_INSET_IPV4_SRC | \
	ICE_INSET_IPV4_PROTO | ICE_INSET_IPV4_TTL | ICE_INSET_IPV4_TOS)
#define ICE_SW_INSET_MAC_QINQ_IPV4 ( \
	ICE_SW_INSET_MAC_QINQ | ICE_SW_INSET_MAC_IPV4)
#define ICE_SW_INSET_MAC_QINQ_IPV4_TCP ( \
	ICE_SW_INSET_MAC_QINQ_IPV4 | \
	ICE_INSET_TCP_DST_PORT | ICE_INSET_TCP_SRC_PORT)
#define ICE_SW_INSET_MAC_QINQ_IPV4_UDP ( \
	ICE_SW_INSET_MAC_QINQ_IPV4 | \
	ICE_INSET_UDP_DST_PORT | ICE_INSET_UDP_SRC_PORT)
#define ICE_SW_INSET_MAC_IPV4_TCP ( \
	ICE_INSET_DMAC | ICE_INSET_IPV4_DST | ICE_INSET_IPV4_SRC | \
	ICE_INSET_IPV4_TTL | ICE_INSET_IPV4_TOS | \
	ICE_INSET_TCP_DST_PORT | ICE_INSET_TCP_SRC_PORT)
#define ICE_SW_INSET_MAC_IPV4_UDP ( \
	ICE_INSET_DMAC | ICE_INSET_IPV4_DST | ICE_INSET_IPV4_SRC | \
	ICE_INSET_IPV4_TTL | ICE_INSET_IPV4_TOS | \
	ICE_INSET_UDP_DST_PORT | ICE_INSET_UDP_SRC_PORT)
#define ICE_SW_INSET_MAC_IPV6 ( \
	ICE_INSET_DMAC | ICE_INSET_IPV6_DST | ICE_INSET_IPV6_SRC | \
	ICE_INSET_IPV6_TC | ICE_INSET_IPV6_HOP_LIMIT | \
	ICE_INSET_IPV6_NEXT_HDR)
#define ICE_SW_INSET_MAC_QINQ_IPV6 ( \
	ICE_SW_INSET_MAC_QINQ | ICE_SW_INSET_MAC_IPV6)
#define ICE_SW_INSET_MAC_QINQ_IPV6_TCP ( \
	ICE_SW_INSET_MAC_QINQ_IPV6 | \
	ICE_INSET_TCP_DST_PORT | ICE_INSET_TCP_SRC_PORT)
#define ICE_SW_INSET_MAC_QINQ_IPV6_UDP ( \
	ICE_SW_INSET_MAC_QINQ_IPV6 | \
	ICE_INSET_UDP_DST_PORT | ICE_INSET_UDP_SRC_PORT)
#define ICE_SW_INSET_MAC_IPV6_TCP ( \
	ICE_INSET_DMAC | ICE_INSET_IPV6_DST | ICE_INSET_IPV6_SRC | \
	ICE_INSET_IPV6_HOP_LIMIT | ICE_INSET_IPV6_TC | \
	ICE_INSET_TCP_DST_PORT | ICE_INSET_TCP_SRC_PORT)
#define ICE_SW_INSET_MAC_IPV6_UDP ( \
	ICE_INSET_DMAC | ICE_INSET_IPV6_DST | ICE_INSET_IPV6_SRC | \
	ICE_INSET_IPV6_HOP_LIMIT | ICE_INSET_IPV6_TC | \
	ICE_INSET_UDP_DST_PORT | ICE_INSET_UDP_SRC_PORT)
#define ICE_SW_INSET_DIST_NVGRE_IPV4 ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | ICE_INSET_DMAC | \
	ICE_INSET_NVGRE_TNI)
#define ICE_SW_INSET_DIST_VXLAN_IPV4 ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | ICE_INSET_DMAC | \
	ICE_INSET_VXLAN_VNI)
#define ICE_SW_INSET_DIST_NVGRE_IPV4_TCP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_TCP_SRC_PORT | ICE_INSET_TCP_DST_PORT | \
	ICE_INSET_DMAC | ICE_INSET_NVGRE_TNI)
#define ICE_SW_INSET_DIST_NVGRE_IPV4_UDP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_UDP_SRC_PORT | ICE_INSET_UDP_DST_PORT | \
	ICE_INSET_DMAC | ICE_INSET_NVGRE_TNI)
#define ICE_SW_INSET_DIST_VXLAN_IPV4_TCP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_TCP_SRC_PORT | ICE_INSET_TCP_DST_PORT | \
	ICE_INSET_DMAC | ICE_INSET_VXLAN_VNI)
#define ICE_SW_INSET_DIST_VXLAN_IPV4_UDP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_UDP_SRC_PORT | ICE_INSET_UDP_DST_PORT | \
	ICE_INSET_DMAC | ICE_INSET_VXLAN_VNI)
#define ICE_SW_INSET_PERM_TUNNEL_IPV4 ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_IPV4_PROTO | ICE_INSET_IPV4_TOS)
#define ICE_SW_INSET_PERM_TUNNEL_IPV4_TCP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_TCP_SRC_PORT | ICE_INSET_TCP_DST_PORT | \
	ICE_INSET_IPV4_TOS)
#define ICE_SW_INSET_PERM_TUNNEL_IPV4_UDP ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_UDP_SRC_PORT | ICE_INSET_UDP_DST_PORT | \
	ICE_INSET_IPV4_TOS)
#define ICE_SW_INSET_MAC_PPPOE  ( \
	ICE_INSET_VLAN_OUTER | ICE_INSET_VLAN_INNER | \
	ICE_INSET_DMAC | ICE_INSET_ETHERTYPE | ICE_INSET_PPPOE_SESSION)
#define ICE_SW_INSET_MAC_PPPOE_PROTO  ( \
	ICE_INSET_VLAN_OUTER | ICE_INSET_VLAN_INNER | \
	ICE_INSET_DMAC | ICE_INSET_ETHERTYPE | ICE_INSET_PPPOE_SESSION | \
	ICE_INSET_PPPOE_PROTO)
#define ICE_SW_INSET_MAC_PPPOE_IPV4 ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV4)
#define ICE_SW_INSET_MAC_PPPOE_IPV4_TCP ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV4_TCP)
#define ICE_SW_INSET_MAC_PPPOE_IPV4_UDP ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV4_UDP)
#define ICE_SW_INSET_MAC_PPPOE_IPV6 ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV6)
#define ICE_SW_INSET_MAC_PPPOE_IPV6_TCP ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV6_TCP)
#define ICE_SW_INSET_MAC_PPPOE_IPV6_UDP ( \
	ICE_SW_INSET_MAC_PPPOE | ICE_SW_INSET_MAC_IPV6_UDP)
#define ICE_SW_INSET_MAC_IPV4_ESP ( \
	ICE_SW_INSET_MAC_IPV4 | ICE_INSET_ESP_SPI)
#define ICE_SW_INSET_MAC_IPV6_ESP ( \
	ICE_SW_INSET_MAC_IPV6 | ICE_INSET_ESP_SPI)
#define ICE_SW_INSET_MAC_IPV4_AH ( \
	ICE_SW_INSET_MAC_IPV4 | ICE_INSET_AH_SPI)
#define ICE_SW_INSET_MAC_IPV6_AH ( \
	ICE_SW_INSET_MAC_IPV6 | ICE_INSET_AH_SPI)
#define ICE_SW_INSET_MAC_IPV4_L2TP ( \
	ICE_SW_INSET_MAC_IPV4 | ICE_INSET_L2TPV3OIP_SESSION_ID)
#define ICE_SW_INSET_MAC_IPV6_L2TP ( \
	ICE_SW_INSET_MAC_IPV6 | ICE_INSET_L2TPV3OIP_SESSION_ID)
#define ICE_SW_INSET_MAC_IPV4_PFCP ( \
	ICE_SW_INSET_MAC_IPV4 | \
	ICE_INSET_PFCP_S_FIELD | ICE_INSET_PFCP_SEID)
#define ICE_SW_INSET_MAC_IPV6_PFCP ( \
	ICE_SW_INSET_MAC_IPV6 | \
	ICE_INSET_PFCP_S_FIELD | ICE_INSET_PFCP_SEID)
#define ICE_SW_INSET_MAC_IPV4_GTPU ( \
	ICE_SW_INSET_MAC_IPV4 | ICE_INSET_GTPU_TEID)
#define ICE_SW_INSET_MAC_IPV6_GTPU ( \
	ICE_SW_INSET_MAC_IPV6 | ICE_INSET_GTPU_TEID)
#define ICE_SW_INSET_MAC_GTPU_OUTER ( \
	ICE_INSET_DMAC | ICE_INSET_GTPU_TEID)
#define ICE_SW_INSET_MAC_GTPU_EH_OUTER ( \
	ICE_SW_INSET_MAC_GTPU_OUTER | ICE_INSET_GTPU_QFI)
#define ICE_SW_INSET_GTPU_IPV4 ( \
	ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST)
#define ICE_SW_INSET_GTPU_IPV6 ( \
	ICE_INSET_IPV6_SRC | ICE_INSET_IPV6_DST)
#define ICE_SW_INSET_GTPU_IPV4_UDP ( \
	ICE_SW_INSET_GTPU_IPV4 | ICE_INSET_UDP_SRC_PORT | \
	ICE_INSET_UDP_DST_PORT)
#define ICE_SW_INSET_GTPU_IPV4_TCP ( \
	ICE_SW_INSET_GTPU_IPV4 | ICE_INSET_TCP_SRC_PORT | \
	ICE_INSET_TCP_DST_PORT)
#define ICE_SW_INSET_GTPU_IPV6_UDP ( \
	ICE_SW_INSET_GTPU_IPV6 | ICE_INSET_UDP_SRC_PORT | \
	ICE_INSET_UDP_DST_PORT)
#define ICE_SW_INSET_GTPU_IPV6_TCP ( \
	ICE_SW_INSET_GTPU_IPV6 | ICE_INSET_TCP_SRC_PORT | \
	ICE_INSET_TCP_DST_PORT)

struct sw_meta {
	struct ice_adv_lkup_elem *list;
	uint16_t lkups_num;
	struct ice_adv_rule_info rule_info;
};

enum ice_sw_fltr_status {
	ICE_SW_FLTR_ADDED,
	ICE_SW_FLTR_RMV_FAILED_ON_RIDRECT,
	ICE_SW_FLTR_ADD_FAILED_ON_RIDRECT,
};

struct ice_switch_filter_conf {
	enum ice_sw_fltr_status fltr_status;

	struct ice_rule_query_data sw_query_data;

	/*
	 * The lookup elements and rule info are saved here when filter creation
	 * succeeds.
	 */
	uint16_t vsi_num;
	uint16_t lkups_num;
	struct ice_adv_lkup_elem *lkups;
	struct ice_adv_rule_info rule_info;
};

static struct ice_flow_parser ice_switch_dist_parser;
static struct ice_flow_parser ice_switch_perm_parser;

static struct
ice_pattern_match_item ice_switch_pattern_dist_list[] = {
	{pattern_any,					ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype,				ICE_SW_INSET_ETHER,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype_vlan,			ICE_SW_INSET_MAC_VLAN,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype_qinq,			ICE_SW_INSET_MAC_QINQ,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_arp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4,				ICE_SW_INSET_MAC_IPV4,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp,				ICE_SW_INSET_MAC_IPV4_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_tcp,				ICE_SW_INSET_MAC_IPV4_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6,				ICE_SW_INSET_MAC_IPV6,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp,				ICE_SW_INSET_MAC_IPV6_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_tcp,				ICE_SW_INSET_MAC_IPV6_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4,		ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_VXLAN_IPV4,		ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4_udp,	ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_VXLAN_IPV4_UDP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4_tcp,	ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_VXLAN_IPV4_TCP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4,		ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_NVGRE_IPV4,		ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4_udp,		ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_NVGRE_IPV4_UDP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4_tcp,		ICE_INSET_IPV4_DST,			ICE_SW_INSET_DIST_NVGRE_IPV4_TCP,	ICE_INSET_NONE},
	{pattern_eth_pppoes,				ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes,			ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4_tcp,			ICE_SW_INSET_MAC_PPPOE_IPV4_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4_udp,			ICE_SW_INSET_MAC_PPPOE_IPV4_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6_tcp,			ICE_SW_INSET_MAC_PPPOE_IPV6_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6_udp,			ICE_SW_INSET_MAC_PPPOE_IPV6_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4_tcp,		ICE_SW_INSET_MAC_PPPOE_IPV4_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4_udp,		ICE_SW_INSET_MAC_PPPOE_IPV4_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6_tcp,		ICE_SW_INSET_MAC_PPPOE_IPV6_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6_udp,		ICE_SW_INSET_MAC_PPPOE_IPV6_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_esp,				ICE_SW_INSET_MAC_IPV4_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_esp,			ICE_SW_INSET_MAC_IPV4_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_esp,				ICE_SW_INSET_MAC_IPV6_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp_esp,			ICE_SW_INSET_MAC_IPV6_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_ah,				ICE_SW_INSET_MAC_IPV4_AH,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_ah,				ICE_SW_INSET_MAC_IPV6_AH,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp_ah,			ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_l2tp,				ICE_SW_INSET_MAC_IPV4_L2TP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_l2tp,				ICE_SW_INSET_MAC_IPV6_L2TP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_pfcp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_pfcp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4,				ICE_SW_INSET_MAC_QINQ_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4_tcp,			ICE_SW_INSET_MAC_QINQ_IPV4_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4_udp,			ICE_SW_INSET_MAC_QINQ_IPV4_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6,				ICE_SW_INSET_MAC_QINQ_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6_tcp,			ICE_SW_INSET_MAC_QINQ_IPV6_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6_udp,			ICE_SW_INSET_MAC_QINQ_IPV6_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes,			ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu,				ICE_SW_INSET_MAC_IPV4_GTPU,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu,				ICE_SW_INSET_MAC_IPV6_GTPU,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
};

static struct
ice_pattern_match_item ice_switch_pattern_perm_list[] = {
	{pattern_any,					ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype,				ICE_SW_INSET_ETHER,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype_vlan,			ICE_SW_INSET_MAC_VLAN,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_ethertype_qinq,			ICE_SW_INSET_MAC_QINQ,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_arp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4,				ICE_SW_INSET_MAC_IPV4,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp,				ICE_SW_INSET_MAC_IPV4_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_tcp,				ICE_SW_INSET_MAC_IPV4_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6,				ICE_SW_INSET_MAC_IPV6,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp,				ICE_SW_INSET_MAC_IPV6_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_tcp,				ICE_SW_INSET_MAC_IPV6_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4,		ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4,		ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4_udp,	ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4_UDP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_vxlan_eth_ipv4_tcp,	ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4_TCP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4,		ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4,		ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4_udp,		ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4_UDP,	ICE_INSET_NONE},
	{pattern_eth_ipv4_nvgre_eth_ipv4_tcp,		ICE_INSET_NONE,				ICE_SW_INSET_PERM_TUNNEL_IPV4_TCP,	ICE_INSET_NONE},
	{pattern_eth_pppoes,				ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes,			ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4_tcp,			ICE_SW_INSET_MAC_PPPOE_IPV4_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv4_udp,			ICE_SW_INSET_MAC_PPPOE_IPV4_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6_tcp,			ICE_SW_INSET_MAC_PPPOE_IPV6_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_pppoes_ipv6_udp,			ICE_SW_INSET_MAC_PPPOE_IPV6_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4_tcp,		ICE_SW_INSET_MAC_PPPOE_IPV4_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv4_udp,		ICE_SW_INSET_MAC_PPPOE_IPV4_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6_tcp,		ICE_SW_INSET_MAC_PPPOE_IPV6_TCP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_vlan_pppoes_ipv6_udp,		ICE_SW_INSET_MAC_PPPOE_IPV6_UDP,	ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_esp,				ICE_SW_INSET_MAC_IPV4_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_udp_esp,			ICE_SW_INSET_MAC_IPV4_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_esp,				ICE_SW_INSET_MAC_IPV6_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp_esp,			ICE_SW_INSET_MAC_IPV6_ESP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_ah,				ICE_SW_INSET_MAC_IPV4_AH,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_ah,				ICE_SW_INSET_MAC_IPV6_AH,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_udp_ah,			ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_l2tp,				ICE_SW_INSET_MAC_IPV4_L2TP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_l2tp,				ICE_SW_INSET_MAC_IPV6_L2TP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_pfcp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_pfcp,				ICE_INSET_NONE,				ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4,				ICE_SW_INSET_MAC_QINQ_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4_tcp,			ICE_SW_INSET_MAC_QINQ_IPV4_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv4_udp,			ICE_SW_INSET_MAC_QINQ_IPV4_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6,				ICE_SW_INSET_MAC_QINQ_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6_tcp,			ICE_SW_INSET_MAC_QINQ_IPV6_TCP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_ipv6_udp,			ICE_SW_INSET_MAC_QINQ_IPV6_UDP,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes,			ICE_SW_INSET_MAC_PPPOE,			ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_proto,			ICE_SW_INSET_MAC_PPPOE_PROTO,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_ipv4,			ICE_SW_INSET_MAC_PPPOE_IPV4,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_qinq_pppoes_ipv6,			ICE_SW_INSET_MAC_PPPOE_IPV6,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu,				ICE_SW_INSET_MAC_IPV4_GTPU,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu,				ICE_SW_INSET_MAC_IPV6_GTPU,		ICE_INSET_NONE,				ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv4_gtpu_eh_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv4_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV4_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6,			ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6,			ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6,			ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6_udp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_UDP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
	{pattern_eth_ipv6_gtpu_eh_ipv6_tcp,		ICE_SW_INSET_MAC_GTPU_EH_OUTER,		ICE_SW_INSET_GTPU_IPV6_TCP,		ICE_INSET_NONE},
};

static int
ice_switch_create(struct ice_adapter *ad,
		struct rte_flow *flow,
		void *meta,
		struct rte_flow_error *error)
{
	int ret = 0;
	struct ice_pf *pf = &ad->pf;
	struct ice_hw *hw = ICE_PF_TO_HW(pf);
	struct ice_rule_query_data rule_added = {0};
	struct ice_switch_filter_conf *filter_conf_ptr;
	struct ice_adv_lkup_elem *list =
		((struct sw_meta *)meta)->list;
	uint16_t lkups_cnt =
		((struct sw_meta *)meta)->lkups_num;
	struct ice_adv_rule_info *rule_info =
		&((struct sw_meta *)meta)->rule_info;

	if (lkups_cnt > ICE_MAX_CHAIN_WORDS) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ITEM, NULL,
			"item number too large for rule");
		goto error;
	}
	if (!list) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ITEM, NULL,
			"lookup list should not be NULL");
		goto error;
	}

	if (ice_dcf_adminq_need_retry(ad)) {
		rte_flow_error_set(error, EAGAIN,
			RTE_FLOW_ERROR_TYPE_ITEM, NULL,
			"DCF is not on");
		goto error;
	}

	ret = ice_add_adv_rule(hw, list, lkups_cnt, rule_info, &rule_added);
	if (!ret) {
		filter_conf_ptr = rte_zmalloc("ice_switch_filter",
			sizeof(struct ice_switch_filter_conf), 0);
		if (!filter_conf_ptr) {
			rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "No memory for ice_switch_filter");
			goto error;
		}

		filter_conf_ptr->sw_query_data = rule_added;

		filter_conf_ptr->vsi_num =
			ice_get_hw_vsi_num(hw, rule_info->sw_act.vsi_handle);
		filter_conf_ptr->lkups = list;
		filter_conf_ptr->lkups_num = lkups_cnt;
		filter_conf_ptr->rule_info = *rule_info;

		filter_conf_ptr->fltr_status = ICE_SW_FLTR_ADDED;

		flow->rule = filter_conf_ptr;
	} else {
		if (ice_dcf_adminq_need_retry(ad))
			ret = -EAGAIN;
		else
			ret = -EINVAL;

		rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"switch filter create flow fail");
		goto error;
	}

	rte_free(meta);
	return 0;

error:
	rte_free(list);
	rte_free(meta);

	return -rte_errno;
}

static inline void
ice_switch_filter_rule_free(struct rte_flow *flow)
{
	struct ice_switch_filter_conf *filter_conf_ptr =
		(struct ice_switch_filter_conf *)flow->rule;

	if (filter_conf_ptr)
		rte_free(filter_conf_ptr->lkups);

	rte_free(filter_conf_ptr);
}

static int
ice_switch_destroy(struct ice_adapter *ad,
		struct rte_flow *flow,
		struct rte_flow_error *error)
{
	struct ice_hw *hw = &ad->hw;
	int ret;
	struct ice_switch_filter_conf *filter_conf_ptr;

	filter_conf_ptr = (struct ice_switch_filter_conf *)
		flow->rule;

	if (!filter_conf_ptr ||
	    filter_conf_ptr->fltr_status == ICE_SW_FLTR_ADD_FAILED_ON_RIDRECT) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"no such flow"
			" create by switch filter");

		ice_switch_filter_rule_free(flow);

		return -rte_errno;
	}

	if (ice_dcf_adminq_need_retry(ad)) {
		rte_flow_error_set(error, EAGAIN,
			RTE_FLOW_ERROR_TYPE_ITEM, NULL,
			"DCF is not on");
		return -rte_errno;
	}

	ret = ice_rem_adv_rule_by_id(hw, &filter_conf_ptr->sw_query_data);
	if (ret) {
		if (ice_dcf_adminq_need_retry(ad))
			ret = -EAGAIN;
		else
			ret = -EINVAL;

		rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"fail to destroy switch filter rule");
		return -rte_errno;
	}

	ice_switch_filter_rule_free(flow);
	return ret;
}

static bool
ice_switch_parse_pattern(const struct rte_flow_item pattern[],
		struct rte_flow_error *error,
		struct ice_adv_lkup_elem *list,
		uint16_t *lkups_num,
		enum ice_sw_tunnel_type *tun_type,
		const struct ice_pattern_match_item *pattern_match_item)
{
	const struct rte_flow_item *item = pattern;
	enum rte_flow_item_type item_type;
	const struct rte_flow_item_eth *eth_spec, *eth_mask;
	const struct rte_flow_item_ipv4 *ipv4_spec, *ipv4_mask;
	const struct rte_flow_item_ipv6 *ipv6_spec, *ipv6_mask;
	const struct rte_flow_item_tcp *tcp_spec, *tcp_mask;
	const struct rte_flow_item_udp *udp_spec, *udp_mask;
	const struct rte_flow_item_sctp *sctp_spec, *sctp_mask;
	const struct rte_flow_item_nvgre *nvgre_spec, *nvgre_mask;
	const struct rte_flow_item_vxlan *vxlan_spec, *vxlan_mask;
	const struct rte_flow_item_vlan *vlan_spec, *vlan_mask;
	const struct rte_flow_item_pppoe *pppoe_spec, *pppoe_mask;
	const struct rte_flow_item_pppoe_proto_id *pppoe_proto_spec,
				*pppoe_proto_mask;
	const struct rte_flow_item_esp *esp_spec, *esp_mask;
	const struct rte_flow_item_ah *ah_spec, *ah_mask;
	const struct rte_flow_item_l2tpv3oip *l2tp_spec, *l2tp_mask;
	const struct rte_flow_item_pfcp *pfcp_spec, *pfcp_mask;
	const struct rte_flow_item_gtp *gtp_spec, *gtp_mask;
	const struct rte_flow_item_gtp_psc *gtp_psc_spec, *gtp_psc_mask;
	uint64_t outer_input_set = ICE_INSET_NONE;
	uint64_t inner_input_set = ICE_INSET_NONE;
	uint64_t *input = NULL;
	uint16_t input_set_byte = 0;
	bool pppoe_elem_valid = 0;
	bool pppoe_patt_valid = 0;
	bool pppoe_prot_valid = 0;
	bool inner_vlan_valid = 0;
	bool outer_vlan_valid = 0;
	bool tunnel_valid = 0;
	bool profile_rule = 0;
	bool nvgre_valid = 0;
	bool vxlan_valid = 0;
	bool qinq_valid = 0;
	bool ipv6_valid = 0;
	bool ipv4_valid = 0;
	bool udp_valid = 0;
	bool tcp_valid = 0;
	bool gtpu_valid = 0;
	bool gtpu_psc_valid = 0;
	bool inner_ipv4_valid = 0;
	bool inner_ipv6_valid = 0;
	bool inner_tcp_valid = 0;
	bool inner_udp_valid = 0;
	uint16_t j, k, t = 0;

	if (*tun_type == ICE_SW_TUN_AND_NON_TUN_QINQ ||
	    *tun_type == ICE_NON_TUN_QINQ)
		qinq_valid = 1;

	for (item = pattern; item->type !=
			RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->last) {
			rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Not support range");
			return false;
		}
		item_type = item->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_ANY:
			*tun_type = ICE_SW_TUN_AND_NON_TUN;
			break;

		case RTE_FLOW_ITEM_TYPE_ETH:
			eth_spec = item->spec;
			eth_mask = item->mask;
			if (eth_spec && eth_mask) {
				const uint8_t *a = eth_mask->src.addr_bytes;
				const uint8_t *b = eth_mask->dst.addr_bytes;
				if (tunnel_valid)
					input = &inner_input_set;
				else
					input = &outer_input_set;
				for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
					if (a[j]) {
						*input |= ICE_INSET_SMAC;
						break;
					}
				}
				for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
					if (b[j]) {
						*input |= ICE_INSET_DMAC;
						break;
					}
				}
				if (eth_mask->type)
					*input |= ICE_INSET_ETHERTYPE;
				list[t].type = (tunnel_valid  == 0) ?
					ICE_MAC_OFOS : ICE_MAC_IL;
				struct ice_ether_hdr *h;
				struct ice_ether_hdr *m;
				uint16_t i = 0;
				h = &list[t].h_u.eth_hdr;
				m = &list[t].m_u.eth_hdr;
				for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
					if (eth_mask->src.addr_bytes[j]) {
						h->src_addr[j] =
						eth_spec->src.addr_bytes[j];
						m->src_addr[j] =
						eth_mask->src.addr_bytes[j];
						i = 1;
						input_set_byte++;
					}
					if (eth_mask->dst.addr_bytes[j]) {
						h->dst_addr[j] =
						eth_spec->dst.addr_bytes[j];
						m->dst_addr[j] =
						eth_mask->dst.addr_bytes[j];
						i = 1;
						input_set_byte++;
					}
				}
				if (i)
					t++;
				if (eth_mask->type) {
					list[t].type = ICE_ETYPE_OL;
					list[t].h_u.ethertype.ethtype_id =
						eth_spec->type;
					list[t].m_u.ethertype.ethtype_id =
						eth_mask->type;
					input_set_byte += 2;
					t++;
				}
			}
			break;

		case RTE_FLOW_ITEM_TYPE_IPV4:
			ipv4_spec = item->spec;
			ipv4_mask = item->mask;
			if (tunnel_valid) {
				inner_ipv4_valid = 1;
				input = &inner_input_set;
			} else {
				ipv4_valid = 1;
				input = &outer_input_set;
			}

			if (ipv4_spec && ipv4_mask) {
				/* Check IPv4 mask and update input set */
				if (ipv4_mask->hdr.version_ihl ||
					ipv4_mask->hdr.total_length ||
					ipv4_mask->hdr.packet_id ||
					ipv4_mask->hdr.hdr_checksum) {
					rte_flow_error_set(error, EINVAL,
						   RTE_FLOW_ERROR_TYPE_ITEM,
						   item,
						   "Invalid IPv4 mask.");
					return false;
				}

				if (ipv4_mask->hdr.src_addr)
					*input |= ICE_INSET_IPV4_SRC;
				if (ipv4_mask->hdr.dst_addr)
					*input |= ICE_INSET_IPV4_DST;
				if (ipv4_mask->hdr.time_to_live)
					*input |= ICE_INSET_IPV4_TTL;
				if (ipv4_mask->hdr.next_proto_id)
					*input |= ICE_INSET_IPV4_PROTO;
				if (ipv4_mask->hdr.type_of_service)
					*input |= ICE_INSET_IPV4_TOS;

				list[t].type = (tunnel_valid  == 0) ?
					ICE_IPV4_OFOS : ICE_IPV4_IL;
				if (ipv4_mask->hdr.src_addr) {
					list[t].h_u.ipv4_hdr.src_addr =
						ipv4_spec->hdr.src_addr;
					list[t].m_u.ipv4_hdr.src_addr =
						ipv4_mask->hdr.src_addr;
					input_set_byte += 2;
				}
				if (ipv4_mask->hdr.dst_addr) {
					list[t].h_u.ipv4_hdr.dst_addr =
						ipv4_spec->hdr.dst_addr;
					list[t].m_u.ipv4_hdr.dst_addr =
						ipv4_mask->hdr.dst_addr;
					input_set_byte += 2;
				}
				if (ipv4_mask->hdr.time_to_live) {
					list[t].h_u.ipv4_hdr.time_to_live =
						ipv4_spec->hdr.time_to_live;
					list[t].m_u.ipv4_hdr.time_to_live =
						ipv4_mask->hdr.time_to_live;
					input_set_byte++;
				}
				if (ipv4_mask->hdr.next_proto_id) {
					list[t].h_u.ipv4_hdr.protocol =
						ipv4_spec->hdr.next_proto_id;
					list[t].m_u.ipv4_hdr.protocol =
						ipv4_mask->hdr.next_proto_id;
					input_set_byte++;
				}
				if ((ipv4_spec->hdr.next_proto_id &
					ipv4_mask->hdr.next_proto_id) ==
					ICE_IPV4_PROTO_NVGRE)
					*tun_type = ICE_SW_TUN_AND_NON_TUN;
				if (ipv4_mask->hdr.type_of_service) {
					list[t].h_u.ipv4_hdr.tos =
						ipv4_spec->hdr.type_of_service;
					list[t].m_u.ipv4_hdr.tos =
						ipv4_mask->hdr.type_of_service;
					input_set_byte++;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_IPV6:
			ipv6_spec = item->spec;
			ipv6_mask = item->mask;
			if (tunnel_valid) {
				inner_ipv6_valid = 1;
				input = &inner_input_set;
			} else {
				ipv6_valid = 1;
				input = &outer_input_set;
			}

			if (ipv6_spec && ipv6_mask) {
				if (ipv6_mask->hdr.payload_len) {
					rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid IPv6 mask");
					return false;
				}

				for (j = 0; j < ICE_IPV6_ADDR_LENGTH; j++) {
					if (ipv6_mask->hdr.src_addr[j]) {
						*input |= ICE_INSET_IPV6_SRC;
						break;
					}
				}
				for (j = 0; j < ICE_IPV6_ADDR_LENGTH; j++) {
					if (ipv6_mask->hdr.dst_addr[j]) {
						*input |= ICE_INSET_IPV6_DST;
						break;
					}
				}
				if (ipv6_mask->hdr.proto)
					*input |= ICE_INSET_IPV6_NEXT_HDR;
				if (ipv6_mask->hdr.hop_limits)
					*input |= ICE_INSET_IPV6_HOP_LIMIT;
				if (ipv6_mask->hdr.vtc_flow &
				    rte_cpu_to_be_32(RTE_IPV6_HDR_TC_MASK))
					*input |= ICE_INSET_IPV6_TC;

				list[t].type = (tunnel_valid  == 0) ?
					ICE_IPV6_OFOS : ICE_IPV6_IL;
				struct ice_ipv6_hdr *f;
				struct ice_ipv6_hdr *s;
				f = &list[t].h_u.ipv6_hdr;
				s = &list[t].m_u.ipv6_hdr;
				for (j = 0; j < ICE_IPV6_ADDR_LENGTH; j++) {
					if (ipv6_mask->hdr.src_addr[j]) {
						f->src_addr[j] =
						ipv6_spec->hdr.src_addr[j];
						s->src_addr[j] =
						ipv6_mask->hdr.src_addr[j];
						input_set_byte++;
					}
					if (ipv6_mask->hdr.dst_addr[j]) {
						f->dst_addr[j] =
						ipv6_spec->hdr.dst_addr[j];
						s->dst_addr[j] =
						ipv6_mask->hdr.dst_addr[j];
						input_set_byte++;
					}
				}
				if (ipv6_mask->hdr.proto) {
					f->next_hdr =
						ipv6_spec->hdr.proto;
					s->next_hdr =
						ipv6_mask->hdr.proto;
					input_set_byte++;
				}
				if (ipv6_mask->hdr.hop_limits) {
					f->hop_limit =
						ipv6_spec->hdr.hop_limits;
					s->hop_limit =
						ipv6_mask->hdr.hop_limits;
					input_set_byte++;
				}
				if (ipv6_mask->hdr.vtc_flow &
						rte_cpu_to_be_32
						(RTE_IPV6_HDR_TC_MASK)) {
					struct ice_le_ver_tc_flow vtf;
					vtf.u.fld.version = 0;
					vtf.u.fld.flow_label = 0;
					vtf.u.fld.tc = (rte_be_to_cpu_32
						(ipv6_spec->hdr.vtc_flow) &
							RTE_IPV6_HDR_TC_MASK) >>
							RTE_IPV6_HDR_TC_SHIFT;
					f->be_ver_tc_flow = CPU_TO_BE32(vtf.u.val);
					vtf.u.fld.tc = (rte_be_to_cpu_32
						(ipv6_mask->hdr.vtc_flow) &
							RTE_IPV6_HDR_TC_MASK) >>
							RTE_IPV6_HDR_TC_SHIFT;
					s->be_ver_tc_flow = CPU_TO_BE32(vtf.u.val);
					input_set_byte += 4;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_UDP:
			udp_spec = item->spec;
			udp_mask = item->mask;
			if (tunnel_valid) {
				inner_udp_valid = 1;
				input = &inner_input_set;
			} else {
				udp_valid = 1;
				input = &outer_input_set;
			}

			if (udp_spec && udp_mask) {
				/* Check UDP mask and update input set*/
				if (udp_mask->hdr.dgram_len ||
				    udp_mask->hdr.dgram_cksum) {
					rte_flow_error_set(error, EINVAL,
						   RTE_FLOW_ERROR_TYPE_ITEM,
						   item,
						   "Invalid UDP mask");
					return false;
				}

				if (udp_mask->hdr.src_port)
					*input |= ICE_INSET_UDP_SRC_PORT;
				if (udp_mask->hdr.dst_port)
					*input |= ICE_INSET_UDP_DST_PORT;

				if (*tun_type == ICE_SW_TUN_VXLAN &&
						tunnel_valid == 0)
					list[t].type = ICE_UDP_OF;
				else
					list[t].type = ICE_UDP_ILOS;
				if (udp_mask->hdr.src_port) {
					list[t].h_u.l4_hdr.src_port =
						udp_spec->hdr.src_port;
					list[t].m_u.l4_hdr.src_port =
						udp_mask->hdr.src_port;
					input_set_byte += 2;
				}
				if (udp_mask->hdr.dst_port) {
					list[t].h_u.l4_hdr.dst_port =
						udp_spec->hdr.dst_port;
					list[t].m_u.l4_hdr.dst_port =
						udp_mask->hdr.dst_port;
					input_set_byte += 2;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_TCP:
			tcp_spec = item->spec;
			tcp_mask = item->mask;
			if (tunnel_valid) {
				inner_tcp_valid = 1;
				input = &inner_input_set;
			} else {
				tcp_valid = 1;
				input = &outer_input_set;
			}

			if (tcp_spec && tcp_mask) {
				/* Check TCP mask and update input set */
				if (tcp_mask->hdr.sent_seq ||
					tcp_mask->hdr.recv_ack ||
					tcp_mask->hdr.data_off ||
					tcp_mask->hdr.tcp_flags ||
					tcp_mask->hdr.rx_win ||
					tcp_mask->hdr.cksum ||
					tcp_mask->hdr.tcp_urp) {
					rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid TCP mask");
					return false;
				}

				if (tcp_mask->hdr.src_port)
					*input |= ICE_INSET_TCP_SRC_PORT;
				if (tcp_mask->hdr.dst_port)
					*input |= ICE_INSET_TCP_DST_PORT;
				list[t].type = ICE_TCP_IL;
				if (tcp_mask->hdr.src_port) {
					list[t].h_u.l4_hdr.src_port =
						tcp_spec->hdr.src_port;
					list[t].m_u.l4_hdr.src_port =
						tcp_mask->hdr.src_port;
					input_set_byte += 2;
				}
				if (tcp_mask->hdr.dst_port) {
					list[t].h_u.l4_hdr.dst_port =
						tcp_spec->hdr.dst_port;
					list[t].m_u.l4_hdr.dst_port =
						tcp_mask->hdr.dst_port;
					input_set_byte += 2;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_SCTP:
			sctp_spec = item->spec;
			sctp_mask = item->mask;
			if (sctp_spec && sctp_mask) {
				/* Check SCTP mask and update input set */
				if (sctp_mask->hdr.cksum) {
					rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid SCTP mask");
					return false;
				}
				if (tunnel_valid)
					input = &inner_input_set;
				else
					input = &outer_input_set;

				if (sctp_mask->hdr.src_port)
					*input |= ICE_INSET_SCTP_SRC_PORT;
				if (sctp_mask->hdr.dst_port)
					*input |= ICE_INSET_SCTP_DST_PORT;

				list[t].type = ICE_SCTP_IL;
				if (sctp_mask->hdr.src_port) {
					list[t].h_u.sctp_hdr.src_port =
						sctp_spec->hdr.src_port;
					list[t].m_u.sctp_hdr.src_port =
						sctp_mask->hdr.src_port;
					input_set_byte += 2;
				}
				if (sctp_mask->hdr.dst_port) {
					list[t].h_u.sctp_hdr.dst_port =
						sctp_spec->hdr.dst_port;
					list[t].m_u.sctp_hdr.dst_port =
						sctp_mask->hdr.dst_port;
					input_set_byte += 2;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_VXLAN:
			vxlan_spec = item->spec;
			vxlan_mask = item->mask;
			/* Check if VXLAN item is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!vxlan_spec && vxlan_mask) ||
			    (vxlan_spec && !vxlan_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid VXLAN item");
				return false;
			}
			vxlan_valid = 1;
			tunnel_valid = 1;
			input = &inner_input_set;
			if (vxlan_spec && vxlan_mask) {
				list[t].type = ICE_VXLAN;
				if (vxlan_mask->vni[0] ||
					vxlan_mask->vni[1] ||
					vxlan_mask->vni[2]) {
					list[t].h_u.tnl_hdr.vni =
						(vxlan_spec->vni[2] << 16) |
						(vxlan_spec->vni[1] << 8) |
						vxlan_spec->vni[0];
					list[t].m_u.tnl_hdr.vni =
						(vxlan_mask->vni[2] << 16) |
						(vxlan_mask->vni[1] << 8) |
						vxlan_mask->vni[0];
					*input |= ICE_INSET_VXLAN_VNI;
					input_set_byte += 2;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_NVGRE:
			nvgre_spec = item->spec;
			nvgre_mask = item->mask;
			/* Check if NVGRE item is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!nvgre_spec && nvgre_mask) ||
			    (nvgre_spec && !nvgre_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid NVGRE item");
				return false;
			}
			nvgre_valid = 1;
			tunnel_valid = 1;
			input = &inner_input_set;
			if (nvgre_spec && nvgre_mask) {
				list[t].type = ICE_NVGRE;
				if (nvgre_mask->tni[0] ||
					nvgre_mask->tni[1] ||
					nvgre_mask->tni[2]) {
					list[t].h_u.nvgre_hdr.tni_flow =
						(nvgre_spec->tni[2] << 16) |
						(nvgre_spec->tni[1] << 8) |
						nvgre_spec->tni[0];
					list[t].m_u.nvgre_hdr.tni_flow =
						(nvgre_mask->tni[2] << 16) |
						(nvgre_mask->tni[1] << 8) |
						nvgre_mask->tni[0];
					*input |= ICE_INSET_NVGRE_TNI;
					input_set_byte += 2;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_VLAN:
			vlan_spec = item->spec;
			vlan_mask = item->mask;
			/* Check if VLAN item is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!vlan_spec && vlan_mask) ||
			    (vlan_spec && !vlan_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid VLAN item");
				return false;
			}

			if (qinq_valid) {
				if (!outer_vlan_valid)
					outer_vlan_valid = 1;
				else
					inner_vlan_valid = 1;
			}

			input = &outer_input_set;

			if (vlan_spec && vlan_mask) {
				if (qinq_valid) {
					if (!inner_vlan_valid) {
						list[t].type = ICE_VLAN_EX;
						*input |=
							ICE_INSET_VLAN_OUTER;
					} else {
						list[t].type = ICE_VLAN_IN;
						*input |=
							ICE_INSET_VLAN_INNER;
					}
				} else {
					list[t].type = ICE_VLAN_OFOS;
					*input |= ICE_INSET_VLAN_INNER;
				}

				if (vlan_mask->tci) {
					list[t].h_u.vlan_hdr.vlan =
						vlan_spec->tci;
					list[t].m_u.vlan_hdr.vlan =
						vlan_mask->tci;
					input_set_byte += 2;
				}
				if (vlan_mask->inner_type) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid VLAN input set.");
					return false;
				}
				t++;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_PPPOED:
		case RTE_FLOW_ITEM_TYPE_PPPOES:
			pppoe_spec = item->spec;
			pppoe_mask = item->mask;
			/* Check if PPPoE item is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!pppoe_spec && pppoe_mask) ||
				(pppoe_spec && !pppoe_mask)) {
				rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Invalid pppoe item");
				return false;
			}
			pppoe_patt_valid = 1;
			input = &outer_input_set;
			if (pppoe_spec && pppoe_mask) {
				/* Check pppoe mask and update input set */
				if (pppoe_mask->length ||
					pppoe_mask->code ||
					pppoe_mask->version_type) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid pppoe mask");
					return false;
				}
				list[t].type = ICE_PPPOE;
				if (pppoe_mask->session_id) {
					list[t].h_u.pppoe_hdr.session_id =
						pppoe_spec->session_id;
					list[t].m_u.pppoe_hdr.session_id =
						pppoe_mask->session_id;
					*input |= ICE_INSET_PPPOE_SESSION;
					input_set_byte += 2;
				}
				t++;
				pppoe_elem_valid = 1;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID:
			pppoe_proto_spec = item->spec;
			pppoe_proto_mask = item->mask;
			/* Check if PPPoE optional proto_id item
			 * is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!pppoe_proto_spec && pppoe_proto_mask) ||
				(pppoe_proto_spec && !pppoe_proto_mask)) {
				rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Invalid pppoe proto item");
				return false;
			}
			input = &outer_input_set;
			if (pppoe_proto_spec && pppoe_proto_mask) {
				if (pppoe_elem_valid)
					t--;
				list[t].type = ICE_PPPOE;
				if (pppoe_proto_mask->proto_id) {
					list[t].h_u.pppoe_hdr.ppp_prot_id =
						pppoe_proto_spec->proto_id;
					list[t].m_u.pppoe_hdr.ppp_prot_id =
						pppoe_proto_mask->proto_id;
					*input |= ICE_INSET_PPPOE_PROTO;
					input_set_byte += 2;
					pppoe_prot_valid = 1;
				}
				if ((pppoe_proto_mask->proto_id &
					pppoe_proto_spec->proto_id) !=
					    CPU_TO_BE16(ICE_PPP_IPV4_PROTO) &&
					(pppoe_proto_mask->proto_id &
					pppoe_proto_spec->proto_id) !=
					    CPU_TO_BE16(ICE_PPP_IPV6_PROTO))
					*tun_type = ICE_SW_TUN_PPPOE_PAY;
				else
					*tun_type = ICE_SW_TUN_PPPOE;
				t++;
			}

			break;

		case RTE_FLOW_ITEM_TYPE_ESP:
			esp_spec = item->spec;
			esp_mask = item->mask;
			if ((esp_spec && !esp_mask) ||
				(!esp_spec && esp_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid esp item");
				return false;
			}
			/* Check esp mask and update input set */
			if (esp_mask && esp_mask->hdr.seq) {
				rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid esp mask");
				return false;
			}
			input = &outer_input_set;
			if (!esp_spec && !esp_mask && !(*input)) {
				profile_rule = 1;
				if (ipv6_valid && udp_valid)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV6_NAT_T;
				else if (ipv6_valid)
					*tun_type = ICE_SW_TUN_PROFID_IPV6_ESP;
				else if (ipv4_valid)
					goto inset_check;
			} else if (esp_spec && esp_mask &&
						esp_mask->hdr.spi){
				if (udp_valid)
					list[t].type = ICE_NAT_T;
				else
					list[t].type = ICE_ESP;
				list[t].h_u.esp_hdr.spi =
					esp_spec->hdr.spi;
				list[t].m_u.esp_hdr.spi =
					esp_mask->hdr.spi;
				*input |= ICE_INSET_ESP_SPI;
				input_set_byte += 4;
				t++;
			}

			if (!profile_rule) {
				if (ipv6_valid && udp_valid)
					*tun_type = ICE_SW_TUN_IPV6_NAT_T;
				else if (ipv4_valid && udp_valid)
					*tun_type = ICE_SW_TUN_IPV4_NAT_T;
				else if (ipv6_valid)
					*tun_type = ICE_SW_TUN_IPV6_ESP;
				else if (ipv4_valid)
					*tun_type = ICE_SW_TUN_IPV4_ESP;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_AH:
			ah_spec = item->spec;
			ah_mask = item->mask;
			if ((ah_spec && !ah_mask) ||
				(!ah_spec && ah_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid ah item");
				return false;
			}
			/* Check ah mask and update input set */
			if (ah_mask &&
				(ah_mask->next_hdr ||
				ah_mask->payload_len ||
				ah_mask->seq_num ||
				ah_mask->reserved)) {
				rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid ah mask");
				return false;
			}

			input = &outer_input_set;
			if (!ah_spec && !ah_mask && !(*input)) {
				profile_rule = 1;
				if (ipv6_valid && udp_valid)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV6_NAT_T;
				else if (ipv6_valid)
					*tun_type = ICE_SW_TUN_PROFID_IPV6_AH;
				else if (ipv4_valid)
					goto inset_check;
			} else if (ah_spec && ah_mask &&
						ah_mask->spi){
				list[t].type = ICE_AH;
				list[t].h_u.ah_hdr.spi =
					ah_spec->spi;
				list[t].m_u.ah_hdr.spi =
					ah_mask->spi;
				*input |= ICE_INSET_AH_SPI;
				input_set_byte += 4;
				t++;
			}

			if (!profile_rule) {
				if (udp_valid)
					goto inset_check;
				else if (ipv6_valid)
					*tun_type = ICE_SW_TUN_IPV6_AH;
				else if (ipv4_valid)
					*tun_type = ICE_SW_TUN_IPV4_AH;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_L2TPV3OIP:
			l2tp_spec = item->spec;
			l2tp_mask = item->mask;
			if ((l2tp_spec && !l2tp_mask) ||
				(!l2tp_spec && l2tp_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid l2tp item");
				return false;
			}

			input = &outer_input_set;
			if (!l2tp_spec && !l2tp_mask && !(*input)) {
				if (ipv6_valid)
					*tun_type =
					ICE_SW_TUN_PROFID_MAC_IPV6_L2TPV3;
				else if (ipv4_valid)
					goto inset_check;
			} else if (l2tp_spec && l2tp_mask &&
						l2tp_mask->session_id){
				list[t].type = ICE_L2TPV3;
				list[t].h_u.l2tpv3_sess_hdr.session_id =
					l2tp_spec->session_id;
				list[t].m_u.l2tpv3_sess_hdr.session_id =
					l2tp_mask->session_id;
				*input |= ICE_INSET_L2TPV3OIP_SESSION_ID;
				input_set_byte += 4;
				t++;
			}

			if (!profile_rule) {
				if (ipv6_valid)
					*tun_type =
					ICE_SW_TUN_IPV6_L2TPV3;
				else if (ipv4_valid)
					*tun_type =
					ICE_SW_TUN_IPV4_L2TPV3;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_PFCP:
			pfcp_spec = item->spec;
			pfcp_mask = item->mask;
			/* Check if PFCP item is used to describe protocol.
			 * If yes, both spec and mask should be NULL.
			 * If no, both spec and mask shouldn't be NULL.
			 */
			if ((!pfcp_spec && pfcp_mask) ||
			    (pfcp_spec && !pfcp_mask)) {
				rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_ITEM,
					   item,
					   "Invalid PFCP item");
				return false;
			}
			if (pfcp_spec && pfcp_mask) {
				/* Check pfcp mask and update input set */
				if (pfcp_mask->msg_type ||
					pfcp_mask->msg_len ||
					pfcp_mask->seid) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid pfcp mask");
					return false;
				}
				if (pfcp_mask->s_field &&
					pfcp_spec->s_field == 0x01 &&
					ipv6_valid)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV6_PFCP_SESSION;
				else if (pfcp_mask->s_field &&
					pfcp_spec->s_field == 0x01)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV4_PFCP_SESSION;
				else if (pfcp_mask->s_field &&
					!pfcp_spec->s_field &&
					ipv6_valid)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV6_PFCP_NODE;
				else if (pfcp_mask->s_field &&
					!pfcp_spec->s_field)
					*tun_type =
					ICE_SW_TUN_PROFID_IPV4_PFCP_NODE;
				else
					return false;
			}
			break;

		case RTE_FLOW_ITEM_TYPE_GTPU:
			gtp_spec = item->spec;
			gtp_mask = item->mask;
			if (gtp_spec && !gtp_mask) {
				rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Invalid GTP item");
				return false;
			}
			if (gtp_spec && gtp_mask) {
				if (gtp_mask->v_pt_rsv_flags ||
				    gtp_mask->msg_type ||
				    gtp_mask->msg_len) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid GTP mask");
					return false;
				}
				input = &outer_input_set;
				if (gtp_mask->teid)
					*input |= ICE_INSET_GTPU_TEID;
				list[t].type = ICE_GTP;
				list[t].h_u.gtp_hdr.teid =
					gtp_spec->teid;
				list[t].m_u.gtp_hdr.teid =
					gtp_mask->teid;
				input_set_byte += 4;
				t++;
			}
			tunnel_valid = 1;
			gtpu_valid = 1;
			break;

		case RTE_FLOW_ITEM_TYPE_GTP_PSC:
			gtp_psc_spec = item->spec;
			gtp_psc_mask = item->mask;
			if (gtp_psc_spec && !gtp_psc_mask) {
				rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Invalid GTPU_EH item");
				return false;
			}
			if (gtp_psc_spec && gtp_psc_mask) {
				if (gtp_psc_mask->hdr.type) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid GTPU_EH mask");
					return false;
				}
				input = &outer_input_set;
				if (gtp_psc_mask->hdr.qfi)
					*input |= ICE_INSET_GTPU_QFI;
				list[t].type = ICE_GTP;
				list[t].h_u.gtp_hdr.qfi =
					gtp_psc_spec->hdr.qfi;
				list[t].m_u.gtp_hdr.qfi =
					gtp_psc_mask->hdr.qfi;
				input_set_byte += 1;
				t++;
			}
			gtpu_psc_valid = 1;
			break;

		case RTE_FLOW_ITEM_TYPE_VOID:
			break;

		default:
			rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM, pattern,
				   "Invalid pattern item.");
			return false;
		}
	}

	if (*tun_type == ICE_SW_TUN_PPPOE_PAY &&
	    inner_vlan_valid && outer_vlan_valid)
		*tun_type = ICE_SW_TUN_PPPOE_PAY_QINQ;
	else if (*tun_type == ICE_SW_TUN_PPPOE &&
		 inner_vlan_valid && outer_vlan_valid)
		*tun_type = ICE_SW_TUN_PPPOE_QINQ;
	else if (*tun_type == ICE_NON_TUN &&
		 inner_vlan_valid && outer_vlan_valid)
		*tun_type = ICE_NON_TUN_QINQ;
	else if (*tun_type == ICE_SW_TUN_AND_NON_TUN &&
		 inner_vlan_valid && outer_vlan_valid)
		*tun_type = ICE_SW_TUN_AND_NON_TUN_QINQ;

	if (pppoe_patt_valid && !pppoe_prot_valid) {
		if (inner_vlan_valid && outer_vlan_valid && ipv4_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV4_QINQ;
		else if (inner_vlan_valid && outer_vlan_valid && ipv6_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV6_QINQ;
		else if (inner_vlan_valid && outer_vlan_valid)
			*tun_type = ICE_SW_TUN_PPPOE_QINQ;
		else if (ipv6_valid && udp_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV6_UDP;
		else if (ipv6_valid && tcp_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV6_TCP;
		else if (ipv4_valid && udp_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV4_UDP;
		else if (ipv4_valid && tcp_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV4_TCP;
		else if (ipv6_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV6;
		else if (ipv4_valid)
			*tun_type = ICE_SW_TUN_PPPOE_IPV4;
		else
			*tun_type = ICE_SW_TUN_PPPOE;
	}

	if (gtpu_valid && gtpu_psc_valid) {
		if (ipv4_valid && inner_ipv4_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV4_UDP;
		else if (ipv4_valid && inner_ipv4_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV4_TCP;
		else if (ipv4_valid && inner_ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV4;
		else if (ipv4_valid && inner_ipv6_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV6_UDP;
		else if (ipv4_valid && inner_ipv6_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV6_TCP;
		else if (ipv4_valid && inner_ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_EH_IPV6;
		else if (ipv6_valid && inner_ipv4_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV4_UDP;
		else if (ipv6_valid && inner_ipv4_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV4_TCP;
		else if (ipv6_valid && inner_ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV4;
		else if (ipv6_valid && inner_ipv6_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV6_UDP;
		else if (ipv6_valid && inner_ipv6_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV6_TCP;
		else if (ipv6_valid && inner_ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_EH_IPV6;
		else if (ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_NO_PAY;
		else if (ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_NO_PAY;
	} else if (gtpu_valid) {
		if (ipv4_valid && inner_ipv4_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV4_UDP;
		else if (ipv4_valid && inner_ipv4_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV4_TCP;
		else if (ipv4_valid && inner_ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV4;
		else if (ipv4_valid && inner_ipv6_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV6_UDP;
		else if (ipv4_valid && inner_ipv6_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV6_TCP;
		else if (ipv4_valid && inner_ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_IPV6;
		else if (ipv6_valid && inner_ipv4_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV4_UDP;
		else if (ipv6_valid && inner_ipv4_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV4_TCP;
		else if (ipv6_valid && inner_ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV4;
		else if (ipv6_valid && inner_ipv6_valid && inner_udp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV6_UDP;
		else if (ipv6_valid && inner_ipv6_valid && inner_tcp_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV6_TCP;
		else if (ipv6_valid && inner_ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_IPV6;
		else if (ipv4_valid)
			*tun_type = ICE_SW_TUN_IPV4_GTPU_NO_PAY;
		else if (ipv6_valid)
			*tun_type = ICE_SW_TUN_IPV6_GTPU_NO_PAY;
	}

	if (*tun_type == ICE_SW_TUN_IPV4_GTPU_NO_PAY ||
	    *tun_type == ICE_SW_TUN_IPV6_GTPU_NO_PAY) {
		for (k = 0; k < t; k++) {
			if (list[k].type == ICE_GTP)
				list[k].type = ICE_GTP_NO_PAY;
		}
	}

	if (*tun_type == ICE_NON_TUN) {
		if (vxlan_valid)
			*tun_type = ICE_SW_TUN_VXLAN;
		else if (nvgre_valid)
			*tun_type = ICE_SW_TUN_NVGRE;
		else if (ipv4_valid && tcp_valid)
			*tun_type = ICE_SW_IPV4_TCP;
		else if (ipv4_valid && udp_valid)
			*tun_type = ICE_SW_IPV4_UDP;
		else if (ipv6_valid && tcp_valid)
			*tun_type = ICE_SW_IPV6_TCP;
		else if (ipv6_valid && udp_valid)
			*tun_type = ICE_SW_IPV6_UDP;
	}

	if (input_set_byte > MAX_INPUT_SET_BYTE) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ITEM,
			item,
			"too much input set");
		return false;
	}

	*lkups_num = t;

inset_check:
	if ((!outer_input_set && !inner_input_set &&
	    !ice_is_prof_rule(*tun_type)) || (outer_input_set &
	    ~pattern_match_item->input_set_mask_o) ||
	    (inner_input_set & ~pattern_match_item->input_set_mask_i))
		return false;

	return true;
}

static int
ice_switch_parse_dcf_action(struct ice_dcf_adapter *ad,
			    const struct rte_flow_action *actions,
			    uint32_t priority,
			    struct rte_flow_error *error,
			    struct ice_adv_rule_info *rule_info)
{
	const struct rte_flow_action_ethdev *act_ethdev;
	const struct rte_flow_action *action;
	const struct rte_eth_dev *repr_dev;
	enum rte_flow_action_type action_type;
	uint16_t rule_port_id, backer_port_id;

	for (action = actions; action->type !=
				RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			rule_info->sw_act.fltr_act = ICE_FWD_TO_VSI;
			act_ethdev = action->conf;

			if (!rte_eth_dev_is_valid_port(act_ethdev->port_id))
				goto invalid_port_id;

			/* For traffic to original DCF port */
			rule_port_id = ad->parent.pf.dev_data->port_id;

			if (rule_port_id != act_ethdev->port_id)
				goto invalid_port_id;

			rule_info->sw_act.vsi_handle = 0;

			break;

invalid_port_id:
			rte_flow_error_set(error,
						EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
						actions,
						"Invalid port_id");
			return -rte_errno;

		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
			rule_info->sw_act.fltr_act = ICE_FWD_TO_VSI;
			act_ethdev = action->conf;

			if (!rte_eth_dev_is_valid_port(act_ethdev->port_id))
				goto invalid;

			repr_dev = &rte_eth_devices[act_ethdev->port_id];

			if (!repr_dev->data)
				goto invalid;

			rule_port_id = ad->parent.pf.dev_data->port_id;
			backer_port_id = repr_dev->data->backer_port_id;

			if (backer_port_id != rule_port_id)
				goto invalid;

			rule_info->sw_act.vsi_handle = repr_dev->data->representor_id;
			break;

invalid:
			rte_flow_error_set(error,
						EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
						actions,
						"Invalid ethdev_port_id");
			return -rte_errno;

		case RTE_FLOW_ACTION_TYPE_DROP:
			rule_info->sw_act.fltr_act = ICE_DROP_PACKET;
			break;

		default:
			rte_flow_error_set(error,
					   EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					   actions,
					   "Invalid action type");
			return -rte_errno;
		}
	}

	rule_info->sw_act.src = rule_info->sw_act.vsi_handle;
	rule_info->sw_act.flag = ICE_FLTR_RX;
	rule_info->rx = 1;
	/* 0 denotes lowest priority of recipe and highest priority
	 * of rte_flow. Change rte_flow priority into recipe priority.
	 */
	rule_info->priority = ICE_SW_PRI_BASE - priority;

	return 0;
}

static int
ice_switch_parse_action(struct ice_pf *pf,
		const struct rte_flow_action *actions,
		uint32_t priority,
		struct rte_flow_error *error,
		struct ice_adv_rule_info *rule_info)
{
	struct ice_vsi *vsi = pf->main_vsi;
	struct rte_eth_dev_data *dev_data = pf->adapter->pf.dev_data;
	const struct rte_flow_action_queue *act_q;
	const struct rte_flow_action_rss *act_qgrop;
	uint16_t base_queue, i;
	const struct rte_flow_action *action;
	enum rte_flow_action_type action_type;
	uint16_t valid_qgrop_number[MAX_QGRP_NUM_TYPE] = {
		 2, 4, 8, 16, 32, 64, 128};

	base_queue = pf->base_queue + vsi->base_queue;
	for (action = actions; action->type !=
			RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_RSS:
			act_qgrop = action->conf;
			if (act_qgrop->queue_num <= 1)
				goto error;
			rule_info->sw_act.fltr_act =
				ICE_FWD_TO_QGRP;
			rule_info->sw_act.fwd_id.q_id =
				base_queue + act_qgrop->queue[0];
			for (i = 0; i < MAX_QGRP_NUM_TYPE; i++) {
				if (act_qgrop->queue_num ==
					valid_qgrop_number[i])
					break;
			}
			if (i == MAX_QGRP_NUM_TYPE)
				goto error;
			if ((act_qgrop->queue[0] +
				act_qgrop->queue_num) >
				dev_data->nb_rx_queues)
				goto error1;
			for (i = 0; i < act_qgrop->queue_num - 1; i++)
				if (act_qgrop->queue[i + 1] !=
					act_qgrop->queue[i] + 1)
					goto error2;
			rule_info->sw_act.qgrp_size =
				act_qgrop->queue_num;
			break;
		case RTE_FLOW_ACTION_TYPE_QUEUE:
			act_q = action->conf;
			if (act_q->index >= dev_data->nb_rx_queues)
				goto error;
			rule_info->sw_act.fltr_act =
				ICE_FWD_TO_Q;
			rule_info->sw_act.fwd_id.q_id =
				base_queue + act_q->index;
			break;

		case RTE_FLOW_ACTION_TYPE_DROP:
			rule_info->sw_act.fltr_act =
				ICE_DROP_PACKET;
			break;

		case RTE_FLOW_ACTION_TYPE_VOID:
			break;

		default:
			goto error;
		}
	}

	rule_info->sw_act.vsi_handle = vsi->idx;
	rule_info->rx = 1;
	rule_info->sw_act.src = vsi->idx;
	/* 0 denotes lowest priority of recipe and highest priority
	 * of rte_flow. Change rte_flow priority into recipe priority.
	 */
	rule_info->priority = ICE_SW_PRI_BASE - priority;

	return 0;

error:
	rte_flow_error_set(error,
		EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
		actions,
		"Invalid action type or queue number");
	return -rte_errno;

error1:
	rte_flow_error_set(error,
		EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
		actions,
		"Invalid queue region indexes");
	return -rte_errno;

error2:
	rte_flow_error_set(error,
		EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
		actions,
		"Discontinuous queue region");
	return -rte_errno;
}

static int
ice_switch_check_action(const struct rte_flow_action *actions,
			    struct rte_flow_error *error)
{
	const struct rte_flow_action *action;
	enum rte_flow_action_type action_type;
	uint16_t actions_num = 0;

	for (action = actions; action->type !=
				RTE_FLOW_ACTION_TYPE_END; action++) {
		action_type = action->type;
		switch (action_type) {
		case RTE_FLOW_ACTION_TYPE_RSS:
		case RTE_FLOW_ACTION_TYPE_QUEUE:
		case RTE_FLOW_ACTION_TYPE_DROP:
		case RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT:
		case RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR:
			actions_num++;
			break;
		case RTE_FLOW_ACTION_TYPE_VOID:
			continue;
		default:
			rte_flow_error_set(error,
					   EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					   actions,
					   "Invalid action type");
			return -rte_errno;
		}
	}

	if (actions_num != 1) {
		rte_flow_error_set(error,
				   EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   actions,
				   "Invalid action number");
		return -rte_errno;
	}

	return 0;
}

static int
ice_switch_parse_pattern_action(struct ice_adapter *ad,
		struct ice_pattern_match_item *array,
		uint32_t array_len,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		uint32_t priority,
		void **meta,
		struct rte_flow_error *error)
{
	struct ice_pf *pf = &ad->pf;
	int ret = 0;
	struct sw_meta *sw_meta_ptr = NULL;
	struct ice_adv_rule_info rule_info;
	struct ice_adv_lkup_elem *list = NULL;
	uint16_t lkups_num = 0;
	const struct rte_flow_item *item = pattern;
	uint16_t item_num = 0;
	uint16_t vlan_num = 0;
	enum ice_sw_tunnel_type tun_type =
			ICE_NON_TUN;
	struct ice_pattern_match_item *pattern_match_item = NULL;

	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		item_num++;
		if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
			const struct rte_flow_item_eth *eth_mask;
			if (item->mask)
				eth_mask = item->mask;
			else
				continue;
			if (eth_mask->type == UINT16_MAX)
				tun_type = ICE_SW_TUN_AND_NON_TUN;
		}

		if (item->type == RTE_FLOW_ITEM_TYPE_VLAN)
			vlan_num++;

		/* reserve one more memory slot for ETH which may
		 * consume 2 lookup items.
		 */
		if (item->type == RTE_FLOW_ITEM_TYPE_ETH)
			item_num++;
	}

	if (vlan_num == 2 && tun_type == ICE_SW_TUN_AND_NON_TUN)
		tun_type = ICE_SW_TUN_AND_NON_TUN_QINQ;
	else if (vlan_num == 2)
		tun_type = ICE_NON_TUN_QINQ;

	/* reserve one more memory slot for direction flag which may
	 * consume 1 lookup item.
	 */
	list = rte_zmalloc(NULL, (item_num + 1) * sizeof(*list), 0);
	if (!list) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "No memory for PMD internal items");
		return -rte_errno;
	}

	sw_meta_ptr =
		rte_zmalloc(NULL, sizeof(*sw_meta_ptr), 0);
	if (!sw_meta_ptr) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "No memory for sw_pattern_meta_ptr");
		goto error;
	}

	pattern_match_item =
		ice_search_pattern_match_item(ad, pattern, array, array_len,
					      error);
	if (!pattern_match_item) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Invalid input pattern");
		goto error;
	}

	if (!ice_switch_parse_pattern(pattern, error, list, &lkups_num,
				   &tun_type, pattern_match_item)) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
				   pattern,
				   "Invalid input set");
		goto error;
	}

	memset(&rule_info, 0, sizeof(rule_info));
	rule_info.tun_type = tun_type;

	ret = ice_switch_check_action(actions, error);
	if (ret)
		goto error;

	if (ad->hw.dcf_enabled)
		ret = ice_switch_parse_dcf_action((void *)ad, actions, priority,
						  error, &rule_info);
	else
		ret = ice_switch_parse_action(pf, actions, priority, error,
					      &rule_info);

	if (ret)
		goto error;

	if (meta) {
		*meta = sw_meta_ptr;
		((struct sw_meta *)*meta)->list = list;
		((struct sw_meta *)*meta)->lkups_num = lkups_num;
		((struct sw_meta *)*meta)->rule_info = rule_info;
	} else {
		rte_free(list);
		rte_free(sw_meta_ptr);
	}

	rte_free(pattern_match_item);

	return 0;

error:
	rte_free(list);
	rte_free(sw_meta_ptr);
	rte_free(pattern_match_item);

	return -rte_errno;
}

static int
ice_switch_query(struct ice_adapter *ad __rte_unused,
		struct rte_flow *flow __rte_unused,
		struct rte_flow_query_count *count __rte_unused,
		struct rte_flow_error *error)
{
	rte_flow_error_set(error, EINVAL,
		RTE_FLOW_ERROR_TYPE_HANDLE,
		NULL,
		"count action not supported by switch filter");

	return -rte_errno;
}

static int
ice_switch_redirect(struct ice_adapter *ad,
		    struct rte_flow *flow,
		    struct ice_flow_redirect *rd)
{
	struct ice_rule_query_data *rdata;
	struct ice_switch_filter_conf *filter_conf_ptr =
		(struct ice_switch_filter_conf *)flow->rule;
	struct ice_rule_query_data added_rdata = { 0 };
	struct ice_adv_fltr_mgmt_list_entry *list_itr;
	struct ice_adv_lkup_elem *lkups_ref = NULL;
	struct ice_adv_lkup_elem *lkups_dp = NULL;
	struct LIST_HEAD_TYPE *list_head;
	struct ice_adv_rule_info rinfo;
	struct ice_hw *hw = &ad->hw;
	struct ice_switch_info *sw;
	uint16_t lkups_cnt;
	int ret;

	rdata = &filter_conf_ptr->sw_query_data;

	if (rdata->vsi_handle != rd->vsi_handle)
		return 0;

	sw = hw->switch_info;
	if (!sw->recp_list[rdata->rid].recp_created)
		return -EINVAL;

	if (rd->type != ICE_FLOW_REDIRECT_VSI)
		return -ENOTSUP;

	switch (filter_conf_ptr->fltr_status) {
	case ICE_SW_FLTR_ADDED:
		list_head = &sw->recp_list[rdata->rid].filt_rules;
		LIST_FOR_EACH_ENTRY(list_itr, list_head,
				    ice_adv_fltr_mgmt_list_entry,
				    list_entry) {
			rinfo = list_itr->rule_info;
			if ((rinfo.fltr_rule_id == rdata->rule_id &&
			    rinfo.sw_act.fltr_act == ICE_FWD_TO_VSI &&
			    rinfo.sw_act.vsi_handle == rd->vsi_handle) ||
			    (rinfo.fltr_rule_id == rdata->rule_id &&
			    rinfo.sw_act.fltr_act == ICE_FWD_TO_VSI_LIST)){
				lkups_cnt = list_itr->lkups_cnt;

				lkups_dp = (struct ice_adv_lkup_elem *)
					ice_memdup(hw, list_itr->lkups,
						   sizeof(*list_itr->lkups) *
						   lkups_cnt,
						   ICE_NONDMA_TO_NONDMA);
				if (!lkups_dp) {
					PMD_DRV_LOG(ERR,
						    "Failed to allocate memory.");
					return -EINVAL;
				}
				lkups_ref = lkups_dp;

				if (rinfo.sw_act.fltr_act ==
				    ICE_FWD_TO_VSI_LIST) {
					rinfo.sw_act.vsi_handle =
						rd->vsi_handle;
					rinfo.sw_act.fltr_act = ICE_FWD_TO_VSI;
				}
				break;
			}
		}

		if (!lkups_ref)
			return -EINVAL;

		goto rmv_rule;
	case ICE_SW_FLTR_RMV_FAILED_ON_RIDRECT:
		/* Recover VSI context */
		hw->vsi_ctx[rd->vsi_handle]->vsi_num = filter_conf_ptr->vsi_num;
		rinfo = filter_conf_ptr->rule_info;
		lkups_cnt = filter_conf_ptr->lkups_num;
		lkups_ref = filter_conf_ptr->lkups;

		if (rinfo.sw_act.fltr_act == ICE_FWD_TO_VSI_LIST) {
			rinfo.sw_act.vsi_handle = rd->vsi_handle;
			rinfo.sw_act.fltr_act = ICE_FWD_TO_VSI;
		}

		goto rmv_rule;
	case ICE_SW_FLTR_ADD_FAILED_ON_RIDRECT:
		rinfo = filter_conf_ptr->rule_info;
		lkups_cnt = filter_conf_ptr->lkups_num;
		lkups_ref = filter_conf_ptr->lkups;

		goto add_rule;
	default:
		return -EINVAL;
	}

rmv_rule:
	if (ice_dcf_adminq_need_retry(ad)) {
		PMD_DRV_LOG(WARNING, "DCF is not on");
		ret = -EAGAIN;
		goto out;
	}

	/* Remove the old rule */
	ret = ice_rem_adv_rule(hw, lkups_ref, lkups_cnt, &rinfo);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to delete the old rule %d",
			    rdata->rule_id);
		filter_conf_ptr->fltr_status =
			ICE_SW_FLTR_RMV_FAILED_ON_RIDRECT;
		ret = -EINVAL;
		goto out;
	}

add_rule:
	if (ice_dcf_adminq_need_retry(ad)) {
		PMD_DRV_LOG(WARNING, "DCF is not on");
		ret = -EAGAIN;
		goto out;
	}

	/* Update VSI context */
	hw->vsi_ctx[rd->vsi_handle]->vsi_num = rd->new_vsi_num;

	/* Replay the rule */
	ret = ice_add_adv_rule(hw, lkups_ref, lkups_cnt,
			       &rinfo, &added_rdata);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to replay the rule");
		filter_conf_ptr->fltr_status =
			ICE_SW_FLTR_ADD_FAILED_ON_RIDRECT;
		ret = -EINVAL;
	} else {
		filter_conf_ptr->sw_query_data = added_rdata;
		/* Save VSI number for failure recover */
		filter_conf_ptr->vsi_num = rd->new_vsi_num;
		filter_conf_ptr->fltr_status = ICE_SW_FLTR_ADDED;
	}

out:
	if (ret == -EINVAL)
		if (ice_dcf_adminq_need_retry(ad))
			ret = -EAGAIN;

	ice_free(hw, lkups_dp);
	return ret;
}

static int
ice_switch_init(struct ice_adapter *ad)
{
	int ret = 0;
	struct ice_flow_parser *dist_parser;
	struct ice_flow_parser *perm_parser;

	if (ad->devargs.pipe_mode_support) {
		perm_parser = &ice_switch_perm_parser;
		ret = ice_register_parser(perm_parser, ad);
	} else {
		dist_parser = &ice_switch_dist_parser;
		ret = ice_register_parser(dist_parser, ad);
	}
	return ret;
}

static void
ice_switch_uninit(struct ice_adapter *ad)
{
	struct ice_flow_parser *dist_parser;
	struct ice_flow_parser *perm_parser;

	if (ad->devargs.pipe_mode_support) {
		perm_parser = &ice_switch_perm_parser;
		ice_unregister_parser(perm_parser, ad);
	} else {
		dist_parser = &ice_switch_dist_parser;
		ice_unregister_parser(dist_parser, ad);
	}
}

static struct
ice_flow_engine ice_switch_engine = {
	.init = ice_switch_init,
	.uninit = ice_switch_uninit,
	.create = ice_switch_create,
	.destroy = ice_switch_destroy,
	.query_count = ice_switch_query,
	.redirect = ice_switch_redirect,
	.free = ice_switch_filter_rule_free,
	.type = ICE_FLOW_ENGINE_SWITCH,
};

static struct
ice_flow_parser ice_switch_dist_parser = {
	.engine = &ice_switch_engine,
	.array = ice_switch_pattern_dist_list,
	.array_len = RTE_DIM(ice_switch_pattern_dist_list),
	.parse_pattern_action = ice_switch_parse_pattern_action,
	.stage = ICE_FLOW_STAGE_DISTRIBUTOR,
};

static struct
ice_flow_parser ice_switch_perm_parser = {
	.engine = &ice_switch_engine,
	.array = ice_switch_pattern_perm_list,
	.array_len = RTE_DIM(ice_switch_pattern_perm_list),
	.parse_pattern_action = ice_switch_parse_pattern_action,
	.stage = ICE_FLOW_STAGE_PERMISSION,
};

RTE_INIT(ice_sw_engine_init)
{
	struct ice_flow_engine *engine = &ice_switch_engine;
	ice_register_flow_engine(engine);
}
