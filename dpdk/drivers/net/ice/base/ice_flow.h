/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _ICE_FLOW_H_
#define _ICE_FLOW_H_

#include "ice_flex_type.h"
#include "ice_acl.h"

#define ICE_IPV4_MAKE_PREFIX_MASK(prefix) ((u32)(~0) << (32 - (prefix)))
#define ICE_FLOW_PROF_ID_INVAL		0xfffffffffffffffful
#define ICE_FLOW_PROF_ID_BYPASS		0
#define ICE_FLOW_PROF_ID_DEFAULT	1
#define ICE_FLOW_ENTRY_HANDLE_INVAL	0
#define ICE_FLOW_VSI_INVAL		0xffff
#define ICE_FLOW_FLD_OFF_INVAL		0xffff

/* Generate flow hash field from flow field type(s) */
#define ICE_FLOW_HASH_ETH	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_ETH_DA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_ETH_SA))
#define ICE_FLOW_HASH_IPV4	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_SA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_IPV4_DA))
#define ICE_FLOW_HASH_IPV6	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_SA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_DA))
#define ICE_FLOW_HASH_IPV6_PRE32	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE32_SA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE32_DA))
#define ICE_FLOW_HASH_IPV6_PRE48	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE48_SA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE48_DA))
#define ICE_FLOW_HASH_IPV6_PRE64	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_SA) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_IPV6_PRE64_DA))
#define ICE_FLOW_HASH_TCP_PORT	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_SRC_PORT) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_TCP_DST_PORT))
#define ICE_FLOW_HASH_UDP_PORT	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_SRC_PORT) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_UDP_DST_PORT))
#define ICE_FLOW_HASH_SCTP_PORT	\
	(BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT) | \
	 BIT_ULL(ICE_FLOW_FIELD_IDX_SCTP_DST_PORT))

#define ICE_HASH_INVALID	0
#define ICE_HASH_TCP_IPV4	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_TCP_PORT)
#define ICE_HASH_TCP_IPV6	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_TCP_PORT)
#define ICE_HASH_UDP_IPV4	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_UDP_PORT)
#define ICE_HASH_UDP_IPV6	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_UDP_PORT)
#define ICE_HASH_SCTP_IPV4	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_SCTP_PORT)
#define ICE_HASH_SCTP_IPV6	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_SCTP_PORT)

#define ICE_HASH_TCP_IPV6_PRE32	 \
	(ICE_FLOW_HASH_IPV6_PRE32 | ICE_FLOW_HASH_TCP_PORT)
#define ICE_HASH_UDP_IPV6_PRE32	 \
	(ICE_FLOW_HASH_IPV6_PRE32 | ICE_FLOW_HASH_UDP_PORT)
#define ICE_HASH_SCTP_IPV6_PRE32 \
	(ICE_FLOW_HASH_IPV6_PRE32 | ICE_FLOW_HASH_SCTP_PORT)
#define ICE_HASH_TCP_IPV6_PRE48	 \
	(ICE_FLOW_HASH_IPV6_PRE48 | ICE_FLOW_HASH_TCP_PORT)
#define ICE_HASH_UDP_IPV6_PRE48	 \
	(ICE_FLOW_HASH_IPV6_PRE48 | ICE_FLOW_HASH_UDP_PORT)
#define ICE_HASH_SCTP_IPV6_PRE48 \
	(ICE_FLOW_HASH_IPV6_PRE48 | ICE_FLOW_HASH_SCTP_PORT)
#define ICE_HASH_TCP_IPV6_PRE64	 \
	(ICE_FLOW_HASH_IPV6_PRE64 | ICE_FLOW_HASH_TCP_PORT)
#define ICE_HASH_UDP_IPV6_PRE64	 \
	(ICE_FLOW_HASH_IPV6_PRE64 | ICE_FLOW_HASH_UDP_PORT)
#define ICE_HASH_SCTP_IPV6_PRE64 \
	(ICE_FLOW_HASH_IPV6_PRE64 | ICE_FLOW_HASH_SCTP_PORT)

#define ICE_FLOW_HASH_VXLAN_VNI \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_VXLAN_VNI))

#define ICE_FLOW_HASH_GTP_TEID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_GTPC_TEID))

#define ICE_FLOW_HASH_GTP_IPV4_TEID \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_GTP_TEID)
#define ICE_FLOW_HASH_GTP_IPV6_TEID \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_GTP_TEID)

#define ICE_FLOW_HASH_GTP_U_TEID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_GTPU_IP_TEID))

#define ICE_FLOW_HASH_GTP_U_IPV4_TEID \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_GTP_U_TEID)
#define ICE_FLOW_HASH_GTP_U_IPV6_TEID \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_GTP_U_TEID)

#define ICE_FLOW_HASH_GTP_U_EH_TEID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_GTPU_EH_TEID))

#define ICE_FLOW_HASH_GTP_U_EH_QFI \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_GTPU_EH_QFI))

#define ICE_FLOW_HASH_GTP_U_IPV4_EH \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_GTP_U_EH_TEID | \
	 ICE_FLOW_HASH_GTP_U_EH_QFI)
#define ICE_FLOW_HASH_GTP_U_IPV6_EH \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_GTP_U_EH_TEID | \
	 ICE_FLOW_HASH_GTP_U_EH_QFI)

#define ICE_FLOW_HASH_PPPOE_SESS_ID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_PPPOE_SESS_ID))

#define ICE_FLOW_HASH_PPPOE_SESS_ID_ETH \
	(ICE_FLOW_HASH_ETH | ICE_FLOW_HASH_PPPOE_SESS_ID)
#define ICE_FLOW_HASH_PPPOE_TCP_ID \
	(ICE_FLOW_HASH_TCP_PORT | ICE_FLOW_HASH_PPPOE_SESS_ID)
#define ICE_FLOW_HASH_PPPOE_UDP_ID \
	(ICE_FLOW_HASH_UDP_PORT | ICE_FLOW_HASH_PPPOE_SESS_ID)

#define ICE_FLOW_HASH_PFCP_SEID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_PFCP_SEID))
#define ICE_FLOW_HASH_PFCP_IPV4_SEID \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_PFCP_SEID)
#define ICE_FLOW_HASH_PFCP_IPV6_SEID \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_PFCP_SEID)

#define ICE_FLOW_HASH_L2TPV3_SESS_ID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV3_SESS_ID))
#define ICE_FLOW_HASH_L2TPV3_IPV4_SESS_ID \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_L2TPV3_SESS_ID)
#define ICE_FLOW_HASH_L2TPV3_IPV6_SESS_ID \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_L2TPV3_SESS_ID)

#define ICE_FLOW_HASH_ESP_SPI \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_ESP_SPI))
#define ICE_FLOW_HASH_ESP_IPV4_SPI \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_ESP_SPI)
#define ICE_FLOW_HASH_ESP_IPV6_SPI \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_ESP_SPI)

#define ICE_FLOW_HASH_AH_SPI \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_AH_SPI))
#define ICE_FLOW_HASH_AH_IPV4_SPI \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_AH_SPI)
#define ICE_FLOW_HASH_AH_IPV6_SPI \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_AH_SPI)

#define ICE_FLOW_HASH_NAT_T_ESP_SPI \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_NAT_T_ESP_SPI))
#define ICE_FLOW_HASH_NAT_T_ESP_IPV4_SPI \
	(ICE_FLOW_HASH_IPV4 | ICE_FLOW_HASH_NAT_T_ESP_SPI)
#define ICE_FLOW_HASH_NAT_T_ESP_IPV6_SPI \
	(ICE_FLOW_HASH_IPV6 | ICE_FLOW_HASH_NAT_T_ESP_SPI)

#define ICE_FLOW_HASH_L2TPV2_SESS_ID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV2_SESS_ID))
#define ICE_FLOW_HASH_L2TPV2_SESS_ID_ETH \
	(ICE_FLOW_HASH_ETH | ICE_FLOW_HASH_L2TPV2_SESS_ID)

#define ICE_FLOW_HASH_L2TPV2_LEN_SESS_ID \
	(BIT_ULL(ICE_FLOW_FIELD_IDX_L2TPV2_LEN_SESS_ID))
#define ICE_FLOW_HASH_L2TPV2_LEN_SESS_ID_ETH \
	(ICE_FLOW_HASH_ETH | ICE_FLOW_HASH_L2TPV2_LEN_SESS_ID)

#define ICE_FLOW_FIELD_IPV4_SRC_OFFSET 12
#define ICE_FLOW_FIELD_IPV4_DST_OFFSET 16
#define ICE_FLOW_FIELD_IPV6_SRC_OFFSET 8
#define ICE_FLOW_FIELD_IPV6_DST_OFFSET 24
#define ICE_FLOW_FIELD_SRC_PORT_OFFSET 0
#define ICE_FLOW_FIELD_DST_PORT_OFFSET 2

/* Protocol header fields within a packet segment. A segment consists of one or
 * more protocol headers that make up a logical group of protocol headers. Each
 * logical group of protocol headers encapsulates or is encapsulated using/by
 * tunneling or encapsulation protocols for network virtualization such as GRE,
 * VxLAN, etc.
 */
enum ice_flow_seg_hdr {
	ICE_FLOW_SEG_HDR_NONE		= 0x00000000,
	ICE_FLOW_SEG_HDR_ETH		= 0x00000001,
	ICE_FLOW_SEG_HDR_VLAN		= 0x00000002,
	ICE_FLOW_SEG_HDR_IPV4		= 0x00000004,
	ICE_FLOW_SEG_HDR_IPV6		= 0x00000008,
	ICE_FLOW_SEG_HDR_ARP		= 0x00000010,
	ICE_FLOW_SEG_HDR_ICMP		= 0x00000020,
	ICE_FLOW_SEG_HDR_TCP		= 0x00000040,
	ICE_FLOW_SEG_HDR_UDP		= 0x00000080,
	ICE_FLOW_SEG_HDR_SCTP		= 0x00000100,
	ICE_FLOW_SEG_HDR_GRE		= 0x00000200,
	ICE_FLOW_SEG_HDR_GTPC		= 0x00000400,
	ICE_FLOW_SEG_HDR_GTPC_TEID	= 0x00000800,
	ICE_FLOW_SEG_HDR_GTPU_IP	= 0x00001000,
	ICE_FLOW_SEG_HDR_GTPU_EH	= 0x00002000,
	ICE_FLOW_SEG_HDR_GTPU_DWN	= 0x00004000,
	ICE_FLOW_SEG_HDR_GTPU_UP	= 0x00008000,
	ICE_FLOW_SEG_HDR_PPPOE		= 0x00010000,
	ICE_FLOW_SEG_HDR_PFCP_NODE	= 0x00020000,
	ICE_FLOW_SEG_HDR_PFCP_SESSION	= 0x00040000,
	ICE_FLOW_SEG_HDR_L2TPV3		= 0x00080000,
	ICE_FLOW_SEG_HDR_ESP		= 0x00100000,
	ICE_FLOW_SEG_HDR_AH		= 0x00200000,
	ICE_FLOW_SEG_HDR_NAT_T_ESP	= 0x00400000,
	ICE_FLOW_SEG_HDR_ETH_NON_IP	= 0x00800000,
	ICE_FLOW_SEG_HDR_GTPU_NON_IP	= 0x01000000,
	ICE_FLOW_SEG_HDR_VXLAN		= 0x02000000,
	ICE_FLOW_SEG_HDR_ECPRI_TP0	= 0x04000000,
	ICE_FLOW_SEG_HDR_UDP_ECPRI_TP0	= 0x08000000,
	ICE_FLOW_SEG_HDR_L2TPV2		= 0x10000000,
	ICE_FLOW_SEG_HDR_PPP		= 0x20000000,
	/* The following is an additive bit for ICE_FLOW_SEG_HDR_IPV4 and
	 * ICE_FLOW_SEG_HDR_IPV6.
	 */
	ICE_FLOW_SEG_HDR_IPV_FRAG	= 0x40000000,
	ICE_FLOW_SEG_HDR_IPV_OTHER	= 0x80000000,
};

/* These segements all have the same PTYPES, but are otherwise distinguished by
 * the value of the gtp_eh_pdu and gtp_eh_pdu_link flags:
 *
 *                                gtp_eh_pdu     gtp_eh_pdu_link
 * ICE_FLOW_SEG_HDR_GTPU_IP           0              0
 * ICE_FLOW_SEG_HDR_GTPU_EH           1              don't care
 * ICE_FLOW_SEG_HDR_GTPU_DWN          1              0
 * ICE_FLOW_SEG_HDR_GTPU_UP           1              1
 */
#define ICE_FLOW_SEG_HDR_GTPU (ICE_FLOW_SEG_HDR_GTPU_IP | \
			       ICE_FLOW_SEG_HDR_GTPU_EH | \
			       ICE_FLOW_SEG_HDR_GTPU_DWN | \
			       ICE_FLOW_SEG_HDR_GTPU_UP)
#define ICE_FLOW_SEG_HDR_PFCP (ICE_FLOW_SEG_HDR_PFCP_NODE | \
			       ICE_FLOW_SEG_HDR_PFCP_SESSION)

enum ice_flow_field {
	/* L2 */
	ICE_FLOW_FIELD_IDX_ETH_DA,
	ICE_FLOW_FIELD_IDX_ETH_SA,
	ICE_FLOW_FIELD_IDX_S_VLAN,
	ICE_FLOW_FIELD_IDX_C_VLAN,
	ICE_FLOW_FIELD_IDX_ETH_TYPE,
	/* L3 */
	ICE_FLOW_FIELD_IDX_IPV4_DSCP,
	ICE_FLOW_FIELD_IDX_IPV6_DSCP,
	ICE_FLOW_FIELD_IDX_IPV4_TTL,
	ICE_FLOW_FIELD_IDX_IPV4_PROT,
	ICE_FLOW_FIELD_IDX_IPV6_TTL,
	ICE_FLOW_FIELD_IDX_IPV6_PROT,
	ICE_FLOW_FIELD_IDX_IPV4_SA,
	ICE_FLOW_FIELD_IDX_IPV4_DA,
	ICE_FLOW_FIELD_IDX_IPV6_SA,
	ICE_FLOW_FIELD_IDX_IPV6_DA,
	ICE_FLOW_FIELD_IDX_IPV4_CHKSUM,
	ICE_FLOW_FIELD_IDX_IPV4_ID,
	ICE_FLOW_FIELD_IDX_IPV6_ID,
	ICE_FLOW_FIELD_IDX_IPV6_PRE32_SA,
	ICE_FLOW_FIELD_IDX_IPV6_PRE32_DA,
	ICE_FLOW_FIELD_IDX_IPV6_PRE48_SA,
	ICE_FLOW_FIELD_IDX_IPV6_PRE48_DA,
	ICE_FLOW_FIELD_IDX_IPV6_PRE64_SA,
	ICE_FLOW_FIELD_IDX_IPV6_PRE64_DA,
	/* L4 */
	ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
	ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
	ICE_FLOW_FIELD_IDX_SCTP_SRC_PORT,
	ICE_FLOW_FIELD_IDX_SCTP_DST_PORT,
	ICE_FLOW_FIELD_IDX_TCP_FLAGS,
	ICE_FLOW_FIELD_IDX_TCP_CHKSUM,
	ICE_FLOW_FIELD_IDX_UDP_CHKSUM,
	ICE_FLOW_FIELD_IDX_SCTP_CHKSUM,
	/* ARP */
	ICE_FLOW_FIELD_IDX_ARP_SIP,
	ICE_FLOW_FIELD_IDX_ARP_DIP,
	ICE_FLOW_FIELD_IDX_ARP_SHA,
	ICE_FLOW_FIELD_IDX_ARP_DHA,
	ICE_FLOW_FIELD_IDX_ARP_OP,
	/* ICMP */
	ICE_FLOW_FIELD_IDX_ICMP_TYPE,
	ICE_FLOW_FIELD_IDX_ICMP_CODE,
	/* GRE */
	ICE_FLOW_FIELD_IDX_GRE_KEYID,
	/* GTPC_TEID */
	ICE_FLOW_FIELD_IDX_GTPC_TEID,
	/* GTPU_IP */
	ICE_FLOW_FIELD_IDX_GTPU_IP_TEID,
	/* GTPU_EH */
	ICE_FLOW_FIELD_IDX_GTPU_EH_TEID,
	ICE_FLOW_FIELD_IDX_GTPU_EH_QFI,
	/* GTPU_UP */
	ICE_FLOW_FIELD_IDX_GTPU_UP_TEID,
	ICE_FLOW_FIELD_IDX_GTPU_UP_QFI,
	/* GTPU_DWN */
	ICE_FLOW_FIELD_IDX_GTPU_DWN_TEID,
	ICE_FLOW_FIELD_IDX_GTPU_DWN_QFI,
	/* PPPOE */
	ICE_FLOW_FIELD_IDX_PPPOE_SESS_ID,
	/* PFCP */
	ICE_FLOW_FIELD_IDX_PFCP_SEID,
	/* L2TPV3 */
	ICE_FLOW_FIELD_IDX_L2TPV3_SESS_ID,
	/* ESP */
	ICE_FLOW_FIELD_IDX_ESP_SPI,
	/* AH */
	ICE_FLOW_FIELD_IDX_AH_SPI,
	/* NAT_T ESP */
	ICE_FLOW_FIELD_IDX_NAT_T_ESP_SPI,
	/* VXLAN VNI */
	ICE_FLOW_FIELD_IDX_VXLAN_VNI,
	/* ECPRI_TP0 */
	ICE_FLOW_FIELD_IDX_ECPRI_TP0_PC_ID,
	/* UDP_ECPRI_TP0 */
	ICE_FLOW_FIELD_IDX_UDP_ECPRI_TP0_PC_ID,
	/* L2TPV2 SESSION ID*/
	ICE_FLOW_FIELD_IDX_L2TPV2_SESS_ID,
	/* L2TPV2_LEN SESSION ID */
	ICE_FLOW_FIELD_IDX_L2TPV2_LEN_SESS_ID,
	 /* The total number of enums must not exceed 64 */
	ICE_FLOW_FIELD_IDX_MAX
};

/* Flow headers and fields for AVF support */
enum ice_flow_avf_hdr_field {
	/* Values 0 - 28 are reserved for future use */
	ICE_AVF_FLOW_FIELD_INVALID		= 0,
	ICE_AVF_FLOW_FIELD_UNICAST_IPV4_UDP	= 29,
	ICE_AVF_FLOW_FIELD_MULTICAST_IPV4_UDP,
	ICE_AVF_FLOW_FIELD_IPV4_UDP,
	ICE_AVF_FLOW_FIELD_IPV4_TCP_SYN_NO_ACK,
	ICE_AVF_FLOW_FIELD_IPV4_TCP,
	ICE_AVF_FLOW_FIELD_IPV4_SCTP,
	ICE_AVF_FLOW_FIELD_IPV4_OTHER,
	ICE_AVF_FLOW_FIELD_FRAG_IPV4,
	/* Values 37-38 are reserved */
	ICE_AVF_FLOW_FIELD_UNICAST_IPV6_UDP	= 39,
	ICE_AVF_FLOW_FIELD_MULTICAST_IPV6_UDP,
	ICE_AVF_FLOW_FIELD_IPV6_UDP,
	ICE_AVF_FLOW_FIELD_IPV6_TCP_SYN_NO_ACK,
	ICE_AVF_FLOW_FIELD_IPV6_TCP,
	ICE_AVF_FLOW_FIELD_IPV6_SCTP,
	ICE_AVF_FLOW_FIELD_IPV6_OTHER,
	ICE_AVF_FLOW_FIELD_FRAG_IPV6,
	ICE_AVF_FLOW_FIELD_RSVD47,
	ICE_AVF_FLOW_FIELD_FCOE_OX,
	ICE_AVF_FLOW_FIELD_FCOE_RX,
	ICE_AVF_FLOW_FIELD_FCOE_OTHER,
	/* Values 51-62 are reserved */
	ICE_AVF_FLOW_FIELD_L2_PAYLOAD		= 63,
	ICE_AVF_FLOW_FIELD_MAX
};

/* Supported RSS offloads  This macro is defined to support
 * VIRTCHNL_OP_GET_RSS_HENA_CAPS ops. PF driver sends the RSS hardware
 * capabilities to the caller of this ops.
 */
#define ICE_DEFAULT_RSS_HENA ( \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_UDP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_SCTP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_TCP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_OTHER) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_FRAG_IPV4) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_UDP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_TCP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_SCTP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_OTHER) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_FRAG_IPV6) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV4_TCP_SYN_NO_ACK) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_UNICAST_IPV4_UDP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_MULTICAST_IPV4_UDP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_IPV6_TCP_SYN_NO_ACK) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_UNICAST_IPV6_UDP) | \
	BIT_ULL(ICE_AVF_FLOW_FIELD_MULTICAST_IPV6_UDP))

enum ice_rss_cfg_hdr_type {
	ICE_RSS_OUTER_HEADERS, /* take outer headers as inputset. */
	ICE_RSS_INNER_HEADERS, /* take inner headers as inputset. */
	/* take inner headers as inputset for packet with outer ipv4. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV4,
	/* take inner headers as inputset for packet with outer ipv6. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV6,
	/* take outer headers first then inner headers as inputset */
	/* take inner as inputset for GTPoGRE with outer ipv4 + gre. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV4_GRE,
	/* take inner as inputset for GTPoGRE with outer ipv6 + gre. */
	ICE_RSS_INNER_HEADERS_W_OUTER_IPV6_GRE,
	ICE_RSS_ANY_HEADERS
};

struct ice_rss_hash_cfg {
	u32 addl_hdrs; /* protocol header fields */
	u64 hash_flds; /* hash bit field (ICE_FLOW_HASH_*) to configure */
	enum ice_rss_cfg_hdr_type hdr_type; /* to specify inner or outer */
	bool symm; /* symmetric or asymmetric hash */
};

enum ice_flow_dir {
	ICE_FLOW_DIR_UNDEFINED	= 0,
	ICE_FLOW_TX		= 0x01,
	ICE_FLOW_RX		= 0x02,
	ICE_FLOW_TX_RX		= ICE_FLOW_RX | ICE_FLOW_TX
};

enum ice_flow_priority {
	ICE_FLOW_PRIO_LOW,
	ICE_FLOW_PRIO_NORMAL,
	ICE_FLOW_PRIO_HIGH
};

#define ICE_FLOW_SEG_SINGLE		1
#define ICE_FLOW_SEG_MAX		2
#define ICE_FLOW_SEG_RAW_FLD_MAX	2
#define ICE_FLOW_PROFILE_MAX		1024
#define ICE_FLOW_SW_FIELD_VECTOR_MAX	48
#define ICE_FLOW_ACL_FIELD_VECTOR_MAX	32
#define ICE_FLOW_FV_EXTRACT_SZ		2

#define ICE_FLOW_SET_HDRS(seg, val)	((seg)->hdrs |= (u32)(val))

struct ice_flow_seg_xtrct {
	u8 prot_id;	/* Protocol ID of extracted header field */
	u16 off;	/* Starting offset of the field in header in bytes */
	u8 idx;		/* Index of FV entry used */
	u8 disp;	/* Displacement of field in bits fr. FV entry's start */
	u16 mask;	/* Mask for field */
};

enum ice_flow_fld_match_type {
	ICE_FLOW_FLD_TYPE_REG,		/* Value, mask */
	ICE_FLOW_FLD_TYPE_RANGE,	/* Value, mask, last (upper bound) */
	ICE_FLOW_FLD_TYPE_PREFIX,	/* IP address, prefix, size of prefix */
	ICE_FLOW_FLD_TYPE_SIZE,		/* Value, mask, size of match */
};

struct ice_flow_fld_loc {
	/* Describe offsets of field information relative to the beginning of
	 * input buffer provided when adding flow entries.
	 */
	u16 val;	/* Offset where the value is located */
	u16 mask;	/* Offset where the mask/prefix value is located */
	u16 last;	/* Length or offset where the upper value is located */
};

struct ice_flow_fld_info {
	enum ice_flow_fld_match_type type;
	/* Location where to retrieve data from an input buffer */
	struct ice_flow_fld_loc src;
	/* Location where to put the data into the final entry buffer */
	struct ice_flow_fld_loc entry;
	struct ice_flow_seg_xtrct xtrct;
};

struct ice_flow_seg_fld_raw {
	struct ice_flow_fld_info info;
	u16 off;	/* Offset from the start of the segment */
};

struct ice_flow_seg_info {
	u32 hdrs;	/* Bitmask indicating protocol headers present */
	u64 match;	/* Bitmask indicating header fields to be matched */
	u64 range;	/* Bitmask indicating header fields matched as ranges */

	struct ice_flow_fld_info fields[ICE_FLOW_FIELD_IDX_MAX];

	u8 raws_cnt;	/* Number of raw fields to be matched */
	struct ice_flow_seg_fld_raw raws[ICE_FLOW_SEG_RAW_FLD_MAX];
};

/* This structure describes a flow entry, and is tracked only in this file */
struct ice_flow_entry {
	struct LIST_ENTRY_TYPE l_entry;

	u64 id;
	struct ice_flow_prof *prof;
	/* Action list */
	struct ice_flow_action *acts;
	/* Flow entry's content */
	void *entry;
	/* Range buffer (For ACL only) */
	struct ice_aqc_acl_profile_ranges *range_buf;
	enum ice_flow_priority priority;
	u16 vsi_handle;
	u16 entry_sz;
	/* Entry index in the ACL's scenario */
	u16 scen_entry_idx;
#define ICE_FLOW_ACL_MAX_NUM_ACT	2
	u8 acts_cnt;
};

#define ICE_FLOW_ENTRY_HNDL(e)	((intptr_t)e)
#define ICE_FLOW_ENTRY_PTR(h)	((struct ice_flow_entry *)(h))

struct ice_flow_prof {
	struct LIST_ENTRY_TYPE l_entry;

	u64 id;
	enum ice_flow_dir dir;
	u8 segs_cnt;
	u8 acts_cnt;

	/* Keep track of flow entries associated with this flow profile */
	struct ice_lock entries_lock;
	struct LIST_HEAD_TYPE entries;

	struct ice_flow_seg_info segs[ICE_FLOW_SEG_MAX];

	/* software VSI handles referenced by this flow profile */
	ice_declare_bitmap(vsis, ICE_MAX_VSI);

	union {
		/* struct sw_recipe */
		struct ice_acl_scen *scen;
		/* struct fd */
		u32 data;
		bool symm; /* Symmetric Hash for RSS */
	} cfg;

	/* Default actions */
	struct ice_flow_action *acts;
};

struct ice_rss_raw_cfg {
	struct ice_parser_profile prof;
	bool raw_ena;
	bool symm;
};

struct ice_rss_cfg {
	struct LIST_ENTRY_TYPE l_entry;
	/* bitmap of VSIs added to the RSS entry */
	ice_declare_bitmap(vsis, ICE_MAX_VSI);
	struct ice_rss_hash_cfg hash;
	struct ice_rss_raw_cfg raw;
};

enum ice_flow_action_type {
	ICE_FLOW_ACT_NOP,
	ICE_FLOW_ACT_ALLOW,
	ICE_FLOW_ACT_DROP,
	ICE_FLOW_ACT_CNTR_PKT,
	ICE_FLOW_ACT_FWD_VSI,
	ICE_FLOW_ACT_FWD_VSI_LIST,	/* Should be abstracted away */
	ICE_FLOW_ACT_FWD_QUEUE,		/* Can Queues be abstracted away? */
	ICE_FLOW_ACT_FWD_QUEUE_GROUP,	/* Can Queues be abstracted away? */
	ICE_FLOW_ACT_PUSH,
	ICE_FLOW_ACT_POP,
	ICE_FLOW_ACT_MODIFY,
	ICE_FLOW_ACT_CNTR_BYTES,
	ICE_FLOW_ACT_CNTR_PKT_BYTES,
	ICE_FLOW_ACT_GENERIC_0,
	ICE_FLOW_ACT_GENERIC_1,
	ICE_FLOW_ACT_GENERIC_2,
	ICE_FLOW_ACT_GENERIC_3,
	ICE_FLOW_ACT_GENERIC_4,
	ICE_FLOW_ACT_RPT_FLOW_ID,
	ICE_FLOW_ACT_BUILD_PROF_IDX,
};

struct ice_flow_action {
	enum ice_flow_action_type type;
	union {
		struct ice_acl_act_entry acl_act;
		u32 dummy;
	} data;
};

u64
ice_flow_find_prof(struct ice_hw *hw, enum ice_block blk, enum ice_flow_dir dir,
		   struct ice_flow_seg_info *segs, u8 segs_cnt);
enum ice_status
ice_flow_add_prof(struct ice_hw *hw, enum ice_block blk, enum ice_flow_dir dir,
		  u64 prof_id, struct ice_flow_seg_info *segs, u8 segs_cnt,
		  struct ice_flow_action *acts, u8 acts_cnt,
		  struct ice_flow_prof **prof);
enum ice_status
ice_flow_rem_prof(struct ice_hw *hw, enum ice_block blk, u64 prof_id);
enum ice_status
ice_flow_assoc_prof(struct ice_hw *hw, enum ice_block blk,
		    struct ice_flow_prof *prof, u16 vsi_handle);
enum ice_status
ice_flow_assoc_vsig_vsi(struct ice_hw *hw, enum ice_block blk, u16 vsi_handle,
			u16 vsig);
enum ice_status
ice_flow_set_hw_prof(struct ice_hw *hw, u16 dest_vsi_handle,
		     u16 fdir_vsi_handle, struct ice_parser_profile *prof,
		     enum ice_block blk);
enum ice_status
ice_flow_get_hw_prof(struct ice_hw *hw, enum ice_block blk, u64 prof_id,
		     u8 *hw_prof);

u64 ice_flow_find_entry(struct ice_hw *hw, enum ice_block blk, u64 entry_id);
enum ice_status
ice_flow_add_entry(struct ice_hw *hw, enum ice_block blk, u64 prof_id,
		   u64 entry_id, u16 vsi, enum ice_flow_priority prio,
		   void *data, struct ice_flow_action *acts, u8 acts_cnt,
		   u64 *entry_h);
enum ice_status
ice_flow_rem_entry(struct ice_hw *hw, enum ice_block blk, u64 entry_h);
void
ice_flow_set_fld(struct ice_flow_seg_info *seg, enum ice_flow_field fld,
		 u16 val_loc, u16 mask_loc, u16 last_loc, bool range);
void
ice_flow_set_fld_prefix(struct ice_flow_seg_info *seg, enum ice_flow_field fld,
			u16 val_loc, u16 prefix_loc, u8 prefix_sz);
void
ice_flow_add_fld_raw(struct ice_flow_seg_info *seg, u16 off, u8 len,
		     u16 val_loc, u16 mask_loc);
enum ice_status ice_flow_rem_vsi_prof(struct ice_hw *hw, enum ice_block blk,
				      u16 vsi_handle, u64 prof_id);
void ice_rem_vsi_rss_list(struct ice_hw *hw, u16 vsi_handle);
enum ice_status ice_replay_rss_cfg(struct ice_hw *hw, u16 vsi_handle);
enum ice_status
ice_add_avf_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u64 hashed_flds);
enum ice_status ice_rem_vsi_rss_cfg(struct ice_hw *hw, u16 vsi_handle);
enum ice_status
ice_add_rss_cfg(struct ice_hw *hw, u16 vsi_handle,
		const struct ice_rss_hash_cfg *cfg);
enum ice_status
ice_rem_rss_cfg(struct ice_hw *hw, u16 vsi_handle,
		const struct ice_rss_hash_cfg *cfg);
void ice_rss_update_raw_symm(struct ice_hw *hw,
			     struct ice_rss_raw_cfg *cfg, u64 id);
u64 ice_get_rss_cfg(struct ice_hw *hw, u16 vsi_handle, u32 hdrs);
#endif /* _ICE_FLOW_H_ */
