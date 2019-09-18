/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation.
 * Copyright 2014 6WIND S.A.
 */

#ifndef _RTE_MBUF_H_
#define _RTE_MBUF_H_

/**
 * @file
 * RTE Mbuf
 *
 * The mbuf library provides the ability to create and destroy buffers
 * that may be used by the RTE application to store message
 * buffers. The message buffers are stored in a mempool, using the
 * RTE mempool library.
 *
 * The preferred way to create a mbuf pool is to use
 * rte_pktmbuf_pool_create(). However, in some situations, an
 * application may want to have more control (ex: populate the pool with
 * specific memory), in this case it is possible to use functions from
 * rte_mempool. See how rte_pktmbuf_pool_create() is implemented for
 * details.
 *
 * This library provides an API to allocate/free packet mbufs, which are
 * used to carry network packets.
 *
 * To understand the concepts of packet buffers or mbufs, you
 * should read "TCP/IP Illustrated, Volume 2: The Implementation,
 * Addison-Wesley, 1995, ISBN 0-201-63354-X from Richard Stevens"
 * http://www.kohala.com/start/tcpipiv2.html
 */

#include <stdint.h>
#include <rte_compat.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_mempool.h>
#include <rte_memory.h>
#include <rte_atomic.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf_ptype.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Packet Offload Features Flags. It also carry packet type information.
 * Critical resources. Both rx/tx shared these bits. Be cautious on any change
 *
 * - RX flags start at bit position zero, and get added to the left of previous
 *   flags.
 * - The most-significant 3 bits are reserved for generic mbuf flags
 * - TX flags therefore start at bit position 60 (i.e. 63-3), and new flags get
 *   added to the right of the previously defined flags i.e. they should count
 *   downwards, not upwards.
 *
 * Keep these flags synchronized with rte_get_rx_ol_flag_name() and
 * rte_get_tx_ol_flag_name().
 */

/**
 * The RX packet is a 802.1q VLAN packet, and the tci has been
 * saved in in mbuf->vlan_tci.
 * If the flag PKT_RX_VLAN_STRIPPED is also present, the VLAN
 * header has been stripped from mbuf data, else it is still
 * present.
 */
#define PKT_RX_VLAN          (1ULL << 0)

#define PKT_RX_RSS_HASH      (1ULL << 1)  /**< RX packet with RSS hash result. */
#define PKT_RX_FDIR          (1ULL << 2)  /**< RX packet with FDIR match indicate. */

/**
 * Deprecated.
 * Checking this flag alone is deprecated: check the 2 bits of
 * PKT_RX_L4_CKSUM_MASK.
 * This flag was set when the L4 checksum of a packet was detected as
 * wrong by the hardware.
 */
#define PKT_RX_L4_CKSUM_BAD  (1ULL << 3)

/**
 * Deprecated.
 * Checking this flag alone is deprecated: check the 2 bits of
 * PKT_RX_IP_CKSUM_MASK.
 * This flag was set when the IP checksum of a packet was detected as
 * wrong by the hardware.
 */
#define PKT_RX_IP_CKSUM_BAD  (1ULL << 4)

#define PKT_RX_EIP_CKSUM_BAD (1ULL << 5)  /**< External IP header checksum error. */

/**
 * A vlan has been stripped by the hardware and its tci is saved in
 * mbuf->vlan_tci. This can only happen if vlan stripping is enabled
 * in the RX configuration of the PMD.
 * When PKT_RX_VLAN_STRIPPED is set, PKT_RX_VLAN must also be set.
 */
#define PKT_RX_VLAN_STRIPPED (1ULL << 6)

/**
 * Mask of bits used to determine the status of RX IP checksum.
 * - PKT_RX_IP_CKSUM_UNKNOWN: no information about the RX IP checksum
 * - PKT_RX_IP_CKSUM_BAD: the IP checksum in the packet is wrong
 * - PKT_RX_IP_CKSUM_GOOD: the IP checksum in the packet is valid
 * - PKT_RX_IP_CKSUM_NONE: the IP checksum is not correct in the packet
 *   data, but the integrity of the IP header is verified.
 */
#define PKT_RX_IP_CKSUM_MASK ((1ULL << 4) | (1ULL << 7))

#define PKT_RX_IP_CKSUM_UNKNOWN 0
#define PKT_RX_IP_CKSUM_BAD     (1ULL << 4)
#define PKT_RX_IP_CKSUM_GOOD    (1ULL << 7)
#define PKT_RX_IP_CKSUM_NONE    ((1ULL << 4) | (1ULL << 7))

/**
 * Mask of bits used to determine the status of RX L4 checksum.
 * - PKT_RX_L4_CKSUM_UNKNOWN: no information about the RX L4 checksum
 * - PKT_RX_L4_CKSUM_BAD: the L4 checksum in the packet is wrong
 * - PKT_RX_L4_CKSUM_GOOD: the L4 checksum in the packet is valid
 * - PKT_RX_L4_CKSUM_NONE: the L4 checksum is not correct in the packet
 *   data, but the integrity of the L4 data is verified.
 */
#define PKT_RX_L4_CKSUM_MASK ((1ULL << 3) | (1ULL << 8))

#define PKT_RX_L4_CKSUM_UNKNOWN 0
#define PKT_RX_L4_CKSUM_BAD     (1ULL << 3)
#define PKT_RX_L4_CKSUM_GOOD    (1ULL << 8)
#define PKT_RX_L4_CKSUM_NONE    ((1ULL << 3) | (1ULL << 8))

#define PKT_RX_IEEE1588_PTP  (1ULL << 9)  /**< RX IEEE1588 L2 Ethernet PT Packet. */
#define PKT_RX_IEEE1588_TMST (1ULL << 10) /**< RX IEEE1588 L2/L4 timestamped packet.*/
#define PKT_RX_FDIR_ID       (1ULL << 13) /**< FD id reported if FDIR match. */
#define PKT_RX_FDIR_FLX      (1ULL << 14) /**< Flexible bytes reported if FDIR match. */

/**
 * The 2 vlans have been stripped by the hardware and their tci are
 * saved in mbuf->vlan_tci (inner) and mbuf->vlan_tci_outer (outer).
 * This can only happen if vlan stripping is enabled in the RX
 * configuration of the PMD.
 * When PKT_RX_QINQ_STRIPPED is set, the flags (PKT_RX_VLAN |
 * PKT_RX_VLAN_STRIPPED | PKT_RX_QINQ) must also be set.
 */
#define PKT_RX_QINQ_STRIPPED (1ULL << 15)

/**
 * When packets are coalesced by a hardware or virtual driver, this flag
 * can be set in the RX mbuf, meaning that the m->tso_segsz field is
 * valid and is set to the segment size of original packets.
 */
#define PKT_RX_LRO           (1ULL << 16)

/**
 * Indicate that the timestamp field in the mbuf is valid.
 */
#define PKT_RX_TIMESTAMP     (1ULL << 17)

/**
 * Indicate that security offload processing was applied on the RX packet.
 */
#define PKT_RX_SEC_OFFLOAD		(1ULL << 18)

/**
 * Indicate that security offload processing failed on the RX packet.
 */
#define PKT_RX_SEC_OFFLOAD_FAILED  	(1ULL << 19)

/**
 * The RX packet is a double VLAN, and the outer tci has been
 * saved in in mbuf->vlan_tci_outer. If PKT_RX_QINQ set, PKT_RX_VLAN
 * also should be set and inner tci should be saved to mbuf->vlan_tci.
 * If the flag PKT_RX_QINQ_STRIPPED is also present, both VLANs
 * headers have been stripped from mbuf data, else they are still
 * present.
 */
#define PKT_RX_QINQ          (1ULL << 20)

/**
 * Mask of bits used to determine the status of outer RX L4 checksum.
 * - PKT_RX_OUTER_L4_CKSUM_UNKNOWN: no info about the outer RX L4 checksum
 * - PKT_RX_OUTER_L4_CKSUM_BAD: the outer L4 checksum in the packet is wrong
 * - PKT_RX_OUTER_L4_CKSUM_GOOD: the outer L4 checksum in the packet is valid
 * - PKT_RX_OUTER_L4_CKSUM_INVALID: invalid outer L4 checksum state.
 *
 * The detection of PKT_RX_OUTER_L4_CKSUM_GOOD shall be based on the given
 * HW capability, At minimum, the PMD should support
 * PKT_RX_OUTER_L4_CKSUM_UNKNOWN and PKT_RX_OUTER_L4_CKSUM_BAD states
 * if the DEV_RX_OFFLOAD_OUTER_UDP_CKSUM offload is available.
 */
#define PKT_RX_OUTER_L4_CKSUM_MASK	((1ULL << 21) | (1ULL << 22))

#define PKT_RX_OUTER_L4_CKSUM_UNKNOWN	0
#define PKT_RX_OUTER_L4_CKSUM_BAD	(1ULL << 21)
#define PKT_RX_OUTER_L4_CKSUM_GOOD	(1ULL << 22)
#define PKT_RX_OUTER_L4_CKSUM_INVALID	((1ULL << 21) | (1ULL << 22))

/* add new RX flags here */

/* add new TX flags here */

/**
 * Indicate that the metadata field in the mbuf is in use.
 */
#define PKT_TX_METADATA	(1ULL << 40)

/**
 * Outer UDP checksum offload flag. This flag is used for enabling
 * outer UDP checksum in PMD. To use outer UDP checksum, the user needs to
 * 1) Enable the following in mbuf,
 * a) Fill outer_l2_len and outer_l3_len in mbuf.
 * b) Set the PKT_TX_OUTER_UDP_CKSUM flag.
 * c) Set the PKT_TX_OUTER_IPV4 or PKT_TX_OUTER_IPV6 flag.
 * 2) Configure DEV_TX_OFFLOAD_OUTER_UDP_CKSUM offload flag.
 */
#define PKT_TX_OUTER_UDP_CKSUM     (1ULL << 41)

/**
 * UDP Fragmentation Offload flag. This flag is used for enabling UDP
 * fragmentation in SW or in HW. When use UFO, mbuf->tso_segsz is used
 * to store the MSS of UDP fragments.
 */
#define PKT_TX_UDP_SEG	(1ULL << 42)

/**
 * Request security offload processing on the TX packet.
 */
#define PKT_TX_SEC_OFFLOAD 		(1ULL << 43)

/**
 * Offload the MACsec. This flag must be set by the application to enable
 * this offload feature for a packet to be transmitted.
 */
#define PKT_TX_MACSEC        (1ULL << 44)

/**
 * Bits 45:48 used for the tunnel type.
 * The tunnel type must be specified for TSO or checksum on the inner part
 * of tunnel packets.
 * These flags can be used with PKT_TX_TCP_SEG for TSO, or PKT_TX_xxx_CKSUM.
 * The mbuf fields for inner and outer header lengths are required:
 * outer_l2_len, outer_l3_len, l2_len, l3_len, l4_len and tso_segsz for TSO.
 */
#define PKT_TX_TUNNEL_VXLAN   (0x1ULL << 45)
#define PKT_TX_TUNNEL_GRE     (0x2ULL << 45)
#define PKT_TX_TUNNEL_IPIP    (0x3ULL << 45)
#define PKT_TX_TUNNEL_GENEVE  (0x4ULL << 45)
/** TX packet with MPLS-in-UDP RFC 7510 header. */
#define PKT_TX_TUNNEL_MPLSINUDP (0x5ULL << 45)
#define PKT_TX_TUNNEL_VXLAN_GPE (0x6ULL << 45)
/**
 * Generic IP encapsulated tunnel type, used for TSO and checksum offload.
 * It can be used for tunnels which are not standards or listed above.
 * It is preferred to use specific tunnel flags like PKT_TX_TUNNEL_GRE
 * or PKT_TX_TUNNEL_IPIP if possible.
 * The ethdev must be configured with DEV_TX_OFFLOAD_IP_TNL_TSO.
 * Outer and inner checksums are done according to the existing flags like
 * PKT_TX_xxx_CKSUM.
 * Specific tunnel headers that contain payload length, sequence id
 * or checksum are not expected to be updated.
 */
#define PKT_TX_TUNNEL_IP (0xDULL << 45)
/**
 * Generic UDP encapsulated tunnel type, used for TSO and checksum offload.
 * UDP tunnel type implies outer IP layer.
 * It can be used for tunnels which are not standards or listed above.
 * It is preferred to use specific tunnel flags like PKT_TX_TUNNEL_VXLAN
 * if possible.
 * The ethdev must be configured with DEV_TX_OFFLOAD_UDP_TNL_TSO.
 * Outer and inner checksums are done according to the existing flags like
 * PKT_TX_xxx_CKSUM.
 * Specific tunnel headers that contain payload length, sequence id
 * or checksum are not expected to be updated.
 */
#define PKT_TX_TUNNEL_UDP (0xEULL << 45)
/* add new TX TUNNEL type here */
#define PKT_TX_TUNNEL_MASK    (0xFULL << 45)

/**
 * Double VLAN insertion (QinQ) request to driver, driver may offload the
 * insertion based on device capability.
 * mbuf 'vlan_tci' & 'vlan_tci_outer' must be valid when this flag is set.
 */
#define PKT_TX_QINQ        (1ULL << 49)
/* this old name is deprecated */
#define PKT_TX_QINQ_PKT    PKT_TX_QINQ

/**
 * TCP segmentation offload. To enable this offload feature for a
 * packet to be transmitted on hardware supporting TSO:
 *  - set the PKT_TX_TCP_SEG flag in mbuf->ol_flags (this flag implies
 *    PKT_TX_TCP_CKSUM)
 *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
 *  - if it's IPv4, set the PKT_TX_IP_CKSUM flag
 *  - fill the mbuf offload information: l2_len, l3_len, l4_len, tso_segsz
 */
#define PKT_TX_TCP_SEG       (1ULL << 50)

#define PKT_TX_IEEE1588_TMST (1ULL << 51) /**< TX IEEE1588 packet to timestamp. */

/**
 * Bits 52+53 used for L4 packet type with checksum enabled: 00: Reserved,
 * 01: TCP checksum, 10: SCTP checksum, 11: UDP checksum. To use hardware
 * L4 checksum offload, the user needs to:
 *  - fill l2_len and l3_len in mbuf
 *  - set the flags PKT_TX_TCP_CKSUM, PKT_TX_SCTP_CKSUM or PKT_TX_UDP_CKSUM
 *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
 */
#define PKT_TX_L4_NO_CKSUM   (0ULL << 52) /**< Disable L4 cksum of TX pkt. */
#define PKT_TX_TCP_CKSUM     (1ULL << 52) /**< TCP cksum of TX pkt. computed by NIC. */
#define PKT_TX_SCTP_CKSUM    (2ULL << 52) /**< SCTP cksum of TX pkt. computed by NIC. */
#define PKT_TX_UDP_CKSUM     (3ULL << 52) /**< UDP cksum of TX pkt. computed by NIC. */
#define PKT_TX_L4_MASK       (3ULL << 52) /**< Mask for L4 cksum offload request. */

/**
 * Offload the IP checksum in the hardware. The flag PKT_TX_IPV4 should
 * also be set by the application, although a PMD will only check
 * PKT_TX_IP_CKSUM.
 *  - fill the mbuf offload information: l2_len, l3_len
 */
#define PKT_TX_IP_CKSUM      (1ULL << 54)

/**
 * Packet is IPv4. This flag must be set when using any offload feature
 * (TSO, L3 or L4 checksum) to tell the NIC that the packet is an IPv4
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define PKT_TX_IPV4          (1ULL << 55)

/**
 * Packet is IPv6. This flag must be set when using an offload feature
 * (TSO or L4 checksum) to tell the NIC that the packet is an IPv6
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define PKT_TX_IPV6          (1ULL << 56)

/**
 * VLAN tag insertion request to driver, driver may offload the insertion
 * based on the device capability.
 * mbuf 'vlan_tci' field must be valid when this flag is set.
 */
#define PKT_TX_VLAN          (1ULL << 57)
/* this old name is deprecated */
#define PKT_TX_VLAN_PKT      PKT_TX_VLAN

/**
 * Offload the IP checksum of an external header in the hardware. The
 * flag PKT_TX_OUTER_IPV4 should also be set by the application, although
 * a PMD will only check PKT_TX_OUTER_IP_CKSUM.
 *  - fill the mbuf offload information: outer_l2_len, outer_l3_len
 */
#define PKT_TX_OUTER_IP_CKSUM   (1ULL << 58)

/**
 * Packet outer header is IPv4. This flag must be set when using any
 * outer offload feature (L3 or L4 checksum) to tell the NIC that the
 * outer header of the tunneled packet is an IPv4 packet.
 */
#define PKT_TX_OUTER_IPV4   (1ULL << 59)

/**
 * Packet outer header is IPv6. This flag must be set when using any
 * outer offload feature (L4 checksum) to tell the NIC that the outer
 * header of the tunneled packet is an IPv6 packet.
 */
#define PKT_TX_OUTER_IPV6    (1ULL << 60)

/**
 * Bitmask of all supported packet Tx offload features flags,
 * which can be set for packet.
 */
#define PKT_TX_OFFLOAD_MASK (    \
		PKT_TX_OUTER_IPV6 |	 \
		PKT_TX_OUTER_IPV4 |	 \
		PKT_TX_OUTER_IP_CKSUM |  \
		PKT_TX_VLAN_PKT |        \
		PKT_TX_IPV6 |		 \
		PKT_TX_IPV4 |		 \
		PKT_TX_IP_CKSUM |        \
		PKT_TX_L4_MASK |         \
		PKT_TX_IEEE1588_TMST |	 \
		PKT_TX_TCP_SEG |         \
		PKT_TX_QINQ_PKT |        \
		PKT_TX_TUNNEL_MASK |	 \
		PKT_TX_MACSEC |		 \
		PKT_TX_SEC_OFFLOAD |	 \
		PKT_TX_UDP_SEG |	 \
		PKT_TX_OUTER_UDP_CKSUM | \
		PKT_TX_METADATA)

/**
 * Mbuf having an external buffer attached. shinfo in mbuf must be filled.
 */
#define EXT_ATTACHED_MBUF    (1ULL << 61)

#define IND_ATTACHED_MBUF    (1ULL << 62) /**< Indirect attached mbuf */

/** Alignment constraint of mbuf private area. */
#define RTE_MBUF_PRIV_ALIGN 8

/**
 * Get the name of a RX offload flag
 *
 * @param mask
 *   The mask describing the flag.
 * @return
 *   The name of this flag, or NULL if it's not a valid RX flag.
 */
const char *rte_get_rx_ol_flag_name(uint64_t mask);

/**
 * Dump the list of RX offload flags in a buffer
 *
 * @param mask
 *   The mask describing the RX flags.
 * @param buf
 *   The output buffer.
 * @param buflen
 *   The length of the buffer.
 * @return
 *   0 on success, (-1) on error.
 */
int rte_get_rx_ol_flag_list(uint64_t mask, char *buf, size_t buflen);

/**
 * Get the name of a TX offload flag
 *
 * @param mask
 *   The mask describing the flag. Usually only one bit must be set.
 *   Several bits can be given if they belong to the same mask.
 *   Ex: PKT_TX_L4_MASK.
 * @return
 *   The name of this flag, or NULL if it's not a valid TX flag.
 */
const char *rte_get_tx_ol_flag_name(uint64_t mask);

/**
 * Dump the list of TX offload flags in a buffer
 *
 * @param mask
 *   The mask describing the TX flags.
 * @param buf
 *   The output buffer.
 * @param buflen
 *   The length of the buffer.
 * @return
 *   0 on success, (-1) on error.
 */
int rte_get_tx_ol_flag_list(uint64_t mask, char *buf, size_t buflen);

/**
 * Some NICs need at least 2KB buffer to RX standard Ethernet frame without
 * splitting it into multiple segments.
 * So, for mbufs that planned to be involved into RX/TX, the recommended
 * minimal buffer length is 2KB + RTE_PKTMBUF_HEADROOM.
 */
#define	RTE_MBUF_DEFAULT_DATAROOM	2048
#define	RTE_MBUF_DEFAULT_BUF_SIZE	\
	(RTE_MBUF_DEFAULT_DATAROOM + RTE_PKTMBUF_HEADROOM)

/* define a set of marker types that can be used to refer to set points in the
 * mbuf */
__extension__
typedef void    *MARKER[0];   /**< generic marker for a point in a structure */
__extension__
typedef uint8_t  MARKER8[0];  /**< generic marker with 1B alignment */
__extension__
typedef uint64_t MARKER64[0]; /**< marker that allows us to overwrite 8 bytes
                               * with a single assignment */

/**
 * The generic rte_mbuf, containing a packet mbuf.
 */
struct rte_mbuf {
	MARKER cacheline0;

	void *buf_addr;           /**< Virtual address of segment buffer. */
	/**
	 * Physical address of segment buffer.
	 * Force alignment to 8-bytes, so as to ensure we have the exact
	 * same mbuf cacheline0 layout for 32-bit and 64-bit. This makes
	 * working on vector drivers easier.
	 */
	RTE_STD_C11
	union {
		rte_iova_t buf_iova;
		rte_iova_t buf_physaddr; /**< deprecated */
	} __rte_aligned(sizeof(rte_iova_t));

	/* next 8 bytes are initialised on RX descriptor rearm */
	MARKER64 rearm_data;
	uint16_t data_off;

	/**
	 * Reference counter. Its size should at least equal to the size
	 * of port field (16 bits), to support zero-copy broadcast.
	 * It should only be accessed using the following functions:
	 * rte_mbuf_refcnt_update(), rte_mbuf_refcnt_read(), and
	 * rte_mbuf_refcnt_set(). The functionality of these functions (atomic,
	 * or non-atomic) is controlled by the CONFIG_RTE_MBUF_REFCNT_ATOMIC
	 * config option.
	 */
	RTE_STD_C11
	union {
		rte_atomic16_t refcnt_atomic; /**< Atomically accessed refcnt */
		uint16_t refcnt;              /**< Non-atomically accessed refcnt */
	};
	uint16_t nb_segs;         /**< Number of segments. */

	/** Input port (16 bits to support more than 256 virtual ports).
	 * The event eth Tx adapter uses this field to specify the output port.
	 */
	uint16_t port;

	uint64_t ol_flags;        /**< Offload features. */

	/* remaining bytes are set on RX when pulling packet from descriptor */
	MARKER rx_descriptor_fields1;

	/*
	 * The packet type, which is the combination of outer/inner L2, L3, L4
	 * and tunnel types. The packet_type is about data really present in the
	 * mbuf. Example: if vlan stripping is enabled, a received vlan packet
	 * would have RTE_PTYPE_L2_ETHER and not RTE_PTYPE_L2_VLAN because the
	 * vlan is stripped from the data.
	 */
	RTE_STD_C11
	union {
		uint32_t packet_type; /**< L2/L3/L4 and tunnel information. */
		struct {
			uint32_t l2_type:4; /**< (Outer) L2 type. */
			uint32_t l3_type:4; /**< (Outer) L3 type. */
			uint32_t l4_type:4; /**< (Outer) L4 type. */
			uint32_t tun_type:4; /**< Tunnel type. */
			RTE_STD_C11
			union {
				uint8_t inner_esp_next_proto;
				/**< ESP next protocol type, valid if
				 * RTE_PTYPE_TUNNEL_ESP tunnel type is set
				 * on both Tx and Rx.
				 */
				__extension__
				struct {
					uint8_t inner_l2_type:4;
					/**< Inner L2 type. */
					uint8_t inner_l3_type:4;
					/**< Inner L3 type. */
				};
			};
			uint32_t inner_l4_type:4; /**< Inner L4 type. */
		};
	};

	uint32_t pkt_len;         /**< Total pkt len: sum of all segments. */
	uint16_t data_len;        /**< Amount of data in segment buffer. */
	/** VLAN TCI (CPU order), valid if PKT_RX_VLAN is set. */
	uint16_t vlan_tci;

	RTE_STD_C11
	union {
		union {
			uint32_t rss;     /**< RSS hash result if RSS enabled */
			struct {
				union {
					struct {
						uint16_t hash;
						uint16_t id;
					};
					uint32_t lo;
					/**< Second 4 flexible bytes */
				};
				uint32_t hi;
				/**< First 4 flexible bytes or FD ID, dependent
				 * on PKT_RX_FDIR_* flag in ol_flags.
				 */
			} fdir;	/**< Filter identifier if FDIR enabled */
			struct {
				uint32_t lo;
				uint32_t hi;
				/**< The event eth Tx adapter uses this field
				 * to store Tx queue id.
				 * @see rte_event_eth_tx_adapter_txq_set()
				 */
			} sched;          /**< Hierarchical scheduler */
			/**< User defined tags. See rte_distributor_process() */
			uint32_t usr;
		} hash;                   /**< hash information */
		struct {
			/**
			 * Application specific metadata value
			 * for egress flow rule match.
			 * Valid if PKT_TX_METADATA is set.
			 * Located here to allow conjunct use
			 * with hash.sched.hi.
			 */
			uint32_t tx_metadata;
			uint32_t reserved;
		};
	};

	/** Outer VLAN TCI (CPU order), valid if PKT_RX_QINQ is set. */
	uint16_t vlan_tci_outer;

	uint16_t buf_len;         /**< Length of segment buffer. */

	/** Valid if PKT_RX_TIMESTAMP is set. The unit and time reference
	 * are not normalized but are always the same for a given port.
	 */
	uint64_t timestamp;

	/* second cache line - fields only used in slow path or on TX */
	MARKER cacheline1 __rte_cache_min_aligned;

	RTE_STD_C11
	union {
		void *userdata;   /**< Can be used for external metadata */
		uint64_t udata64; /**< Allow 8-byte userdata on 32-bit */
	};

	struct rte_mempool *pool; /**< Pool from which mbuf was allocated. */
	struct rte_mbuf *next;    /**< Next segment of scattered packet. */

	/* fields to support TX offloads */
	RTE_STD_C11
	union {
		uint64_t tx_offload;       /**< combined for easy fetch */
		__extension__
		struct {
			uint64_t l2_len:7;
			/**< L2 (MAC) Header Length for non-tunneling pkt.
			 * Outer_L4_len + ... + Inner_L2_len for tunneling pkt.
			 */
			uint64_t l3_len:9; /**< L3 (IP) Header Length. */
			uint64_t l4_len:8; /**< L4 (TCP/UDP) Header Length. */
			uint64_t tso_segsz:16; /**< TCP TSO segment size */

			/* fields for TX offloading of tunnels */
			uint64_t outer_l3_len:9; /**< Outer L3 (IP) Hdr Length. */
			uint64_t outer_l2_len:7; /**< Outer L2 (MAC) Hdr Length. */

			/* uint64_t unused:8; */
		};
	};

	/** Size of the application private data. In case of an indirect
	 * mbuf, it stores the direct mbuf private data size. */
	uint16_t priv_size;

	/** Timesync flags for use with IEEE1588. */
	uint16_t timesync;

	/** Sequence number. See also rte_reorder_insert(). */
	uint32_t seqn;

	/** Shared data for external buffer attached to mbuf. See
	 * rte_pktmbuf_attach_extbuf().
	 */
	struct rte_mbuf_ext_shared_info *shinfo;

} __rte_cache_aligned;

/**
 * Function typedef of callback to free externally attached buffer.
 */
typedef void (*rte_mbuf_extbuf_free_callback_t)(void *addr, void *opaque);

/**
 * Shared data at the end of an external buffer.
 */
struct rte_mbuf_ext_shared_info {
	rte_mbuf_extbuf_free_callback_t free_cb; /**< Free callback function */
	void *fcb_opaque;                        /**< Free callback argument */
	rte_atomic16_t refcnt_atomic;        /**< Atomically accessed refcnt */
};

/**< Maximum number of nb_segs allowed. */
#define RTE_MBUF_MAX_NB_SEGS	UINT16_MAX

/**
 * Prefetch the first part of the mbuf
 *
 * The first 64 bytes of the mbuf corresponds to fields that are used early
 * in the receive path. If the cache line of the architecture is higher than
 * 64B, the second part will also be prefetched.
 *
 * @param m
 *   The pointer to the mbuf.
 */
static inline void
rte_mbuf_prefetch_part1(struct rte_mbuf *m)
{
	rte_prefetch0(&m->cacheline0);
}

/**
 * Prefetch the second part of the mbuf
 *
 * The next 64 bytes of the mbuf corresponds to fields that are used in the
 * transmit path. If the cache line of the architecture is higher than 64B,
 * this function does nothing as it is expected that the full mbuf is
 * already in cache.
 *
 * @param m
 *   The pointer to the mbuf.
 */
static inline void
rte_mbuf_prefetch_part2(struct rte_mbuf *m)
{
#if RTE_CACHE_LINE_SIZE == 64
	rte_prefetch0(&m->cacheline1);
#else
	RTE_SET_USED(m);
#endif
}


static inline uint16_t rte_pktmbuf_priv_size(struct rte_mempool *mp);

/**
 * Return the IO address of the beginning of the mbuf data
 *
 * @param mb
 *   The pointer to the mbuf.
 * @return
 *   The IO address of the beginning of the mbuf data
 */
static inline rte_iova_t
rte_mbuf_data_iova(const struct rte_mbuf *mb)
{
	return mb->buf_iova + mb->data_off;
}

__rte_deprecated
static inline phys_addr_t
rte_mbuf_data_dma_addr(const struct rte_mbuf *mb)
{
	return rte_mbuf_data_iova(mb);
}

/**
 * Return the default IO address of the beginning of the mbuf data
 *
 * This function is used by drivers in their receive function, as it
 * returns the location where data should be written by the NIC, taking
 * the default headroom in account.
 *
 * @param mb
 *   The pointer to the mbuf.
 * @return
 *   The IO address of the beginning of the mbuf data
 */
static inline rte_iova_t
rte_mbuf_data_iova_default(const struct rte_mbuf *mb)
{
	return mb->buf_iova + RTE_PKTMBUF_HEADROOM;
}

__rte_deprecated
static inline phys_addr_t
rte_mbuf_data_dma_addr_default(const struct rte_mbuf *mb)
{
	return rte_mbuf_data_iova_default(mb);
}

/**
 * Return the mbuf owning the data buffer address of an indirect mbuf.
 *
 * @param mi
 *   The pointer to the indirect mbuf.
 * @return
 *   The address of the direct mbuf corresponding to buffer_addr.
 */
static inline struct rte_mbuf *
rte_mbuf_from_indirect(struct rte_mbuf *mi)
{
	return (struct rte_mbuf *)RTE_PTR_SUB(mi->buf_addr, sizeof(*mi) + mi->priv_size);
}

/**
 * Return the buffer address embedded in the given mbuf.
 *
 * @param md
 *   The pointer to the mbuf.
 * @return
 *   The address of the data buffer owned by the mbuf.
 */
static inline char *
rte_mbuf_to_baddr(struct rte_mbuf *md)
{
	char *buffer_addr;
	buffer_addr = (char *)md + sizeof(*md) + rte_pktmbuf_priv_size(md->pool);
	return buffer_addr;
}

/**
 * Return the starting address of the private data area embedded in
 * the given mbuf.
 *
 * Note that no check is made to ensure that a private data area
 * actually exists in the supplied mbuf.
 *
 * @param m
 *   The pointer to the mbuf.
 * @return
 *   The starting address of the private data area of the given mbuf.
 */
static inline void * __rte_experimental
rte_mbuf_to_priv(struct rte_mbuf *m)
{
	return RTE_PTR_ADD(m, sizeof(struct rte_mbuf));
}

/**
 * Returns TRUE if given mbuf is cloned by mbuf indirection, or FALSE
 * otherwise.
 *
 * If a mbuf has its data in another mbuf and references it by mbuf
 * indirection, this mbuf can be defined as a cloned mbuf.
 */
#define RTE_MBUF_CLONED(mb)     ((mb)->ol_flags & IND_ATTACHED_MBUF)

/**
 * Deprecated.
 * Use RTE_MBUF_CLONED().
 */
#define RTE_MBUF_INDIRECT(mb)   RTE_MBUF_CLONED(mb)

/**
 * Returns TRUE if given mbuf has an external buffer, or FALSE otherwise.
 *
 * External buffer is a user-provided anonymous buffer.
 */
#define RTE_MBUF_HAS_EXTBUF(mb) ((mb)->ol_flags & EXT_ATTACHED_MBUF)

/**
 * Returns TRUE if given mbuf is direct, or FALSE otherwise.
 *
 * If a mbuf embeds its own data after the rte_mbuf structure, this mbuf
 * can be defined as a direct mbuf.
 */
#define RTE_MBUF_DIRECT(mb) \
	(!((mb)->ol_flags & (IND_ATTACHED_MBUF | EXT_ATTACHED_MBUF)))

/**
 * Private data in case of pktmbuf pool.
 *
 * A structure that contains some pktmbuf_pool-specific data that are
 * appended after the mempool structure (in private data).
 */
struct rte_pktmbuf_pool_private {
	uint16_t mbuf_data_room_size; /**< Size of data space in each mbuf. */
	uint16_t mbuf_priv_size;      /**< Size of private area in each mbuf. */
};

#ifdef RTE_LIBRTE_MBUF_DEBUG

/**  check mbuf type in debug mode */
#define __rte_mbuf_sanity_check(m, is_h) rte_mbuf_sanity_check(m, is_h)

#else /*  RTE_LIBRTE_MBUF_DEBUG */

/**  check mbuf type in debug mode */
#define __rte_mbuf_sanity_check(m, is_h) do { } while (0)

#endif /*  RTE_LIBRTE_MBUF_DEBUG */

#ifdef RTE_MBUF_REFCNT_ATOMIC

/**
 * Reads the value of an mbuf's refcnt.
 * @param m
 *   Mbuf to read
 * @return
 *   Reference count number.
 */
static inline uint16_t
rte_mbuf_refcnt_read(const struct rte_mbuf *m)
{
	return (uint16_t)(rte_atomic16_read(&m->refcnt_atomic));
}

/**
 * Sets an mbuf's refcnt to a defined value.
 * @param m
 *   Mbuf to update
 * @param new_value
 *   Value set
 */
static inline void
rte_mbuf_refcnt_set(struct rte_mbuf *m, uint16_t new_value)
{
	rte_atomic16_set(&m->refcnt_atomic, (int16_t)new_value);
}

/* internal */
static inline uint16_t
__rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value)
{
	return (uint16_t)(rte_atomic16_add_return(&m->refcnt_atomic, value));
}

/**
 * Adds given value to an mbuf's refcnt and returns its new value.
 * @param m
 *   Mbuf to update
 * @param value
 *   Value to add/subtract
 * @return
 *   Updated value
 */
static inline uint16_t
rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value)
{
	/*
	 * The atomic_add is an expensive operation, so we don't want to
	 * call it in the case where we know we are the unique holder of
	 * this mbuf (i.e. ref_cnt == 1). Otherwise, an atomic
	 * operation has to be used because concurrent accesses on the
	 * reference counter can occur.
	 */
	if (likely(rte_mbuf_refcnt_read(m) == 1)) {
		++value;
		rte_mbuf_refcnt_set(m, (uint16_t)value);
		return (uint16_t)value;
	}

	return __rte_mbuf_refcnt_update(m, value);
}

#else /* ! RTE_MBUF_REFCNT_ATOMIC */

/* internal */
static inline uint16_t
__rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value)
{
	m->refcnt = (uint16_t)(m->refcnt + value);
	return m->refcnt;
}

/**
 * Adds given value to an mbuf's refcnt and returns its new value.
 */
static inline uint16_t
rte_mbuf_refcnt_update(struct rte_mbuf *m, int16_t value)
{
	return __rte_mbuf_refcnt_update(m, value);
}

/**
 * Reads the value of an mbuf's refcnt.
 */
static inline uint16_t
rte_mbuf_refcnt_read(const struct rte_mbuf *m)
{
	return m->refcnt;
}

/**
 * Sets an mbuf's refcnt to the defined value.
 */
static inline void
rte_mbuf_refcnt_set(struct rte_mbuf *m, uint16_t new_value)
{
	m->refcnt = new_value;
}

#endif /* RTE_MBUF_REFCNT_ATOMIC */

/**
 * Reads the refcnt of an external buffer.
 *
 * @param shinfo
 *   Shared data of the external buffer.
 * @return
 *   Reference count number.
 */
static inline uint16_t
rte_mbuf_ext_refcnt_read(const struct rte_mbuf_ext_shared_info *shinfo)
{
	return (uint16_t)(rte_atomic16_read(&shinfo->refcnt_atomic));
}

/**
 * Set refcnt of an external buffer.
 *
 * @param shinfo
 *   Shared data of the external buffer.
 * @param new_value
 *   Value set
 */
static inline void
rte_mbuf_ext_refcnt_set(struct rte_mbuf_ext_shared_info *shinfo,
	uint16_t new_value)
{
	rte_atomic16_set(&shinfo->refcnt_atomic, (int16_t)new_value);
}

/**
 * Add given value to refcnt of an external buffer and return its new
 * value.
 *
 * @param shinfo
 *   Shared data of the external buffer.
 * @param value
 *   Value to add/subtract
 * @return
 *   Updated value
 */
static inline uint16_t
rte_mbuf_ext_refcnt_update(struct rte_mbuf_ext_shared_info *shinfo,
	int16_t value)
{
	if (likely(rte_mbuf_ext_refcnt_read(shinfo) == 1)) {
		++value;
		rte_mbuf_ext_refcnt_set(shinfo, (uint16_t)value);
		return (uint16_t)value;
	}

	return (uint16_t)rte_atomic16_add_return(&shinfo->refcnt_atomic, value);
}

/** Mbuf prefetch */
#define RTE_MBUF_PREFETCH_TO_FREE(m) do {       \
	if ((m) != NULL)                        \
		rte_prefetch0(m);               \
} while (0)


/**
 * Sanity checks on an mbuf.
 *
 * Check the consistency of the given mbuf. The function will cause a
 * panic if corruption is detected.
 *
 * @param m
 *   The mbuf to be checked.
 * @param is_header
 *   True if the mbuf is a packet header, false if it is a sub-segment
 *   of a packet (in this case, some fields like nb_segs are not checked)
 */
void
rte_mbuf_sanity_check(const struct rte_mbuf *m, int is_header);

#define MBUF_RAW_ALLOC_CHECK(m) do {				\
	RTE_ASSERT(rte_mbuf_refcnt_read(m) == 1);		\
	RTE_ASSERT((m)->next == NULL);				\
	RTE_ASSERT((m)->nb_segs == 1);				\
	__rte_mbuf_sanity_check(m, 0);				\
} while (0)

/**
 * Allocate an uninitialized mbuf from mempool *mp*.
 *
 * This function can be used by PMDs (especially in RX functions) to
 * allocate an uninitialized mbuf. The driver is responsible of
 * initializing all the required fields. See rte_pktmbuf_reset().
 * For standard needs, prefer rte_pktmbuf_alloc().
 *
 * The caller can expect that the following fields of the mbuf structure
 * are initialized: buf_addr, buf_iova, buf_len, refcnt=1, nb_segs=1,
 * next=NULL, pool, priv_size. The other fields must be initialized
 * by the caller.
 *
 * @param mp
 *   The mempool from which mbuf is allocated.
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation failed.
 */
static inline struct rte_mbuf *rte_mbuf_raw_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	if (rte_mempool_get(mp, (void **)&m) < 0)
		return NULL;
	MBUF_RAW_ALLOC_CHECK(m);
	return m;
}

/**
 * Put mbuf back into its original mempool.
 *
 * The caller must ensure that the mbuf is direct and properly
 * reinitialized (refcnt=1, next=NULL, nb_segs=1), as done by
 * rte_pktmbuf_prefree_seg().
 *
 * This function should be used with care, when optimization is
 * required. For standard needs, prefer rte_pktmbuf_free() or
 * rte_pktmbuf_free_seg().
 *
 * @param m
 *   The mbuf to be freed.
 */
static __rte_always_inline void
rte_mbuf_raw_free(struct rte_mbuf *m)
{
	RTE_ASSERT(RTE_MBUF_DIRECT(m));
	RTE_ASSERT(rte_mbuf_refcnt_read(m) == 1);
	RTE_ASSERT(m->next == NULL);
	RTE_ASSERT(m->nb_segs == 1);
	__rte_mbuf_sanity_check(m, 0);
	rte_mempool_put(m->pool, m);
}

/**
 * The packet mbuf constructor.
 *
 * This function initializes some fields in the mbuf structure that are
 * not modified by the user once created (origin pool, buffer start
 * address, and so on). This function is given as a callback function to
 * rte_mempool_obj_iter() or rte_mempool_create() at pool creation time.
 *
 * @param mp
 *   The mempool from which mbufs originate.
 * @param opaque_arg
 *   A pointer that can be used by the user to retrieve useful information
 *   for mbuf initialization. This pointer is the opaque argument passed to
 *   rte_mempool_obj_iter() or rte_mempool_create().
 * @param m
 *   The mbuf to initialize.
 * @param i
 *   The index of the mbuf in the pool table.
 */
void rte_pktmbuf_init(struct rte_mempool *mp, void *opaque_arg,
		      void *m, unsigned i);


/**
 * A  packet mbuf pool constructor.
 *
 * This function initializes the mempool private data in the case of a
 * pktmbuf pool. This private data is needed by the driver. The
 * function must be called on the mempool before it is used, or it
 * can be given as a callback function to rte_mempool_create() at
 * pool creation. It can be extended by the user, for example, to
 * provide another packet size.
 *
 * @param mp
 *   The mempool from which mbufs originate.
 * @param opaque_arg
 *   A pointer that can be used by the user to retrieve useful information
 *   for mbuf initialization. This pointer is the opaque argument passed to
 *   rte_mempool_create().
 */
void rte_pktmbuf_pool_init(struct rte_mempool *mp, void *opaque_arg);

/**
 * Create a mbuf pool.
 *
 * This function creates and initializes a packet mbuf pool. It is
 * a wrapper to rte_mempool functions.
 *
 * @param name
 *   The name of the mbuf pool.
 * @param n
 *   The number of elements in the mbuf pool. The optimum size (in terms
 *   of memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param cache_size
 *   Size of the per-core object cache. See rte_mempool_create() for
 *   details.
 * @param priv_size
 *   Size of application private are between the rte_mbuf structure
 *   and the data buffer. This value must be aligned to RTE_MBUF_PRIV_ALIGN.
 * @param data_room_size
 *   Size of data buffer in each mbuf, including RTE_PKTMBUF_HEADROOM.
 * @param socket_id
 *   The socket identifier where the memory should be allocated. The
 *   value can be *SOCKET_ID_ANY* if there is no NUMA constraint for the
 *   reserved zone.
 * @return
 *   The pointer to the new allocated mempool, on success. NULL on error
 *   with rte_errno set appropriately. Possible rte_errno values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - EINVAL - cache size provided is too large, or priv_size is not aligned.
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct rte_mempool *
rte_pktmbuf_pool_create(const char *name, unsigned n,
	unsigned cache_size, uint16_t priv_size, uint16_t data_room_size,
	int socket_id);

/**
 * Create a mbuf pool with a given mempool ops name
 *
 * This function creates and initializes a packet mbuf pool. It is
 * a wrapper to rte_mempool functions.
 *
 * @param name
 *   The name of the mbuf pool.
 * @param n
 *   The number of elements in the mbuf pool. The optimum size (in terms
 *   of memory usage) for a mempool is when n is a power of two minus one:
 *   n = (2^q - 1).
 * @param cache_size
 *   Size of the per-core object cache. See rte_mempool_create() for
 *   details.
 * @param priv_size
 *   Size of application private are between the rte_mbuf structure
 *   and the data buffer. This value must be aligned to RTE_MBUF_PRIV_ALIGN.
 * @param data_room_size
 *   Size of data buffer in each mbuf, including RTE_PKTMBUF_HEADROOM.
 * @param socket_id
 *   The socket identifier where the memory should be allocated. The
 *   value can be *SOCKET_ID_ANY* if there is no NUMA constraint for the
 *   reserved zone.
 * @param ops_name
 *   The mempool ops name to be used for this mempool instead of
 *   default mempool. The value can be *NULL* to use default mempool.
 * @return
 *   The pointer to the new allocated mempool, on success. NULL on error
 *   with rte_errno set appropriately. Possible rte_errno values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - EINVAL - cache size provided is too large, or priv_size is not aligned.
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
struct rte_mempool *
rte_pktmbuf_pool_create_by_ops(const char *name, unsigned int n,
	unsigned int cache_size, uint16_t priv_size, uint16_t data_room_size,
	int socket_id, const char *ops_name);

/**
 * Get the data room size of mbufs stored in a pktmbuf_pool
 *
 * The data room size is the amount of data that can be stored in a
 * mbuf including the headroom (RTE_PKTMBUF_HEADROOM).
 *
 * @param mp
 *   The packet mbuf pool.
 * @return
 *   The data room size of mbufs stored in this mempool.
 */
static inline uint16_t
rte_pktmbuf_data_room_size(struct rte_mempool *mp)
{
	struct rte_pktmbuf_pool_private *mbp_priv;

	mbp_priv = (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(mp);
	return mbp_priv->mbuf_data_room_size;
}

/**
 * Get the application private size of mbufs stored in a pktmbuf_pool
 *
 * The private size of mbuf is a zone located between the rte_mbuf
 * structure and the data buffer where an application can store data
 * associated to a packet.
 *
 * @param mp
 *   The packet mbuf pool.
 * @return
 *   The private size of mbufs stored in this mempool.
 */
static inline uint16_t
rte_pktmbuf_priv_size(struct rte_mempool *mp)
{
	struct rte_pktmbuf_pool_private *mbp_priv;

	mbp_priv = (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(mp);
	return mbp_priv->mbuf_priv_size;
}

/**
 * Reset the data_off field of a packet mbuf to its default value.
 *
 * The given mbuf must have only one segment, which should be empty.
 *
 * @param m
 *   The packet mbuf's data_off field has to be reset.
 */
static inline void rte_pktmbuf_reset_headroom(struct rte_mbuf *m)
{
	m->data_off = (uint16_t)RTE_MIN((uint16_t)RTE_PKTMBUF_HEADROOM,
					(uint16_t)m->buf_len);
}

/**
 * Reset the fields of a packet mbuf to their default values.
 *
 * The given mbuf must have only one segment.
 *
 * @param m
 *   The packet mbuf to be reset.
 */
#define MBUF_INVALID_PORT UINT16_MAX

static inline void rte_pktmbuf_reset(struct rte_mbuf *m)
{
	m->next = NULL;
	m->pkt_len = 0;
	m->tx_offload = 0;
	m->vlan_tci = 0;
	m->vlan_tci_outer = 0;
	m->nb_segs = 1;
	m->port = MBUF_INVALID_PORT;

	m->ol_flags = 0;
	m->packet_type = 0;
	rte_pktmbuf_reset_headroom(m);

	m->data_len = 0;
	__rte_mbuf_sanity_check(m, 1);
}

/**
 * Allocate a new mbuf from a mempool.
 *
 * This new mbuf contains one segment, which has a length of 0. The pointer
 * to data is initialized to have some bytes of headroom in the buffer
 * (if buffer size allows).
 *
 * @param mp
 *   The mempool from which the mbuf is allocated.
 * @return
 *   - The pointer to the new mbuf on success.
 *   - NULL if allocation failed.
 */
static inline struct rte_mbuf *rte_pktmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;
	if ((m = rte_mbuf_raw_alloc(mp)) != NULL)
		rte_pktmbuf_reset(m);
	return m;
}

/**
 * Allocate a bulk of mbufs, initialize refcnt and reset the fields to default
 * values.
 *
 *  @param pool
 *    The mempool from which mbufs are allocated.
 *  @param mbufs
 *    Array of pointers to mbufs
 *  @param count
 *    Array size
 *  @return
 *   - 0: Success
 *   - -ENOENT: Not enough entries in the mempool; no mbufs are retrieved.
 */
static inline int rte_pktmbuf_alloc_bulk(struct rte_mempool *pool,
	 struct rte_mbuf **mbufs, unsigned count)
{
	unsigned idx = 0;
	int rc;

	rc = rte_mempool_get_bulk(pool, (void **)mbufs, count);
	if (unlikely(rc))
		return rc;

	/* To understand duff's device on loop unwinding optimization, see
	 * https://en.wikipedia.org/wiki/Duff's_device.
	 * Here while() loop is used rather than do() while{} to avoid extra
	 * check if count is zero.
	 */
	switch (count % 4) {
	case 0:
		while (idx != count) {
			MBUF_RAW_ALLOC_CHECK(mbufs[idx]);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
			/* fall-through */
	case 3:
			MBUF_RAW_ALLOC_CHECK(mbufs[idx]);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
			/* fall-through */
	case 2:
			MBUF_RAW_ALLOC_CHECK(mbufs[idx]);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
			/* fall-through */
	case 1:
			MBUF_RAW_ALLOC_CHECK(mbufs[idx]);
			rte_pktmbuf_reset(mbufs[idx]);
			idx++;
			/* fall-through */
		}
	}
	return 0;
}

/**
 * Initialize shared data at the end of an external buffer before attaching
 * to a mbuf by ``rte_pktmbuf_attach_extbuf()``. This is not a mandatory
 * initialization but a helper function to simply spare a few bytes at the
 * end of the buffer for shared data. If shared data is allocated
 * separately, this should not be called but application has to properly
 * initialize the shared data according to its need.
 *
 * Free callback and its argument is saved and the refcnt is set to 1.
 *
 * @warning
 * The value of buf_len will be reduced to RTE_PTR_DIFF(shinfo, buf_addr)
 * after this initialization. This shall be used for
 * ``rte_pktmbuf_attach_extbuf()``
 *
 * @param buf_addr
 *   The pointer to the external buffer.
 * @param [in,out] buf_len
 *   The pointer to length of the external buffer. Input value must be
 *   larger than the size of ``struct rte_mbuf_ext_shared_info`` and
 *   padding for alignment. If not enough, this function will return NULL.
 *   Adjusted buffer length will be returned through this pointer.
 * @param free_cb
 *   Free callback function to call when the external buffer needs to be
 *   freed.
 * @param fcb_opaque
 *   Argument for the free callback function.
 *
 * @return
 *   A pointer to the initialized shared data on success, return NULL
 *   otherwise.
 */
static inline struct rte_mbuf_ext_shared_info *
rte_pktmbuf_ext_shinfo_init_helper(void *buf_addr, uint16_t *buf_len,
	rte_mbuf_extbuf_free_callback_t free_cb, void *fcb_opaque)
{
	struct rte_mbuf_ext_shared_info *shinfo;
	void *buf_end = RTE_PTR_ADD(buf_addr, *buf_len);
	void *addr;

	addr = RTE_PTR_ALIGN_FLOOR(RTE_PTR_SUB(buf_end, sizeof(*shinfo)),
				   sizeof(uintptr_t));
	if (addr <= buf_addr)
		return NULL;

	shinfo = (struct rte_mbuf_ext_shared_info *)addr;
	shinfo->free_cb = free_cb;
	shinfo->fcb_opaque = fcb_opaque;
	rte_mbuf_ext_refcnt_set(shinfo, 1);

	*buf_len = (uint16_t)RTE_PTR_DIFF(shinfo, buf_addr);
	return shinfo;
}

/**
 * Attach an external buffer to a mbuf.
 *
 * User-managed anonymous buffer can be attached to an mbuf. When attaching
 * it, corresponding free callback function and its argument should be
 * provided via shinfo. This callback function will be called once all the
 * mbufs are detached from the buffer (refcnt becomes zero).
 *
 * The headroom for the attaching mbuf will be set to zero and this can be
 * properly adjusted after attachment. For example, ``rte_pktmbuf_adj()``
 * or ``rte_pktmbuf_reset_headroom()`` might be used.
 *
 * More mbufs can be attached to the same external buffer by
 * ``rte_pktmbuf_attach()`` once the external buffer has been attached by
 * this API.
 *
 * Detachment can be done by either ``rte_pktmbuf_detach_extbuf()`` or
 * ``rte_pktmbuf_detach()``.
 *
 * Memory for shared data must be provided and user must initialize all of
 * the content properly, especially free callback and refcnt. The pointer
 * of shared data will be stored in m->shinfo.
 * ``rte_pktmbuf_ext_shinfo_init_helper`` can help to simply spare a few
 * bytes at the end of buffer for the shared data, store free callback and
 * its argument and set the refcnt to 1. The following is an example:
 *
 *   struct rte_mbuf_ext_shared_info *shinfo =
 *          rte_pktmbuf_ext_shinfo_init_helper(buf_addr, &buf_len,
 *                                             free_cb, fcb_arg);
 *   rte_pktmbuf_attach_extbuf(m, buf_addr, buf_iova, buf_len, shinfo);
 *   rte_pktmbuf_reset_headroom(m);
 *   rte_pktmbuf_adj(m, data_len);
 *
 * Attaching an external buffer is quite similar to mbuf indirection in
 * replacing buffer addresses and length of a mbuf, but a few differences:
 * - When an indirect mbuf is attached, refcnt of the direct mbuf would be
 *   2 as long as the direct mbuf itself isn't freed after the attachment.
 *   In such cases, the buffer area of a direct mbuf must be read-only. But
 *   external buffer has its own refcnt and it starts from 1. Unless
 *   multiple mbufs are attached to a mbuf having an external buffer, the
 *   external buffer is writable.
 * - There's no need to allocate buffer from a mempool. Any buffer can be
 *   attached with appropriate free callback and its IO address.
 * - Smaller metadata is required to maintain shared data such as refcnt.
 *
 * @warning
 * @b EXPERIMENTAL: This API may change without prior notice.
 * Once external buffer is enabled by allowing experimental API,
 * ``RTE_MBUF_DIRECT()`` and ``RTE_MBUF_INDIRECT()`` are no longer
 * exclusive. A mbuf can be considered direct if it is neither indirect nor
 * having external buffer.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param buf_addr
 *   The pointer to the external buffer.
 * @param buf_iova
 *   IO address of the external buffer.
 * @param buf_len
 *   The size of the external buffer.
 * @param shinfo
 *   User-provided memory for shared data of the external buffer.
 */
static inline void __rte_experimental
rte_pktmbuf_attach_extbuf(struct rte_mbuf *m, void *buf_addr,
	rte_iova_t buf_iova, uint16_t buf_len,
	struct rte_mbuf_ext_shared_info *shinfo)
{
	/* mbuf should not be read-only */
	RTE_ASSERT(RTE_MBUF_DIRECT(m) && rte_mbuf_refcnt_read(m) == 1);
	RTE_ASSERT(shinfo->free_cb != NULL);

	m->buf_addr = buf_addr;
	m->buf_iova = buf_iova;
	m->buf_len = buf_len;

	m->data_len = 0;
	m->data_off = 0;

	m->ol_flags |= EXT_ATTACHED_MBUF;
	m->shinfo = shinfo;
}

/**
 * Detach the external buffer attached to a mbuf, same as
 * ``rte_pktmbuf_detach()``
 *
 * @param m
 *   The mbuf having external buffer.
 */
#define rte_pktmbuf_detach_extbuf(m) rte_pktmbuf_detach(m)

/**
 * Attach packet mbuf to another packet mbuf.
 *
 * If the mbuf we are attaching to isn't a direct buffer and is attached to
 * an external buffer, the mbuf being attached will be attached to the
 * external buffer instead of mbuf indirection.
 *
 * Otherwise, the mbuf will be indirectly attached. After attachment we
 * refer the mbuf we attached as 'indirect', while mbuf we attached to as
 * 'direct'.  The direct mbuf's reference counter is incremented.
 *
 * Right now, not supported:
 *  - attachment for already indirect mbuf (e.g. - mi has to be direct).
 *  - mbuf we trying to attach (mi) is used by someone else
 *    e.g. it's reference counter is greater then 1.
 *
 * @param mi
 *   The indirect packet mbuf.
 * @param m
 *   The packet mbuf we're attaching to.
 */
static inline void rte_pktmbuf_attach(struct rte_mbuf *mi, struct rte_mbuf *m)
{
	RTE_ASSERT(RTE_MBUF_DIRECT(mi) &&
	    rte_mbuf_refcnt_read(mi) == 1);

	if (RTE_MBUF_HAS_EXTBUF(m)) {
		rte_mbuf_ext_refcnt_update(m->shinfo, 1);
		mi->ol_flags = m->ol_flags;
		mi->shinfo = m->shinfo;
	} else {
		/* if m is not direct, get the mbuf that embeds the data */
		rte_mbuf_refcnt_update(rte_mbuf_from_indirect(m), 1);
		mi->priv_size = m->priv_size;
		mi->ol_flags = m->ol_flags | IND_ATTACHED_MBUF;
	}

	mi->buf_iova = m->buf_iova;
	mi->buf_addr = m->buf_addr;
	mi->buf_len = m->buf_len;

	mi->data_off = m->data_off;
	mi->data_len = m->data_len;
	mi->port = m->port;
	mi->vlan_tci = m->vlan_tci;
	mi->vlan_tci_outer = m->vlan_tci_outer;
	mi->tx_offload = m->tx_offload;
	mi->hash = m->hash;

	mi->next = NULL;
	mi->pkt_len = mi->data_len;
	mi->nb_segs = 1;
	mi->packet_type = m->packet_type;
	mi->timestamp = m->timestamp;

	__rte_mbuf_sanity_check(mi, 1);
	__rte_mbuf_sanity_check(m, 0);
}

/**
 * @internal used by rte_pktmbuf_detach().
 *
 * Decrement the reference counter of the external buffer. When the
 * reference counter becomes 0, the buffer is freed by pre-registered
 * callback.
 */
static inline void
__rte_pktmbuf_free_extbuf(struct rte_mbuf *m)
{
	RTE_ASSERT(RTE_MBUF_HAS_EXTBUF(m));
	RTE_ASSERT(m->shinfo != NULL);

	if (rte_mbuf_ext_refcnt_update(m->shinfo, -1) == 0)
		m->shinfo->free_cb(m->buf_addr, m->shinfo->fcb_opaque);
}

/**
 * @internal used by rte_pktmbuf_detach().
 *
 * Decrement the direct mbuf's reference counter. When the reference
 * counter becomes 0, the direct mbuf is freed.
 */
static inline void
__rte_pktmbuf_free_direct(struct rte_mbuf *m)
{
	struct rte_mbuf *md;

	RTE_ASSERT(RTE_MBUF_INDIRECT(m));

	md = rte_mbuf_from_indirect(m);

	if (rte_mbuf_refcnt_update(md, -1) == 0) {
		md->next = NULL;
		md->nb_segs = 1;
		rte_mbuf_refcnt_set(md, 1);
		rte_mbuf_raw_free(md);
	}
}

/**
 * Detach a packet mbuf from external buffer or direct buffer.
 *
 *  - decrement refcnt and free the external/direct buffer if refcnt
 *    becomes zero.
 *  - restore original mbuf address and length values.
 *  - reset pktmbuf data and data_len to their default values.
 *
 * All other fields of the given packet mbuf will be left intact.
 *
 * @param m
 *   The indirect attached packet mbuf.
 */
static inline void rte_pktmbuf_detach(struct rte_mbuf *m)
{
	struct rte_mempool *mp = m->pool;
	uint32_t mbuf_size, buf_len;
	uint16_t priv_size;

	if (RTE_MBUF_HAS_EXTBUF(m))
		__rte_pktmbuf_free_extbuf(m);
	else
		__rte_pktmbuf_free_direct(m);

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = (uint32_t)(sizeof(struct rte_mbuf) + priv_size);
	buf_len = rte_pktmbuf_data_room_size(mp);

	m->priv_size = priv_size;
	m->buf_addr = (char *)m + mbuf_size;
	m->buf_iova = rte_mempool_virt2iova(m) + mbuf_size;
	m->buf_len = (uint16_t)buf_len;
	rte_pktmbuf_reset_headroom(m);
	m->data_len = 0;
	m->ol_flags = 0;
}

/**
 * Decrease reference counter and unlink a mbuf segment
 *
 * This function does the same than a free, except that it does not
 * return the segment to its pool.
 * It decreases the reference counter, and if it reaches 0, it is
 * detached from its parent for an indirect mbuf.
 *
 * @param m
 *   The mbuf to be unlinked
 * @return
 *   - (m) if it is the last reference. It can be recycled or freed.
 *   - (NULL) if the mbuf still has remaining references on it.
 */
static __rte_always_inline struct rte_mbuf *
rte_pktmbuf_prefree_seg(struct rte_mbuf *m)
{
	__rte_mbuf_sanity_check(m, 0);

	if (likely(rte_mbuf_refcnt_read(m) == 1)) {

		if (!RTE_MBUF_DIRECT(m))
			rte_pktmbuf_detach(m);

		if (m->next != NULL) {
			m->next = NULL;
			m->nb_segs = 1;
		}

		return m;

	} else if (__rte_mbuf_refcnt_update(m, -1) == 0) {

		if (!RTE_MBUF_DIRECT(m))
			rte_pktmbuf_detach(m);

		if (m->next != NULL) {
			m->next = NULL;
			m->nb_segs = 1;
		}
		rte_mbuf_refcnt_set(m, 1);

		return m;
	}
	return NULL;
}

/**
 * Free a segment of a packet mbuf into its original mempool.
 *
 * Free an mbuf, without parsing other segments in case of chained
 * buffers.
 *
 * @param m
 *   The packet mbuf segment to be freed.
 */
static __rte_always_inline void
rte_pktmbuf_free_seg(struct rte_mbuf *m)
{
	m = rte_pktmbuf_prefree_seg(m);
	if (likely(m != NULL))
		rte_mbuf_raw_free(m);
}

/**
 * Free a packet mbuf back into its original mempool.
 *
 * Free an mbuf, and all its segments in case of chained buffers. Each
 * segment is added back into its original mempool.
 *
 * @param m
 *   The packet mbuf to be freed. If NULL, the function does nothing.
 */
static inline void rte_pktmbuf_free(struct rte_mbuf *m)
{
	struct rte_mbuf *m_next;

	if (m != NULL)
		__rte_mbuf_sanity_check(m, 1);

	while (m != NULL) {
		m_next = m->next;
		rte_pktmbuf_free_seg(m);
		m = m_next;
	}
}

/**
 * Creates a "clone" of the given packet mbuf.
 *
 * Walks through all segments of the given packet mbuf, and for each of them:
 *  - Creates a new packet mbuf from the given pool.
 *  - Attaches newly created mbuf to the segment.
 * Then updates pkt_len and nb_segs of the "clone" packet mbuf to match values
 * from the original packet mbuf.
 *
 * @param md
 *   The packet mbuf to be cloned.
 * @param mp
 *   The mempool from which the "clone" mbufs are allocated.
 * @return
 *   - The pointer to the new "clone" mbuf on success.
 *   - NULL if allocation fails.
 */
static inline struct rte_mbuf *rte_pktmbuf_clone(struct rte_mbuf *md,
		struct rte_mempool *mp)
{
	struct rte_mbuf *mc, *mi, **prev;
	uint32_t pktlen;
	uint16_t nseg;

	if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
		return NULL;

	mi = mc;
	prev = &mi->next;
	pktlen = md->pkt_len;
	nseg = 0;

	do {
		nseg++;
		rte_pktmbuf_attach(mi, md);
		*prev = mi;
		prev = &mi->next;
	} while ((md = md->next) != NULL &&
	    (mi = rte_pktmbuf_alloc(mp)) != NULL);

	*prev = NULL;
	mc->nb_segs = nseg;
	mc->pkt_len = pktlen;

	/* Allocation of new indirect segment failed */
	if (unlikely (mi == NULL)) {
		rte_pktmbuf_free(mc);
		return NULL;
	}

	__rte_mbuf_sanity_check(mc, 1);
	return mc;
}

/**
 * Adds given value to the refcnt of all packet mbuf segments.
 *
 * Walks through all segments of given packet mbuf and for each of them
 * invokes rte_mbuf_refcnt_update().
 *
 * @param m
 *   The packet mbuf whose refcnt to be updated.
 * @param v
 *   The value to add to the mbuf's segments refcnt.
 */
static inline void rte_pktmbuf_refcnt_update(struct rte_mbuf *m, int16_t v)
{
	__rte_mbuf_sanity_check(m, 1);

	do {
		rte_mbuf_refcnt_update(m, v);
	} while ((m = m->next) != NULL);
}

/**
 * Get the headroom in a packet mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   The length of the headroom.
 */
static inline uint16_t rte_pktmbuf_headroom(const struct rte_mbuf *m)
{
	__rte_mbuf_sanity_check(m, 0);
	return m->data_off;
}

/**
 * Get the tailroom of a packet mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   The length of the tailroom.
 */
static inline uint16_t rte_pktmbuf_tailroom(const struct rte_mbuf *m)
{
	__rte_mbuf_sanity_check(m, 0);
	return (uint16_t)(m->buf_len - rte_pktmbuf_headroom(m) -
			  m->data_len);
}

/**
 * Get the last segment of the packet.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   The last segment of the given mbuf.
 */
static inline struct rte_mbuf *rte_pktmbuf_lastseg(struct rte_mbuf *m)
{
	__rte_mbuf_sanity_check(m, 1);
	while (m->next != NULL)
		m = m->next;
	return m;
}

/**
 * A macro that points to an offset into the data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that the first segment is large
 * enough to accommodate its data.
 *
 * @param m
 *   The packet mbuf.
 * @param o
 *   The offset into the mbuf data.
 * @param t
 *   The type to cast the result into.
 */
#define rte_pktmbuf_mtod_offset(m, t, o)	\
	((t)((char *)(m)->buf_addr + (m)->data_off + (o)))

/**
 * A macro that points to the start of the data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that the first segment is large
 * enough to accommodate its data.
 *
 * @param m
 *   The packet mbuf.
 * @param t
 *   The type to cast the result into.
 */
#define rte_pktmbuf_mtod(m, t) rte_pktmbuf_mtod_offset(m, t, 0)

/**
 * A macro that returns the IO address that points to an offset of the
 * start of the data in the mbuf
 *
 * @param m
 *   The packet mbuf.
 * @param o
 *   The offset into the data to calculate address from.
 */
#define rte_pktmbuf_iova_offset(m, o) \
	(rte_iova_t)((m)->buf_iova + (m)->data_off + (o))

/* deprecated */
#define rte_pktmbuf_mtophys_offset(m, o) \
	rte_pktmbuf_iova_offset(m, o)

/**
 * A macro that returns the IO address that points to the start of the
 * data in the mbuf
 *
 * @param m
 *   The packet mbuf.
 */
#define rte_pktmbuf_iova(m) rte_pktmbuf_iova_offset(m, 0)

/* deprecated */
#define rte_pktmbuf_mtophys(m) rte_pktmbuf_iova(m)

/**
 * A macro that returns the length of the packet.
 *
 * The value can be read or assigned.
 *
 * @param m
 *   The packet mbuf.
 */
#define rte_pktmbuf_pkt_len(m) ((m)->pkt_len)

/**
 * A macro that returns the length of the segment.
 *
 * The value can be read or assigned.
 *
 * @param m
 *   The packet mbuf.
 */
#define rte_pktmbuf_data_len(m) ((m)->data_len)

/**
 * Prepend len bytes to an mbuf data area.
 *
 * Returns a pointer to the new
 * data start address. If there is not enough headroom in the first
 * segment, the function will return NULL, without modifying the mbuf.
 *
 * @param m
 *   The pkt mbuf.
 * @param len
 *   The amount of data to prepend (in bytes).
 * @return
 *   A pointer to the start of the newly prepended data, or
 *   NULL if there is not enough headroom space in the first segment
 */
static inline char *rte_pktmbuf_prepend(struct rte_mbuf *m,
					uint16_t len)
{
	__rte_mbuf_sanity_check(m, 1);

	if (unlikely(len > rte_pktmbuf_headroom(m)))
		return NULL;

	/* NB: elaborating the subtraction like this instead of using
	 *     -= allows us to ensure the result type is uint16_t
	 *     avoiding compiler warnings on gcc 8.1 at least */
	m->data_off = (uint16_t)(m->data_off - len);
	m->data_len = (uint16_t)(m->data_len + len);
	m->pkt_len  = (m->pkt_len + len);

	return (char *)m->buf_addr + m->data_off;
}

/**
 * Append len bytes to an mbuf.
 *
 * Append len bytes to an mbuf and return a pointer to the start address
 * of the added data. If there is not enough tailroom in the last
 * segment, the function will return NULL, without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to append (in bytes).
 * @return
 *   A pointer to the start of the newly appended data, or
 *   NULL if there is not enough tailroom space in the last segment
 */
static inline char *rte_pktmbuf_append(struct rte_mbuf *m, uint16_t len)
{
	void *tail;
	struct rte_mbuf *m_last;

	__rte_mbuf_sanity_check(m, 1);

	m_last = rte_pktmbuf_lastseg(m);
	if (unlikely(len > rte_pktmbuf_tailroom(m_last)))
		return NULL;

	tail = (char *)m_last->buf_addr + m_last->data_off + m_last->data_len;
	m_last->data_len = (uint16_t)(m_last->data_len + len);
	m->pkt_len  = (m->pkt_len + len);
	return (char*) tail;
}

/**
 * Remove len bytes at the beginning of an mbuf.
 *
 * Returns a pointer to the start address of the new data area. If the
 * length is greater than the length of the first segment, then the
 * function will fail and return NULL, without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to remove (in bytes).
 * @return
 *   A pointer to the new start of the data.
 */
static inline char *rte_pktmbuf_adj(struct rte_mbuf *m, uint16_t len)
{
	__rte_mbuf_sanity_check(m, 1);

	if (unlikely(len > m->data_len))
		return NULL;

	/* NB: elaborating the addition like this instead of using
	 *     += allows us to ensure the result type is uint16_t
	 *     avoiding compiler warnings on gcc 8.1 at least */
	m->data_len = (uint16_t)(m->data_len - len);
	m->data_off = (uint16_t)(m->data_off + len);
	m->pkt_len  = (m->pkt_len - len);
	return (char *)m->buf_addr + m->data_off;
}

/**
 * Remove len bytes of data at the end of the mbuf.
 *
 * If the length is greater than the length of the last segment, the
 * function will fail and return -1 without modifying the mbuf.
 *
 * @param m
 *   The packet mbuf.
 * @param len
 *   The amount of data to remove (in bytes).
 * @return
 *   - 0: On success.
 *   - -1: On error.
 */
static inline int rte_pktmbuf_trim(struct rte_mbuf *m, uint16_t len)
{
	struct rte_mbuf *m_last;

	__rte_mbuf_sanity_check(m, 1);

	m_last = rte_pktmbuf_lastseg(m);
	if (unlikely(len > m_last->data_len))
		return -1;

	m_last->data_len = (uint16_t)(m_last->data_len - len);
	m->pkt_len  = (m->pkt_len - len);
	return 0;
}

/**
 * Test if mbuf data is contiguous.
 *
 * @param m
 *   The packet mbuf.
 * @return
 *   - 1, if all data is contiguous (one segment).
 *   - 0, if there is several segments.
 */
static inline int rte_pktmbuf_is_contiguous(const struct rte_mbuf *m)
{
	__rte_mbuf_sanity_check(m, 1);
	return !!(m->nb_segs == 1);
}

/**
 * @internal used by rte_pktmbuf_read().
 */
const void *__rte_pktmbuf_read(const struct rte_mbuf *m, uint32_t off,
	uint32_t len, void *buf);

/**
 * Read len data bytes in a mbuf at specified offset.
 *
 * If the data is contiguous, return the pointer in the mbuf data, else
 * copy the data in the buffer provided by the user and return its
 * pointer.
 *
 * @param m
 *   The pointer to the mbuf.
 * @param off
 *   The offset of the data in the mbuf.
 * @param len
 *   The amount of bytes to read.
 * @param buf
 *   The buffer where data is copied if it is not contiguous in mbuf
 *   data. Its length should be at least equal to the len parameter.
 * @return
 *   The pointer to the data, either in the mbuf if it is contiguous,
 *   or in the user buffer. If mbuf is too small, NULL is returned.
 */
static inline const void *rte_pktmbuf_read(const struct rte_mbuf *m,
	uint32_t off, uint32_t len, void *buf)
{
	if (likely(off + len <= rte_pktmbuf_data_len(m)))
		return rte_pktmbuf_mtod_offset(m, char *, off);
	else
		return __rte_pktmbuf_read(m, off, len, buf);
}

/**
 * Chain an mbuf to another, thereby creating a segmented packet.
 *
 * Note: The implementation will do a linear walk over the segments to find
 * the tail entry. For cases when there are many segments, it's better to
 * chain the entries manually.
 *
 * @param head
 *   The head of the mbuf chain (the first packet)
 * @param tail
 *   The mbuf to put last in the chain
 *
 * @return
 *   - 0, on success.
 *   - -EOVERFLOW, if the chain segment limit exceeded
 */
static inline int rte_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *tail)
{
	struct rte_mbuf *cur_tail;

	/* Check for number-of-segments-overflow */
	if (head->nb_segs + tail->nb_segs > RTE_MBUF_MAX_NB_SEGS)
		return -EOVERFLOW;

	/* Chain 'tail' onto the old tail */
	cur_tail = rte_pktmbuf_lastseg(head);
	cur_tail->next = tail;

	/* accumulate number of segments and total length.
	 * NB: elaborating the addition like this instead of using
	 *     -= allows us to ensure the result type is uint16_t
	 *     avoiding compiler warnings on gcc 8.1 at least */
	head->nb_segs = (uint16_t)(head->nb_segs + tail->nb_segs);
	head->pkt_len += tail->pkt_len;

	/* pkt_len is only set in the head */
	tail->pkt_len = tail->data_len;

	return 0;
}

/**
 * Validate general requirements for Tx offload in mbuf.
 *
 * This function checks correctness and completeness of Tx offload settings.
 *
 * @param m
 *   The packet mbuf to be validated.
 * @return
 *   0 if packet is valid
 */
static inline int
rte_validate_tx_offload(const struct rte_mbuf *m)
{
	uint64_t ol_flags = m->ol_flags;
	uint64_t inner_l3_offset = m->l2_len;

	/* Does packet set any of available offloads? */
	if (!(ol_flags & PKT_TX_OFFLOAD_MASK))
		return 0;

	if (ol_flags & PKT_TX_OUTER_IP_CKSUM)
		/* NB: elaborating the addition like this instead of using
		 *     += gives the result uint64_t type instead of int,
		 *     avoiding compiler warnings on gcc 8.1 at least */
		inner_l3_offset = inner_l3_offset + m->outer_l2_len +
				  m->outer_l3_len;

	/* Headers are fragmented */
	if (rte_pktmbuf_data_len(m) < inner_l3_offset + m->l3_len + m->l4_len)
		return -ENOTSUP;

	/* IP checksum can be counted only for IPv4 packet */
	if ((ol_flags & PKT_TX_IP_CKSUM) && (ol_flags & PKT_TX_IPV6))
		return -EINVAL;

	/* IP type not set when required */
	if (ol_flags & (PKT_TX_L4_MASK | PKT_TX_TCP_SEG))
		if (!(ol_flags & (PKT_TX_IPV4 | PKT_TX_IPV6)))
			return -EINVAL;

	/* Check requirements for TSO packet */
	if (ol_flags & PKT_TX_TCP_SEG)
		if ((m->tso_segsz == 0) ||
				((ol_flags & PKT_TX_IPV4) &&
				!(ol_flags & PKT_TX_IP_CKSUM)))
			return -EINVAL;

	/* PKT_TX_OUTER_IP_CKSUM set for non outer IPv4 packet. */
	if ((ol_flags & PKT_TX_OUTER_IP_CKSUM) &&
			!(ol_flags & PKT_TX_OUTER_IPV4))
		return -EINVAL;

	return 0;
}

/**
 * Linearize data in mbuf.
 *
 * This function moves the mbuf data in the first segment if there is enough
 * tailroom. The subsequent segments are unchained and freed.
 *
 * @param mbuf
 *   mbuf to linearize
 * @return
 *   - 0, on success
 *   - -1, on error
 */
static inline int
rte_pktmbuf_linearize(struct rte_mbuf *mbuf)
{
	size_t seg_len, copy_len;
	struct rte_mbuf *m;
	struct rte_mbuf *m_next;
	char *buffer;

	if (rte_pktmbuf_is_contiguous(mbuf))
		return 0;

	/* Extend first segment to the total packet length */
	copy_len = rte_pktmbuf_pkt_len(mbuf) - rte_pktmbuf_data_len(mbuf);

	if (unlikely(copy_len > rte_pktmbuf_tailroom(mbuf)))
		return -1;

	buffer = rte_pktmbuf_mtod_offset(mbuf, char *, mbuf->data_len);
	mbuf->data_len = (uint16_t)(mbuf->pkt_len);

	/* Append data from next segments to the first one */
	m = mbuf->next;
	while (m != NULL) {
		m_next = m->next;

		seg_len = rte_pktmbuf_data_len(m);
		rte_memcpy(buffer, rte_pktmbuf_mtod(m, char *), seg_len);
		buffer += seg_len;

		rte_pktmbuf_free_seg(m);
		m = m_next;
	}

	mbuf->next = NULL;
	mbuf->nb_segs = 1;

	return 0;
}

/**
 * Dump an mbuf structure to a file.
 *
 * Dump all fields for the given packet mbuf and all its associated
 * segments (in the case of a chained buffer).
 *
 * @param f
 *   A pointer to a file for output
 * @param m
 *   The packet mbuf.
 * @param dump_len
 *   If dump_len != 0, also dump the "dump_len" first data bytes of
 *   the packet.
 */
void rte_pktmbuf_dump(FILE *f, const struct rte_mbuf *m, unsigned dump_len);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MBUF_H_ */
