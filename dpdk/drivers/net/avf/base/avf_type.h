/*******************************************************************************

Copyright (c) 2013 - 2015, Intel Corporation
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 3. Neither the name of the Intel Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/

#ifndef _AVF_TYPE_H_
#define _AVF_TYPE_H_

#include "avf_status.h"
#include "avf_osdep.h"
#include "avf_register.h"
#include "avf_adminq.h"
#include "avf_hmc.h"
#include "avf_lan_hmc.h"
#include "avf_devids.h"

#define UNREFERENCED_XPARAMETER
#define UNREFERENCED_1PARAMETER(_p) (_p);
#define UNREFERENCED_2PARAMETER(_p, _q) (_p); (_q);
#define UNREFERENCED_3PARAMETER(_p, _q, _r) (_p); (_q); (_r);
#define UNREFERENCED_4PARAMETER(_p, _q, _r, _s) (_p); (_q); (_r); (_s);
#define UNREFERENCED_5PARAMETER(_p, _q, _r, _s, _t) (_p); (_q); (_r); (_s); (_t);

#ifndef LINUX_MACROS
#ifndef BIT
#define BIT(a) (1UL << (a))
#endif /* BIT */
#ifndef BIT_ULL
#define BIT_ULL(a) (1ULL << (a))
#endif /* BIT_ULL */
#endif /* LINUX_MACROS */

#ifndef AVF_MASK
/* AVF_MASK is a macro used on 32 bit registers */
#define AVF_MASK(mask, shift) (mask << shift)
#endif

#define AVF_MAX_PF			16
#define AVF_MAX_PF_VSI			64
#define AVF_MAX_PF_QP			128
#define AVF_MAX_VSI_QP			16
#define AVF_MAX_VF_VSI			3
#define AVF_MAX_CHAINED_RX_BUFFERS	5
#define AVF_MAX_PF_UDP_OFFLOAD_PORTS	16

/* something less than 1 minute */
#define AVF_HEARTBEAT_TIMEOUT		(HZ * 50)

/* Max default timeout in ms, */
#define AVF_MAX_NVM_TIMEOUT		18000

/* Max timeout in ms for the phy to respond */
#define AVF_MAX_PHY_TIMEOUT		500

/* Check whether address is multicast. */
#define AVF_IS_MULTICAST(address) (bool)(((u8 *)(address))[0] & ((u8)0x01))

/* Check whether an address is broadcast. */
#define AVF_IS_BROADCAST(address)	\
	((((u8 *)(address))[0] == ((u8)0xff)) && \
	(((u8 *)(address))[1] == ((u8)0xff)))

/* Switch from ms to the 1usec global time (this is the GTIME resolution) */
#define AVF_MS_TO_GTIME(time)		((time) * 1000)

/* forward declaration */
struct avf_hw;
typedef void (*AVF_ADMINQ_CALLBACK)(struct avf_hw *, struct avf_aq_desc *);

#ifndef ETH_ALEN
#define ETH_ALEN	6
#endif
/* Data type manipulation macros. */
#define AVF_HI_DWORD(x)	((u32)((((x) >> 16) >> 16) & 0xFFFFFFFF))
#define AVF_LO_DWORD(x)	((u32)((x) & 0xFFFFFFFF))

#define AVF_HI_WORD(x)		((u16)(((x) >> 16) & 0xFFFF))
#define AVF_LO_WORD(x)		((u16)((x) & 0xFFFF))

#define AVF_HI_BYTE(x)		((u8)(((x) >> 8) & 0xFF))
#define AVF_LO_BYTE(x)		((u8)((x) & 0xFF))

/* Number of Transmit Descriptors must be a multiple of 8. */
#define AVF_REQ_TX_DESCRIPTOR_MULTIPLE	8
/* Number of Receive Descriptors must be a multiple of 32 if
 * the number of descriptors is greater than 32.
 */
#define AVF_REQ_RX_DESCRIPTOR_MULTIPLE	32

#define AVF_DESC_UNUSED(R)	\
	((((R)->next_to_clean > (R)->next_to_use) ? 0 : (R)->count) + \
	(R)->next_to_clean - (R)->next_to_use - 1)

/* bitfields for Tx queue mapping in QTX_CTL */
#define AVF_QTX_CTL_VF_QUEUE	0x0
#define AVF_QTX_CTL_VM_QUEUE	0x1
#define AVF_QTX_CTL_PF_QUEUE	0x2

/* debug masks - set these bits in hw->debug_mask to control output */
enum avf_debug_mask {
	AVF_DEBUG_INIT			= 0x00000001,
	AVF_DEBUG_RELEASE		= 0x00000002,

	AVF_DEBUG_LINK			= 0x00000010,
	AVF_DEBUG_PHY			= 0x00000020,
	AVF_DEBUG_HMC			= 0x00000040,
	AVF_DEBUG_NVM			= 0x00000080,
	AVF_DEBUG_LAN			= 0x00000100,
	AVF_DEBUG_FLOW			= 0x00000200,
	AVF_DEBUG_DCB			= 0x00000400,
	AVF_DEBUG_DIAG			= 0x00000800,
	AVF_DEBUG_FD			= 0x00001000,
	AVF_DEBUG_PACKAGE		= 0x00002000,

	AVF_DEBUG_AQ_MESSAGE		= 0x01000000,
	AVF_DEBUG_AQ_DESCRIPTOR	= 0x02000000,
	AVF_DEBUG_AQ_DESC_BUFFER	= 0x04000000,
	AVF_DEBUG_AQ_COMMAND		= 0x06000000,
	AVF_DEBUG_AQ			= 0x0F000000,

	AVF_DEBUG_USER			= 0xF0000000,

	AVF_DEBUG_ALL			= 0xFFFFFFFF
};

/* PCI Bus Info */
#define AVF_PCI_LINK_STATUS		0xB2
#define AVF_PCI_LINK_WIDTH		0x3F0
#define AVF_PCI_LINK_WIDTH_1		0x10
#define AVF_PCI_LINK_WIDTH_2		0x20
#define AVF_PCI_LINK_WIDTH_4		0x40
#define AVF_PCI_LINK_WIDTH_8		0x80
#define AVF_PCI_LINK_SPEED		0xF
#define AVF_PCI_LINK_SPEED_2500	0x1
#define AVF_PCI_LINK_SPEED_5000	0x2
#define AVF_PCI_LINK_SPEED_8000	0x3

#define AVF_MDIO_CLAUSE22_STCODE_MASK	AVF_MASK(1, \
						  AVF_GLGEN_MSCA_STCODE_SHIFT)
#define AVF_MDIO_CLAUSE22_OPCODE_WRITE_MASK	AVF_MASK(1, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)
#define AVF_MDIO_CLAUSE22_OPCODE_READ_MASK	AVF_MASK(2, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)

#define AVF_MDIO_CLAUSE45_STCODE_MASK	AVF_MASK(0, \
						  AVF_GLGEN_MSCA_STCODE_SHIFT)
#define AVF_MDIO_CLAUSE45_OPCODE_ADDRESS_MASK	AVF_MASK(0, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)
#define AVF_MDIO_CLAUSE45_OPCODE_WRITE_MASK	AVF_MASK(1, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)
#define AVF_MDIO_CLAUSE45_OPCODE_READ_INC_ADDR_MASK	AVF_MASK(2, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)
#define AVF_MDIO_CLAUSE45_OPCODE_READ_MASK	AVF_MASK(3, \
						  AVF_GLGEN_MSCA_OPCODE_SHIFT)

#define AVF_PHY_COM_REG_PAGE			0x1E
#define AVF_PHY_LED_LINK_MODE_MASK		0xF0
#define AVF_PHY_LED_MANUAL_ON			0x100
#define AVF_PHY_LED_PROV_REG_1			0xC430
#define AVF_PHY_LED_MODE_MASK			0xFFFF
#define AVF_PHY_LED_MODE_ORIG			0x80000000

/* Memory types */
enum avf_memset_type {
	AVF_NONDMA_MEM = 0,
	AVF_DMA_MEM
};

/* Memcpy types */
enum avf_memcpy_type {
	AVF_NONDMA_TO_NONDMA = 0,
	AVF_NONDMA_TO_DMA,
	AVF_DMA_TO_DMA,
	AVF_DMA_TO_NONDMA
};

/* These are structs for managing the hardware information and the operations.
 * The structures of function pointers are filled out at init time when we
 * know for sure exactly which hardware we're working with.  This gives us the
 * flexibility of using the same main driver code but adapting to slightly
 * different hardware needs as new parts are developed.  For this architecture,
 * the Firmware and AdminQ are intended to insulate the driver from most of the
 * future changes, but these structures will also do part of the job.
 */
enum avf_mac_type {
	AVF_MAC_UNKNOWN = 0,
	AVF_MAC_XL710,
	AVF_MAC_VF,
	AVF_MAC_X722,
	AVF_MAC_X722_VF,
	AVF_MAC_GENERIC,
};

enum avf_media_type {
	AVF_MEDIA_TYPE_UNKNOWN = 0,
	AVF_MEDIA_TYPE_FIBER,
	AVF_MEDIA_TYPE_BASET,
	AVF_MEDIA_TYPE_BACKPLANE,
	AVF_MEDIA_TYPE_CX4,
	AVF_MEDIA_TYPE_DA,
	AVF_MEDIA_TYPE_VIRTUAL
};

enum avf_fc_mode {
	AVF_FC_NONE = 0,
	AVF_FC_RX_PAUSE,
	AVF_FC_TX_PAUSE,
	AVF_FC_FULL,
	AVF_FC_PFC,
	AVF_FC_DEFAULT
};

enum avf_set_fc_aq_failures {
	AVF_SET_FC_AQ_FAIL_NONE = 0,
	AVF_SET_FC_AQ_FAIL_GET = 1,
	AVF_SET_FC_AQ_FAIL_SET = 2,
	AVF_SET_FC_AQ_FAIL_UPDATE = 4,
	AVF_SET_FC_AQ_FAIL_SET_UPDATE = 6
};

enum avf_vsi_type {
	AVF_VSI_MAIN	= 0,
	AVF_VSI_VMDQ1	= 1,
	AVF_VSI_VMDQ2	= 2,
	AVF_VSI_CTRL	= 3,
	AVF_VSI_FCOE	= 4,
	AVF_VSI_MIRROR	= 5,
	AVF_VSI_SRIOV	= 6,
	AVF_VSI_FDIR	= 7,
	AVF_VSI_TYPE_UNKNOWN
};

enum avf_queue_type {
	AVF_QUEUE_TYPE_RX = 0,
	AVF_QUEUE_TYPE_TX,
	AVF_QUEUE_TYPE_PE_CEQ,
	AVF_QUEUE_TYPE_UNKNOWN
};

struct avf_link_status {
	enum avf_aq_phy_type phy_type;
	enum avf_aq_link_speed link_speed;
	u8 link_info;
	u8 an_info;
	u8 req_fec_info;
	u8 fec_info;
	u8 ext_info;
	u8 loopback;
	/* is Link Status Event notification to SW enabled */
	bool lse_enable;
	u16 max_frame_size;
	bool crc_enable;
	u8 pacing;
	u8 requested_speeds;
	u8 module_type[3];
	/* 1st byte: module identifier */
#define AVF_MODULE_TYPE_SFP		0x03
#define AVF_MODULE_TYPE_QSFP		0x0D
	/* 2nd byte: ethernet compliance codes for 10/40G */
#define AVF_MODULE_TYPE_40G_ACTIVE	0x01
#define AVF_MODULE_TYPE_40G_LR4	0x02
#define AVF_MODULE_TYPE_40G_SR4	0x04
#define AVF_MODULE_TYPE_40G_CR4	0x08
#define AVF_MODULE_TYPE_10G_BASE_SR	0x10
#define AVF_MODULE_TYPE_10G_BASE_LR	0x20
#define AVF_MODULE_TYPE_10G_BASE_LRM	0x40
#define AVF_MODULE_TYPE_10G_BASE_ER	0x80
	/* 3rd byte: ethernet compliance codes for 1G */
#define AVF_MODULE_TYPE_1000BASE_SX	0x01
#define AVF_MODULE_TYPE_1000BASE_LX	0x02
#define AVF_MODULE_TYPE_1000BASE_CX	0x04
#define AVF_MODULE_TYPE_1000BASE_T	0x08
};

struct avf_phy_info {
	struct avf_link_status link_info;
	struct avf_link_status link_info_old;
	bool get_link_info;
	enum avf_media_type media_type;
	/* all the phy types the NVM is capable of */
	u64 phy_types;
};

#define AVF_CAP_PHY_TYPE_SGMII BIT_ULL(AVF_PHY_TYPE_SGMII)
#define AVF_CAP_PHY_TYPE_1000BASE_KX BIT_ULL(AVF_PHY_TYPE_1000BASE_KX)
#define AVF_CAP_PHY_TYPE_10GBASE_KX4 BIT_ULL(AVF_PHY_TYPE_10GBASE_KX4)
#define AVF_CAP_PHY_TYPE_10GBASE_KR BIT_ULL(AVF_PHY_TYPE_10GBASE_KR)
#define AVF_CAP_PHY_TYPE_40GBASE_KR4 BIT_ULL(AVF_PHY_TYPE_40GBASE_KR4)
#define AVF_CAP_PHY_TYPE_XAUI BIT_ULL(AVF_PHY_TYPE_XAUI)
#define AVF_CAP_PHY_TYPE_XFI BIT_ULL(AVF_PHY_TYPE_XFI)
#define AVF_CAP_PHY_TYPE_SFI BIT_ULL(AVF_PHY_TYPE_SFI)
#define AVF_CAP_PHY_TYPE_XLAUI BIT_ULL(AVF_PHY_TYPE_XLAUI)
#define AVF_CAP_PHY_TYPE_XLPPI BIT_ULL(AVF_PHY_TYPE_XLPPI)
#define AVF_CAP_PHY_TYPE_40GBASE_CR4_CU BIT_ULL(AVF_PHY_TYPE_40GBASE_CR4_CU)
#define AVF_CAP_PHY_TYPE_10GBASE_CR1_CU BIT_ULL(AVF_PHY_TYPE_10GBASE_CR1_CU)
#define AVF_CAP_PHY_TYPE_10GBASE_AOC BIT_ULL(AVF_PHY_TYPE_10GBASE_AOC)
#define AVF_CAP_PHY_TYPE_40GBASE_AOC BIT_ULL(AVF_PHY_TYPE_40GBASE_AOC)
#define AVF_CAP_PHY_TYPE_100BASE_TX BIT_ULL(AVF_PHY_TYPE_100BASE_TX)
#define AVF_CAP_PHY_TYPE_1000BASE_T BIT_ULL(AVF_PHY_TYPE_1000BASE_T)
#define AVF_CAP_PHY_TYPE_10GBASE_T BIT_ULL(AVF_PHY_TYPE_10GBASE_T)
#define AVF_CAP_PHY_TYPE_10GBASE_SR BIT_ULL(AVF_PHY_TYPE_10GBASE_SR)
#define AVF_CAP_PHY_TYPE_10GBASE_LR BIT_ULL(AVF_PHY_TYPE_10GBASE_LR)
#define AVF_CAP_PHY_TYPE_10GBASE_SFPP_CU BIT_ULL(AVF_PHY_TYPE_10GBASE_SFPP_CU)
#define AVF_CAP_PHY_TYPE_10GBASE_CR1 BIT_ULL(AVF_PHY_TYPE_10GBASE_CR1)
#define AVF_CAP_PHY_TYPE_40GBASE_CR4 BIT_ULL(AVF_PHY_TYPE_40GBASE_CR4)
#define AVF_CAP_PHY_TYPE_40GBASE_SR4 BIT_ULL(AVF_PHY_TYPE_40GBASE_SR4)
#define AVF_CAP_PHY_TYPE_40GBASE_LR4 BIT_ULL(AVF_PHY_TYPE_40GBASE_LR4)
#define AVF_CAP_PHY_TYPE_1000BASE_SX BIT_ULL(AVF_PHY_TYPE_1000BASE_SX)
#define AVF_CAP_PHY_TYPE_1000BASE_LX BIT_ULL(AVF_PHY_TYPE_1000BASE_LX)
#define AVF_CAP_PHY_TYPE_1000BASE_T_OPTICAL \
				BIT_ULL(AVF_PHY_TYPE_1000BASE_T_OPTICAL)
#define AVF_CAP_PHY_TYPE_20GBASE_KR2 BIT_ULL(AVF_PHY_TYPE_20GBASE_KR2)
/*
 * Defining the macro AVF_TYPE_OFFSET to implement a bit shift for some
 * PHY types. There is an unused bit (31) in the AVF_CAP_PHY_TYPE_* bit
 * fields but no corresponding gap in the avf_aq_phy_type enumeration. So,
 * a shift is needed to adjust for this with values larger than 31. The
 * only affected values are AVF_PHY_TYPE_25GBASE_*.
 */
#define AVF_PHY_TYPE_OFFSET 1
#define AVF_CAP_PHY_TYPE_25GBASE_KR BIT_ULL(AVF_PHY_TYPE_25GBASE_KR + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_CAP_PHY_TYPE_25GBASE_CR BIT_ULL(AVF_PHY_TYPE_25GBASE_CR + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_CAP_PHY_TYPE_25GBASE_SR BIT_ULL(AVF_PHY_TYPE_25GBASE_SR + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_CAP_PHY_TYPE_25GBASE_LR BIT_ULL(AVF_PHY_TYPE_25GBASE_LR + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_CAP_PHY_TYPE_25GBASE_AOC BIT_ULL(AVF_PHY_TYPE_25GBASE_AOC + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_CAP_PHY_TYPE_25GBASE_ACC BIT_ULL(AVF_PHY_TYPE_25GBASE_ACC + \
					     AVF_PHY_TYPE_OFFSET)
#define AVF_HW_CAP_MAX_GPIO			30
#define AVF_HW_CAP_MDIO_PORT_MODE_MDIO		0
#define AVF_HW_CAP_MDIO_PORT_MODE_I2C		1

enum avf_acpi_programming_method {
	AVF_ACPI_PROGRAMMING_METHOD_HW_FVL = 0,
	AVF_ACPI_PROGRAMMING_METHOD_AQC_FPK = 1
};

#define AVF_WOL_SUPPORT_MASK			0x1
#define AVF_ACPI_PROGRAMMING_METHOD_MASK	0x2
#define AVF_PROXY_SUPPORT_MASK			0x4

/* Capabilities of a PF or a VF or the whole device */
struct avf_hw_capabilities {
	u32  switch_mode;
#define AVF_NVM_IMAGE_TYPE_EVB		0x0
#define AVF_NVM_IMAGE_TYPE_CLOUD	0x2
#define AVF_NVM_IMAGE_TYPE_UDP_CLOUD	0x3

	u32  management_mode;
	u32  mng_protocols_over_mctp;
#define AVF_MNG_PROTOCOL_PLDM		0x2
#define AVF_MNG_PROTOCOL_OEM_COMMANDS	0x4
#define AVF_MNG_PROTOCOL_NCSI		0x8
	u32  npar_enable;
	u32  os2bmc;
	u32  valid_functions;
	bool sr_iov_1_1;
	bool vmdq;
	bool evb_802_1_qbg; /* Edge Virtual Bridging */
	bool evb_802_1_qbh; /* Bridge Port Extension */
	bool dcb;
	bool fcoe;
	bool iscsi; /* Indicates iSCSI enabled */
	bool flex10_enable;
	bool flex10_capable;
	u32  flex10_mode;
#define AVF_FLEX10_MODE_UNKNOWN	0x0
#define AVF_FLEX10_MODE_DCC		0x1
#define AVF_FLEX10_MODE_DCI		0x2

	u32 flex10_status;
#define AVF_FLEX10_STATUS_DCC_ERROR	0x1
#define AVF_FLEX10_STATUS_VC_MODE	0x2

	bool sec_rev_disabled;
	bool update_disabled;
#define AVF_NVM_MGMT_SEC_REV_DISABLED	0x1
#define AVF_NVM_MGMT_UPDATE_DISABLED	0x2

	bool mgmt_cem;
	bool ieee_1588;
	bool iwarp;
	bool fd;
	u32 fd_filters_guaranteed;
	u32 fd_filters_best_effort;
	bool rss;
	u32 rss_table_size;
	u32 rss_table_entry_width;
	bool led[AVF_HW_CAP_MAX_GPIO];
	bool sdp[AVF_HW_CAP_MAX_GPIO];
	u32 nvm_image_type;
	u32 num_flow_director_filters;
	u32 num_vfs;
	u32 vf_base_id;
	u32 num_vsis;
	u32 num_rx_qp;
	u32 num_tx_qp;
	u32 base_queue;
	u32 num_msix_vectors;
	u32 num_msix_vectors_vf;
	u32 led_pin_num;
	u32 sdp_pin_num;
	u32 mdio_port_num;
	u32 mdio_port_mode;
	u8 rx_buf_chain_len;
	u32 enabled_tcmap;
	u32 maxtc;
	u64 wr_csr_prot;
	bool apm_wol_support;
	enum avf_acpi_programming_method acpi_prog_method;
	bool proxy_support;
};

struct avf_mac_info {
	enum avf_mac_type type;
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
	u8 san_addr[ETH_ALEN];
	u8 port_addr[ETH_ALEN];
	u16 max_fcoeq;
};

enum avf_aq_resources_ids {
	AVF_NVM_RESOURCE_ID = 1
};

enum avf_aq_resource_access_type {
	AVF_RESOURCE_READ = 1,
	AVF_RESOURCE_WRITE
};

struct avf_nvm_info {
	u64 hw_semaphore_timeout; /* usec global time (GTIME resolution) */
	u32 timeout;              /* [ms] */
	u16 sr_size;              /* Shadow RAM size in words */
	bool blank_nvm_mode;      /* is NVM empty (no FW present)*/
	u16 version;              /* NVM package version */
	u32 eetrack;              /* NVM data version */
	u32 oem_ver;              /* OEM version info */
};

/* definitions used in NVM update support */

enum avf_nvmupd_cmd {
	AVF_NVMUPD_INVALID,
	AVF_NVMUPD_READ_CON,
	AVF_NVMUPD_READ_SNT,
	AVF_NVMUPD_READ_LCB,
	AVF_NVMUPD_READ_SA,
	AVF_NVMUPD_WRITE_ERA,
	AVF_NVMUPD_WRITE_CON,
	AVF_NVMUPD_WRITE_SNT,
	AVF_NVMUPD_WRITE_LCB,
	AVF_NVMUPD_WRITE_SA,
	AVF_NVMUPD_CSUM_CON,
	AVF_NVMUPD_CSUM_SA,
	AVF_NVMUPD_CSUM_LCB,
	AVF_NVMUPD_STATUS,
	AVF_NVMUPD_EXEC_AQ,
	AVF_NVMUPD_GET_AQ_RESULT,
	AVF_NVMUPD_GET_AQ_EVENT,
};

enum avf_nvmupd_state {
	AVF_NVMUPD_STATE_INIT,
	AVF_NVMUPD_STATE_READING,
	AVF_NVMUPD_STATE_WRITING,
	AVF_NVMUPD_STATE_INIT_WAIT,
	AVF_NVMUPD_STATE_WRITE_WAIT,
	AVF_NVMUPD_STATE_ERROR
};

/* nvm_access definition and its masks/shifts need to be accessible to
 * application, core driver, and shared code.  Where is the right file?
 */
#define AVF_NVM_READ	0xB
#define AVF_NVM_WRITE	0xC

#define AVF_NVM_MOD_PNT_MASK 0xFF

#define AVF_NVM_TRANS_SHIFT			8
#define AVF_NVM_TRANS_MASK			(0xf << AVF_NVM_TRANS_SHIFT)
#define AVF_NVM_PRESERVATION_FLAGS_SHIFT	12
#define AVF_NVM_PRESERVATION_FLAGS_MASK \
				(0x3 << AVF_NVM_PRESERVATION_FLAGS_SHIFT)
#define AVF_NVM_PRESERVATION_FLAGS_SELECTED	0x01
#define AVF_NVM_PRESERVATION_FLAGS_ALL		0x02
#define AVF_NVM_CON				0x0
#define AVF_NVM_SNT				0x1
#define AVF_NVM_LCB				0x2
#define AVF_NVM_SA				(AVF_NVM_SNT | AVF_NVM_LCB)
#define AVF_NVM_ERA				0x4
#define AVF_NVM_CSUM				0x8
#define AVF_NVM_AQE				0xe
#define AVF_NVM_EXEC				0xf

#define AVF_NVM_ADAPT_SHIFT	16
#define AVF_NVM_ADAPT_MASK	(0xffffULL << AVF_NVM_ADAPT_SHIFT)

#define AVF_NVMUPD_MAX_DATA	4096
#define AVF_NVMUPD_IFACE_TIMEOUT 2 /* seconds */

struct avf_nvm_access {
	u32 command;
	u32 config;
	u32 offset;	/* in bytes */
	u32 data_size;	/* in bytes */
	u8 data[1];
};

/* (Q)SFP module access definitions */
#define AVF_I2C_EEPROM_DEV_ADDR	0xA0
#define AVF_I2C_EEPROM_DEV_ADDR2	0xA2
#define AVF_MODULE_TYPE_ADDR		0x00
#define AVF_MODULE_REVISION_ADDR	0x01
#define AVF_MODULE_SFF_8472_COMP	0x5E
#define AVF_MODULE_SFF_8472_SWAP	0x5C
#define AVF_MODULE_SFF_ADDR_MODE	0x04
#define AVF_MODULE_SFF_DIAG_CAPAB	0x40
#define AVF_MODULE_TYPE_QSFP_PLUS	0x0D
#define AVF_MODULE_TYPE_QSFP28		0x11
#define AVF_MODULE_QSFP_MAX_LEN	640

/* PCI bus types */
enum avf_bus_type {
	avf_bus_type_unknown = 0,
	avf_bus_type_pci,
	avf_bus_type_pcix,
	avf_bus_type_pci_express,
	avf_bus_type_reserved
};

/* PCI bus speeds */
enum avf_bus_speed {
	avf_bus_speed_unknown	= 0,
	avf_bus_speed_33	= 33,
	avf_bus_speed_66	= 66,
	avf_bus_speed_100	= 100,
	avf_bus_speed_120	= 120,
	avf_bus_speed_133	= 133,
	avf_bus_speed_2500	= 2500,
	avf_bus_speed_5000	= 5000,
	avf_bus_speed_8000	= 8000,
	avf_bus_speed_reserved
};

/* PCI bus widths */
enum avf_bus_width {
	avf_bus_width_unknown	= 0,
	avf_bus_width_pcie_x1	= 1,
	avf_bus_width_pcie_x2	= 2,
	avf_bus_width_pcie_x4	= 4,
	avf_bus_width_pcie_x8	= 8,
	avf_bus_width_32	= 32,
	avf_bus_width_64	= 64,
	avf_bus_width_reserved
};

/* Bus parameters */
struct avf_bus_info {
	enum avf_bus_speed speed;
	enum avf_bus_width width;
	enum avf_bus_type type;

	u16 func;
	u16 device;
	u16 lan_id;
	u16 bus_id;
};

/* Flow control (FC) parameters */
struct avf_fc_info {
	enum avf_fc_mode current_mode; /* FC mode in effect */
	enum avf_fc_mode requested_mode; /* FC mode requested by caller */
};

#define AVF_MAX_TRAFFIC_CLASS		8
#define AVF_MAX_USER_PRIORITY		8
#define AVF_DCBX_MAX_APPS		32
#define AVF_LLDPDU_SIZE		1500
#define AVF_TLV_STATUS_OPER		0x1
#define AVF_TLV_STATUS_SYNC		0x2
#define AVF_TLV_STATUS_ERR		0x4
#define AVF_CEE_OPER_MAX_APPS		3
#define AVF_APP_PROTOID_FCOE		0x8906
#define AVF_APP_PROTOID_ISCSI		0x0cbc
#define AVF_APP_PROTOID_FIP		0x8914
#define AVF_APP_SEL_ETHTYPE		0x1
#define AVF_APP_SEL_TCPIP		0x2
#define AVF_CEE_APP_SEL_ETHTYPE	0x0
#define AVF_CEE_APP_SEL_TCPIP		0x1

/* CEE or IEEE 802.1Qaz ETS Configuration data */
struct avf_dcb_ets_config {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prioritytable[AVF_MAX_TRAFFIC_CLASS];
	u8 tcbwtable[AVF_MAX_TRAFFIC_CLASS];
	u8 tsatable[AVF_MAX_TRAFFIC_CLASS];
};

/* CEE or IEEE 802.1Qaz PFC Configuration data */
struct avf_dcb_pfc_config {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcenable;
};

/* CEE or IEEE 802.1Qaz Application Priority data */
struct avf_dcb_app_priority_table {
	u8  priority;
	u8  selector;
	u16 protocolid;
};

struct avf_dcbx_config {
	u8  dcbx_mode;
#define AVF_DCBX_MODE_CEE	0x1
#define AVF_DCBX_MODE_IEEE	0x2
	u8  app_mode;
#define AVF_DCBX_APPS_NON_WILLING	0x1
	u32 numapps;
	u32 tlv_status; /* CEE mode TLV status */
	struct avf_dcb_ets_config etscfg;
	struct avf_dcb_ets_config etsrec;
	struct avf_dcb_pfc_config pfc;
	struct avf_dcb_app_priority_table app[AVF_DCBX_MAX_APPS];
};

/* Port hardware description */
struct avf_hw {
	u8 *hw_addr;
	void *back;

	/* subsystem structs */
	struct avf_phy_info phy;
	struct avf_mac_info mac;
	struct avf_bus_info bus;
	struct avf_nvm_info nvm;
	struct avf_fc_info fc;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;
	u8 port;
	bool adapter_stopped;

	/* capabilities for entire device and PCI func */
	struct avf_hw_capabilities dev_caps;
	struct avf_hw_capabilities func_caps;

	/* Flow Director shared filter space */
	u16 fdir_shared_filter_count;

	/* device profile info */
	u8  pf_id;
	u16 main_vsi_seid;

	/* for multi-function MACs */
	u16 partition_id;
	u16 num_partitions;
	u16 num_ports;

	/* Closest numa node to the device */
	u16 numa_node;

	/* Admin Queue info */
	struct avf_adminq_info aq;

	/* state of nvm update process */
	enum avf_nvmupd_state nvmupd_state;
	struct avf_aq_desc nvm_wb_desc;
	struct avf_aq_desc nvm_aq_event_desc;
	struct avf_virt_mem nvm_buff;
	bool nvm_release_on_done;
	u16 nvm_wait_opcode;

	/* HMC info */
	struct avf_hmc_info hmc; /* HMC info struct */

	/* LLDP/DCBX Status */
	u16 dcbx_status;

	/* DCBX info */
	struct avf_dcbx_config local_dcbx_config; /* Oper/Local Cfg */
	struct avf_dcbx_config remote_dcbx_config; /* Peer Cfg */
	struct avf_dcbx_config desired_dcbx_config; /* CEE Desired Cfg */

	/* WoL and proxy support */
	u16 num_wol_proxy_filters;
	u16 wol_proxy_vsi_seid;

#define AVF_HW_FLAG_AQ_SRCTL_ACCESS_ENABLE BIT_ULL(0)
#define AVF_HW_FLAG_802_1AD_CAPABLE        BIT_ULL(1)
#define AVF_HW_FLAG_AQ_PHY_ACCESS_CAPABLE  BIT_ULL(2)
#define AVF_HW_FLAG_NVM_READ_REQUIRES_LOCK BIT_ULL(3)
	u64 flags;

	/* Used in set switch config AQ command */
	u16 switch_tag;
	u16 first_tag;
	u16 second_tag;

	/* debug mask */
	u32 debug_mask;
	char err_str[16];
};

STATIC INLINE bool avf_is_vf(struct avf_hw *hw)
{
	return (hw->mac.type == AVF_MAC_VF ||
		hw->mac.type == AVF_MAC_X722_VF);
}

struct avf_driver_version {
	u8 major_version;
	u8 minor_version;
	u8 build_version;
	u8 subbuild_version;
	u8 driver_string[32];
};

/* RX Descriptors */
union avf_16byte_rx_desc {
	struct {
		__le64 pkt_addr; /* Packet buffer address */
		__le64 hdr_addr; /* Header buffer address */
	} read;
	struct {
		struct {
			struct {
				union {
					__le16 mirroring_status;
					__le16 fcoe_ctx_id;
				} mirr_fcoe;
				__le16 l2tag1;
			} lo_dword;
			union {
				__le32 rss; /* RSS Hash */
				__le32 fd_id; /* Flow director filter id */
				__le32 fcoe_param; /* FCoE DDP Context id */
			} hi_dword;
		} qword0;
		struct {
			/* ext status/error/pktype/length */
			__le64 status_error_len;
		} qword1;
	} wb;  /* writeback */
};

union avf_32byte_rx_desc {
	struct {
		__le64  pkt_addr; /* Packet buffer address */
		__le64  hdr_addr; /* Header buffer address */
			/* bit 0 of hdr_buffer_addr is DD bit */
		__le64  rsvd1;
		__le64  rsvd2;
	} read;
	struct {
		struct {
			struct {
				union {
					__le16 mirroring_status;
					__le16 fcoe_ctx_id;
				} mirr_fcoe;
				__le16 l2tag1;
			} lo_dword;
			union {
				__le32 rss; /* RSS Hash */
				__le32 fcoe_param; /* FCoE DDP Context id */
				/* Flow director filter id in case of
				 * Programming status desc WB
				 */
				__le32 fd_id;
			} hi_dword;
		} qword0;
		struct {
			/* status/error/pktype/length */
			__le64 status_error_len;
		} qword1;
		struct {
			__le16 ext_status; /* extended status */
			__le16 rsvd;
			__le16 l2tag2_1;
			__le16 l2tag2_2;
		} qword2;
		struct {
			union {
				__le32 flex_bytes_lo;
				__le32 pe_status;
			} lo_dword;
			union {
				__le32 flex_bytes_hi;
				__le32 fd_id;
			} hi_dword;
		} qword3;
	} wb;  /* writeback */
};

#define AVF_RXD_QW0_MIRROR_STATUS_SHIFT	8
#define AVF_RXD_QW0_MIRROR_STATUS_MASK	(0x3FUL << \
					 AVF_RXD_QW0_MIRROR_STATUS_SHIFT)
#define AVF_RXD_QW0_FCOEINDX_SHIFT	0
#define AVF_RXD_QW0_FCOEINDX_MASK	(0xFFFUL << \
					 AVF_RXD_QW0_FCOEINDX_SHIFT)

enum avf_rx_desc_status_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_DESC_STATUS_DD_SHIFT		= 0,
	AVF_RX_DESC_STATUS_EOF_SHIFT		= 1,
	AVF_RX_DESC_STATUS_L2TAG1P_SHIFT	= 2,
	AVF_RX_DESC_STATUS_L3L4P_SHIFT		= 3,
	AVF_RX_DESC_STATUS_CRCP_SHIFT		= 4,
	AVF_RX_DESC_STATUS_TSYNINDX_SHIFT	= 5, /* 2 BITS */
	AVF_RX_DESC_STATUS_TSYNVALID_SHIFT	= 7,
	AVF_RX_DESC_STATUS_EXT_UDP_0_SHIFT	= 8,

	AVF_RX_DESC_STATUS_UMBCAST_SHIFT	= 9, /* 2 BITS */
	AVF_RX_DESC_STATUS_FLM_SHIFT		= 11,
	AVF_RX_DESC_STATUS_FLTSTAT_SHIFT	= 12, /* 2 BITS */
	AVF_RX_DESC_STATUS_LPBK_SHIFT		= 14,
	AVF_RX_DESC_STATUS_IPV6EXADD_SHIFT	= 15,
	AVF_RX_DESC_STATUS_RESERVED2_SHIFT	= 16, /* 2 BITS */
	AVF_RX_DESC_STATUS_INT_UDP_0_SHIFT	= 18,
	AVF_RX_DESC_STATUS_LAST /* this entry must be last!!! */
};

#define AVF_RXD_QW1_STATUS_SHIFT	0
#define AVF_RXD_QW1_STATUS_MASK	((BIT(AVF_RX_DESC_STATUS_LAST) - 1) << \
					 AVF_RXD_QW1_STATUS_SHIFT)

#define AVF_RXD_QW1_STATUS_TSYNINDX_SHIFT   AVF_RX_DESC_STATUS_TSYNINDX_SHIFT
#define AVF_RXD_QW1_STATUS_TSYNINDX_MASK	(0x3UL << \
					     AVF_RXD_QW1_STATUS_TSYNINDX_SHIFT)

#define AVF_RXD_QW1_STATUS_TSYNVALID_SHIFT  AVF_RX_DESC_STATUS_TSYNVALID_SHIFT
#define AVF_RXD_QW1_STATUS_TSYNVALID_MASK   BIT_ULL(AVF_RXD_QW1_STATUS_TSYNVALID_SHIFT)

#define AVF_RXD_QW1_STATUS_UMBCAST_SHIFT	AVF_RX_DESC_STATUS_UMBCAST
#define AVF_RXD_QW1_STATUS_UMBCAST_MASK	(0x3UL << \
					 AVF_RXD_QW1_STATUS_UMBCAST_SHIFT)

enum avf_rx_desc_fltstat_values {
	AVF_RX_DESC_FLTSTAT_NO_DATA	= 0,
	AVF_RX_DESC_FLTSTAT_RSV_FD_ID	= 1, /* 16byte desc? FD_ID : RSV */
	AVF_RX_DESC_FLTSTAT_RSV	= 2,
	AVF_RX_DESC_FLTSTAT_RSS_HASH	= 3,
};

#define AVF_RXD_PACKET_TYPE_UNICAST	0
#define AVF_RXD_PACKET_TYPE_MULTICAST	1
#define AVF_RXD_PACKET_TYPE_BROADCAST	2
#define AVF_RXD_PACKET_TYPE_MIRRORED	3

#define AVF_RXD_QW1_ERROR_SHIFT	19
#define AVF_RXD_QW1_ERROR_MASK		(0xFFUL << AVF_RXD_QW1_ERROR_SHIFT)

enum avf_rx_desc_error_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_DESC_ERROR_RXE_SHIFT		= 0,
	AVF_RX_DESC_ERROR_RECIPE_SHIFT		= 1,
	AVF_RX_DESC_ERROR_HBO_SHIFT		= 2,
	AVF_RX_DESC_ERROR_L3L4E_SHIFT		= 3, /* 3 BITS */
	AVF_RX_DESC_ERROR_IPE_SHIFT		= 3,
	AVF_RX_DESC_ERROR_L4E_SHIFT		= 4,
	AVF_RX_DESC_ERROR_EIPE_SHIFT		= 5,
	AVF_RX_DESC_ERROR_OVERSIZE_SHIFT	= 6,
	AVF_RX_DESC_ERROR_PPRS_SHIFT		= 7
};

enum avf_rx_desc_error_l3l4e_fcoe_masks {
	AVF_RX_DESC_ERROR_L3L4E_NONE		= 0,
	AVF_RX_DESC_ERROR_L3L4E_PROT		= 1,
	AVF_RX_DESC_ERROR_L3L4E_FC		= 2,
	AVF_RX_DESC_ERROR_L3L4E_DMAC_ERR	= 3,
	AVF_RX_DESC_ERROR_L3L4E_DMAC_WARN	= 4
};

#define AVF_RXD_QW1_PTYPE_SHIFT	30
#define AVF_RXD_QW1_PTYPE_MASK		(0xFFULL << AVF_RXD_QW1_PTYPE_SHIFT)

/* Packet type non-ip values */
enum avf_rx_l2_ptype {
	AVF_RX_PTYPE_L2_RESERVED			= 0,
	AVF_RX_PTYPE_L2_MAC_PAY2			= 1,
	AVF_RX_PTYPE_L2_TIMESYNC_PAY2			= 2,
	AVF_RX_PTYPE_L2_FIP_PAY2			= 3,
	AVF_RX_PTYPE_L2_OUI_PAY2			= 4,
	AVF_RX_PTYPE_L2_MACCNTRL_PAY2			= 5,
	AVF_RX_PTYPE_L2_LLDP_PAY2			= 6,
	AVF_RX_PTYPE_L2_ECP_PAY2			= 7,
	AVF_RX_PTYPE_L2_EVB_PAY2			= 8,
	AVF_RX_PTYPE_L2_QCN_PAY2			= 9,
	AVF_RX_PTYPE_L2_EAPOL_PAY2			= 10,
	AVF_RX_PTYPE_L2_ARP				= 11,
	AVF_RX_PTYPE_L2_FCOE_PAY3			= 12,
	AVF_RX_PTYPE_L2_FCOE_FCDATA_PAY3		= 13,
	AVF_RX_PTYPE_L2_FCOE_FCRDY_PAY3		= 14,
	AVF_RX_PTYPE_L2_FCOE_FCRSP_PAY3		= 15,
	AVF_RX_PTYPE_L2_FCOE_FCOTHER_PA		= 16,
	AVF_RX_PTYPE_L2_FCOE_VFT_PAY3			= 17,
	AVF_RX_PTYPE_L2_FCOE_VFT_FCDATA		= 18,
	AVF_RX_PTYPE_L2_FCOE_VFT_FCRDY			= 19,
	AVF_RX_PTYPE_L2_FCOE_VFT_FCRSP			= 20,
	AVF_RX_PTYPE_L2_FCOE_VFT_FCOTHER		= 21,
	AVF_RX_PTYPE_GRENAT4_MAC_PAY3			= 58,
	AVF_RX_PTYPE_GRENAT4_MACVLAN_IPV6_ICMP_PAY4	= 87,
	AVF_RX_PTYPE_GRENAT6_MAC_PAY3			= 124,
	AVF_RX_PTYPE_GRENAT6_MACVLAN_IPV6_ICMP_PAY4	= 153
};

struct avf_rx_ptype_decoded {
	u32 ptype:8;
	u32 known:1;
	u32 outer_ip:1;
	u32 outer_ip_ver:1;
	u32 outer_frag:1;
	u32 tunnel_type:3;
	u32 tunnel_end_prot:2;
	u32 tunnel_end_frag:1;
	u32 inner_prot:4;
	u32 payload_layer:3;
};

enum avf_rx_ptype_outer_ip {
	AVF_RX_PTYPE_OUTER_L2	= 0,
	AVF_RX_PTYPE_OUTER_IP	= 1
};

enum avf_rx_ptype_outer_ip_ver {
	AVF_RX_PTYPE_OUTER_NONE	= 0,
	AVF_RX_PTYPE_OUTER_IPV4	= 0,
	AVF_RX_PTYPE_OUTER_IPV6	= 1
};

enum avf_rx_ptype_outer_fragmented {
	AVF_RX_PTYPE_NOT_FRAG	= 0,
	AVF_RX_PTYPE_FRAG	= 1
};

enum avf_rx_ptype_tunnel_type {
	AVF_RX_PTYPE_TUNNEL_NONE		= 0,
	AVF_RX_PTYPE_TUNNEL_IP_IP		= 1,
	AVF_RX_PTYPE_TUNNEL_IP_GRENAT		= 2,
	AVF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC	= 3,
	AVF_RX_PTYPE_TUNNEL_IP_GRENAT_MAC_VLAN	= 4,
};

enum avf_rx_ptype_tunnel_end_prot {
	AVF_RX_PTYPE_TUNNEL_END_NONE	= 0,
	AVF_RX_PTYPE_TUNNEL_END_IPV4	= 1,
	AVF_RX_PTYPE_TUNNEL_END_IPV6	= 2,
};

enum avf_rx_ptype_inner_prot {
	AVF_RX_PTYPE_INNER_PROT_NONE		= 0,
	AVF_RX_PTYPE_INNER_PROT_UDP		= 1,
	AVF_RX_PTYPE_INNER_PROT_TCP		= 2,
	AVF_RX_PTYPE_INNER_PROT_SCTP		= 3,
	AVF_RX_PTYPE_INNER_PROT_ICMP		= 4,
	AVF_RX_PTYPE_INNER_PROT_TIMESYNC	= 5
};

enum avf_rx_ptype_payload_layer {
	AVF_RX_PTYPE_PAYLOAD_LAYER_NONE	= 0,
	AVF_RX_PTYPE_PAYLOAD_LAYER_PAY2	= 1,
	AVF_RX_PTYPE_PAYLOAD_LAYER_PAY3	= 2,
	AVF_RX_PTYPE_PAYLOAD_LAYER_PAY4	= 3,
};

#define AVF_RX_PTYPE_BIT_MASK		0x0FFFFFFF
#define AVF_RX_PTYPE_SHIFT		56

#define AVF_RXD_QW1_LENGTH_PBUF_SHIFT	38
#define AVF_RXD_QW1_LENGTH_PBUF_MASK	(0x3FFFULL << \
					 AVF_RXD_QW1_LENGTH_PBUF_SHIFT)

#define AVF_RXD_QW1_LENGTH_HBUF_SHIFT	52
#define AVF_RXD_QW1_LENGTH_HBUF_MASK	(0x7FFULL << \
					 AVF_RXD_QW1_LENGTH_HBUF_SHIFT)

#define AVF_RXD_QW1_LENGTH_SPH_SHIFT	63
#define AVF_RXD_QW1_LENGTH_SPH_MASK	BIT_ULL(AVF_RXD_QW1_LENGTH_SPH_SHIFT)

#define AVF_RXD_QW1_NEXTP_SHIFT	38
#define AVF_RXD_QW1_NEXTP_MASK		(0x1FFFULL << AVF_RXD_QW1_NEXTP_SHIFT)

#define AVF_RXD_QW2_EXT_STATUS_SHIFT	0
#define AVF_RXD_QW2_EXT_STATUS_MASK	(0xFFFFFUL << \
					 AVF_RXD_QW2_EXT_STATUS_SHIFT)

enum avf_rx_desc_ext_status_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_DESC_EXT_STATUS_L2TAG2P_SHIFT	= 0,
	AVF_RX_DESC_EXT_STATUS_L2TAG3P_SHIFT	= 1,
	AVF_RX_DESC_EXT_STATUS_FLEXBL_SHIFT	= 2, /* 2 BITS */
	AVF_RX_DESC_EXT_STATUS_FLEXBH_SHIFT	= 4, /* 2 BITS */
	AVF_RX_DESC_EXT_STATUS_FDLONGB_SHIFT	= 9,
	AVF_RX_DESC_EXT_STATUS_FCOELONGB_SHIFT	= 10,
	AVF_RX_DESC_EXT_STATUS_PELONGB_SHIFT	= 11,
};

#define AVF_RXD_QW2_L2TAG2_SHIFT	0
#define AVF_RXD_QW2_L2TAG2_MASK	(0xFFFFUL << AVF_RXD_QW2_L2TAG2_SHIFT)

#define AVF_RXD_QW2_L2TAG3_SHIFT	16
#define AVF_RXD_QW2_L2TAG3_MASK	(0xFFFFUL << AVF_RXD_QW2_L2TAG3_SHIFT)

enum avf_rx_desc_pe_status_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_DESC_PE_STATUS_QPID_SHIFT	= 0, /* 18 BITS */
	AVF_RX_DESC_PE_STATUS_L4PORT_SHIFT	= 0, /* 16 BITS */
	AVF_RX_DESC_PE_STATUS_IPINDEX_SHIFT	= 16, /* 8 BITS */
	AVF_RX_DESC_PE_STATUS_QPIDHIT_SHIFT	= 24,
	AVF_RX_DESC_PE_STATUS_APBVTHIT_SHIFT	= 25,
	AVF_RX_DESC_PE_STATUS_PORTV_SHIFT	= 26,
	AVF_RX_DESC_PE_STATUS_URG_SHIFT	= 27,
	AVF_RX_DESC_PE_STATUS_IPFRAG_SHIFT	= 28,
	AVF_RX_DESC_PE_STATUS_IPOPT_SHIFT	= 29
};

#define AVF_RX_PROG_STATUS_DESC_LENGTH_SHIFT		38
#define AVF_RX_PROG_STATUS_DESC_LENGTH			0x2000000

#define AVF_RX_PROG_STATUS_DESC_QW1_PROGID_SHIFT	2
#define AVF_RX_PROG_STATUS_DESC_QW1_PROGID_MASK	(0x7UL << \
				AVF_RX_PROG_STATUS_DESC_QW1_PROGID_SHIFT)

#define AVF_RX_PROG_STATUS_DESC_QW1_STATUS_SHIFT	0
#define AVF_RX_PROG_STATUS_DESC_QW1_STATUS_MASK	(0x7FFFUL << \
				AVF_RX_PROG_STATUS_DESC_QW1_STATUS_SHIFT)

#define AVF_RX_PROG_STATUS_DESC_QW1_ERROR_SHIFT	19
#define AVF_RX_PROG_STATUS_DESC_QW1_ERROR_MASK		(0x3FUL << \
				AVF_RX_PROG_STATUS_DESC_QW1_ERROR_SHIFT)

enum avf_rx_prog_status_desc_status_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_PROG_STATUS_DESC_DD_SHIFT	= 0,
	AVF_RX_PROG_STATUS_DESC_PROG_ID_SHIFT	= 2 /* 3 BITS */
};

enum avf_rx_prog_status_desc_prog_id_masks {
	AVF_RX_PROG_STATUS_DESC_FD_FILTER_STATUS	= 1,
	AVF_RX_PROG_STATUS_DESC_FCOE_CTXT_PROG_STATUS	= 2,
	AVF_RX_PROG_STATUS_DESC_FCOE_CTXT_INVL_STATUS	= 4,
};

enum avf_rx_prog_status_desc_error_bits {
	/* Note: These are predefined bit offsets */
	AVF_RX_PROG_STATUS_DESC_FD_TBL_FULL_SHIFT	= 0,
	AVF_RX_PROG_STATUS_DESC_NO_FD_ENTRY_SHIFT	= 1,
	AVF_RX_PROG_STATUS_DESC_FCOE_TBL_FULL_SHIFT	= 2,
	AVF_RX_PROG_STATUS_DESC_FCOE_CONFLICT_SHIFT	= 3
};

#define AVF_TWO_BIT_MASK	0x3
#define AVF_THREE_BIT_MASK	0x7
#define AVF_FOUR_BIT_MASK	0xF
#define AVF_EIGHTEEN_BIT_MASK	0x3FFFF

/* TX Descriptor */
struct avf_tx_desc {
	__le64 buffer_addr; /* Address of descriptor's data buf */
	__le64 cmd_type_offset_bsz;
};

#define AVF_TXD_QW1_DTYPE_SHIFT	0
#define AVF_TXD_QW1_DTYPE_MASK		(0xFUL << AVF_TXD_QW1_DTYPE_SHIFT)

enum avf_tx_desc_dtype_value {
	AVF_TX_DESC_DTYPE_DATA		= 0x0,
	AVF_TX_DESC_DTYPE_NOP		= 0x1, /* same as Context desc */
	AVF_TX_DESC_DTYPE_CONTEXT	= 0x1,
	AVF_TX_DESC_DTYPE_FCOE_CTX	= 0x2,
	AVF_TX_DESC_DTYPE_FILTER_PROG	= 0x8,
	AVF_TX_DESC_DTYPE_DDP_CTX	= 0x9,
	AVF_TX_DESC_DTYPE_FLEX_DATA	= 0xB,
	AVF_TX_DESC_DTYPE_FLEX_CTX_1	= 0xC,
	AVF_TX_DESC_DTYPE_FLEX_CTX_2	= 0xD,
	AVF_TX_DESC_DTYPE_DESC_DONE	= 0xF
};

#define AVF_TXD_QW1_CMD_SHIFT	4
#define AVF_TXD_QW1_CMD_MASK	(0x3FFUL << AVF_TXD_QW1_CMD_SHIFT)

enum avf_tx_desc_cmd_bits {
	AVF_TX_DESC_CMD_EOP			= 0x0001,
	AVF_TX_DESC_CMD_RS			= 0x0002,
	AVF_TX_DESC_CMD_ICRC			= 0x0004,
	AVF_TX_DESC_CMD_IL2TAG1		= 0x0008,
	AVF_TX_DESC_CMD_DUMMY			= 0x0010,
	AVF_TX_DESC_CMD_IIPT_NONIP		= 0x0000, /* 2 BITS */
	AVF_TX_DESC_CMD_IIPT_IPV6		= 0x0020, /* 2 BITS */
	AVF_TX_DESC_CMD_IIPT_IPV4		= 0x0040, /* 2 BITS */
	AVF_TX_DESC_CMD_IIPT_IPV4_CSUM		= 0x0060, /* 2 BITS */
	AVF_TX_DESC_CMD_FCOET			= 0x0080,
	AVF_TX_DESC_CMD_L4T_EOFT_UNK		= 0x0000, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_TCP		= 0x0100, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_SCTP		= 0x0200, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_UDP		= 0x0300, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_EOF_N		= 0x0000, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_EOF_T		= 0x0100, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_EOF_NI	= 0x0200, /* 2 BITS */
	AVF_TX_DESC_CMD_L4T_EOFT_EOF_A		= 0x0300, /* 2 BITS */
};

#define AVF_TXD_QW1_OFFSET_SHIFT	16
#define AVF_TXD_QW1_OFFSET_MASK	(0x3FFFFULL << \
					 AVF_TXD_QW1_OFFSET_SHIFT)

enum avf_tx_desc_length_fields {
	/* Note: These are predefined bit offsets */
	AVF_TX_DESC_LENGTH_MACLEN_SHIFT	= 0, /* 7 BITS */
	AVF_TX_DESC_LENGTH_IPLEN_SHIFT		= 7, /* 7 BITS */
	AVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT	= 14 /* 4 BITS */
};

#define AVF_TXD_QW1_MACLEN_MASK (0x7FUL << AVF_TX_DESC_LENGTH_MACLEN_SHIFT)
#define AVF_TXD_QW1_IPLEN_MASK  (0x7FUL << AVF_TX_DESC_LENGTH_IPLEN_SHIFT)
#define AVF_TXD_QW1_L4LEN_MASK  (0xFUL << AVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT)
#define AVF_TXD_QW1_FCLEN_MASK  (0xFUL << AVF_TX_DESC_LENGTH_L4_FC_LEN_SHIFT)

#define AVF_TXD_QW1_TX_BUF_SZ_SHIFT	34
#define AVF_TXD_QW1_TX_BUF_SZ_MASK	(0x3FFFULL << \
					 AVF_TXD_QW1_TX_BUF_SZ_SHIFT)

#define AVF_TXD_QW1_L2TAG1_SHIFT	48
#define AVF_TXD_QW1_L2TAG1_MASK	(0xFFFFULL << AVF_TXD_QW1_L2TAG1_SHIFT)

/* Context descriptors */
struct avf_tx_context_desc {
	__le32 tunneling_params;
	__le16 l2tag2;
	__le16 rsvd;
	__le64 type_cmd_tso_mss;
};

#define AVF_TXD_CTX_QW1_DTYPE_SHIFT	0
#define AVF_TXD_CTX_QW1_DTYPE_MASK	(0xFUL << AVF_TXD_CTX_QW1_DTYPE_SHIFT)

#define AVF_TXD_CTX_QW1_CMD_SHIFT	4
#define AVF_TXD_CTX_QW1_CMD_MASK	(0xFFFFUL << AVF_TXD_CTX_QW1_CMD_SHIFT)

enum avf_tx_ctx_desc_cmd_bits {
	AVF_TX_CTX_DESC_TSO		= 0x01,
	AVF_TX_CTX_DESC_TSYN		= 0x02,
	AVF_TX_CTX_DESC_IL2TAG2	= 0x04,
	AVF_TX_CTX_DESC_IL2TAG2_IL2H	= 0x08,
	AVF_TX_CTX_DESC_SWTCH_NOTAG	= 0x00,
	AVF_TX_CTX_DESC_SWTCH_UPLINK	= 0x10,
	AVF_TX_CTX_DESC_SWTCH_LOCAL	= 0x20,
	AVF_TX_CTX_DESC_SWTCH_VSI	= 0x30,
	AVF_TX_CTX_DESC_SWPE		= 0x40
};

#define AVF_TXD_CTX_QW1_TSO_LEN_SHIFT	30
#define AVF_TXD_CTX_QW1_TSO_LEN_MASK	(0x3FFFFULL << \
					 AVF_TXD_CTX_QW1_TSO_LEN_SHIFT)

#define AVF_TXD_CTX_QW1_MSS_SHIFT	50
#define AVF_TXD_CTX_QW1_MSS_MASK	(0x3FFFULL << \
					 AVF_TXD_CTX_QW1_MSS_SHIFT)

#define AVF_TXD_CTX_QW1_VSI_SHIFT	50
#define AVF_TXD_CTX_QW1_VSI_MASK	(0x1FFULL << AVF_TXD_CTX_QW1_VSI_SHIFT)

#define AVF_TXD_CTX_QW0_EXT_IP_SHIFT	0
#define AVF_TXD_CTX_QW0_EXT_IP_MASK	(0x3ULL << \
					 AVF_TXD_CTX_QW0_EXT_IP_SHIFT)

enum avf_tx_ctx_desc_eipt_offload {
	AVF_TX_CTX_EXT_IP_NONE		= 0x0,
	AVF_TX_CTX_EXT_IP_IPV6		= 0x1,
	AVF_TX_CTX_EXT_IP_IPV4_NO_CSUM	= 0x2,
	AVF_TX_CTX_EXT_IP_IPV4		= 0x3
};

#define AVF_TXD_CTX_QW0_EXT_IPLEN_SHIFT	2
#define AVF_TXD_CTX_QW0_EXT_IPLEN_MASK	(0x3FULL << \
					 AVF_TXD_CTX_QW0_EXT_IPLEN_SHIFT)

#define AVF_TXD_CTX_QW0_NATT_SHIFT	9
#define AVF_TXD_CTX_QW0_NATT_MASK	(0x3ULL << AVF_TXD_CTX_QW0_NATT_SHIFT)

#define AVF_TXD_CTX_UDP_TUNNELING	BIT_ULL(AVF_TXD_CTX_QW0_NATT_SHIFT)
#define AVF_TXD_CTX_GRE_TUNNELING	(0x2ULL << AVF_TXD_CTX_QW0_NATT_SHIFT)

#define AVF_TXD_CTX_QW0_EIP_NOINC_SHIFT	11
#define AVF_TXD_CTX_QW0_EIP_NOINC_MASK	BIT_ULL(AVF_TXD_CTX_QW0_EIP_NOINC_SHIFT)

#define AVF_TXD_CTX_EIP_NOINC_IPID_CONST	AVF_TXD_CTX_QW0_EIP_NOINC_MASK

#define AVF_TXD_CTX_QW0_NATLEN_SHIFT	12
#define AVF_TXD_CTX_QW0_NATLEN_MASK	(0X7FULL << \
					 AVF_TXD_CTX_QW0_NATLEN_SHIFT)

#define AVF_TXD_CTX_QW0_DECTTL_SHIFT	19
#define AVF_TXD_CTX_QW0_DECTTL_MASK	(0xFULL << \
					 AVF_TXD_CTX_QW0_DECTTL_SHIFT)

#define AVF_TXD_CTX_QW0_L4T_CS_SHIFT	23
#define AVF_TXD_CTX_QW0_L4T_CS_MASK	BIT_ULL(AVF_TXD_CTX_QW0_L4T_CS_SHIFT)
struct avf_nop_desc {
	__le64 rsvd;
	__le64 dtype_cmd;
};

#define AVF_TXD_NOP_QW1_DTYPE_SHIFT	0
#define AVF_TXD_NOP_QW1_DTYPE_MASK	(0xFUL << AVF_TXD_NOP_QW1_DTYPE_SHIFT)

#define AVF_TXD_NOP_QW1_CMD_SHIFT	4
#define AVF_TXD_NOP_QW1_CMD_MASK	(0x7FUL << AVF_TXD_NOP_QW1_CMD_SHIFT)

enum avf_tx_nop_desc_cmd_bits {
	/* Note: These are predefined bit offsets */
	AVF_TX_NOP_DESC_EOP_SHIFT	= 0,
	AVF_TX_NOP_DESC_RS_SHIFT	= 1,
	AVF_TX_NOP_DESC_RSV_SHIFT	= 2 /* 5 bits */
};

struct avf_filter_program_desc {
	__le32 qindex_flex_ptype_vsi;
	__le32 rsvd;
	__le32 dtype_cmd_cntindex;
	__le32 fd_id;
};
#define AVF_TXD_FLTR_QW0_QINDEX_SHIFT	0
#define AVF_TXD_FLTR_QW0_QINDEX_MASK	(0x7FFUL << \
					 AVF_TXD_FLTR_QW0_QINDEX_SHIFT)
#define AVF_TXD_FLTR_QW0_FLEXOFF_SHIFT	11
#define AVF_TXD_FLTR_QW0_FLEXOFF_MASK	(0x7UL << \
					 AVF_TXD_FLTR_QW0_FLEXOFF_SHIFT)
#define AVF_TXD_FLTR_QW0_PCTYPE_SHIFT	17
#define AVF_TXD_FLTR_QW0_PCTYPE_MASK	(0x3FUL << \
					 AVF_TXD_FLTR_QW0_PCTYPE_SHIFT)

/* Packet Classifier Types for filters */
enum avf_filter_pctype {
	/* Note: Values 0-28 are reserved for future use.
	 * Value 29, 30, 32 are not supported on XL710 and X710.
	 */
	AVF_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP	= 29,
	AVF_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP	= 30,
	AVF_FILTER_PCTYPE_NONF_IPV4_UDP		= 31,
	AVF_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK	= 32,
	AVF_FILTER_PCTYPE_NONF_IPV4_TCP		= 33,
	AVF_FILTER_PCTYPE_NONF_IPV4_SCTP		= 34,
	AVF_FILTER_PCTYPE_NONF_IPV4_OTHER		= 35,
	AVF_FILTER_PCTYPE_FRAG_IPV4			= 36,
	/* Note: Values 37-38 are reserved for future use.
	 * Value 39, 40, 42 are not supported on XL710 and X710.
	 */
	AVF_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP	= 39,
	AVF_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP	= 40,
	AVF_FILTER_PCTYPE_NONF_IPV6_UDP		= 41,
	AVF_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK	= 42,
	AVF_FILTER_PCTYPE_NONF_IPV6_TCP		= 43,
	AVF_FILTER_PCTYPE_NONF_IPV6_SCTP		= 44,
	AVF_FILTER_PCTYPE_NONF_IPV6_OTHER		= 45,
	AVF_FILTER_PCTYPE_FRAG_IPV6			= 46,
	/* Note: Value 47 is reserved for future use */
	AVF_FILTER_PCTYPE_FCOE_OX			= 48,
	AVF_FILTER_PCTYPE_FCOE_RX			= 49,
	AVF_FILTER_PCTYPE_FCOE_OTHER			= 50,
	/* Note: Values 51-62 are reserved for future use */
	AVF_FILTER_PCTYPE_L2_PAYLOAD			= 63,
};

enum avf_filter_program_desc_dest {
	AVF_FILTER_PROGRAM_DESC_DEST_DROP_PACKET		= 0x0,
	AVF_FILTER_PROGRAM_DESC_DEST_DIRECT_PACKET_QINDEX	= 0x1,
	AVF_FILTER_PROGRAM_DESC_DEST_DIRECT_PACKET_OTHER	= 0x2,
};

enum avf_filter_program_desc_fd_status {
	AVF_FILTER_PROGRAM_DESC_FD_STATUS_NONE			= 0x0,
	AVF_FILTER_PROGRAM_DESC_FD_STATUS_FD_ID		= 0x1,
	AVF_FILTER_PROGRAM_DESC_FD_STATUS_FD_ID_4FLEX_BYTES	= 0x2,
	AVF_FILTER_PROGRAM_DESC_FD_STATUS_8FLEX_BYTES		= 0x3,
};

#define AVF_TXD_FLTR_QW0_DEST_VSI_SHIFT	23
#define AVF_TXD_FLTR_QW0_DEST_VSI_MASK	(0x1FFUL << \
					 AVF_TXD_FLTR_QW0_DEST_VSI_SHIFT)

#define AVF_TXD_FLTR_QW1_DTYPE_SHIFT	0
#define AVF_TXD_FLTR_QW1_DTYPE_MASK	(0xFUL << AVF_TXD_FLTR_QW1_DTYPE_SHIFT)

#define AVF_TXD_FLTR_QW1_CMD_SHIFT	4
#define AVF_TXD_FLTR_QW1_CMD_MASK	(0xFFFFULL << \
					 AVF_TXD_FLTR_QW1_CMD_SHIFT)

#define AVF_TXD_FLTR_QW1_PCMD_SHIFT	(0x0ULL + AVF_TXD_FLTR_QW1_CMD_SHIFT)
#define AVF_TXD_FLTR_QW1_PCMD_MASK	(0x7ULL << AVF_TXD_FLTR_QW1_PCMD_SHIFT)

enum avf_filter_program_desc_pcmd {
	AVF_FILTER_PROGRAM_DESC_PCMD_ADD_UPDATE	= 0x1,
	AVF_FILTER_PROGRAM_DESC_PCMD_REMOVE		= 0x2,
};

#define AVF_TXD_FLTR_QW1_DEST_SHIFT	(0x3ULL + AVF_TXD_FLTR_QW1_CMD_SHIFT)
#define AVF_TXD_FLTR_QW1_DEST_MASK	(0x3ULL << AVF_TXD_FLTR_QW1_DEST_SHIFT)

#define AVF_TXD_FLTR_QW1_CNT_ENA_SHIFT	(0x7ULL + AVF_TXD_FLTR_QW1_CMD_SHIFT)
#define AVF_TXD_FLTR_QW1_CNT_ENA_MASK	BIT_ULL(AVF_TXD_FLTR_QW1_CNT_ENA_SHIFT)

#define AVF_TXD_FLTR_QW1_FD_STATUS_SHIFT	(0x9ULL + \
						 AVF_TXD_FLTR_QW1_CMD_SHIFT)
#define AVF_TXD_FLTR_QW1_FD_STATUS_MASK (0x3ULL << \
					  AVF_TXD_FLTR_QW1_FD_STATUS_SHIFT)

#define AVF_TXD_FLTR_QW1_ATR_SHIFT	(0xEULL + \
					 AVF_TXD_FLTR_QW1_CMD_SHIFT)
#define AVF_TXD_FLTR_QW1_ATR_MASK	BIT_ULL(AVF_TXD_FLTR_QW1_ATR_SHIFT)

#define AVF_TXD_FLTR_QW1_CNTINDEX_SHIFT 20
#define AVF_TXD_FLTR_QW1_CNTINDEX_MASK	(0x1FFUL << \
					 AVF_TXD_FLTR_QW1_CNTINDEX_SHIFT)

enum avf_filter_type {
	AVF_FLOW_DIRECTOR_FLTR = 0,
	AVF_PE_QUAD_HASH_FLTR = 1,
	AVF_ETHERTYPE_FLTR,
	AVF_FCOE_CTX_FLTR,
	AVF_MAC_VLAN_FLTR,
	AVF_HASH_FLTR
};

struct avf_vsi_context {
	u16 seid;
	u16 uplink_seid;
	u16 vsi_number;
	u16 vsis_allocated;
	u16 vsis_unallocated;
	u16 flags;
	u8 pf_num;
	u8 vf_num;
	u8 connection_type;
	struct avf_aqc_vsi_properties_data info;
};

struct avf_veb_context {
	u16 seid;
	u16 uplink_seid;
	u16 veb_number;
	u16 vebs_allocated;
	u16 vebs_unallocated;
	u16 flags;
	struct avf_aqc_get_veb_parameters_completion info;
};

/* Statistics collected by each port, VSI, VEB, and S-channel */
struct avf_eth_stats {
	u64 rx_bytes;			/* gorc */
	u64 rx_unicast;			/* uprc */
	u64 rx_multicast;		/* mprc */
	u64 rx_broadcast;		/* bprc */
	u64 rx_discards;		/* rdpc */
	u64 rx_unknown_protocol;	/* rupp */
	u64 tx_bytes;			/* gotc */
	u64 tx_unicast;			/* uptc */
	u64 tx_multicast;		/* mptc */
	u64 tx_broadcast;		/* bptc */
	u64 tx_discards;		/* tdpc */
	u64 tx_errors;			/* tepc */
};

/* Statistics collected per VEB per TC */
struct avf_veb_tc_stats {
	u64 tc_rx_packets[AVF_MAX_TRAFFIC_CLASS];
	u64 tc_rx_bytes[AVF_MAX_TRAFFIC_CLASS];
	u64 tc_tx_packets[AVF_MAX_TRAFFIC_CLASS];
	u64 tc_tx_bytes[AVF_MAX_TRAFFIC_CLASS];
};

/* Statistics collected per function for FCoE */
struct avf_fcoe_stats {
	u64 rx_fcoe_packets;		/* fcoeprc */
	u64 rx_fcoe_dwords;		/* focedwrc */
	u64 rx_fcoe_dropped;		/* fcoerpdc */
	u64 tx_fcoe_packets;		/* fcoeptc */
	u64 tx_fcoe_dwords;		/* focedwtc */
	u64 fcoe_bad_fccrc;		/* fcoecrc */
	u64 fcoe_last_error;		/* fcoelast */
	u64 fcoe_ddp_count;		/* fcoeddpc */
};

/* offset to per function FCoE statistics block */
#define AVF_FCOE_VF_STAT_OFFSET	0
#define AVF_FCOE_PF_STAT_OFFSET	128
#define AVF_FCOE_STAT_MAX		(AVF_FCOE_PF_STAT_OFFSET + AVF_MAX_PF)

/* Statistics collected by the MAC */
struct avf_hw_port_stats {
	/* eth stats collected by the port */
	struct avf_eth_stats eth;

	/* additional port specific stats */
	u64 tx_dropped_link_down;	/* tdold */
	u64 crc_errors;			/* crcerrs */
	u64 illegal_bytes;		/* illerrc */
	u64 error_bytes;		/* errbc */
	u64 mac_local_faults;		/* mlfc */
	u64 mac_remote_faults;		/* mrfc */
	u64 rx_length_errors;		/* rlec */
	u64 link_xon_rx;		/* lxonrxc */
	u64 link_xoff_rx;		/* lxoffrxc */
	u64 priority_xon_rx[8];		/* pxonrxc[8] */
	u64 priority_xoff_rx[8];	/* pxoffrxc[8] */
	u64 link_xon_tx;		/* lxontxc */
	u64 link_xoff_tx;		/* lxofftxc */
	u64 priority_xon_tx[8];		/* pxontxc[8] */
	u64 priority_xoff_tx[8];	/* pxofftxc[8] */
	u64 priority_xon_2_xoff[8];	/* pxon2offc[8] */
	u64 rx_size_64;			/* prc64 */
	u64 rx_size_127;		/* prc127 */
	u64 rx_size_255;		/* prc255 */
	u64 rx_size_511;		/* prc511 */
	u64 rx_size_1023;		/* prc1023 */
	u64 rx_size_1522;		/* prc1522 */
	u64 rx_size_big;		/* prc9522 */
	u64 rx_undersize;		/* ruc */
	u64 rx_fragments;		/* rfc */
	u64 rx_oversize;		/* roc */
	u64 rx_jabber;			/* rjc */
	u64 tx_size_64;			/* ptc64 */
	u64 tx_size_127;		/* ptc127 */
	u64 tx_size_255;		/* ptc255 */
	u64 tx_size_511;		/* ptc511 */
	u64 tx_size_1023;		/* ptc1023 */
	u64 tx_size_1522;		/* ptc1522 */
	u64 tx_size_big;		/* ptc9522 */
	u64 mac_short_packet_dropped;	/* mspdc */
	u64 checksum_error;		/* xec */
	/* flow director stats */
	u64 fd_atr_match;
	u64 fd_sb_match;
	u64 fd_atr_tunnel_match;
	u32 fd_atr_status;
	u32 fd_sb_status;
	/* EEE LPI */
	u32 tx_lpi_status;
	u32 rx_lpi_status;
	u64 tx_lpi_count;		/* etlpic */
	u64 rx_lpi_count;		/* erlpic */
};

/* Checksum and Shadow RAM pointers */
#define AVF_SR_NVM_CONTROL_WORD		0x00
#define AVF_SR_PCIE_ANALOG_CONFIG_PTR		0x03
#define AVF_SR_PHY_ANALOG_CONFIG_PTR		0x04
#define AVF_SR_OPTION_ROM_PTR			0x05
#define AVF_SR_RO_PCIR_REGS_AUTO_LOAD_PTR	0x06
#define AVF_SR_AUTO_GENERATED_POINTERS_PTR	0x07
#define AVF_SR_PCIR_REGS_AUTO_LOAD_PTR		0x08
#define AVF_SR_EMP_GLOBAL_MODULE_PTR		0x09
#define AVF_SR_RO_PCIE_LCB_PTR			0x0A
#define AVF_SR_EMP_IMAGE_PTR			0x0B
#define AVF_SR_PE_IMAGE_PTR			0x0C
#define AVF_SR_CSR_PROTECTED_LIST_PTR		0x0D
#define AVF_SR_MNG_CONFIG_PTR			0x0E
#define AVF_EMP_MODULE_PTR			0x0F
#define AVF_SR_EMP_MODULE_PTR			0x48
#define AVF_SR_PBA_FLAGS			0x15
#define AVF_SR_PBA_BLOCK_PTR			0x16
#define AVF_SR_BOOT_CONFIG_PTR			0x17
#define AVF_NVM_OEM_VER_OFF			0x83
#define AVF_SR_NVM_DEV_STARTER_VERSION		0x18
#define AVF_SR_NVM_WAKE_ON_LAN			0x19
#define AVF_SR_ALTERNATE_SAN_MAC_ADDRESS_PTR	0x27
#define AVF_SR_PERMANENT_SAN_MAC_ADDRESS_PTR	0x28
#define AVF_SR_NVM_MAP_VERSION			0x29
#define AVF_SR_NVM_IMAGE_VERSION		0x2A
#define AVF_SR_NVM_STRUCTURE_VERSION		0x2B
#define AVF_SR_NVM_EETRACK_LO			0x2D
#define AVF_SR_NVM_EETRACK_HI			0x2E
#define AVF_SR_VPD_PTR				0x2F
#define AVF_SR_PXE_SETUP_PTR			0x30
#define AVF_SR_PXE_CONFIG_CUST_OPTIONS_PTR	0x31
#define AVF_SR_NVM_ORIGINAL_EETRACK_LO		0x34
#define AVF_SR_NVM_ORIGINAL_EETRACK_HI		0x35
#define AVF_SR_SW_ETHERNET_MAC_ADDRESS_PTR	0x37
#define AVF_SR_POR_REGS_AUTO_LOAD_PTR		0x38
#define AVF_SR_EMPR_REGS_AUTO_LOAD_PTR		0x3A
#define AVF_SR_GLOBR_REGS_AUTO_LOAD_PTR	0x3B
#define AVF_SR_CORER_REGS_AUTO_LOAD_PTR	0x3C
#define AVF_SR_PHY_ACTIVITY_LIST_PTR		0x3D
#define AVF_SR_PCIE_ALT_AUTO_LOAD_PTR		0x3E
#define AVF_SR_SW_CHECKSUM_WORD		0x3F
#define AVF_SR_1ST_FREE_PROVISION_AREA_PTR	0x40
#define AVF_SR_4TH_FREE_PROVISION_AREA_PTR	0x42
#define AVF_SR_3RD_FREE_PROVISION_AREA_PTR	0x44
#define AVF_SR_2ND_FREE_PROVISION_AREA_PTR	0x46
#define AVF_SR_EMP_SR_SETTINGS_PTR		0x48
#define AVF_SR_FEATURE_CONFIGURATION_PTR	0x49
#define AVF_SR_CONFIGURATION_METADATA_PTR	0x4D
#define AVF_SR_IMMEDIATE_VALUES_PTR		0x4E

/* Auxiliary field, mask and shift definition for Shadow RAM and NVM Flash */
#define AVF_SR_VPD_MODULE_MAX_SIZE		1024
#define AVF_SR_PCIE_ALT_MODULE_MAX_SIZE	1024
#define AVF_SR_CONTROL_WORD_1_SHIFT		0x06
#define AVF_SR_CONTROL_WORD_1_MASK	(0x03 << AVF_SR_CONTROL_WORD_1_SHIFT)
#define AVF_SR_CONTROL_WORD_1_NVM_BANK_VALID	BIT(5)
#define AVF_SR_NVM_MAP_STRUCTURE_TYPE		BIT(12)
#define AVF_PTR_TYPE                           BIT(15)

/* Shadow RAM related */
#define AVF_SR_SECTOR_SIZE_IN_WORDS	0x800
#define AVF_SR_BUF_ALIGNMENT		4096
#define AVF_SR_WORDS_IN_1KB		512
/* Checksum should be calculated such that after adding all the words,
 * including the checksum word itself, the sum should be 0xBABA.
 */
#define AVF_SR_SW_CHECKSUM_BASE	0xBABA

#define AVF_SRRD_SRCTL_ATTEMPTS	100000

/* FCoE Tx context descriptor - Use the avf_tx_context_desc struct */

enum i40E_fcoe_tx_ctx_desc_cmd_bits {
	AVF_FCOE_TX_CTX_DESC_OPCODE_SINGLE_SEND	= 0x00, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_TSO_FC_CLASS2	= 0x01, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_TSO_FC_CLASS3	= 0x05, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_ETSO_FC_CLASS2	= 0x02, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_ETSO_FC_CLASS3	= 0x06, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_DWO_FC_CLASS2	= 0x03, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_DWO_FC_CLASS3	= 0x07, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_DDP_CTX_INVL	= 0x08, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_OPCODE_DWO_CTX_INVL	= 0x09, /* 4 BITS */
	AVF_FCOE_TX_CTX_DESC_RELOFF			= 0x10,
	AVF_FCOE_TX_CTX_DESC_CLRSEQ			= 0x20,
	AVF_FCOE_TX_CTX_DESC_DIFENA			= 0x40,
	AVF_FCOE_TX_CTX_DESC_IL2TAG2			= 0x80
};

/* FCoE DIF/DIX Context descriptor */
struct avf_fcoe_difdix_context_desc {
	__le64 flags_buff0_buff1_ref;
	__le64 difapp_msk_bias;
};

#define AVF_FCOE_DIFDIX_CTX_QW0_FLAGS_SHIFT	0
#define AVF_FCOE_DIFDIX_CTX_QW0_FLAGS_MASK	(0xFFFULL << \
					AVF_FCOE_DIFDIX_CTX_QW0_FLAGS_SHIFT)

enum avf_fcoe_difdix_ctx_desc_flags_bits {
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_RSVD				= 0x0000,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_APPTYPE_TAGCHK		= 0x0000,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_APPTYPE_TAGNOTCHK		= 0x0004,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_GTYPE_OPAQUE			= 0x0000,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_GTYPE_CHKINTEGRITY		= 0x0008,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_GTYPE_CHKINTEGRITY_APPTAG	= 0x0010,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_GTYPE_CHKINTEGRITY_APPREFTAG	= 0x0018,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_REFTYPE_CNST			= 0x0000,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_REFTYPE_INC1BLK		= 0x0020,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_REFTYPE_APPTAG		= 0x0040,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_REFTYPE_RSVD			= 0x0060,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_DIXMODE_XSUM			= 0x0000,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_DIXMODE_CRC			= 0x0080,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFHOST_UNTAG			= 0x0000,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFHOST_BUF			= 0x0100,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFHOST_RSVD			= 0x0200,
	/* 2 BITS */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFHOST_EMBDTAGS		= 0x0300,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFLAN_UNTAG			= 0x0000,
	/* 1 BIT  */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFLAN_TAG			= 0x0400,
	/* 1 BIT */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFBLK_512B			= 0x0000,
	/* 1 BIT */
	AVF_FCOE_DIFDIX_CTX_DESC_DIFBLK_4K			= 0x0800
};

#define AVF_FCOE_DIFDIX_CTX_QW0_BUFF0_SHIFT	12
#define AVF_FCOE_DIFDIX_CTX_QW0_BUFF0_MASK	(0x3FFULL << \
					AVF_FCOE_DIFDIX_CTX_QW0_BUFF0_SHIFT)

#define AVF_FCOE_DIFDIX_CTX_QW0_BUFF1_SHIFT	22
#define AVF_FCOE_DIFDIX_CTX_QW0_BUFF1_MASK	(0x3FFULL << \
					AVF_FCOE_DIFDIX_CTX_QW0_BUFF1_SHIFT)

#define AVF_FCOE_DIFDIX_CTX_QW0_REF_SHIFT	32
#define AVF_FCOE_DIFDIX_CTX_QW0_REF_MASK	(0xFFFFFFFFULL << \
					AVF_FCOE_DIFDIX_CTX_QW0_REF_SHIFT)

#define AVF_FCOE_DIFDIX_CTX_QW1_APP_SHIFT	0
#define AVF_FCOE_DIFDIX_CTX_QW1_APP_MASK	(0xFFFFULL << \
					AVF_FCOE_DIFDIX_CTX_QW1_APP_SHIFT)

#define AVF_FCOE_DIFDIX_CTX_QW1_APP_MSK_SHIFT	16
#define AVF_FCOE_DIFDIX_CTX_QW1_APP_MSK_MASK	(0xFFFFULL << \
					AVF_FCOE_DIFDIX_CTX_QW1_APP_MSK_SHIFT)

#define AVF_FCOE_DIFDIX_CTX_QW1_REF_BIAS_SHIFT	32
#define AVF_FCOE_DIFDIX_CTX_QW0_REF_BIAS_MASK	(0xFFFFFFFFULL << \
					AVF_FCOE_DIFDIX_CTX_QW1_REF_BIAS_SHIFT)

/* FCoE DIF/DIX Buffers descriptor */
struct avf_fcoe_difdix_buffers_desc {
	__le64 buff_addr0;
	__le64 buff_addr1;
};

/* FCoE DDP Context descriptor */
struct avf_fcoe_ddp_context_desc {
	__le64 rsvd;
	__le64 type_cmd_foff_lsize;
};

#define AVF_FCOE_DDP_CTX_QW1_DTYPE_SHIFT	0
#define AVF_FCOE_DDP_CTX_QW1_DTYPE_MASK	(0xFULL << \
					AVF_FCOE_DDP_CTX_QW1_DTYPE_SHIFT)

#define AVF_FCOE_DDP_CTX_QW1_CMD_SHIFT	4
#define AVF_FCOE_DDP_CTX_QW1_CMD_MASK	(0xFULL << \
					 AVF_FCOE_DDP_CTX_QW1_CMD_SHIFT)

enum avf_fcoe_ddp_ctx_desc_cmd_bits {
	AVF_FCOE_DDP_CTX_DESC_BSIZE_512B	= 0x00, /* 2 BITS */
	AVF_FCOE_DDP_CTX_DESC_BSIZE_4K		= 0x01, /* 2 BITS */
	AVF_FCOE_DDP_CTX_DESC_BSIZE_8K		= 0x02, /* 2 BITS */
	AVF_FCOE_DDP_CTX_DESC_BSIZE_16K	= 0x03, /* 2 BITS */
	AVF_FCOE_DDP_CTX_DESC_DIFENA		= 0x04, /* 1 BIT  */
	AVF_FCOE_DDP_CTX_DESC_LASTSEQH		= 0x08, /* 1 BIT  */
};

#define AVF_FCOE_DDP_CTX_QW1_FOFF_SHIFT	16
#define AVF_FCOE_DDP_CTX_QW1_FOFF_MASK	(0x3FFFULL << \
					 AVF_FCOE_DDP_CTX_QW1_FOFF_SHIFT)

#define AVF_FCOE_DDP_CTX_QW1_LSIZE_SHIFT	32
#define AVF_FCOE_DDP_CTX_QW1_LSIZE_MASK	(0x3FFFULL << \
					AVF_FCOE_DDP_CTX_QW1_LSIZE_SHIFT)

/* FCoE DDP/DWO Queue Context descriptor */
struct avf_fcoe_queue_context_desc {
	__le64 dmaindx_fbase;           /* 0:11 DMAINDX, 12:63 FBASE */
	__le64 flen_tph;                /* 0:12 FLEN, 13:15 TPH */
};

#define AVF_FCOE_QUEUE_CTX_QW0_DMAINDX_SHIFT	0
#define AVF_FCOE_QUEUE_CTX_QW0_DMAINDX_MASK	(0xFFFULL << \
					AVF_FCOE_QUEUE_CTX_QW0_DMAINDX_SHIFT)

#define AVF_FCOE_QUEUE_CTX_QW0_FBASE_SHIFT	12
#define AVF_FCOE_QUEUE_CTX_QW0_FBASE_MASK	(0xFFFFFFFFFFFFFULL << \
					AVF_FCOE_QUEUE_CTX_QW0_FBASE_SHIFT)

#define AVF_FCOE_QUEUE_CTX_QW1_FLEN_SHIFT	0
#define AVF_FCOE_QUEUE_CTX_QW1_FLEN_MASK	(0x1FFFULL << \
					AVF_FCOE_QUEUE_CTX_QW1_FLEN_SHIFT)

#define AVF_FCOE_QUEUE_CTX_QW1_TPH_SHIFT	13
#define AVF_FCOE_QUEUE_CTX_QW1_TPH_MASK	(0x7ULL << \
					AVF_FCOE_QUEUE_CTX_QW1_FLEN_SHIFT)

enum avf_fcoe_queue_ctx_desc_tph_bits {
	AVF_FCOE_QUEUE_CTX_DESC_TPHRDESC	= 0x1,
	AVF_FCOE_QUEUE_CTX_DESC_TPHDATA	= 0x2
};

#define AVF_FCOE_QUEUE_CTX_QW1_RECIPE_SHIFT	30
#define AVF_FCOE_QUEUE_CTX_QW1_RECIPE_MASK	(0x3ULL << \
					AVF_FCOE_QUEUE_CTX_QW1_RECIPE_SHIFT)

/* FCoE DDP/DWO Filter Context descriptor */
struct avf_fcoe_filter_context_desc {
	__le32 param;
	__le16 seqn;

	/* 48:51(0:3) RSVD, 52:63(4:15) DMAINDX */
	__le16 rsvd_dmaindx;

	/* 0:7 FLAGS, 8:52 RSVD, 53:63 LANQ */
	__le64 flags_rsvd_lanq;
};

#define AVF_FCOE_FILTER_CTX_QW0_DMAINDX_SHIFT	4
#define AVF_FCOE_FILTER_CTX_QW0_DMAINDX_MASK	(0xFFF << \
					AVF_FCOE_FILTER_CTX_QW0_DMAINDX_SHIFT)

enum avf_fcoe_filter_ctx_desc_flags_bits {
	AVF_FCOE_FILTER_CTX_DESC_CTYP_DDP	= 0x00,
	AVF_FCOE_FILTER_CTX_DESC_CTYP_DWO	= 0x01,
	AVF_FCOE_FILTER_CTX_DESC_ENODE_INIT	= 0x00,
	AVF_FCOE_FILTER_CTX_DESC_ENODE_RSP	= 0x02,
	AVF_FCOE_FILTER_CTX_DESC_FC_CLASS2	= 0x00,
	AVF_FCOE_FILTER_CTX_DESC_FC_CLASS3	= 0x04
};

#define AVF_FCOE_FILTER_CTX_QW1_FLAGS_SHIFT	0
#define AVF_FCOE_FILTER_CTX_QW1_FLAGS_MASK	(0xFFULL << \
					AVF_FCOE_FILTER_CTX_QW1_FLAGS_SHIFT)

#define AVF_FCOE_FILTER_CTX_QW1_PCTYPE_SHIFT     8
#define AVF_FCOE_FILTER_CTX_QW1_PCTYPE_MASK      (0x3FULL << \
			AVF_FCOE_FILTER_CTX_QW1_PCTYPE_SHIFT)

#define AVF_FCOE_FILTER_CTX_QW1_LANQINDX_SHIFT     53
#define AVF_FCOE_FILTER_CTX_QW1_LANQINDX_MASK      (0x7FFULL << \
			AVF_FCOE_FILTER_CTX_QW1_LANQINDX_SHIFT)

enum avf_switch_element_types {
	AVF_SWITCH_ELEMENT_TYPE_MAC	= 1,
	AVF_SWITCH_ELEMENT_TYPE_PF	= 2,
	AVF_SWITCH_ELEMENT_TYPE_VF	= 3,
	AVF_SWITCH_ELEMENT_TYPE_EMP	= 4,
	AVF_SWITCH_ELEMENT_TYPE_BMC	= 6,
	AVF_SWITCH_ELEMENT_TYPE_PE	= 16,
	AVF_SWITCH_ELEMENT_TYPE_VEB	= 17,
	AVF_SWITCH_ELEMENT_TYPE_PA	= 18,
	AVF_SWITCH_ELEMENT_TYPE_VSI	= 19,
};

/* Supported EtherType filters */
enum avf_ether_type_index {
	AVF_ETHER_TYPE_1588		= 0,
	AVF_ETHER_TYPE_FIP		= 1,
	AVF_ETHER_TYPE_OUI_EXTENDED	= 2,
	AVF_ETHER_TYPE_MAC_CONTROL	= 3,
	AVF_ETHER_TYPE_LLDP		= 4,
	AVF_ETHER_TYPE_EVB_PROTOCOL1	= 5,
	AVF_ETHER_TYPE_EVB_PROTOCOL2	= 6,
	AVF_ETHER_TYPE_QCN_CNM		= 7,
	AVF_ETHER_TYPE_8021X		= 8,
	AVF_ETHER_TYPE_ARP		= 9,
	AVF_ETHER_TYPE_RSV1		= 10,
	AVF_ETHER_TYPE_RSV2		= 11,
};

/* Filter context base size is 1K */
#define AVF_HASH_FILTER_BASE_SIZE	1024
/* Supported Hash filter values */
enum avf_hash_filter_size {
	AVF_HASH_FILTER_SIZE_1K	= 0,
	AVF_HASH_FILTER_SIZE_2K	= 1,
	AVF_HASH_FILTER_SIZE_4K	= 2,
	AVF_HASH_FILTER_SIZE_8K	= 3,
	AVF_HASH_FILTER_SIZE_16K	= 4,
	AVF_HASH_FILTER_SIZE_32K	= 5,
	AVF_HASH_FILTER_SIZE_64K	= 6,
	AVF_HASH_FILTER_SIZE_128K	= 7,
	AVF_HASH_FILTER_SIZE_256K	= 8,
	AVF_HASH_FILTER_SIZE_512K	= 9,
	AVF_HASH_FILTER_SIZE_1M	= 10,
};

/* DMA context base size is 0.5K */
#define AVF_DMA_CNTX_BASE_SIZE		512
/* Supported DMA context values */
enum avf_dma_cntx_size {
	AVF_DMA_CNTX_SIZE_512		= 0,
	AVF_DMA_CNTX_SIZE_1K		= 1,
	AVF_DMA_CNTX_SIZE_2K		= 2,
	AVF_DMA_CNTX_SIZE_4K		= 3,
	AVF_DMA_CNTX_SIZE_8K		= 4,
	AVF_DMA_CNTX_SIZE_16K		= 5,
	AVF_DMA_CNTX_SIZE_32K		= 6,
	AVF_DMA_CNTX_SIZE_64K		= 7,
	AVF_DMA_CNTX_SIZE_128K		= 8,
	AVF_DMA_CNTX_SIZE_256K		= 9,
};

/* Supported Hash look up table (LUT) sizes */
enum avf_hash_lut_size {
	AVF_HASH_LUT_SIZE_128		= 0,
	AVF_HASH_LUT_SIZE_512		= 1,
};

/* Structure to hold a per PF filter control settings */
struct avf_filter_control_settings {
	/* number of PE Quad Hash filter buckets */
	enum avf_hash_filter_size pe_filt_num;
	/* number of PE Quad Hash contexts */
	enum avf_dma_cntx_size pe_cntx_num;
	/* number of FCoE filter buckets */
	enum avf_hash_filter_size fcoe_filt_num;
	/* number of FCoE DDP contexts */
	enum avf_dma_cntx_size fcoe_cntx_num;
	/* size of the Hash LUT */
	enum avf_hash_lut_size	hash_lut_size;
	/* enable FDIR filters for PF and its VFs */
	bool enable_fdir;
	/* enable Ethertype filters for PF and its VFs */
	bool enable_ethtype;
	/* enable MAC/VLAN filters for PF and its VFs */
	bool enable_macvlan;
};

/* Structure to hold device level control filter counts */
struct avf_control_filter_stats {
	u16 mac_etype_used;   /* Used perfect match MAC/EtherType filters */
	u16 etype_used;       /* Used perfect EtherType filters */
	u16 mac_etype_free;   /* Un-used perfect match MAC/EtherType filters */
	u16 etype_free;       /* Un-used perfect EtherType filters */
};

enum avf_reset_type {
	AVF_RESET_POR		= 0,
	AVF_RESET_CORER	= 1,
	AVF_RESET_GLOBR	= 2,
	AVF_RESET_EMPR		= 3,
};

/* IEEE 802.1AB LLDP Agent Variables from NVM */
#define AVF_NVM_LLDP_CFG_PTR   0x06
#define AVF_SR_LLDP_CFG_PTR    0x31
struct avf_lldp_variables {
	u16 length;
	u16 adminstatus;
	u16 msgfasttx;
	u16 msgtxinterval;
	u16 txparams;
	u16 timers;
	u16 crc8;
};

/* Offsets into Alternate Ram */
#define AVF_ALT_STRUCT_FIRST_PF_OFFSET		0   /* in dwords */
#define AVF_ALT_STRUCT_DWORDS_PER_PF		64   /* in dwords */
#define AVF_ALT_STRUCT_OUTER_VLAN_TAG_OFFSET	0xD  /* in dwords */
#define AVF_ALT_STRUCT_USER_PRIORITY_OFFSET	0xC  /* in dwords */
#define AVF_ALT_STRUCT_MIN_BW_OFFSET		0xE  /* in dwords */
#define AVF_ALT_STRUCT_MAX_BW_OFFSET		0xF  /* in dwords */

/* Alternate Ram Bandwidth Masks */
#define AVF_ALT_BW_VALUE_MASK		0xFF
#define AVF_ALT_BW_RELATIVE_MASK	0x40000000
#define AVF_ALT_BW_VALID_MASK		0x80000000

/* RSS Hash Table Size */
#define AVF_PFQF_CTL_0_HASHLUTSIZE_512	0x00010000

/* INPUT SET MASK for RSS, flow director, and flexible payload */
#define AVF_L3_SRC_SHIFT		47
#define AVF_L3_SRC_MASK		(0x3ULL << AVF_L3_SRC_SHIFT)
#define AVF_L3_V6_SRC_SHIFT		43
#define AVF_L3_V6_SRC_MASK		(0xFFULL << AVF_L3_V6_SRC_SHIFT)
#define AVF_L3_DST_SHIFT		35
#define AVF_L3_DST_MASK		(0x3ULL << AVF_L3_DST_SHIFT)
#define AVF_L3_V6_DST_SHIFT		35
#define AVF_L3_V6_DST_MASK		(0xFFULL << AVF_L3_V6_DST_SHIFT)
#define AVF_L4_SRC_SHIFT		34
#define AVF_L4_SRC_MASK		(0x1ULL << AVF_L4_SRC_SHIFT)
#define AVF_L4_DST_SHIFT		33
#define AVF_L4_DST_MASK		(0x1ULL << AVF_L4_DST_SHIFT)
#define AVF_VERIFY_TAG_SHIFT		31
#define AVF_VERIFY_TAG_MASK		(0x3ULL << AVF_VERIFY_TAG_SHIFT)

#define AVF_FLEX_50_SHIFT		13
#define AVF_FLEX_50_MASK		(0x1ULL << AVF_FLEX_50_SHIFT)
#define AVF_FLEX_51_SHIFT		12
#define AVF_FLEX_51_MASK		(0x1ULL << AVF_FLEX_51_SHIFT)
#define AVF_FLEX_52_SHIFT		11
#define AVF_FLEX_52_MASK		(0x1ULL << AVF_FLEX_52_SHIFT)
#define AVF_FLEX_53_SHIFT		10
#define AVF_FLEX_53_MASK		(0x1ULL << AVF_FLEX_53_SHIFT)
#define AVF_FLEX_54_SHIFT		9
#define AVF_FLEX_54_MASK		(0x1ULL << AVF_FLEX_54_SHIFT)
#define AVF_FLEX_55_SHIFT		8
#define AVF_FLEX_55_MASK		(0x1ULL << AVF_FLEX_55_SHIFT)
#define AVF_FLEX_56_SHIFT		7
#define AVF_FLEX_56_MASK		(0x1ULL << AVF_FLEX_56_SHIFT)
#define AVF_FLEX_57_SHIFT		6
#define AVF_FLEX_57_MASK		(0x1ULL << AVF_FLEX_57_SHIFT)

/* Version format for Dynamic Device Personalization(DDP) */
struct avf_ddp_version {
	u8 major;
	u8 minor;
	u8 update;
	u8 draft;
};

#define AVF_DDP_NAME_SIZE	32

/* Package header */
struct avf_package_header {
	struct avf_ddp_version version;
	u32 segment_count;
	u32 segment_offset[1];
};

/* Generic segment header */
struct avf_generic_seg_header {
#define SEGMENT_TYPE_METADATA	0x00000001
#define SEGMENT_TYPE_NOTES	0x00000002
#define SEGMENT_TYPE_AVF	0x00000011
#define SEGMENT_TYPE_X722	0x00000012
	u32 type;
	struct avf_ddp_version version;
	u32 size;
	char name[AVF_DDP_NAME_SIZE];
};

struct avf_metadata_segment {
	struct avf_generic_seg_header header;
	struct avf_ddp_version version;
#define AVF_DDP_TRACKID_RDONLY		0
#define AVF_DDP_TRACKID_INVALID	0xFFFFFFFF
	u32 track_id;
	char name[AVF_DDP_NAME_SIZE];
};

struct avf_device_id_entry {
	u32 vendor_dev_id;
	u32 sub_vendor_dev_id;
};

struct avf_profile_segment {
	struct avf_generic_seg_header header;
	struct avf_ddp_version version;
	char name[AVF_DDP_NAME_SIZE];
	u32 device_table_count;
	struct avf_device_id_entry device_table[1];
};

struct avf_section_table {
	u32 section_count;
	u32 section_offset[1];
};

struct avf_profile_section_header {
	u16 tbl_size;
	u16 data_end;
	struct {
#define SECTION_TYPE_INFO	0x00000010
#define SECTION_TYPE_MMIO	0x00000800
#define SECTION_TYPE_RB_MMIO	0x00001800
#define SECTION_TYPE_AQ		0x00000801
#define SECTION_TYPE_RB_AQ	0x00001801
#define SECTION_TYPE_NOTE	0x80000000
#define SECTION_TYPE_NAME	0x80000001
#define SECTION_TYPE_PROTO	0x80000002
#define SECTION_TYPE_PCTYPE	0x80000003
#define SECTION_TYPE_PTYPE	0x80000004
		u32 type;
		u32 offset;
		u32 size;
	} section;
};

struct avf_profile_tlv_section_record {
	u8 rtype;
	u8 type;
	u16 len;
	u8 data[12];
};

/* Generic AQ section in proflie */
struct avf_profile_aq_section {
	u16 opcode;
	u16 flags;
	u8  param[16];
	u16 datalen;
	u8  data[1];
};

struct avf_profile_info {
	u32 track_id;
	struct avf_ddp_version version;
	u8 op;
#define AVF_DDP_ADD_TRACKID		0x01
#define AVF_DDP_REMOVE_TRACKID	0x02
	u8 reserved[7];
	u8 name[AVF_DDP_NAME_SIZE];
};
#endif /* _AVF_TYPE_H_ */
