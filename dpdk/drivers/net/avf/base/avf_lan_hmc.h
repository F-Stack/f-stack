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

#ifndef _AVF_LAN_HMC_H_
#define _AVF_LAN_HMC_H_

/* forward-declare the HW struct for the compiler */
struct avf_hw;

/* HMC element context information */

/* Rx queue context data
 *
 * The sizes of the variables may be larger than needed due to crossing byte
 * boundaries. If we do not have the width of the variable set to the correct
 * size then we could end up shifting bits off the top of the variable when the
 * variable is at the top of a byte and crosses over into the next byte.
 */
struct avf_hmc_obj_rxq {
	u16 head;
	u16 cpuid; /* bigger than needed, see above for reason */
	u64 base;
	u16 qlen;
#define AVF_RXQ_CTX_DBUFF_SHIFT 7
	u16 dbuff; /* bigger than needed, see above for reason */
#define AVF_RXQ_CTX_HBUFF_SHIFT 6
	u16 hbuff; /* bigger than needed, see above for reason */
	u8  dtype;
	u8  dsize;
	u8  crcstrip;
	u8  fc_ena;
	u8  l2tsel;
	u8  hsplit_0;
	u8  hsplit_1;
	u8  showiv;
	u32 rxmax; /* bigger than needed, see above for reason */
	u8  tphrdesc_ena;
	u8  tphwdesc_ena;
	u8  tphdata_ena;
	u8  tphhead_ena;
	u16 lrxqthresh; /* bigger than needed, see above for reason */
	u8  prefena;	/* NOTE: normally must be set to 1 at init */
};

/* Tx queue context data
*
* The sizes of the variables may be larger than needed due to crossing byte
* boundaries. If we do not have the width of the variable set to the correct
* size then we could end up shifting bits off the top of the variable when the
* variable is at the top of a byte and crosses over into the next byte.
*/
struct avf_hmc_obj_txq {
	u16 head;
	u8  new_context;
	u64 base;
	u8  fc_ena;
	u8  timesync_ena;
	u8  fd_ena;
	u8  alt_vlan_ena;
	u16 thead_wb;
	u8  cpuid;
	u8  head_wb_ena;
	u16 qlen;
	u8  tphrdesc_ena;
	u8  tphrpacket_ena;
	u8  tphwdesc_ena;
	u64 head_wb_addr;
	u32 crc;
	u16 rdylist;
	u8  rdylist_act;
};

/* for hsplit_0 field of Rx HMC context */
enum avf_hmc_obj_rx_hsplit_0 {
	AVF_HMC_OBJ_RX_HSPLIT_0_NO_SPLIT      = 0,
	AVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_L2      = 1,
	AVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_IP      = 2,
	AVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_TCP_UDP = 4,
	AVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_SCTP    = 8,
};

/* fcoe_cntx and fcoe_filt are for debugging purpose only */
struct avf_hmc_obj_fcoe_cntx {
	u32 rsv[32];
};

struct avf_hmc_obj_fcoe_filt {
	u32 rsv[8];
};

/* Context sizes for LAN objects */
enum avf_hmc_lan_object_size {
	AVF_HMC_LAN_OBJ_SZ_8   = 0x3,
	AVF_HMC_LAN_OBJ_SZ_16  = 0x4,
	AVF_HMC_LAN_OBJ_SZ_32  = 0x5,
	AVF_HMC_LAN_OBJ_SZ_64  = 0x6,
	AVF_HMC_LAN_OBJ_SZ_128 = 0x7,
	AVF_HMC_LAN_OBJ_SZ_256 = 0x8,
	AVF_HMC_LAN_OBJ_SZ_512 = 0x9,
};

#define AVF_HMC_L2OBJ_BASE_ALIGNMENT 512
#define AVF_HMC_OBJ_SIZE_TXQ         128
#define AVF_HMC_OBJ_SIZE_RXQ         32
#define AVF_HMC_OBJ_SIZE_FCOE_CNTX   64
#define AVF_HMC_OBJ_SIZE_FCOE_FILT   64

enum avf_hmc_lan_rsrc_type {
	AVF_HMC_LAN_FULL  = 0,
	AVF_HMC_LAN_TX    = 1,
	AVF_HMC_LAN_RX    = 2,
	AVF_HMC_FCOE_CTX  = 3,
	AVF_HMC_FCOE_FILT = 4,
	AVF_HMC_LAN_MAX   = 5
};

enum avf_hmc_model {
	AVF_HMC_MODEL_DIRECT_PREFERRED = 0,
	AVF_HMC_MODEL_DIRECT_ONLY      = 1,
	AVF_HMC_MODEL_PAGED_ONLY       = 2,
	AVF_HMC_MODEL_UNKNOWN,
};

struct avf_hmc_lan_create_obj_info {
	struct avf_hmc_info *hmc_info;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
	enum avf_sd_entry_type entry_type;
	u64 direct_mode_sz;
};

struct avf_hmc_lan_delete_obj_info {
	struct avf_hmc_info *hmc_info;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
};

enum avf_status_code avf_init_lan_hmc(struct avf_hw *hw, u32 txq_num,
					u32 rxq_num, u32 fcoe_cntx_num,
					u32 fcoe_filt_num);
enum avf_status_code avf_configure_lan_hmc(struct avf_hw *hw,
					     enum avf_hmc_model model);
enum avf_status_code avf_shutdown_lan_hmc(struct avf_hw *hw);

u64 avf_calculate_l2fpm_size(u32 txq_num, u32 rxq_num,
			      u32 fcoe_cntx_num, u32 fcoe_filt_num);
enum avf_status_code avf_get_lan_tx_queue_context(struct avf_hw *hw,
						    u16 queue,
						    struct avf_hmc_obj_txq *s);
enum avf_status_code avf_clear_lan_tx_queue_context(struct avf_hw *hw,
						      u16 queue);
enum avf_status_code avf_set_lan_tx_queue_context(struct avf_hw *hw,
						    u16 queue,
						    struct avf_hmc_obj_txq *s);
enum avf_status_code avf_get_lan_rx_queue_context(struct avf_hw *hw,
						    u16 queue,
						    struct avf_hmc_obj_rxq *s);
enum avf_status_code avf_clear_lan_rx_queue_context(struct avf_hw *hw,
						      u16 queue);
enum avf_status_code avf_set_lan_rx_queue_context(struct avf_hw *hw,
						    u16 queue,
						    struct avf_hmc_obj_rxq *s);
enum avf_status_code avf_create_lan_hmc_object(struct avf_hw *hw,
				struct avf_hmc_lan_create_obj_info *info);
enum avf_status_code avf_delete_lan_hmc_object(struct avf_hw *hw,
				struct avf_hmc_lan_delete_obj_info *info);

#endif /* _AVF_LAN_HMC_H_ */
