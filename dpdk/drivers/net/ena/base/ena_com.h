/*-
* BSD LICENSE
*
* Copyright (c) 2015-2016 Amazon.com, Inc. or its affiliates.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* * Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* * Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
* * Neither the name of copyright holder nor the names of its
* contributors may be used to endorse or promote products derived
* from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef ENA_COM
#define ENA_COM

#include "ena_plat.h"
#include "ena_includes.h"

#define ENA_MAX_NUM_IO_QUEUES		128U
/* We need to queues for each IO (on for Tx and one for Rx) */
#define ENA_TOTAL_NUM_QUEUES		(2 * (ENA_MAX_NUM_IO_QUEUES))

#define ENA_MAX_HANDLERS 256

#define ENA_MAX_PHYS_ADDR_SIZE_BITS 48

/* Unit in usec */
#define ENA_REG_READ_TIMEOUT 200000

#define ADMIN_SQ_SIZE(depth)	((depth) * sizeof(struct ena_admin_aq_entry))
#define ADMIN_CQ_SIZE(depth)	((depth) * sizeof(struct ena_admin_acq_entry))
#define ADMIN_AENQ_SIZE(depth)	((depth) * sizeof(struct ena_admin_aenq_entry))

/*****************************************************************************/
/*****************************************************************************/
/* ENA adaptive interrupt moderation settings */

#define ENA_INTR_LOWEST_USECS           (0)
#define ENA_INTR_LOWEST_PKTS            (3)
#define ENA_INTR_LOWEST_BYTES           (2 * 1524)

#define ENA_INTR_LOW_USECS              (32)
#define ENA_INTR_LOW_PKTS               (12)
#define ENA_INTR_LOW_BYTES              (16 * 1024)

#define ENA_INTR_MID_USECS              (80)
#define ENA_INTR_MID_PKTS               (48)
#define ENA_INTR_MID_BYTES              (64 * 1024)

#define ENA_INTR_HIGH_USECS             (128)
#define ENA_INTR_HIGH_PKTS              (96)
#define ENA_INTR_HIGH_BYTES             (128 * 1024)

#define ENA_INTR_HIGHEST_USECS          (192)
#define ENA_INTR_HIGHEST_PKTS           (128)
#define ENA_INTR_HIGHEST_BYTES          (192 * 1024)

#define ENA_INTR_INITIAL_TX_INTERVAL_USECS		196
#define ENA_INTR_INITIAL_RX_INTERVAL_USECS		4
#define ENA_INTR_DELAY_OLD_VALUE_WEIGHT			6
#define ENA_INTR_DELAY_NEW_VALUE_WEIGHT			4

#define ENA_INTR_MODER_LEVEL_STRIDE			1
#define ENA_INTR_BYTE_COUNT_NOT_SUPPORTED		0xFFFFFF

#define ENA_HW_HINTS_NO_TIMEOUT				0xFFFF

enum ena_intr_moder_level {
	ENA_INTR_MODER_LOWEST = 0,
	ENA_INTR_MODER_LOW,
	ENA_INTR_MODER_MID,
	ENA_INTR_MODER_HIGH,
	ENA_INTR_MODER_HIGHEST,
	ENA_INTR_MAX_NUM_OF_LEVELS,
};

struct ena_intr_moder_entry {
	unsigned int intr_moder_interval;
	unsigned int pkts_per_interval;
	unsigned int bytes_per_interval;
};

enum queue_direction {
	ENA_COM_IO_QUEUE_DIRECTION_TX,
	ENA_COM_IO_QUEUE_DIRECTION_RX
};

struct ena_com_buf {
	dma_addr_t paddr; /**< Buffer physical address */
	u16 len; /**< Buffer length in bytes */
};

struct ena_com_rx_buf_info {
	u16 len;
	u16 req_id;
};

struct ena_com_io_desc_addr {
	u8 __iomem *pbuf_dev_addr; /* LLQ address */
	u8 *virt_addr;
	dma_addr_t phys_addr;
	ena_mem_handle_t mem_handle;
};

struct ena_com_tx_meta {
	u16 mss;
	u16 l3_hdr_len;
	u16 l3_hdr_offset;
	u16 l4_hdr_len; /* In words */
};

struct ena_com_io_cq {
	struct ena_com_io_desc_addr cdesc_addr;
	void *bus;

	/* Interrupt unmask register */
	u32 __iomem *unmask_reg;

	/* The completion queue head doorbell register */
	u32 __iomem *cq_head_db_reg;

	/* numa configuration register (for TPH) */
	u32 __iomem *numa_node_cfg_reg;

	/* The value to write to the above register to unmask
	 * the interrupt of this queue
	 */
	u32 msix_vector;

	enum queue_direction direction;

	/* holds the number of cdesc of the current packet */
	u16 cur_rx_pkt_cdesc_count;
	/* save the firt cdesc idx of the current packet */
	u16 cur_rx_pkt_cdesc_start_idx;

	u16 q_depth;
	/* Caller qid */
	u16 qid;

	/* Device queue index */
	u16 idx;
	u16 head;
	u16 last_head_update;
	u8 phase;
	u8 cdesc_entry_size_in_bytes;

} ____cacheline_aligned;

struct ena_com_io_sq {
	struct ena_com_io_desc_addr desc_addr;
	void *bus;

	u32 __iomem *db_addr;
	u8 __iomem *header_addr;

	enum queue_direction direction;
	enum ena_admin_placement_policy_type mem_queue_type;

	u32 msix_vector;
	struct ena_com_tx_meta cached_tx_meta;

	u16 q_depth;
	u16 qid;

	u16 idx;
	u16 tail;
	u16 next_to_comp;
	u32 tx_max_header_size;
	u8 phase;
	u8 desc_entry_size;
	u8 dma_addr_bits;
} ____cacheline_aligned;

struct ena_com_admin_cq {
	struct ena_admin_acq_entry *entries;
	ena_mem_handle_t mem_handle;
	dma_addr_t dma_addr;

	u16 head;
	u8 phase;
};

struct ena_com_admin_sq {
	struct ena_admin_aq_entry *entries;
	ena_mem_handle_t mem_handle;
	dma_addr_t dma_addr;

	u32 __iomem *db_addr;

	u16 head;
	u16 tail;
	u8 phase;

};

struct ena_com_stats_admin {
	u32 aborted_cmd;
	u32 submitted_cmd;
	u32 completed_cmd;
	u32 out_of_space;
	u32 no_completion;
};

struct ena_com_admin_queue {
	void *q_dmadev;
	void *bus;
	ena_spinlock_t q_lock; /* spinlock for the admin queue */

	struct ena_comp_ctx *comp_ctx;
	u32 completion_timeout;
	u16 q_depth;
	struct ena_com_admin_cq cq;
	struct ena_com_admin_sq sq;

	/* Indicate if the admin queue should poll for completion */
	bool polling;

	u16 curr_cmd_id;

	/* Indicate that the ena was initialized and can
	 * process new admin commands
	 */
	bool running_state;

	/* Count the number of outstanding admin commands */
	ena_atomic32_t outstanding_cmds;

	struct ena_com_stats_admin stats;
};

struct ena_aenq_handlers;

struct ena_com_aenq {
	u16 head;
	u8 phase;
	struct ena_admin_aenq_entry *entries;
	dma_addr_t dma_addr;
	ena_mem_handle_t mem_handle;
	u16 q_depth;
	struct ena_aenq_handlers *aenq_handlers;
};

struct ena_com_mmio_read {
	struct ena_admin_ena_mmio_req_read_less_resp *read_resp;
	dma_addr_t read_resp_dma_addr;
	ena_mem_handle_t read_resp_mem_handle;
	u32 reg_read_to; /* in us */
	u16 seq_num;
	bool readless_supported;
	/* spin lock to ensure a single outstanding read */
	ena_spinlock_t lock;
};

struct ena_rss {
	/* Indirect table */
	u16 *host_rss_ind_tbl;
	struct ena_admin_rss_ind_table_entry *rss_ind_tbl;
	dma_addr_t rss_ind_tbl_dma_addr;
	ena_mem_handle_t rss_ind_tbl_mem_handle;
	u16 tbl_log_size;

	/* Hash key */
	enum ena_admin_hash_functions hash_func;
	struct ena_admin_feature_rss_flow_hash_control *hash_key;
	dma_addr_t hash_key_dma_addr;
	ena_mem_handle_t hash_key_mem_handle;
	u32 hash_init_val;

	/* Flow Control */
	struct ena_admin_feature_rss_hash_control *hash_ctrl;
	dma_addr_t hash_ctrl_dma_addr;
	ena_mem_handle_t hash_ctrl_mem_handle;

};

struct ena_host_attribute {
	/* Debug area */
	u8 *debug_area_virt_addr;
	dma_addr_t debug_area_dma_addr;
	ena_mem_handle_t debug_area_dma_handle;
	u32 debug_area_size;

	/* Host information */
	struct ena_admin_host_info *host_info;
	dma_addr_t host_info_dma_addr;
	ena_mem_handle_t host_info_dma_handle;
};

/* Each ena_dev is a PCI function. */
struct ena_com_dev {
	struct ena_com_admin_queue admin_queue;
	struct ena_com_aenq aenq;
	struct ena_com_io_cq io_cq_queues[ENA_TOTAL_NUM_QUEUES];
	struct ena_com_io_sq io_sq_queues[ENA_TOTAL_NUM_QUEUES];
	u8 __iomem *reg_bar;
	void __iomem *mem_bar;
	void *dmadev;
	void *bus;

	enum ena_admin_placement_policy_type tx_mem_queue_type;
	u32 tx_max_header_size;
	u16 stats_func; /* Selected function for extended statistic dump */
	u16 stats_queue; /* Selected queue for extended statistic dump */

	struct ena_com_mmio_read mmio_read;

	struct ena_rss rss;
	u32 supported_features;
	u32 dma_addr_bits;

	struct ena_host_attribute host_attr;
	bool adaptive_coalescing;
	u16 intr_delay_resolution;
	u32 intr_moder_tx_interval;
	struct ena_intr_moder_entry *intr_moder_tbl;
};

struct ena_com_dev_get_features_ctx {
	struct ena_admin_queue_feature_desc max_queues;
	struct ena_admin_device_attr_feature_desc dev_attr;
	struct ena_admin_feature_aenq_desc aenq;
	struct ena_admin_feature_offload_desc offload;
	struct ena_admin_ena_hw_hints hw_hints;
};

struct ena_com_create_io_ctx {
	enum ena_admin_placement_policy_type mem_queue_type;
	enum queue_direction direction;
	int numa_node;
	u32 msix_vector;
	u16 queue_size;
	u16 qid;
};

typedef void (*ena_aenq_handler)(void *data,
	struct ena_admin_aenq_entry *aenq_e);

/* Holds aenq handlers. Indexed by AENQ event group */
struct ena_aenq_handlers {
	ena_aenq_handler handlers[ENA_MAX_HANDLERS];
	ena_aenq_handler unimplemented_handler;
};

/*****************************************************************************/
/*****************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/* ena_com_mmio_reg_read_request_init - Init the mmio reg read mechanism
 * @ena_dev: ENA communication layer struct
 *
 * Initialize the register read mechanism.
 *
 * @note: This method must be the first stage in the initialization sequence.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_mmio_reg_read_request_init(struct ena_com_dev *ena_dev);

/* ena_com_set_mmio_read_mode - Enable/disable the mmio reg read mechanism
 * @ena_dev: ENA communication layer struct
 * @readless_supported: readless mode (enable/disable)
 */
void ena_com_set_mmio_read_mode(struct ena_com_dev *ena_dev,
				bool readless_supported);

/* ena_com_mmio_reg_read_request_write_dev_addr - Write the mmio reg read return
 * value physical address.
 * @ena_dev: ENA communication layer struct
 */
void ena_com_mmio_reg_read_request_write_dev_addr(struct ena_com_dev *ena_dev);

/* ena_com_mmio_reg_read_request_destroy - Destroy the mmio reg read mechanism
 * @ena_dev: ENA communication layer struct
 */
void ena_com_mmio_reg_read_request_destroy(struct ena_com_dev *ena_dev);

/* ena_com_admin_init - Init the admin and the async queues
 * @ena_dev: ENA communication layer struct
 * @aenq_handlers: Those handlers to be called upon event.
 * @init_spinlock: Indicate if this method should init the admin spinlock or
 * the spinlock was init before (for example, in a case of FLR).
 *
 * Initialize the admin submission and completion queues.
 * Initialize the asynchronous events notification queues.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_admin_init(struct ena_com_dev *ena_dev,
		       struct ena_aenq_handlers *aenq_handlers,
		       bool init_spinlock);

/* ena_com_admin_destroy - Destroy the admin and the async events queues.
 * @ena_dev: ENA communication layer struct
 *
 * @note: Before calling this method, the caller must validate that the device
 * won't send any additional admin completions/aenq.
 * To achieve that, a FLR is recommended.
 */
void ena_com_admin_destroy(struct ena_com_dev *ena_dev);

/* ena_com_dev_reset - Perform device FLR to the device.
 * @ena_dev: ENA communication layer struct
 * @reset_reason: Specify what is the trigger for the reset in case of an error.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_dev_reset(struct ena_com_dev *ena_dev,
		      enum ena_regs_reset_reason_types reset_reason);

/* ena_com_create_io_queue - Create io queue.
 * @ena_dev: ENA communication layer struct
 * @ctx - create context structure
 *
 * Create the submission and the completion queues.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_create_io_queue(struct ena_com_dev *ena_dev,
			    struct ena_com_create_io_ctx *ctx);

/* ena_com_destroy_io_queue - Destroy IO queue with the queue id - qid.
 * @ena_dev: ENA communication layer struct
 * @qid - the caller virtual queue id.
 */
void ena_com_destroy_io_queue(struct ena_com_dev *ena_dev, u16 qid);

/* ena_com_get_io_handlers - Return the io queue handlers
 * @ena_dev: ENA communication layer struct
 * @qid - the caller virtual queue id.
 * @io_sq - IO submission queue handler
 * @io_cq - IO completion queue handler.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_get_io_handlers(struct ena_com_dev *ena_dev, u16 qid,
			    struct ena_com_io_sq **io_sq,
			    struct ena_com_io_cq **io_cq);

/* ena_com_admin_aenq_enable - ENAble asynchronous event notifications
 * @ena_dev: ENA communication layer struct
 *
 * After this method, aenq event can be received via AENQ.
 */
void ena_com_admin_aenq_enable(struct ena_com_dev *ena_dev);

/* ena_com_set_admin_running_state - Set the state of the admin queue
 * @ena_dev: ENA communication layer struct
 *
 * Change the state of the admin queue (enable/disable)
 */
void ena_com_set_admin_running_state(struct ena_com_dev *ena_dev, bool state);

/* ena_com_get_admin_running_state - Get the admin queue state
 * @ena_dev: ENA communication layer struct
 *
 * Retrieve the state of the admin queue (enable/disable)
 *
 * @return - current polling mode (enable/disable)
 */
bool ena_com_get_admin_running_state(struct ena_com_dev *ena_dev);

/* ena_com_set_admin_polling_mode - Set the admin completion queue polling mode
 * @ena_dev: ENA communication layer struct
 * @polling: ENAble/Disable polling mode
 *
 * Set the admin completion mode.
 */
void ena_com_set_admin_polling_mode(struct ena_com_dev *ena_dev, bool polling);

/* ena_com_set_admin_polling_mode - Get the admin completion queue polling mode
 * @ena_dev: ENA communication layer struct
 *
 * Get the admin completion mode.
 * If polling mode is on, ena_com_execute_admin_command will perform a
 * polling on the admin completion queue for the commands completion,
 * otherwise it will wait on wait event.
 *
 * @return state
 */
bool ena_com_get_ena_admin_polling_mode(struct ena_com_dev *ena_dev);

/* ena_com_admin_q_comp_intr_handler - admin queue interrupt handler
 * @ena_dev: ENA communication layer struct
 *
 * This method go over the admin completion queue and wake up all the pending
 * threads that wait on the commands wait event.
 *
 * @note: Should be called after MSI-X interrupt.
 */
void ena_com_admin_q_comp_intr_handler(struct ena_com_dev *ena_dev);

/* ena_com_aenq_intr_handler - AENQ interrupt handler
 * @ena_dev: ENA communication layer struct
 *
 * This method go over the async event notification queue and call the proper
 * aenq handler.
 */
void ena_com_aenq_intr_handler(struct ena_com_dev *dev, void *data);

/* ena_com_abort_admin_commands - Abort all the outstanding admin commands.
 * @ena_dev: ENA communication layer struct
 *
 * This method aborts all the outstanding admin commands.
 * The caller should then call ena_com_wait_for_abort_completion to make sure
 * all the commands were completed.
 */
void ena_com_abort_admin_commands(struct ena_com_dev *ena_dev);

/* ena_com_wait_for_abort_completion - Wait for admin commands abort.
 * @ena_dev: ENA communication layer struct
 *
 * This method wait until all the outstanding admin commands will be completed.
 */
void ena_com_wait_for_abort_completion(struct ena_com_dev *ena_dev);

/* ena_com_validate_version - Validate the device parameters
 * @ena_dev: ENA communication layer struct
 *
 * This method validate the device parameters are the same as the saved
 * parameters in ena_dev.
 * This method is useful after device reset, to validate the device mac address
 * and the device offloads are the same as before the reset.
 *
 * @return - 0 on success negative value otherwise.
 */
int ena_com_validate_version(struct ena_com_dev *ena_dev);

/* ena_com_get_link_params - Retrieve physical link parameters.
 * @ena_dev: ENA communication layer struct
 * @resp: Link parameters
 *
 * Retrieve the physical link parameters,
 * like speed, auto-negotiation and full duplex support.
 *
 * @return - 0 on Success negative value otherwise.
 */
int ena_com_get_link_params(struct ena_com_dev *ena_dev,
			    struct ena_admin_get_feat_resp *resp);

/* ena_com_get_dma_width - Retrieve physical dma address width the device
 * supports.
 * @ena_dev: ENA communication layer struct
 *
 * Retrieve the maximum physical address bits the device can handle.
 *
 * @return: > 0 on Success and negative value otherwise.
 */
int ena_com_get_dma_width(struct ena_com_dev *ena_dev);

/* ena_com_set_aenq_config - Set aenq groups configurations
 * @ena_dev: ENA communication layer struct
 * @groups flag: bit fields flags of enum ena_admin_aenq_group.
 *
 * Configure which aenq event group the driver would like to receive.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_aenq_config(struct ena_com_dev *ena_dev, u32 groups_flag);

/* ena_com_get_dev_attr_feat - Get device features
 * @ena_dev: ENA communication layer struct
 * @get_feat_ctx: returned context that contain the get features.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_get_dev_attr_feat(struct ena_com_dev *ena_dev,
			      struct ena_com_dev_get_features_ctx *get_feat_ctx);

/* ena_com_get_dev_basic_stats - Get device basic statistics
 * @ena_dev: ENA communication layer struct
 * @stats: stats return value
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_get_dev_basic_stats(struct ena_com_dev *ena_dev,
				struct ena_admin_basic_stats *stats);

/* ena_com_set_dev_mtu - Configure the device mtu.
 * @ena_dev: ENA communication layer struct
 * @mtu: mtu value
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_dev_mtu(struct ena_com_dev *ena_dev, int mtu);

/* ena_com_get_offload_settings - Retrieve the device offloads capabilities
 * @ena_dev: ENA communication layer struct
 * @offlad: offload return value
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_get_offload_settings(struct ena_com_dev *ena_dev,
				 struct ena_admin_feature_offload_desc *offload);

/* ena_com_rss_init - Init RSS
 * @ena_dev: ENA communication layer struct
 * @log_size: indirection log size
 *
 * Allocate RSS/RFS resources.
 * The caller then can configure rss using ena_com_set_hash_function,
 * ena_com_set_hash_ctrl and ena_com_indirect_table_set.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_rss_init(struct ena_com_dev *ena_dev, u16 log_size);

/* ena_com_rss_destroy - Destroy rss
 * @ena_dev: ENA communication layer struct
 *
 * Free all the RSS/RFS resources.
 */
void ena_com_rss_destroy(struct ena_com_dev *ena_dev);

/* ena_com_fill_hash_function - Fill RSS hash function
 * @ena_dev: ENA communication layer struct
 * @func: The hash function (Toeplitz or crc)
 * @key: Hash key (for toeplitz hash)
 * @key_len: key length (max length 10 DW)
 * @init_val: initial value for the hash function
 *
 * Fill the ena_dev resources with the desire hash function, hash key, key_len
 * and key initial value (if needed by the hash function).
 * To flush the key into the device the caller should call
 * ena_com_set_hash_function.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_fill_hash_function(struct ena_com_dev *ena_dev,
			       enum ena_admin_hash_functions func,
			       const u8 *key, u16 key_len, u32 init_val);

/* ena_com_set_hash_function - Flush the hash function and it dependencies to
 * the device.
 * @ena_dev: ENA communication layer struct
 *
 * Flush the hash function and it dependencies (key, key length and
 * initial value) if needed.
 *
 * @note: Prior to this method the caller should call ena_com_fill_hash_function
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_hash_function(struct ena_com_dev *ena_dev);

/* ena_com_get_hash_function - Retrieve the hash function and the hash key
 * from the device.
 * @ena_dev: ENA communication layer struct
 * @func: hash function
 * @key: hash key
 *
 * Retrieve the hash function and the hash key from the device.
 *
 * @note: If the caller called ena_com_fill_hash_function but didn't flash
 * it to the device, the new configuration will be lost.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_get_hash_function(struct ena_com_dev *ena_dev,
			      enum ena_admin_hash_functions *func,
			      u8 *key);

/* ena_com_fill_hash_ctrl - Fill RSS hash control
 * @ena_dev: ENA communication layer struct.
 * @proto: The protocol to configure.
 * @hash_fields: bit mask of ena_admin_flow_hash_fields
 *
 * Fill the ena_dev resources with the desire hash control (the ethernet
 * fields that take part of the hash) for a specific protocol.
 * To flush the hash control to the device, the caller should call
 * ena_com_set_hash_ctrl.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_fill_hash_ctrl(struct ena_com_dev *ena_dev,
			   enum ena_admin_flow_hash_proto proto,
			   u16 hash_fields);

/* ena_com_set_hash_ctrl - Flush the hash control resources to the device.
 * @ena_dev: ENA communication layer struct
 *
 * Flush the hash control (the ethernet fields that take part of the hash)
 *
 * @note: Prior to this method the caller should call ena_com_fill_hash_ctrl.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_hash_ctrl(struct ena_com_dev *ena_dev);

/* ena_com_get_hash_ctrl - Retrieve the hash control from the device.
 * @ena_dev: ENA communication layer struct
 * @proto: The protocol to retrieve.
 * @fields: bit mask of ena_admin_flow_hash_fields.
 *
 * Retrieve the hash control from the device.
 *
 * @note, If the caller called ena_com_fill_hash_ctrl but didn't flash
 * it to the device, the new configuration will be lost.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_get_hash_ctrl(struct ena_com_dev *ena_dev,
			  enum ena_admin_flow_hash_proto proto,
			  u16 *fields);

/* ena_com_set_default_hash_ctrl - Set the hash control to a default
 * configuration.
 * @ena_dev: ENA communication layer struct
 *
 * Fill the ena_dev resources with the default hash control configuration.
 * To flush the hash control to the device, the caller should call
 * ena_com_set_hash_ctrl.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_default_hash_ctrl(struct ena_com_dev *ena_dev);

/* ena_com_indirect_table_fill_entry - Fill a single entry in the RSS
 * indirection table
 * @ena_dev: ENA communication layer struct.
 * @entry_idx - indirection table entry.
 * @entry_value - redirection value
 *
 * Fill a single entry of the RSS indirection table in the ena_dev resources.
 * To flush the indirection table to the device, the called should call
 * ena_com_indirect_table_set.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_indirect_table_fill_entry(struct ena_com_dev *ena_dev,
				      u16 entry_idx, u16 entry_value);

/* ena_com_indirect_table_set - Flush the indirection table to the device.
 * @ena_dev: ENA communication layer struct
 *
 * Flush the indirection hash control to the device.
 * Prior to this method the caller should call ena_com_indirect_table_fill_entry
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_indirect_table_set(struct ena_com_dev *ena_dev);

/* ena_com_indirect_table_get - Retrieve the indirection table from the device.
 * @ena_dev: ENA communication layer struct
 * @ind_tbl: indirection table
 *
 * Retrieve the RSS indirection table from the device.
 *
 * @note: If the caller called ena_com_indirect_table_fill_entry but didn't flash
 * it to the device, the new configuration will be lost.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_indirect_table_get(struct ena_com_dev *ena_dev, u32 *ind_tbl);

/* ena_com_allocate_host_info - Allocate host info resources.
 * @ena_dev: ENA communication layer struct
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_allocate_host_info(struct ena_com_dev *ena_dev);

/* ena_com_allocate_debug_area - Allocate debug area.
 * @ena_dev: ENA communication layer struct
 * @debug_area_size - debug area size.
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_allocate_debug_area(struct ena_com_dev *ena_dev,
				u32 debug_area_size);

/* ena_com_delete_debug_area - Free the debug area resources.
 * @ena_dev: ENA communication layer struct
 *
 * Free the allocate debug area.
 */
void ena_com_delete_debug_area(struct ena_com_dev *ena_dev);

/* ena_com_delete_host_info - Free the host info resources.
 * @ena_dev: ENA communication layer struct
 *
 * Free the allocate host info.
 */
void ena_com_delete_host_info(struct ena_com_dev *ena_dev);

/* ena_com_set_host_attributes - Update the device with the host
 * attributes (debug area and host info) base address.
 * @ena_dev: ENA communication layer struct
 *
 * @return: 0 on Success and negative value otherwise.
 */
int ena_com_set_host_attributes(struct ena_com_dev *ena_dev);

/* ena_com_create_io_cq - Create io completion queue.
 * @ena_dev: ENA communication layer struct
 * @io_cq - io completion queue handler

 * Create IO completion queue.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_create_io_cq(struct ena_com_dev *ena_dev,
			 struct ena_com_io_cq *io_cq);

/* ena_com_destroy_io_cq - Destroy io completion queue.
 * @ena_dev: ENA communication layer struct
 * @io_cq - io completion queue handler

 * Destroy IO completion queue.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_destroy_io_cq(struct ena_com_dev *ena_dev,
			  struct ena_com_io_cq *io_cq);

/* ena_com_execute_admin_command - Execute admin command
 * @admin_queue: admin queue.
 * @cmd: the admin command to execute.
 * @cmd_size: the command size.
 * @cmd_completion: command completion return value.
 * @cmd_comp_size: command completion size.

 * Submit an admin command and then wait until the device will return a
 * completion.
 * The completion will be copyed into cmd_comp.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_execute_admin_command(struct ena_com_admin_queue *admin_queue,
				  struct ena_admin_aq_entry *cmd,
				  size_t cmd_size,
				  struct ena_admin_acq_entry *cmd_comp,
				  size_t cmd_comp_size);

/* ena_com_init_interrupt_moderation - Init interrupt moderation
 * @ena_dev: ENA communication layer struct
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_init_interrupt_moderation(struct ena_com_dev *ena_dev);

/* ena_com_destroy_interrupt_moderation - Destroy interrupt moderation resources
 * @ena_dev: ENA communication layer struct
 */
void ena_com_destroy_interrupt_moderation(struct ena_com_dev *ena_dev);

/* ena_com_interrupt_moderation_supported - Return if interrupt moderation
 * capability is supported by the device.
 *
 * @return - supported or not.
 */
bool ena_com_interrupt_moderation_supported(struct ena_com_dev *ena_dev);

/* ena_com_config_default_interrupt_moderation_table - Restore the interrupt
 * moderation table back to the default parameters.
 * @ena_dev: ENA communication layer struct
 */
void ena_com_config_default_interrupt_moderation_table(struct ena_com_dev *ena_dev);

/* ena_com_update_nonadaptive_moderation_interval_tx - Update the
 * non-adaptive interval in Tx direction.
 * @ena_dev: ENA communication layer struct
 * @tx_coalesce_usecs: Interval in usec.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_update_nonadaptive_moderation_interval_tx(struct ena_com_dev *ena_dev,
						      u32 tx_coalesce_usecs);

/* ena_com_update_nonadaptive_moderation_interval_rx - Update the
 * non-adaptive interval in Rx direction.
 * @ena_dev: ENA communication layer struct
 * @rx_coalesce_usecs: Interval in usec.
 *
 * @return - 0 on success, negative value on failure.
 */
int ena_com_update_nonadaptive_moderation_interval_rx(struct ena_com_dev *ena_dev,
						      u32 rx_coalesce_usecs);

/* ena_com_get_nonadaptive_moderation_interval_tx - Retrieve the
 * non-adaptive interval in Tx direction.
 * @ena_dev: ENA communication layer struct
 *
 * @return - interval in usec
 */
unsigned int ena_com_get_nonadaptive_moderation_interval_tx(struct ena_com_dev *ena_dev);

/* ena_com_get_nonadaptive_moderation_interval_rx - Retrieve the
 * non-adaptive interval in Rx direction.
 * @ena_dev: ENA communication layer struct
 *
 * @return - interval in usec
 */
unsigned int ena_com_get_nonadaptive_moderation_interval_rx(struct ena_com_dev *ena_dev);

/* ena_com_init_intr_moderation_entry - Update a single entry in the interrupt
 * moderation table.
 * @ena_dev: ENA communication layer struct
 * @level: Interrupt moderation table level
 * @entry: Entry value
 *
 * Update a single entry in the interrupt moderation table.
 */
void ena_com_init_intr_moderation_entry(struct ena_com_dev *ena_dev,
					enum ena_intr_moder_level level,
					struct ena_intr_moder_entry *entry);

/* ena_com_get_intr_moderation_entry - Init ena_intr_moder_entry.
 * @ena_dev: ENA communication layer struct
 * @level: Interrupt moderation table level
 * @entry: Entry to fill.
 *
 * Initialize the entry according to the adaptive interrupt moderation table.
 */
void ena_com_get_intr_moderation_entry(struct ena_com_dev *ena_dev,
				       enum ena_intr_moder_level level,
				       struct ena_intr_moder_entry *entry);

static inline bool ena_com_get_adaptive_moderation_enabled(struct ena_com_dev *ena_dev)
{
	return ena_dev->adaptive_coalescing;
}

static inline void ena_com_enable_adaptive_moderation(struct ena_com_dev *ena_dev)
{
	ena_dev->adaptive_coalescing = true;
}

static inline void ena_com_disable_adaptive_moderation(struct ena_com_dev *ena_dev)
{
	ena_dev->adaptive_coalescing = false;
}

/* ena_com_calculate_interrupt_delay - Calculate new interrupt delay
 * @ena_dev: ENA communication layer struct
 * @pkts: Number of packets since the last update
 * @bytes: Number of bytes received since the last update.
 * @smoothed_interval: Returned interval
 * @moder_tbl_idx: Current table level as input update new level as return
 * value.
 */
static inline void ena_com_calculate_interrupt_delay(struct ena_com_dev *ena_dev,
						     unsigned int pkts,
						     unsigned int bytes,
						     unsigned int *smoothed_interval,
						     unsigned int *moder_tbl_idx)
{
	enum ena_intr_moder_level curr_moder_idx, new_moder_idx;
	struct ena_intr_moder_entry *curr_moder_entry;
	struct ena_intr_moder_entry *pred_moder_entry;
	struct ena_intr_moder_entry *new_moder_entry;
	struct ena_intr_moder_entry *intr_moder_tbl = ena_dev->intr_moder_tbl;
	unsigned int interval;

	/* We apply adaptive moderation on Rx path only.
	 * Tx uses static interrupt moderation.
	 */
	if (!pkts || !bytes)
		/* Tx interrupt, or spurious interrupt,
		 * in both cases we just use same delay values
		 */
		return;

	curr_moder_idx = (enum ena_intr_moder_level)(*moder_tbl_idx);
	if (unlikely(curr_moder_idx >=  ENA_INTR_MAX_NUM_OF_LEVELS)) {
		ena_trc_err("Wrong moderation index %u\n", curr_moder_idx);
		return;
	}

	curr_moder_entry = &intr_moder_tbl[curr_moder_idx];
	new_moder_idx = curr_moder_idx;

	if (curr_moder_idx == ENA_INTR_MODER_LOWEST) {
		if ((pkts > curr_moder_entry->pkts_per_interval) ||
		    (bytes > curr_moder_entry->bytes_per_interval))
			new_moder_idx =
				(enum ena_intr_moder_level)(curr_moder_idx + ENA_INTR_MODER_LEVEL_STRIDE);
	} else {
		pred_moder_entry = &intr_moder_tbl[curr_moder_idx - ENA_INTR_MODER_LEVEL_STRIDE];

		if ((pkts <= pred_moder_entry->pkts_per_interval) ||
		    (bytes <= pred_moder_entry->bytes_per_interval))
			new_moder_idx =
				(enum ena_intr_moder_level)(curr_moder_idx - ENA_INTR_MODER_LEVEL_STRIDE);
		else if ((pkts > curr_moder_entry->pkts_per_interval) ||
			 (bytes > curr_moder_entry->bytes_per_interval)) {
			if (curr_moder_idx != ENA_INTR_MODER_HIGHEST)
				new_moder_idx =
					(enum ena_intr_moder_level)(curr_moder_idx + ENA_INTR_MODER_LEVEL_STRIDE);
		}
	}
	new_moder_entry = &intr_moder_tbl[new_moder_idx];

	interval = new_moder_entry->intr_moder_interval;
	*smoothed_interval = (
		(interval * ENA_INTR_DELAY_NEW_VALUE_WEIGHT +
		ENA_INTR_DELAY_OLD_VALUE_WEIGHT * (*smoothed_interval)) + 5) /
		10;

	*moder_tbl_idx = new_moder_idx;
}

/* ena_com_update_intr_reg - Prepare interrupt register
 * @intr_reg: interrupt register to update.
 * @rx_delay_interval: Rx interval in usecs
 * @tx_delay_interval: Tx interval in usecs
 * @unmask: unask enable/disable
 *
 * Prepare interrupt update register with the supplied parameters.
 */
static inline void ena_com_update_intr_reg(struct ena_eth_io_intr_reg *intr_reg,
					   u32 rx_delay_interval,
					   u32 tx_delay_interval,
					   bool unmask)
{
	intr_reg->intr_control = 0;
	intr_reg->intr_control |= rx_delay_interval &
		ENA_ETH_IO_INTR_REG_RX_INTR_DELAY_MASK;

	intr_reg->intr_control |=
		(tx_delay_interval << ENA_ETH_IO_INTR_REG_TX_INTR_DELAY_SHIFT)
		& ENA_ETH_IO_INTR_REG_TX_INTR_DELAY_MASK;

	if (unmask)
		intr_reg->intr_control |= ENA_ETH_IO_INTR_REG_INTR_UNMASK_MASK;
}

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* !(ENA_COM) */
