/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2007-2013 Broadcom Corporation.
 *
 * Eric Davis        <edavis@broadcom.com>
 * David Christensen <davidch@broadcom.com>
 * Gary Zambrano     <zambrano@broadcom.com>
 *
 * Copyright (c) 2013-2015 Brocade Communications Systems, Inc.
 * Copyright (c) 2015-2018 Cavium Inc.
 * All rights reserved.
 * www.cavium.com
 */

#ifndef ECORE_SP_H
#define ECORE_SP_H

#include <rte_byteorder.h>

#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN RTE_LITTLE_ENDIAN
#endif
#undef __BIG_ENDIAN
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN    RTE_BIG_ENDIAN
#endif
#undef __LITTLE_ENDIAN
#endif

#include "ecore_mfw_req.h"
#include "ecore_fw_defs.h"
#include "ecore_hsi.h"
#include "ecore_reg.h"

struct bnx2x_softc;
typedef rte_iova_t ecore_dma_addr_t; /* expected to be 64 bit wide */
typedef volatile int ecore_atomic_t;


#define ETH_ALEN ETHER_ADDR_LEN /* 6 */

#define ECORE_SWCID_SHIFT   17
#define ECORE_SWCID_MASK    ((0x1 << ECORE_SWCID_SHIFT) - 1)

#define ECORE_MC_HASH_SIZE 8
#define ECORE_MC_HASH_OFFSET(sc, i)                                          \
    (BAR_TSTRORM_INTMEM +                                                    \
     TSTORM_APPROXIMATE_MATCH_MULTICAST_FILTERING_OFFSET(FUNC_ID(sc)) + i*4)

#define ECORE_MAX_MULTICAST   64
#define ECORE_MAX_EMUL_MULTI  1

#define IRO sc->iro_array

typedef rte_spinlock_t ECORE_MUTEX;
#define ECORE_MUTEX_INIT(_mutex)           rte_spinlock_init(_mutex)
#define ECORE_MUTEX_LOCK(_mutex)           rte_spinlock_lock(_mutex)
#define ECORE_MUTEX_UNLOCK(_mutex)         rte_spinlock_unlock(_mutex)

typedef rte_spinlock_t ECORE_MUTEX_SPIN;
#define ECORE_SPIN_LOCK_INIT(_spin, _sc)   rte_spinlock_init(_spin)
#define ECORE_SPIN_LOCK_BH(_spin)          rte_spinlock_lock(_spin) /* bh = bottom-half */
#define ECORE_SPIN_UNLOCK_BH(_spin)        rte_spinlock_unlock(_spin) /* bh = bottom-half */

#define ECORE_SMP_MB_AFTER_CLEAR_BIT()     mb()
#define ECORE_SMP_MB_BEFORE_CLEAR_BIT()    mb()
#define ECORE_SMP_MB()                     mb()
#define ECORE_SMP_RMB()                    rmb()
#define ECORE_SMP_WMB()                    wmb()
#define ECORE_MMIOWB()                     wmb()

#define ECORE_SET_BIT_NA(bit, var)         (*var |= (1 << bit))
#define ECORE_CLEAR_BIT_NA(bit, var)       (*var &= ~(1 << bit))

#define ECORE_TEST_BIT(bit, var)           bnx2x_test_bit(bit, var)
#define ECORE_SET_BIT(bit, var)            bnx2x_set_bit(bit, var)
#define ECORE_CLEAR_BIT(bit, var)          bnx2x_clear_bit(bit, var)
#define ECORE_TEST_AND_CLEAR_BIT(bit, var) bnx2x_test_and_clear_bit(bit, var)

#define atomic_load_acq_int                (int)*
#define atomic_store_rel_int(a, v)         (*a = v)
#define atomic_cmpset_acq_int(a, o, n)     ((*a = (o & (n)) | (n)) ^ o)

#define atomic_load_acq_long               (long)*
#define atomic_store_rel_long(a, v)        (*a = v)
#define atomic_set_acq_long(a, v)          (*a |= v)
#define atomic_clear_acq_long(a, v)        (*a &= ~v)
#define atomic_cmpset_acq_long(a, o, n)    ((*a = (o & (n)) | (n)) ^ o)
#define atomic_subtract_acq_long(a, v)     (*a -= v)
#define atomic_add_acq_long(a, v)          (*a += v)

#define ECORE_ATOMIC_READ(a) atomic_load_acq_int((volatile int *)a)
#define ECORE_ATOMIC_SET(a, v) atomic_store_rel_int((volatile int *)a, v)
#define ECORE_ATOMIC_CMPXCHG(a, o, n) bnx2x_cmpxchg((volatile int *)a, o, n)

#define ECORE_RET_PENDING(pending_bit, pending) \
    (ECORE_TEST_BIT(pending_bit, pending) ? ECORE_PENDING : ECORE_SUCCESS)

#define ECORE_SET_FLAG(value, mask, flag)      \
    do {                                       \
	(value) &= ~(mask);                    \
	(value) |= ((flag) << (mask##_SHIFT)); \
    } while (0)

#define ECORE_GET_FLAG(value, mask) \
    (((value) &= (mask)) >> (mask##_SHIFT))

#define ECORE_MIGHT_SLEEP()

#define ECORE_FCOE_CID(sc) ((sc)->fp[FCOE_IDX(sc)].cl_id)

#define ECORE_MEMCMP(_a, _b, _s) memcmp(_a, _b, _s)
#define ECORE_MEMCPY(_a, _b, _s) rte_memcpy(_a, _b, _s)
#define ECORE_MEMSET(_a, _c, _s) memset(_a, _c, _s)

#define ECORE_CPU_TO_LE16(x) htole16(x)
#define ECORE_CPU_TO_LE32(x) htole32(x)

#define ECORE_WAIT(_s, _t) DELAY(1000)
#define ECORE_MSLEEP(_t)   DELAY((_t) * 1000)

#define ECORE_LIKELY(x)   likely(x)
#define ECORE_UNLIKELY(x) unlikely(x)

#define ECORE_ZALLOC(_size, _flags, _sc) \
    rte_zmalloc("", _size, RTE_CACHE_LINE_SIZE)

#define ECORE_CALLOC(_len, _size, _flags, _sc) \
    rte_calloc("", _len, _size, RTE_CACHE_LINE_SIZE)

#define ECORE_FREE(_s, _buf, _size) \
    rte_free(_buf)

#define SC_ILT(sc)  ((sc)->ilt)
#define ILOG2(x)    bnx2x_ilog2(x)

#define ECORE_ILT_ZALLOC(x, y, size, str)				\
	do {								\
		x = rte_malloc("", sizeof(struct bnx2x_dma), RTE_CACHE_LINE_SIZE); \
		if (x) {						\
			if (bnx2x_dma_alloc((struct bnx2x_softc *)sc,	\
					  size, (struct bnx2x_dma *)x,	\
					  str, RTE_CACHE_LINE_SIZE) != 0) { \
				rte_free(x);				\
				x = NULL;				\
				*y = 0;					\
			} else {					\
				*y = ((struct bnx2x_dma *)x)->paddr;	\
			}						\
		}							\
	} while (0)

#define ECORE_ILT_FREE(x, y, size)					\
	do {								\
		if (x) {						\
			bnx2x_dma_free((struct bnx2x_dma *)x);		\
			rte_free(x);					\
			x = NULL;					\
			y = 0;						\
		}							\
	} while (0)

#define ECORE_IS_VALID_ETHER_ADDR(_mac) TRUE

#define ECORE_IS_MF_SD_MODE   IS_MF_SD_MODE
#define ECORE_IS_MF_SI_MODE   IS_MF_SI_MODE
#define ECORE_IS_MF_AFEX_MODE IS_MF_AFEX_MODE

#define ECORE_SET_CTX_VALIDATION bnx2x_set_ctx_validation

#define ECORE_UPDATE_COALESCE_SB_INDEX bnx2x_update_coalesce_sb_index

#define ECORE_ALIGN(x, a) ((((x) + (a) - 1) / (a)) * (a))

#define ECORE_REG_WR_DMAE_LEN REG_WR_DMAE_LEN

#define ECORE_PATH_ID     SC_PATH
#define ECORE_PORT_ID     SC_PORT
#define ECORE_FUNC_ID     SC_FUNC
#define ECORE_ABS_FUNC_ID SC_ABS_FUNC

#define CRCPOLY_LE 0xedb88320
uint32_t ecore_calc_crc32(uint32_t crc, uint8_t const *p,
			  uint32_t len, uint32_t magic);

uint8_t ecore_calc_crc8(uint32_t data, uint8_t crc);


static inline uint32_t
ECORE_CRC32_LE(uint32_t seed, uint8_t *mac, uint32_t len)
{
	return ecore_calc_crc32(seed, mac, len, CRCPOLY_LE);
}

#define ecore_sp_post(_sc, _a, _b, _c, _d) \
    bnx2x_sp_post(_sc, _a, _b, U64_HI(_c), U64_LO(_c), _d)

#define ECORE_DBG_BREAK_IF(exp)     \
    do {                            \
	if (unlikely(exp)) {        \
	    rte_panic("ECORE");     \
	}                           \
    } while (0)

#define ECORE_BUG()                                   \
    do {                                              \
	rte_panic("BUG (%s:%d)", __FILE__, __LINE__); \
    } while(0);

#define ECORE_BUG_ON(exp)                                    \
    do {                                                     \
	if (likely(exp)) {                                   \
	    rte_panic("BUG_ON (%s:%d)", __FILE__, __LINE__); \
	}                                                    \
    } while (0)


#define ECORE_MSG(sc, m, ...) \
	PMD_DRV_LOG(DEBUG, sc, m, ##__VA_ARGS__)

typedef struct _ecore_list_entry_t
{
    struct _ecore_list_entry_t *next, *prev;
} ecore_list_entry_t;

typedef struct ecore_list_t
{
    ecore_list_entry_t *head, *tail;
    unsigned long cnt;
} ecore_list_t;

/* initialize the list */
#define ECORE_LIST_INIT(_list) \
    do {                       \
	(_list)->head = NULL;  \
	(_list)->tail = NULL;  \
	(_list)->cnt  = 0;     \
    } while (0)

/* return TRUE if the element is the last on the list */
#define ECORE_LIST_IS_LAST(_elem, _list) \
    (_elem == (_list)->tail)

/* return TRUE if the list is empty */
#define ECORE_LIST_IS_EMPTY(_list) \
    ((_list)->cnt == 0)

/* return the first element */
#define ECORE_LIST_FIRST_ENTRY(_list, cast, _link) \
    (cast *)((_list)->head)

/* return the next element */
#define ECORE_LIST_NEXT(_elem, _link, cast) \
    (cast *)((&((_elem)->_link))->next)

/* push an element on the head of the list */
#define ECORE_LIST_PUSH_HEAD(_elem, _list)              \
    do {                                                \
	(_elem)->prev = (ecore_list_entry_t *)0;        \
	(_elem)->next = (_list)->head;                  \
	if ((_list)->tail == (ecore_list_entry_t *)0) { \
	    (_list)->tail = (_elem);                    \
	} else {                                        \
	    (_list)->head->prev = (_elem);              \
	}                                               \
	(_list)->head = (_elem);                        \
	(_list)->cnt++;                                 \
    } while (0)

/* push an element on the tail of the list */
#define ECORE_LIST_PUSH_TAIL(_elem, _list)       \
    do {                                         \
	(_elem)->next = (ecore_list_entry_t *)0; \
	(_elem)->prev = (_list)->tail;           \
	if ((_list)->tail) {                     \
	    (_list)->tail->next = (_elem);       \
	} else {                                 \
	    (_list)->head = (_elem);             \
	}                                        \
	(_list)->tail = (_elem);                 \
	(_list)->cnt++;                          \
    } while (0)

/* push list1 on the head of list2 and return with list1 as empty */
#define ECORE_LIST_SPLICE_INIT(_list1, _list2)     \
    do {                                           \
	(_list1)->tail->next = (_list2)->head;     \
	if ((_list2)->head) {                      \
	    (_list2)->head->prev = (_list1)->tail; \
	} else {                                   \
	    (_list2)->tail = (_list1)->tail;       \
	}                                          \
	(_list2)->head = (_list1)->head;           \
	(_list2)->cnt += (_list1)->cnt;            \
	(_list1)->head = NULL;                     \
	(_list1)->tail = NULL;                     \
	(_list1)->cnt  = 0;                        \
    } while (0)

/* remove an element from the list */
#define ECORE_LIST_REMOVE_ENTRY(_elem, _list)                      \
    do {                                                           \
	if ((_list)->head == (_elem)) {                            \
	    if ((_list)->head) {                                   \
		(_list)->head = (_list)->head->next;               \
		if ((_list)->head) {                               \
		    (_list)->head->prev = (ecore_list_entry_t *)0; \
		} else {                                           \
		    (_list)->tail = (ecore_list_entry_t *)0;       \
		}                                                  \
		(_list)->cnt--;                                    \
	    }                                                      \
	} else if ((_list)->tail == (_elem)) {                     \
	    if ((_list)->tail) {                                   \
		(_list)->tail = (_list)->tail->prev;               \
		if ((_list)->tail) {                               \
		    (_list)->tail->next = (ecore_list_entry_t *)0; \
		} else {                                           \
		    (_list)->head = (ecore_list_entry_t *)0;       \
		}                                                  \
		(_list)->cnt--;                                    \
	    }                                                      \
	} else {                                                   \
	    (_elem)->prev->next = (_elem)->next;                   \
	    (_elem)->next->prev = (_elem)->prev;                   \
	    (_list)->cnt--;                                        \
	}                                                          \
    } while (0)

/* walk the list */
#define ECORE_LIST_FOR_EACH_ENTRY(pos, _list, _link, cast) \
    for (pos = ECORE_LIST_FIRST_ENTRY(_list, cast, _link); \
	 pos;                                              \
	 pos = ECORE_LIST_NEXT(pos, _link, cast))

/* walk the list (safely) */
#define ECORE_LIST_FOR_EACH_ENTRY_SAFE(pos, n, _list, _link, cast) \
     for (pos = ECORE_LIST_FIRST_ENTRY(_list, cast, _lint),        \
	  n = (pos) ? ECORE_LIST_NEXT(pos, _link, cast) : NULL;    \
	  pos != NULL;                                             \
	  pos = (cast *)n,                                         \
	  n = (pos) ? ECORE_LIST_NEXT(pos, _link, cast) : NULL)


/* Manipulate a bit vector defined as an array of uint64_t */

/* Number of bits in one sge_mask array element */
#define BIT_VEC64_ELEM_SZ     64
#define BIT_VEC64_ELEM_SHIFT  6
#define BIT_VEC64_ELEM_MASK   ((uint64_t)BIT_VEC64_ELEM_SZ - 1)

#define __BIT_VEC64_SET_BIT(el, bit)            \
    do {                                        \
	el = ((el) | ((uint64_t)0x1 << (bit))); \
    } while (0)

#define __BIT_VEC64_CLEAR_BIT(el, bit)             \
    do {                                           \
	el = ((el) & (~((uint64_t)0x1 << (bit)))); \
    } while (0)

#define BIT_VEC64_SET_BIT(vec64, idx)                           \
    __BIT_VEC64_SET_BIT((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT], \
			(idx) & BIT_VEC64_ELEM_MASK)

#define BIT_VEC64_CLEAR_BIT(vec64, idx)                           \
    __BIT_VEC64_CLEAR_BIT((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT], \
			  (idx) & BIT_VEC64_ELEM_MASK)

#define BIT_VEC64_TEST_BIT(vec64, idx)          \
    (((vec64)[(idx) >> BIT_VEC64_ELEM_SHIFT] >> \
      ((idx) & BIT_VEC64_ELEM_MASK)) & 0x1)

/*
 * Creates a bitmask of all ones in less significant bits.
 * idx - index of the most significant bit in the created mask
 */
#define BIT_VEC64_ONES_MASK(idx)                                 \
    (((uint64_t)0x1 << (((idx) & BIT_VEC64_ELEM_MASK) + 1)) - 1)
#define BIT_VEC64_ELEM_ONE_MASK ((uint64_t)(~0))

/* fill in a MAC address the way the FW likes it */
static inline void
ecore_set_fw_mac_addr(uint16_t *fw_hi,
		      uint16_t *fw_mid,
		      uint16_t *fw_lo,
		      uint8_t  *mac)
{
    ((uint8_t *)fw_hi)[0]  = mac[1];
    ((uint8_t *)fw_hi)[1]  = mac[0];
    ((uint8_t *)fw_mid)[0] = mac[3];
    ((uint8_t *)fw_mid)[1] = mac[2];
    ((uint8_t *)fw_lo)[0]  = mac[5];
    ((uint8_t *)fw_lo)[1]  = mac[4];
}


enum ecore_status_t {
    ECORE_EXISTS  = -6,
    ECORE_IO      = -5,
    ECORE_TIMEOUT = -4,
    ECORE_INVAL   = -3,
    ECORE_BUSY    = -2,
    ECORE_NOMEM   = -1,
    ECORE_SUCCESS = 0,
    /* PENDING is not an error and should be positive */
    ECORE_PENDING = 1,
};

enum {
    SWITCH_UPDATE,
    AFEX_UPDATE,
};




struct bnx2x_softc;
struct eth_context;

/* Bits representing general command's configuration */
enum {
	RAMROD_TX,
	RAMROD_RX,
	/* Wait until all pending commands complete */
	RAMROD_COMP_WAIT,
	/* Don't send a ramrod, only update a registry */
	RAMROD_DRV_CLR_ONLY,
	/* Configure HW according to the current object state */
	RAMROD_RESTORE,
	 /* Execute the next command now */
	RAMROD_EXEC,
	/* Don't add a new command and continue execution of posponed
	 * commands. If not set a new command will be added to the
	 * pending commands list.
	 */
	RAMROD_CONT,
	/* If there is another pending ramrod, wait until it finishes and
	 * re-try to submit this one. This flag can be set only in sleepable
	 * context, and should not be set from the context that completes the
	 * ramrods as deadlock will occur.
	 */
	RAMROD_RETRY,
};

typedef enum {
	ECORE_OBJ_TYPE_RX,
	ECORE_OBJ_TYPE_TX,
	ECORE_OBJ_TYPE_RX_TX,
} ecore_obj_type;

/* Public slow path states */
enum {
	ECORE_FILTER_MAC_PENDING,
	ECORE_FILTER_VLAN_PENDING,
	ECORE_FILTER_VLAN_MAC_PENDING,
	ECORE_FILTER_RX_MODE_PENDING,
	ECORE_FILTER_RX_MODE_SCHED,
	ECORE_FILTER_ISCSI_ETH_START_SCHED,
	ECORE_FILTER_ISCSI_ETH_STOP_SCHED,
	ECORE_FILTER_FCOE_ETH_START_SCHED,
	ECORE_FILTER_FCOE_ETH_STOP_SCHED,
	ECORE_FILTER_MCAST_PENDING,
	ECORE_FILTER_MCAST_SCHED,
	ECORE_FILTER_RSS_CONF_PENDING,
	ECORE_AFEX_FCOE_Q_UPDATE_PENDING,
	ECORE_AFEX_PENDING_VIFSET_MCP_ACK
};

struct ecore_raw_obj {
	uint8_t		func_id;

	/* Queue params */
	uint8_t		cl_id;
	uint32_t		cid;

	/* Ramrod data buffer params */
	void		*rdata;
	ecore_dma_addr_t	rdata_mapping;

	/* Ramrod state params */
	int		state;   /* "ramrod is pending" state bit */
	unsigned long	*pstate; /* pointer to state buffer */

	ecore_obj_type	obj_type;

	int (*wait_comp)(struct bnx2x_softc *sc,
			 struct ecore_raw_obj *o);

	int (*check_pending)(struct ecore_raw_obj *o);
	void (*clear_pending)(struct ecore_raw_obj *o);
	void (*set_pending)(struct ecore_raw_obj *o);
};

/************************* VLAN-MAC commands related parameters ***************/
struct ecore_mac_ramrod_data {
	uint8_t mac[ETH_ALEN];
	uint8_t is_inner_mac;
};

struct ecore_vlan_ramrod_data {
	uint16_t vlan;
};

struct ecore_vlan_mac_ramrod_data {
	uint8_t mac[ETH_ALEN];
	uint8_t is_inner_mac;
	uint16_t vlan;
};

union ecore_classification_ramrod_data {
	struct ecore_mac_ramrod_data mac;
	struct ecore_vlan_ramrod_data vlan;
	struct ecore_vlan_mac_ramrod_data vlan_mac;
};

/* VLAN_MAC commands */
enum ecore_vlan_mac_cmd {
	ECORE_VLAN_MAC_ADD,
	ECORE_VLAN_MAC_DEL,
	ECORE_VLAN_MAC_MOVE,
};

struct ecore_vlan_mac_data {
	/* Requested command: ECORE_VLAN_MAC_XX */
	enum ecore_vlan_mac_cmd cmd;
	/* used to contain the data related vlan_mac_flags bits from
	 * ramrod parameters.
	 */
	unsigned long vlan_mac_flags;

	/* Needed for MOVE command */
	struct ecore_vlan_mac_obj *target_obj;

	union ecore_classification_ramrod_data u;
};

/*************************** Exe Queue obj ************************************/
union ecore_exe_queue_cmd_data {
	struct ecore_vlan_mac_data vlan_mac;

	struct {
	} mcast;
};

struct ecore_exeq_elem {
	ecore_list_entry_t		link;

	/* Length of this element in the exe_chunk. */
	int				cmd_len;

	union ecore_exe_queue_cmd_data	cmd_data;
};

union ecore_qable_obj;

union ecore_exeq_comp_elem {
	union event_ring_elem *elem;
};

struct ecore_exe_queue_obj;

typedef int (*exe_q_validate)(struct bnx2x_softc *sc,
			      union ecore_qable_obj *o,
			      struct ecore_exeq_elem *elem);

typedef int (*exe_q_remove)(struct bnx2x_softc *sc,
			    union ecore_qable_obj *o,
			    struct ecore_exeq_elem *elem);

/* Return positive if entry was optimized, 0 - if not, negative
 * in case of an error.
 */
typedef int (*exe_q_optimize)(struct bnx2x_softc *sc,
			      union ecore_qable_obj *o,
			      struct ecore_exeq_elem *elem);
typedef int (*exe_q_execute)(struct bnx2x_softc *sc,
			     union ecore_qable_obj *o,
			     ecore_list_t *exe_chunk,
			     unsigned long *ramrod_flags);
typedef struct ecore_exeq_elem *
			(*exe_q_get)(struct ecore_exe_queue_obj *o,
				     struct ecore_exeq_elem *elem);

struct ecore_exe_queue_obj {
	/* Commands pending for an execution. */
	ecore_list_t	exe_queue;

	/* Commands pending for an completion. */
	ecore_list_t	pending_comp;

	ECORE_MUTEX_SPIN		lock;

	/* Maximum length of commands' list for one execution */
	int			exe_chunk_len;

	union ecore_qable_obj	*owner;

	/****** Virtual functions ******/
	/**
	 * Called before commands execution for commands that are really
	 * going to be executed (after 'optimize').
	 *
	 * Must run under exe_queue->lock
	 */
	exe_q_validate		validate;

	/**
	 * Called before removing pending commands, cleaning allocated
	 * resources (e.g., credits from validate)
	 */
	 exe_q_remove		remove;

	/**
	 * This will try to cancel the current pending commands list
	 * considering the new command.
	 *
	 * Returns the number of optimized commands or a negative error code
	 *
	 * Must run under exe_queue->lock
	 */
	exe_q_optimize		optimize;

	/**
	 * Run the next commands chunk (owner specific).
	 */
	exe_q_execute		execute;

	/**
	 * Return the exe_queue element containing the specific command
	 * if any. Otherwise return NULL.
	 */
	exe_q_get		get;
};
/***************** Classification verbs: Set/Del MAC/VLAN/VLAN-MAC ************/
/*
 * Element in the VLAN_MAC registry list having all current configured
 * rules.
 */
struct ecore_vlan_mac_registry_elem {
	ecore_list_entry_t	link;

	/* Used to store the cam offset used for the mac/vlan/vlan-mac.
	 * Relevant for 57711 only. VLANs and MACs share the
	 * same CAM for these chips.
	 */
	int			cam_offset;

	/* Needed for DEL and RESTORE flows */
	unsigned long		vlan_mac_flags;

	union ecore_classification_ramrod_data u;
};

/* Bits representing VLAN_MAC commands specific flags */
enum {
	ECORE_UC_LIST_MAC,
	ECORE_ETH_MAC,
	ECORE_ISCSI_ETH_MAC,
	ECORE_NETQ_ETH_MAC,
	ECORE_DONT_CONSUME_CAM_CREDIT,
	ECORE_DONT_CONSUME_CAM_CREDIT_DEST,
};

struct ecore_vlan_mac_ramrod_params {
	/* Object to run the command from */
	struct ecore_vlan_mac_obj *vlan_mac_obj;

	/* General command flags: COMP_WAIT, etc. */
	unsigned long ramrod_flags;

	/* Command specific configuration request */
	struct ecore_vlan_mac_data user_req;
};

struct ecore_vlan_mac_obj {
	struct ecore_raw_obj raw;

	/* Bookkeeping list: will prevent the addition of already existing
	 * entries.
	 */
	ecore_list_t		head;
	/* Implement a simple reader/writer lock on the head list.
	 * all these fields should only be accessed under the exe_queue lock
	 */
	uint8_t		head_reader; /* Num. of readers accessing head list */
	int		head_exe_request; /* Pending execution request. */
	unsigned long	saved_ramrod_flags; /* Ramrods of pending execution */

	/* Execution queue interface instance */
	struct ecore_exe_queue_obj	exe_queue;

	/* MACs credit pool */
	struct ecore_credit_pool_obj	*macs_pool;

	/* VLANs credit pool */
	struct ecore_credit_pool_obj	*vlans_pool;

	/* RAMROD command to be used */
	int				ramrod_cmd;

	/* copy first n elements onto preallocated buffer
	 *
	 * @param n number of elements to get
	 * @param buf buffer preallocated by caller into which elements
	 *            will be copied. Note elements are 4-byte aligned
	 *            so buffer size must be able to accommodate the
	 *            aligned elements.
	 *
	 * @return number of copied bytes
	 */

	int (*get_n_elements)(struct bnx2x_softc *sc,
			      struct ecore_vlan_mac_obj *o, int n, uint8_t *base,
			      uint8_t stride, uint8_t size);

	/**
	 * Checks if ADD-ramrod with the given params may be performed.
	 *
	 * @return zero if the element may be added
	 */

	int (*check_add)(struct bnx2x_softc *sc,
			 struct ecore_vlan_mac_obj *o,
			 union ecore_classification_ramrod_data *data);

	/**
	 * Checks if DEL-ramrod with the given params may be performed.
	 *
	 * @return TRUE if the element may be deleted
	 */
	struct ecore_vlan_mac_registry_elem *
		(*check_del)(struct bnx2x_softc *sc,
			     struct ecore_vlan_mac_obj *o,
			     union ecore_classification_ramrod_data *data);

	/**
	 * Checks if DEL-ramrod with the given params may be performed.
	 *
	 * @return TRUE if the element may be deleted
	 */
	int (*check_move)(struct bnx2x_softc *sc,
			   struct ecore_vlan_mac_obj *src_o,
			   struct ecore_vlan_mac_obj *dst_o,
			   union ecore_classification_ramrod_data *data);

	/**
	 *  Update the relevant credit object(s) (consume/return
	 *  correspondingly).
	 */
	int (*get_credit)(struct ecore_vlan_mac_obj *o);
	int (*put_credit)(struct ecore_vlan_mac_obj *o);
	int (*get_cam_offset)(struct ecore_vlan_mac_obj *o, int *offset);
	int (*put_cam_offset)(struct ecore_vlan_mac_obj *o, int offset);

	/**
	 * Configures one rule in the ramrod data buffer.
	 */
	void (*set_one_rule)(struct bnx2x_softc *sc,
			     struct ecore_vlan_mac_obj *o,
			     struct ecore_exeq_elem *elem, int rule_idx,
			     int cam_offset);

	/**
	*  Delete all configured elements having the given
	*  vlan_mac_flags specification. Assumes no pending for
	*  execution commands. Will schedule all all currently
	*  configured MACs/VLANs/VLAN-MACs matching the vlan_mac_flags
	*  specification for deletion and will use the given
	*  ramrod_flags for the last DEL operation.
	 *
	 * @param sc
	 * @param o
	 * @param ramrod_flags RAMROD_XX flags
	 *
	 * @return 0 if the last operation has completed successfully
	 *         and there are no more elements left, positive value
	 *         if there are pending for completion commands,
	 *         negative value in case of failure.
	 */
	int (*delete_all)(struct bnx2x_softc *sc,
			  struct ecore_vlan_mac_obj *o,
			  unsigned long *vlan_mac_flags,
			  unsigned long *ramrod_flags);

	/**
	 * Reconfigures the next MAC/VLAN/VLAN-MAC element from the previously
	 * configured elements list.
	 *
	 * @param sc
	 * @param p Command parameters (RAMROD_COMP_WAIT bit in
	 *          ramrod_flags is only taken into an account)
	 * @param ppos a pointer to the cookie that should be given back in the
	 *        next call to make function handle the next element. If
	 *        *ppos is set to NULL it will restart the iterator.
	 *        If returned *ppos == NULL this means that the last
	 *        element has been handled.
	 *
	 * @return int
	 */
	int (*restore)(struct bnx2x_softc *sc,
		       struct ecore_vlan_mac_ramrod_params *p,
		       struct ecore_vlan_mac_registry_elem **ppos);

	/**
	 * Should be called on a completion arrival.
	 *
	 * @param sc
	 * @param o
	 * @param cqe Completion element we are handling
	 * @param ramrod_flags if RAMROD_CONT is set the next bulk of
	 *		       pending commands will be executed.
	 *		       RAMROD_DRV_CLR_ONLY and RAMROD_RESTORE
	 *		       may also be set if needed.
	 *
	 * @return 0 if there are neither pending nor waiting for
	 *         completion commands. Positive value if there are
	 *         pending for execution or for completion commands.
	 *         Negative value in case of an error (including an
	 *         error in the cqe).
	 */
	int (*complete)(struct bnx2x_softc *sc, struct ecore_vlan_mac_obj *o,
			union event_ring_elem *cqe,
			unsigned long *ramrod_flags);

	/**
	 * Wait for completion of all commands. Don't schedule new ones,
	 * just wait. It assumes that the completion code will schedule
	 * for new commands.
	 */
	int (*wait)(struct bnx2x_softc *sc, struct ecore_vlan_mac_obj *o);
};

enum {
	ECORE_LLH_CAM_ISCSI_ETH_LINE = 0,
	ECORE_LLH_CAM_ETH_LINE,
	ECORE_LLH_CAM_MAX_PF_LINE = NIG_REG_LLH1_FUNC_MEM_SIZE / 2
};

/** RX_MODE verbs:DROP_ALL/ACCEPT_ALL/ACCEPT_ALL_MULTI/ACCEPT_ALL_VLAN/NORMAL */

/* RX_MODE ramrod special flags: set in rx_mode_flags field in
 * a ecore_rx_mode_ramrod_params.
 */
enum {
	ECORE_RX_MODE_FCOE_ETH,
	ECORE_RX_MODE_ISCSI_ETH,
};

enum {
	ECORE_ACCEPT_UNICAST,
	ECORE_ACCEPT_MULTICAST,
	ECORE_ACCEPT_ALL_UNICAST,
	ECORE_ACCEPT_ALL_MULTICAST,
	ECORE_ACCEPT_BROADCAST,
	ECORE_ACCEPT_UNMATCHED,
	ECORE_ACCEPT_ANY_VLAN
};

struct ecore_rx_mode_ramrod_params {
	struct ecore_rx_mode_obj *rx_mode_obj;
	unsigned long *pstate;
	int state;
	uint8_t cl_id;
	uint32_t cid;
	uint8_t func_id;
	unsigned long ramrod_flags;
	unsigned long rx_mode_flags;

	/* rdata is either a pointer to eth_filter_rules_ramrod_data(e2) or to
	 * a tstorm_eth_mac_filter_config (e1x).
	 */
	void *rdata;
	ecore_dma_addr_t rdata_mapping;

	/* Rx mode settings */
	unsigned long rx_accept_flags;

	/* internal switching settings */
	unsigned long tx_accept_flags;
};

struct ecore_rx_mode_obj {
	int (*config_rx_mode)(struct bnx2x_softc *sc,
			      struct ecore_rx_mode_ramrod_params *p);

	int (*wait_comp)(struct bnx2x_softc *sc,
			 struct ecore_rx_mode_ramrod_params *p);
};

/********************** Set multicast group ***********************************/

struct ecore_mcast_list_elem {
	ecore_list_entry_t link;
	uint8_t *mac;
};

union ecore_mcast_config_data {
	uint8_t *mac;
	uint8_t bin; /* used in a RESTORE flow */
};

struct ecore_mcast_ramrod_params {
	struct ecore_mcast_obj *mcast_obj;

	/* Relevant options are RAMROD_COMP_WAIT and RAMROD_DRV_CLR_ONLY */
	unsigned long ramrod_flags;

	ecore_list_t mcast_list; /* list of struct ecore_mcast_list_elem */
	int mcast_list_len;
};

enum ecore_mcast_cmd {
	ECORE_MCAST_CMD_ADD,
	ECORE_MCAST_CMD_CONT,
	ECORE_MCAST_CMD_DEL,
	ECORE_MCAST_CMD_RESTORE,
};

struct ecore_mcast_obj {
	struct ecore_raw_obj raw;

	union {
		struct {
		#define ECORE_MCAST_BINS_NUM	256
		#define ECORE_MCAST_VEC_SZ	(ECORE_MCAST_BINS_NUM / 64)
			uint64_t vec[ECORE_MCAST_VEC_SZ];

			/** Number of BINs to clear. Should be updated
			 *  immediately when a command arrives in order to
			 *  properly create DEL commands.
			 */
			int num_bins_set;
		} aprox_match;

		struct {
			ecore_list_t macs;
			int num_macs_set;
		} exact_match;
	} registry;

	/* Pending commands */
	ecore_list_t pending_cmds_head;

	/* A state that is set in raw.pstate, when there are pending commands */
	int sched_state;

	/* Maximal number of mcast MACs configured in one command */
	int max_cmd_len;

	/* Total number of currently pending MACs to configure: both
	 * in the pending commands list and in the current command.
	 */
	int total_pending_num;

	uint8_t engine_id;

	/**
	 * @param cmd command to execute (ECORE_MCAST_CMD_X, see above)
	 */
	int (*config_mcast)(struct bnx2x_softc *sc,
			    struct ecore_mcast_ramrod_params *p,
			    enum ecore_mcast_cmd cmd);

	/**
	 * Fills the ramrod data during the RESTORE flow.
	 *
	 * @param sc
	 * @param o
	 * @param start_idx Registry index to start from
	 * @param rdata_idx Index in the ramrod data to start from
	 *
	 * @return -1 if we handled the whole registry or index of the last
	 *         handled registry element.
	 */
	int (*hdl_restore)(struct bnx2x_softc *sc, struct ecore_mcast_obj *o,
			   int start_bin, int *rdata_idx);

	int (*enqueue_cmd)(struct bnx2x_softc *sc, struct ecore_mcast_obj *o,
			   struct ecore_mcast_ramrod_params *p,
			   enum ecore_mcast_cmd cmd);

	void (*set_one_rule)(struct bnx2x_softc *sc,
			     struct ecore_mcast_obj *o, int idx,
			     union ecore_mcast_config_data *cfg_data,
			     enum ecore_mcast_cmd cmd);

	/** Checks if there are more mcast MACs to be set or a previous
	 *  command is still pending.
	 */
	int (*check_pending)(struct ecore_mcast_obj *o);

	/**
	 * Set/Clear/Check SCHEDULED state of the object
	 */
	void (*set_sched)(struct ecore_mcast_obj *o);
	void (*clear_sched)(struct ecore_mcast_obj *o);
	int (*check_sched)(struct ecore_mcast_obj *o);

	/* Wait until all pending commands complete */
	int (*wait_comp)(struct bnx2x_softc *sc, struct ecore_mcast_obj *o);

	/**
	 * Handle the internal object counters needed for proper
	 * commands handling. Checks that the provided parameters are
	 * feasible.
	 */
	int (*validate)(struct bnx2x_softc *sc,
			struct ecore_mcast_ramrod_params *p,
			enum ecore_mcast_cmd cmd);

	/**
	 * Restore the values of internal counters in case of a failure.
	 */
	void (*revert)(struct bnx2x_softc *sc,
		       struct ecore_mcast_ramrod_params *p,
		       int old_num_bins);

	int (*get_registry_size)(struct ecore_mcast_obj *o);
	void (*set_registry_size)(struct ecore_mcast_obj *o, int n);
};

/*************************** Credit handling **********************************/
struct ecore_credit_pool_obj {

	/* Current amount of credit in the pool */
	ecore_atomic_t	credit;

	/* Maximum allowed credit. put() will check against it. */
	int		pool_sz;

	/* Allocate a pool table statically.
	 *
	 * Currently the maximum allowed size is MAX_MAC_CREDIT_E2(272)
	 *
	 * The set bit in the table will mean that the entry is available.
	 */
#define ECORE_POOL_VEC_SIZE	(MAX_MAC_CREDIT_E2 / 64)
	uint64_t		pool_mirror[ECORE_POOL_VEC_SIZE];

	/* Base pool offset (initialized differently */
	int		base_pool_offset;

	/**
	 * Get the next free pool entry.
	 *
	 * @return TRUE if there was a free entry in the pool
	 */
	int (*get_entry)(struct ecore_credit_pool_obj *o, int *entry);

	/**
	 * Return the entry back to the pool.
	 *
	 * @return TRUE if entry is legal and has been successfully
	 *         returned to the pool.
	 */
	int (*put_entry)(struct ecore_credit_pool_obj *o, int entry);

	/**
	 * Get the requested amount of credit from the pool.
	 *
	 * @param cnt Amount of requested credit
	 * @return TRUE if the operation is successful
	 */
	int (*get)(struct ecore_credit_pool_obj *o, int cnt);

	/**
	 * Returns the credit to the pool.
	 *
	 * @param cnt Amount of credit to return
	 * @return TRUE if the operation is successful
	 */
	int (*put)(struct ecore_credit_pool_obj *o, int cnt);

	/**
	 * Reads the current amount of credit.
	 */
	int (*check)(struct ecore_credit_pool_obj *o);
};

/*************************** RSS configuration ********************************/
enum {
	/* RSS_MODE bits are mutually exclusive */
	ECORE_RSS_MODE_DISABLED,
	ECORE_RSS_MODE_REGULAR,

	ECORE_RSS_SET_SRCH, /* Setup searcher, E1x specific flag */

	ECORE_RSS_IPV4,
	ECORE_RSS_IPV4_TCP,
	ECORE_RSS_IPV4_UDP,
	ECORE_RSS_IPV6,
	ECORE_RSS_IPV6_TCP,
	ECORE_RSS_IPV6_UDP,

	ECORE_RSS_TUNNELING,
};

struct ecore_config_rss_params {
	struct ecore_rss_config_obj *rss_obj;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long	ramrod_flags;

	/* ECORE_RSS_X bits */
	unsigned long	rss_flags;

	/* Number hash bits to take into an account */
	uint8_t		rss_result_mask;

	/* Indirection table */
	uint8_t		ind_table[T_ETH_INDIRECTION_TABLE_SIZE];

	/* RSS hash values */
	uint32_t		rss_key[10];

	/* valid only if ECORE_RSS_UPDATE_TOE is set */
	uint16_t		toe_rss_bitmap;

	/* valid if ECORE_RSS_TUNNELING is set */
	uint16_t		tunnel_value;
	uint16_t		tunnel_mask;
};

struct ecore_rss_config_obj {
	struct ecore_raw_obj	raw;

	/* RSS engine to use */
	uint8_t			engine_id;

	/* Last configured indirection table */
	uint8_t			ind_table[T_ETH_INDIRECTION_TABLE_SIZE];

	/* flags for enabling 4-tupple hash on UDP */
	uint8_t			udp_rss_v4;
	uint8_t			udp_rss_v6;

	int (*config_rss)(struct bnx2x_softc *sc,
			  struct ecore_config_rss_params *p);
};

/*********************** Queue state update ***********************************/

/* UPDATE command options */
enum {
	ECORE_Q_UPDATE_IN_VLAN_REM,
	ECORE_Q_UPDATE_IN_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_OUT_VLAN_REM,
	ECORE_Q_UPDATE_OUT_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_ANTI_SPOOF,
	ECORE_Q_UPDATE_ANTI_SPOOF_CHNG,
	ECORE_Q_UPDATE_ACTIVATE,
	ECORE_Q_UPDATE_ACTIVATE_CHNG,
	ECORE_Q_UPDATE_DEF_VLAN_EN,
	ECORE_Q_UPDATE_DEF_VLAN_EN_CHNG,
	ECORE_Q_UPDATE_SILENT_VLAN_REM_CHNG,
	ECORE_Q_UPDATE_SILENT_VLAN_REM,
	ECORE_Q_UPDATE_TX_SWITCHING_CHNG,
	ECORE_Q_UPDATE_TX_SWITCHING,
};

/* Allowed Queue states */
enum ecore_q_state {
	ECORE_Q_STATE_RESET,
	ECORE_Q_STATE_INITIALIZED,
	ECORE_Q_STATE_ACTIVE,
	ECORE_Q_STATE_MULTI_COS,
	ECORE_Q_STATE_MCOS_TERMINATED,
	ECORE_Q_STATE_INACTIVE,
	ECORE_Q_STATE_STOPPED,
	ECORE_Q_STATE_TERMINATED,
	ECORE_Q_STATE_FLRED,
	ECORE_Q_STATE_MAX,
};

/* Allowed Queue states */
enum ecore_q_logical_state {
	ECORE_Q_LOGICAL_STATE_ACTIVE,
	ECORE_Q_LOGICAL_STATE_STOPPED,
};

/* Allowed commands */
enum ecore_queue_cmd {
	ECORE_Q_CMD_INIT,
	ECORE_Q_CMD_SETUP,
	ECORE_Q_CMD_SETUP_TX_ONLY,
	ECORE_Q_CMD_DEACTIVATE,
	ECORE_Q_CMD_ACTIVATE,
	ECORE_Q_CMD_UPDATE,
	ECORE_Q_CMD_UPDATE_TPA,
	ECORE_Q_CMD_HALT,
	ECORE_Q_CMD_CFC_DEL,
	ECORE_Q_CMD_TERMINATE,
	ECORE_Q_CMD_EMPTY,
	ECORE_Q_CMD_MAX,
};

/* queue SETUP + INIT flags */
enum {
	ECORE_Q_FLG_TPA,
	ECORE_Q_FLG_TPA_IPV6,
	ECORE_Q_FLG_TPA_GRO,
	ECORE_Q_FLG_STATS,
	ECORE_Q_FLG_ZERO_STATS,
	ECORE_Q_FLG_ACTIVE,
	ECORE_Q_FLG_OV,
	ECORE_Q_FLG_VLAN,
	ECORE_Q_FLG_COS,
	ECORE_Q_FLG_HC,
	ECORE_Q_FLG_HC_EN,
	ECORE_Q_FLG_DHC,
	ECORE_Q_FLG_OOO,
	ECORE_Q_FLG_FCOE,
	ECORE_Q_FLG_LEADING_RSS,
	ECORE_Q_FLG_MCAST,
	ECORE_Q_FLG_DEF_VLAN,
	ECORE_Q_FLG_TX_SWITCH,
	ECORE_Q_FLG_TX_SEC,
	ECORE_Q_FLG_ANTI_SPOOF,
	ECORE_Q_FLG_SILENT_VLAN_REM,
	ECORE_Q_FLG_FORCE_DEFAULT_PRI,
	ECORE_Q_FLG_REFUSE_OUTBAND_VLAN,
	ECORE_Q_FLG_PCSUM_ON_PKT,
	ECORE_Q_FLG_TUN_INC_INNER_IP_ID
};

/* Queue type options: queue type may be a combination of below. */
enum ecore_q_type {
	ECORE_Q_TYPE_FWD,
	ECORE_Q_TYPE_HAS_RX,
	ECORE_Q_TYPE_HAS_TX,
};

#define ECORE_PRIMARY_CID_INDEX			0
#define ECORE_MULTI_TX_COS_E1X			3 /* QM only */
#define ECORE_MULTI_TX_COS_E2_E3A0		2
#define ECORE_MULTI_TX_COS_E3B0			3
#define ECORE_MULTI_TX_COS			3 /* Maximum possible */
#define MAC_PAD (ECORE_ALIGN(ETH_ALEN, sizeof(uint32_t)) - ETH_ALEN)

struct ecore_queue_init_params {
	struct {
		unsigned long	flags;
		uint16_t		hc_rate;
		uint8_t		fw_sb_id;
		uint8_t		sb_cq_index;
	} tx;

	struct {
		unsigned long	flags;
		uint16_t		hc_rate;
		uint8_t		fw_sb_id;
		uint8_t		sb_cq_index;
	} rx;

	/* CID context in the host memory */
	struct eth_context *cxts[ECORE_MULTI_TX_COS];

	/* maximum number of cos supported by hardware */
	uint8_t max_cos;
};

struct ecore_queue_terminate_params {
	/* index within the tx_only cids of this queue object */
	uint8_t cid_index;
};

struct ecore_queue_cfc_del_params {
	/* index within the tx_only cids of this queue object */
	uint8_t cid_index;
};

struct ecore_queue_update_params {
	unsigned long	update_flags; /* ECORE_Q_UPDATE_XX bits */
	uint16_t		def_vlan;
	uint16_t		silent_removal_value;
	uint16_t		silent_removal_mask;
/* index within the tx_only cids of this queue object */
	uint8_t		cid_index;
};

struct rxq_pause_params {
	uint16_t		bd_th_lo;
	uint16_t		bd_th_hi;
	uint16_t		rcq_th_lo;
	uint16_t		rcq_th_hi;
	uint16_t		sge_th_lo; /* valid if ECORE_Q_FLG_TPA */
	uint16_t		sge_th_hi; /* valid if ECORE_Q_FLG_TPA */
	uint16_t		pri_map;
};

/* general */
struct ecore_general_setup_params {
	/* valid if ECORE_Q_FLG_STATS */
	uint8_t		stat_id;

	uint8_t		spcl_id;
	uint16_t		mtu;
	uint8_t		cos;
};

struct ecore_rxq_setup_params {
	/* dma */
	ecore_dma_addr_t	dscr_map;
	ecore_dma_addr_t	rcq_map;
	ecore_dma_addr_t	rcq_np_map;

	uint16_t		drop_flags;
	uint16_t		buf_sz;
	uint8_t		fw_sb_id;
	uint8_t		cl_qzone_id;

	/* valid if ECORE_Q_FLG_TPA */
	uint16_t		tpa_agg_sz;
	uint8_t		max_tpa_queues;
	uint8_t		rss_engine_id;

	/* valid if ECORE_Q_FLG_MCAST */
	uint8_t		mcast_engine_id;

	uint8_t		cache_line_log;

	uint8_t		sb_cq_index;

	/* valid if BXN2X_Q_FLG_SILENT_VLAN_REM */
	uint16_t silent_removal_value;
	uint16_t silent_removal_mask;
};

struct ecore_txq_setup_params {
	/* dma */
	ecore_dma_addr_t	dscr_map;

	uint8_t		fw_sb_id;
	uint8_t		sb_cq_index;
	uint8_t		cos;		/* valid if ECORE_Q_FLG_COS */
	uint16_t		traffic_type;
	/* equals to the leading rss client id, used for TX classification*/
	uint8_t		tss_leading_cl_id;

	/* valid if ECORE_Q_FLG_DEF_VLAN */
	uint16_t		default_vlan;
};

struct ecore_queue_setup_params {
	struct ecore_general_setup_params gen_params;
	struct ecore_txq_setup_params txq_params;
	struct ecore_rxq_setup_params rxq_params;
	struct rxq_pause_params pause_params;
	unsigned long flags;
};

struct ecore_queue_setup_tx_only_params {
	struct ecore_general_setup_params	gen_params;
	struct ecore_txq_setup_params		txq_params;
	unsigned long				flags;
	/* index within the tx_only cids of this queue object */
	uint8_t					cid_index;
};

struct ecore_queue_state_params {
	struct ecore_queue_sp_obj *q_obj;

	/* Current command */
	enum ecore_queue_cmd cmd;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long ramrod_flags;

	/* Params according to the current command */
	union {
		struct ecore_queue_update_params	update;
		struct ecore_queue_setup_params		setup;
		struct ecore_queue_init_params		init;
		struct ecore_queue_setup_tx_only_params	tx_only;
		struct ecore_queue_terminate_params	terminate;
		struct ecore_queue_cfc_del_params	cfc_del;
	} params;
};

struct ecore_viflist_params {
	uint8_t echo_res;
	uint8_t func_bit_map_res;
};

struct ecore_queue_sp_obj {
	uint32_t		cids[ECORE_MULTI_TX_COS];
	uint8_t		cl_id;
	uint8_t		func_id;

	/* number of traffic classes supported by queue.
	 * The primary connection of the queue supports the first traffic
	 * class. Any further traffic class is supported by a tx-only
	 * connection.
	 *
	 * Therefore max_cos is also a number of valid entries in the cids
	 * array.
	 */
	uint8_t max_cos;
	uint8_t num_tx_only, next_tx_only;

	enum ecore_q_state state, next_state;

	/* bits from enum ecore_q_type */
	unsigned long	type;

	/* ECORE_Q_CMD_XX bits. This object implements "one
	 * pending" paradigm but for debug and tracing purposes it's
	 * more convenient to have different bits for different
	 * commands.
	 */
	unsigned long	pending;

	/* Buffer to use as a ramrod data and its mapping */
	void		*rdata;
	ecore_dma_addr_t	rdata_mapping;

	/**
	 * Performs one state change according to the given parameters.
	 *
	 * @return 0 in case of success and negative value otherwise.
	 */
	int (*send_cmd)(struct bnx2x_softc *sc,
			struct ecore_queue_state_params *params);

	/**
	 * Sets the pending bit according to the requested transition.
	 */
	int (*set_pending)(struct ecore_queue_sp_obj *o,
			   struct ecore_queue_state_params *params);

	/**
	 * Checks that the requested state transition is legal.
	 */
	int (*check_transition)(struct bnx2x_softc *sc,
				struct ecore_queue_sp_obj *o,
				struct ecore_queue_state_params *params);

	/**
	 * Completes the pending command.
	 */
	int (*complete_cmd)(struct bnx2x_softc *sc,
			    struct ecore_queue_sp_obj *o,
			    enum ecore_queue_cmd);

	int (*wait_comp)(struct bnx2x_softc *sc,
			 struct ecore_queue_sp_obj *o,
			 enum ecore_queue_cmd cmd);
};

/********************** Function state update *********************************/
/* Allowed Function states */
enum ecore_func_state {
	ECORE_F_STATE_RESET,
	ECORE_F_STATE_INITIALIZED,
	ECORE_F_STATE_STARTED,
	ECORE_F_STATE_TX_STOPPED,
	ECORE_F_STATE_MAX,
};

/* Allowed Function commands */
enum ecore_func_cmd {
	ECORE_F_CMD_HW_INIT,
	ECORE_F_CMD_START,
	ECORE_F_CMD_STOP,
	ECORE_F_CMD_HW_RESET,
	ECORE_F_CMD_AFEX_UPDATE,
	ECORE_F_CMD_AFEX_VIFLISTS,
	ECORE_F_CMD_TX_STOP,
	ECORE_F_CMD_TX_START,
	ECORE_F_CMD_SWITCH_UPDATE,
	ECORE_F_CMD_MAX,
};

struct ecore_func_hw_init_params {
	/* A load phase returned by MCP.
	 *
	 * May be:
	 *		FW_MSG_CODE_DRV_LOAD_COMMON_CHIP
	 *		FW_MSG_CODE_DRV_LOAD_COMMON
	 *		FW_MSG_CODE_DRV_LOAD_PORT
	 *		FW_MSG_CODE_DRV_LOAD_FUNCTION
	 */
	uint32_t load_phase;
};

struct ecore_func_hw_reset_params {
	/* A load phase returned by MCP.
	 *
	 * May be:
	 *		FW_MSG_CODE_DRV_LOAD_COMMON_CHIP
	 *		FW_MSG_CODE_DRV_LOAD_COMMON
	 *		FW_MSG_CODE_DRV_LOAD_PORT
	 *		FW_MSG_CODE_DRV_LOAD_FUNCTION
	 */
	uint32_t reset_phase;
};

struct ecore_func_start_params {
	/* Multi Function mode:
	 *	- Single Function
	 *	- Switch Dependent
	 *	- Switch Independent
	 */
	uint16_t mf_mode;

	/* Switch Dependent mode outer VLAN tag */
	uint16_t sd_vlan_tag;

	/* Function cos mode */
	uint8_t network_cos_mode;

	/* NVGRE classification enablement */
	uint8_t nvgre_clss_en;

	/* NO_GRE_TUNNEL/NVGRE_TUNNEL/L2GRE_TUNNEL/IPGRE_TUNNEL */
	uint8_t gre_tunnel_mode;

	/* GRE_OUTER_HEADERS_RSS/GRE_INNER_HEADERS_RSS/NVGRE_KEY_ENTROPY_RSS */
	uint8_t gre_tunnel_rss;

};

struct ecore_func_switch_update_params {
	uint8_t suspend;
};

struct ecore_func_afex_update_params {
	uint16_t vif_id;
	uint16_t afex_default_vlan;
	uint8_t allowed_priorities;
};

struct ecore_func_afex_viflists_params {
	uint16_t vif_list_index;
	uint8_t func_bit_map;
	uint8_t afex_vif_list_command;
	uint8_t func_to_clear;
};
struct ecore_func_tx_start_params {
	struct priority_cos traffic_type_to_priority_cos[MAX_TRAFFIC_TYPES];
	uint8_t dcb_enabled;
	uint8_t dcb_version;
	uint8_t dont_add_pri_0;
};

struct ecore_func_state_params {
	struct ecore_func_sp_obj *f_obj;

	/* Current command */
	enum ecore_func_cmd cmd;

	/* may have RAMROD_COMP_WAIT set only */
	unsigned long	ramrod_flags;

	/* Params according to the current command */
	union {
		struct ecore_func_hw_init_params hw_init;
		struct ecore_func_hw_reset_params hw_reset;
		struct ecore_func_start_params start;
		struct ecore_func_switch_update_params switch_update;
		struct ecore_func_afex_update_params afex_update;
		struct ecore_func_afex_viflists_params afex_viflists;
		struct ecore_func_tx_start_params tx_start;
	} params;
};

struct ecore_func_sp_drv_ops {
	/* Init tool + runtime initialization:
	 *      - Common Chip
	 *      - Common (per Path)
	 *      - Port
	 *      - Function phases
	 */
	int (*init_hw_cmn_chip)(struct bnx2x_softc *sc);
	int (*init_hw_cmn)(struct bnx2x_softc *sc);
	int (*init_hw_port)(struct bnx2x_softc *sc);
	int (*init_hw_func)(struct bnx2x_softc *sc);

	/* Reset Function HW: Common, Port, Function phases. */
	void (*reset_hw_cmn)(struct bnx2x_softc *sc);
	void (*reset_hw_port)(struct bnx2x_softc *sc);
	void (*reset_hw_func)(struct bnx2x_softc *sc);

	/* Prepare/Release FW resources */
	int (*init_fw)(struct bnx2x_softc *sc);
	void (*release_fw)(struct bnx2x_softc *sc);
};

struct ecore_func_sp_obj {
	enum ecore_func_state	state, next_state;

	/* ECORE_FUNC_CMD_XX bits. This object implements "one
	 * pending" paradigm but for debug and tracing purposes it's
	 * more convenient to have different bits for different
	 * commands.
	 */
	unsigned long		pending;

	/* Buffer to use as a ramrod data and its mapping */
	void			*rdata;
	ecore_dma_addr_t		rdata_mapping;

	/* Buffer to use as a afex ramrod data and its mapping.
	 * This can't be same rdata as above because afex ramrod requests
	 * can arrive to the object in parallel to other ramrod requests.
	 */
	void			*afex_rdata;
	ecore_dma_addr_t		afex_rdata_mapping;

	/* this mutex validates that when pending flag is taken, the next
	 * ramrod to be sent will be the one set the pending bit
	 */
	ECORE_MUTEX		one_pending_mutex;

	/* Driver interface */
	struct ecore_func_sp_drv_ops	*drv;

	/**
	 * Performs one state change according to the given parameters.
	 *
	 * @return 0 in case of success and negative value otherwise.
	 */
	int (*send_cmd)(struct bnx2x_softc *sc,
			struct ecore_func_state_params *params);

	/**
	 * Checks that the requested state transition is legal.
	 */
	int (*check_transition)(struct bnx2x_softc *sc,
				struct ecore_func_sp_obj *o,
				struct ecore_func_state_params *params);

	/**
	 * Completes the pending command.
	 */
	int (*complete_cmd)(struct bnx2x_softc *sc,
			    struct ecore_func_sp_obj *o,
			    enum ecore_func_cmd cmd);

	int (*wait_comp)(struct bnx2x_softc *sc, struct ecore_func_sp_obj *o,
			 enum ecore_func_cmd cmd);
};

/********************** Interfaces ********************************************/
/* Queueable objects set */
union ecore_qable_obj {
	struct ecore_vlan_mac_obj vlan_mac;
};
/************** Function state update *********/
void ecore_init_func_obj(struct bnx2x_softc *sc,
			 struct ecore_func_sp_obj *obj,
			 void *rdata, ecore_dma_addr_t rdata_mapping,
			 void *afex_rdata, ecore_dma_addr_t afex_rdata_mapping,
			 struct ecore_func_sp_drv_ops *drv_iface);

int ecore_func_state_change(struct bnx2x_softc *sc,
			    struct ecore_func_state_params *params);

enum ecore_func_state ecore_func_get_state(struct bnx2x_softc *sc,
					   struct ecore_func_sp_obj *o);
/******************* Queue State **************/
void ecore_init_queue_obj(struct bnx2x_softc *sc,
			  struct ecore_queue_sp_obj *obj, uint8_t cl_id, uint32_t *cids,
			  uint8_t cid_cnt, uint8_t func_id, void *rdata,
			  ecore_dma_addr_t rdata_mapping, unsigned long type);

int ecore_queue_state_change(struct bnx2x_softc *sc,
			     struct ecore_queue_state_params *params);

/********************* VLAN-MAC ****************/
void ecore_init_mac_obj(struct bnx2x_softc *sc,
			struct ecore_vlan_mac_obj *mac_obj,
			uint8_t cl_id, uint32_t cid, uint8_t func_id, void *rdata,
			ecore_dma_addr_t rdata_mapping, int state,
			unsigned long *pstate, ecore_obj_type type,
			struct ecore_credit_pool_obj *macs_pool);

void ecore_vlan_mac_h_read_unlock(struct bnx2x_softc *sc,
				  struct ecore_vlan_mac_obj *o);
int ecore_vlan_mac_h_write_lock(struct bnx2x_softc *sc,
				struct ecore_vlan_mac_obj *o);
void ecore_vlan_mac_h_write_unlock(struct bnx2x_softc *sc,
					  struct ecore_vlan_mac_obj *o);
int ecore_config_vlan_mac(struct bnx2x_softc *sc,
			   struct ecore_vlan_mac_ramrod_params *p);

int ecore_vlan_mac_move(struct bnx2x_softc *sc,
			struct ecore_vlan_mac_ramrod_params *p,
			struct ecore_vlan_mac_obj *dest_o);

/********************* RX MODE ****************/

void ecore_init_rx_mode_obj(struct bnx2x_softc *sc,
			    struct ecore_rx_mode_obj *o);

/**
 * ecore_config_rx_mode - Send and RX_MODE ramrod according to the provided parameters.
 *
 * @p: Command parameters
 *
 * Return: 0 - if operation was successful and there is no pending completions,
 *         positive number - if there are pending completions,
 *         negative - if there were errors
 */
int ecore_config_rx_mode(struct bnx2x_softc *sc,
			 struct ecore_rx_mode_ramrod_params *p);

/****************** MULTICASTS ****************/

void ecore_init_mcast_obj(struct bnx2x_softc *sc,
			  struct ecore_mcast_obj *mcast_obj,
			  uint8_t mcast_cl_id, uint32_t mcast_cid, uint8_t func_id,
			  uint8_t engine_id, void *rdata, ecore_dma_addr_t rdata_mapping,
			  int state, unsigned long *pstate,
			  ecore_obj_type type);

/**
 * ecore_config_mcast - Configure multicast MACs list.
 *
 * @cmd: command to execute: BNX2X_MCAST_CMD_X
 *
 * May configure a new list
 * provided in p->mcast_list (ECORE_MCAST_CMD_ADD), clean up
 * (ECORE_MCAST_CMD_DEL) or restore (ECORE_MCAST_CMD_RESTORE) a current
 * configuration, continue to execute the pending commands
 * (ECORE_MCAST_CMD_CONT).
 *
 * If previous command is still pending or if number of MACs to
 * configure is more that maximum number of MACs in one command,
 * the current command will be enqueued to the tail of the
 * pending commands list.
 *
 * Return: 0 is operation was successful and there are no pending completions,
 *         negative if there were errors, positive if there are pending
 *         completions.
 */
int ecore_config_mcast(struct bnx2x_softc *sc,
		       struct ecore_mcast_ramrod_params *p,
		       enum ecore_mcast_cmd cmd);

/****************** CREDIT POOL ****************/
void ecore_init_mac_credit_pool(struct bnx2x_softc *sc,
				struct ecore_credit_pool_obj *p, uint8_t func_id,
				uint8_t func_num);
void ecore_init_vlan_credit_pool(struct bnx2x_softc *sc,
				 struct ecore_credit_pool_obj *p, uint8_t func_id,
				 uint8_t func_num);

/****************** RSS CONFIGURATION ****************/
void ecore_init_rss_config_obj(struct ecore_rss_config_obj *rss_obj,
			       uint8_t cl_id, uint32_t cid, uint8_t func_id, uint8_t engine_id,
			       void *rdata, ecore_dma_addr_t rdata_mapping,
			       int state, unsigned long *pstate,
			       ecore_obj_type type);

/**
 * ecore_config_rss - Updates RSS configuration according to provided parameters
 *
 * Return: 0 in case of success
 */
int ecore_config_rss(struct bnx2x_softc *sc,
		     struct ecore_config_rss_params *p);


#endif /* ECORE_SP_H */
