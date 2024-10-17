/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#include "roc_api.h"
#include "roc_priv.h"

static void
npc_prep_mcam_ldata(uint8_t *ptr, const uint8_t *data, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		ptr[idx] = data[len - 1 - idx];
}

static int
npc_check_copysz(size_t size, size_t len)
{
	if (len <= size)
		return len;
	return NPC_ERR_PARAM;
}

static inline int
npc_mem_is_zero(const void *mem, int len)
{
	const char *m = mem;
	int i;

	for (i = 0; i < len; i++) {
		if (m[i] != 0)
			return 0;
	}
	return 1;
}

static void
npc_set_hw_mask(struct npc_parse_item_info *info, struct npc_xtract_info *xinfo,
		char *hw_mask)
{
	int max_off, offset;
	int j;

	if (xinfo->enable == 0)
		return;

	if (xinfo->hdr_off < info->hw_hdr_len)
		return;

	max_off = xinfo->hdr_off + xinfo->len - info->hw_hdr_len;

	if (max_off > info->len)
		max_off = info->len;

	offset = xinfo->hdr_off - info->hw_hdr_len;
	for (j = offset; j < max_off; j++)
		hw_mask[j] = 0xff;
}

void
npc_get_hw_supp_mask(struct npc_parse_state *pst,
		     struct npc_parse_item_info *info, int lid, int lt)
{
	struct npc_xtract_info *xinfo, *lfinfo;
	char *hw_mask = info->hw_mask;
	int lf_cfg = 0;
	int i, j;
	int intf;

	intf = pst->nix_intf;
	xinfo = pst->npc->prx_dxcfg[intf][lid][lt].xtract;
	memset(hw_mask, 0, info->len);

	for (i = 0; i < NPC_MAX_LD; i++)
		npc_set_hw_mask(info, &xinfo[i], hw_mask);

	for (i = 0; i < NPC_MAX_LD; i++) {
		if (xinfo[i].flags_enable == 0)
			continue;

		lf_cfg = pst->npc->prx_lfcfg[i].i;
		if (lf_cfg == lid) {
			for (j = 0; j < NPC_MAX_LFL; j++) {
				lfinfo = pst->npc->prx_fxcfg[intf][i][j].xtract;
				npc_set_hw_mask(info, &lfinfo[0], hw_mask);
			}
		}
	}
}

inline int
npc_mask_is_supported(const char *mask, const char *hw_mask, int len)
{
	/*
	 * If no hw_mask, assume nothing is supported.
	 * mask is never NULL
	 */
	if (hw_mask == NULL)
		return npc_mem_is_zero(mask, len);

	while (len--) {
		if ((mask[len] | hw_mask[len]) != hw_mask[len])
			return 0; /* False */
	}
	return 1;
}

int
npc_parse_item_basic(const struct roc_npc_item_info *item,
		     struct npc_parse_item_info *info)
{
	/* Item must not be NULL */
	if (item == NULL)
		return NPC_ERR_PARAM;

	/* Don't support ranges */
	if (item->last != NULL)
		return NPC_ERR_INVALID_RANGE;

	/* If spec is NULL, both mask and last must be NULL, this
	 * makes it to match ANY value (eq to mask = 0).
	 * Setting either mask or last without spec is an error
	 */
	if (item->spec == NULL) {
		if (item->last == NULL && item->mask == NULL) {
			info->spec = NULL;
			return 0;
		}
		return NPC_ERR_INVALID_SPEC;
	}

	/* We have valid spec */
	if (item->type != ROC_NPC_ITEM_TYPE_RAW)
		info->spec = item->spec;

	/* If mask is not set, use default mask, err if default mask is
	 * also NULL.
	 */
	if (item->mask == NULL) {
		if (info->def_mask == NULL)
			return NPC_ERR_PARAM;
		info->mask = info->def_mask;
	} else {
		if (item->type != ROC_NPC_ITEM_TYPE_RAW)
			info->mask = item->mask;
	}

	if (info->mask == NULL)
		return NPC_ERR_INVALID_MASK;

	/* mask specified must be subset of hw supported mask
	 * mask | hw_mask == hw_mask
	 */
	if (!npc_mask_is_supported(info->mask, info->hw_mask, info->len))
		return NPC_ERR_INVALID_MASK;

	return 0;
}

static int
npc_update_extraction_data(struct npc_parse_state *pst,
			   struct npc_parse_item_info *info,
			   struct npc_xtract_info *xinfo)
{
	uint8_t int_info_mask[NPC_MAX_EXTRACT_DATA_LEN];
	uint8_t int_info[NPC_MAX_EXTRACT_DATA_LEN];
	struct npc_xtract_info *x;
	int hdr_off;
	int len = 0;

	x = xinfo;
	if (x->len > NPC_MAX_EXTRACT_DATA_LEN)
		return NPC_ERR_INVALID_SIZE;

	len = x->len;
	hdr_off = x->hdr_off;

	if (hdr_off < info->hw_hdr_len)
		return 0;

	if (x->enable == 0)
		return 0;

	hdr_off -= info->hw_hdr_len;

	if (hdr_off >= info->len)
		return 0;

	if (hdr_off + len > info->len)
		len = info->len - hdr_off;

	len = npc_check_copysz((ROC_NPC_MAX_MCAM_WIDTH_DWORDS * 8) - x->key_off,
			       len);
	if (len < 0)
		return NPC_ERR_INVALID_SIZE;

	/* Need to reverse complete structure so that dest addr is at
	 * MSB so as to program the MCAM using mcam_data & mcam_mask
	 * arrays
	 */
	npc_prep_mcam_ldata(int_info, (const uint8_t *)info->spec + hdr_off,
			    x->len);
	npc_prep_mcam_ldata(int_info_mask,
			    (const uint8_t *)info->mask + hdr_off, x->len);

	memcpy(pst->mcam_mask + x->key_off, int_info_mask, len);
	memcpy(pst->mcam_data + x->key_off, int_info, len);
	return 0;
}

int
npc_update_parse_state(struct npc_parse_state *pst,
		       struct npc_parse_item_info *info, int lid, int lt,
		       uint8_t flags)
{
	struct npc_lid_lt_xtract_info *xinfo;
	struct roc_npc_flow_dump_data *dump;
	struct npc_xtract_info *lfinfo;
	int intf, lf_cfg;
	int i, j, rc = 0;

	pst->layer_mask |= lid;
	pst->lt[lid] = lt;
	pst->flags[lid] = flags;

	intf = pst->nix_intf;
	xinfo = &pst->npc->prx_dxcfg[intf][lid][lt];
	if (xinfo->is_terminating)
		pst->terminate = 1;

	if (info->spec == NULL)
		goto done;

	for (i = 0; i < NPC_MAX_LD; i++) {
		rc = npc_update_extraction_data(pst, info, &xinfo->xtract[i]);
		if (rc != 0)
			return rc;
	}

	for (i = 0; i < NPC_MAX_LD; i++) {
		if (xinfo->xtract[i].flags_enable == 0)
			continue;

		lf_cfg = pst->npc->prx_lfcfg[i].i;
		if (lf_cfg == lid) {
			for (j = 0; j < NPC_MAX_LFL; j++) {
				lfinfo = pst->npc->prx_fxcfg[intf][i][j].xtract;
				rc = npc_update_extraction_data(pst, info,
								&lfinfo[0]);
				if (rc != 0)
					return rc;

				if (lfinfo[0].enable)
					pst->flags[lid] = j;
			}
		}
	}

done:
	dump = &pst->flow->dump_data[pst->flow->num_patterns++];
	dump->lid = lid;
	dump->ltype = lt;
	pst->pattern++;
	return 0;
}

int
npc_mcam_init(struct npc *npc, struct roc_npc_flow *flow, int mcam_id)
{
	struct npc_mcam_write_entry_req *req;
	struct npc_mcam_write_entry_rsq *rsp;
	int rc = 0, idx;

	req = mbox_alloc_msg_npc_mcam_write_entry(npc->mbox);
	if (req == NULL)
		return -ENOSPC;
	req->set_cntr = 0;
	req->cntr = 0;
	req->entry = mcam_id;

	req->intf = (flow->nix_intf == NIX_INTF_RX) ? NPC_MCAM_RX : NPC_MCAM_TX;
	req->enable_entry = 1;
	req->entry_data.action = flow->npc_action;
	req->entry_data.vtag_action = flow->vtag_action;

	for (idx = 0; idx < ROC_NPC_MAX_MCAM_WIDTH_DWORDS; idx++) {
		req->entry_data.kw[idx] = 0x0;
		req->entry_data.kw_mask[idx] = 0x0;
	}

	if (flow->nix_intf == NIX_INTF_RX) {
		req->entry_data.kw[0] |= (uint64_t)npc->channel;
		req->entry_data.kw_mask[0] |= (BIT_ULL(12) - 1);
	} else {
		uint16_t pf_func = (flow->npc_action >> 4) & 0xffff;

		pf_func = plt_cpu_to_be_16(pf_func);
		req->entry_data.kw[0] |= ((uint64_t)pf_func << 32);
		req->entry_data.kw_mask[0] |= ((uint64_t)0xffff << 32);
	}

	rc = mbox_process_msg(npc->mbox, (void *)&rsp);
	if (rc != 0) {
		plt_err("npc: mcam initialisation write failed");
		return rc;
	}
	return 0;
}

int
npc_mcam_move(struct mbox *mbox, uint16_t old_ent, uint16_t new_ent)
{
	struct npc_mcam_shift_entry_req *req;
	struct npc_mcam_shift_entry_rsp *rsp;
	int rc = -ENOSPC;

	/* Old entry is disabled & it's contents are moved to new_entry,
	 * new entry is enabled finally.
	 */
	req = mbox_alloc_msg_npc_mcam_shift_entry(mbox);
	if (req == NULL)
		return rc;
	req->curr_entry[0] = old_ent;
	req->new_entry[0] = new_ent;
	req->shift_count = 1;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		return rc;

	return 0;
}

enum SHIFT_DIR {
	SLIDE_ENTRIES_TO_LOWER_INDEX,
	SLIDE_ENTRIES_TO_HIGHER_INDEX,
};

static int
npc_slide_mcam_entries(struct mbox *mbox, struct npc *npc, int prio,
		       uint16_t *free_mcam_id, int dir)
{
	uint16_t to_mcam_id = 0, from_mcam_id = 0;
	struct npc_prio_flow_list_head *list;
	struct npc_prio_flow_entry *curr = 0;
	int rc = 0;

	list = &npc->prio_flow_list[prio];

	to_mcam_id = *free_mcam_id;
	if (dir == SLIDE_ENTRIES_TO_HIGHER_INDEX)
		curr = TAILQ_LAST(list, npc_prio_flow_list_head);
	else if (dir == SLIDE_ENTRIES_TO_LOWER_INDEX)
		curr = TAILQ_FIRST(list);

	while (curr) {
		from_mcam_id = curr->flow->mcam_id;
		if ((dir == SLIDE_ENTRIES_TO_HIGHER_INDEX &&
		     from_mcam_id < to_mcam_id) ||
		    (dir == SLIDE_ENTRIES_TO_LOWER_INDEX &&
		     from_mcam_id > to_mcam_id)) {
			/* Newly allocated entry and the source entry given to
			 * npc_mcam_shift_entry_req will be in disabled state.
			 * Initialise and enable before moving an entry into
			 * this mcam.
			 */
			rc = npc_mcam_init(npc, curr->flow, to_mcam_id);
			if (rc)
				return rc;
			rc = npc_mcam_move(mbox, from_mcam_id, to_mcam_id);
			if (rc)
				return rc;
			curr->flow->mcam_id = to_mcam_id;
			to_mcam_id = from_mcam_id;
		}

		if (dir == SLIDE_ENTRIES_TO_HIGHER_INDEX)
			curr = TAILQ_PREV(curr, npc_prio_flow_list_head, next);
		else if (dir == SLIDE_ENTRIES_TO_LOWER_INDEX)
			curr = TAILQ_NEXT(curr, next);
	}

	*free_mcam_id = from_mcam_id;

	return 0;
}

/*
 * The mcam_alloc request is first made with NPC_MCAM_LOWER_PRIO with the last
 * entry in the requested priority level as the reference entry. If it fails,
 * the alloc request is retried with NPC_MCAM_HIGHER_PRIO with the first entry
 * in the next lower priority level as the reference entry. After obtaining
 * the free MCAM from kernel, we check if it is at the right user requested
 * priority level. If not, the flow rules are moved across MCAM entries till
 * the user requested priority levels are met.
 * The MCAM sorting algorithm works as below.
 * For any given free MCAM obtained from the kernel, there are 3 possibilities.
 * Case 1:
 * There are entries belonging to higher user priority level (numerically
 * lesser) in higher mcam indices. In this case, the entries with higher user
 * priority are slided towards lower indices and a free entry is created in the
 * higher indices.
 * Example:
 * Assume free entry = 1610, user requested priority = 2 and
 * max user priority levels = 5 with below entries in respective priority
 * levels.
 * 0: 1630, 1635, 1641
 * 1: 1646, 1650, 1651
 * 2: 1652, 1655, 1660
 * 3: 1661, 1662, 1663, 1664
 * 4: 1665, 1667, 1670
 *
 * Entries (1630, 1635, 1641, 1646, 1650, 1651) have to be slided down towards
 * lower indices.
 * Shifting sequence will be as below:
 *     1610 <- 1630 <- 1635 <- 1641 <- 1646 <- 1650 <- 1651
 * Entry 1651 will be free-ed for writing the new flow. This entry will now
 * become the head of priority level 2.
 *
 * Case 2:
 * There are entries belonging to lower user priority level (numerically
 * bigger) in lower mcam indices. In this case, the entries with lower user
 * priority are slided towards higher indices and a free entry is created in the
 * lower indices.
 *
 * Example:
 * free entry = 1653, user requested priority = 0
 * 0: 1630, 1635, 1641
 * 1: 1646, 1650, 1651
 * 2: 1652, 1655, 1660
 * 3: 1661, 1662, 1663, 1664
 * 4: 1665, 1667, 1670
 *
 * Entries (1646, 1650, 1651, 1652) have to be slided up towards higher
 * indices.
 * Shifting sequence will be as below:
 *     1646 -> 1650 -> 1651 -> 1652 -> 1653
 * Entry 1646 will be free-ed for writing the new flow. This entry will now
 * become the last element in priority level 0.
 *
 * Case 3:
 * Free mcam is at the right place, ie, all higher user priority level
 * mcams lie in lower indices and all lower user priority level mcams lie in
 * higher mcam indices.
 *
 * The priority level lists are scanned first for case (1) and if the
 * condition is found true, case(2) is skipped because they are mutually
 * exclusive. For example, consider below state.
 * 0: 1630, 1635, 1641
 * 1: 1646, 1650, 1651
 * 2: 1652, 1655, 1660
 * 3: 1661, 1662, 1663, 1664
 * 4: 1665, 1667, 1670
 * free entry = 1610, user requested priority = 2
 *
 * Case 1: Here the condition is;
 * "if (requested_prio > prio_idx && free_mcam < tail->flow->mcam_id ){}"
 * If this condition is true, it means at some higher priority level than
 * requested priority level, there are entries at lower indices than the given
 * free mcam. That is, we have found in levels 0,1 there is an mcam X which is
 * greater than 1610.
 * If, for any free entry and user req prio, the above condition is true, then
 * the below case(2) condition will always be false since the lists are kept
 * sorted. The case(2) condition is;
 *  "if (requested_prio < prio_idx && free_mcam > head->flow->mcam_id){}"
 * There can't be entries at lower indices at priority level higher
 * than the requested priority level. That is, here, at levels 3 & 4 there
 * cannot be any entry greater than 1610. Because all entries in 3 & 4 must be
 * greater than X which was found to be greater than 1610 earlier.
 */

static int
npc_sort_mcams_by_user_prio_level(struct mbox *mbox,
				  struct npc_prio_flow_entry *flow_list_entry,
				  struct npc *npc,
				  struct npc_mcam_alloc_entry_rsp *rsp)
{
	int requested_prio = flow_list_entry->flow->priority;
	struct npc_prio_flow_entry *head, *tail;
	struct npc_prio_flow_list_head *list;
	uint16_t free_mcam = rsp->entry;
	bool do_reverse_scan = true;
	int prio_idx = 0, rc = 0;

	while (prio_idx <= npc->flow_max_priority - 1) {
		list = &npc->prio_flow_list[prio_idx];
		tail = TAILQ_LAST(list, npc_prio_flow_list_head);

		/* requested priority is lower than current level
		 * ie, numerically req prio is higher
		 */
		if ((requested_prio > prio_idx) && tail) {
			/* but there are some mcams in current level
			 * at higher indices, ie, at priority lower
			 * than free_mcam.
			 */
			if (free_mcam < tail->flow->mcam_id) {
				rc = npc_slide_mcam_entries(
					mbox, npc, prio_idx, &free_mcam,
					SLIDE_ENTRIES_TO_LOWER_INDEX);
				if (rc)
					return rc;
				do_reverse_scan = false;
			}
		}
		prio_idx++;
	}

	prio_idx = npc->flow_max_priority - 1;
	while (prio_idx && do_reverse_scan) {
		list = &npc->prio_flow_list[prio_idx];
		head = TAILQ_FIRST(list);

		/* requested priority is higher than current level
		 * ie, numerically req prio is lower
		 */
		if (requested_prio < prio_idx && head) {
			/* but free mcam is higher than lowest priority
			 * mcam in current level
			 */
			if (free_mcam > head->flow->mcam_id) {
				rc = npc_slide_mcam_entries(
					mbox, npc, prio_idx, &free_mcam,
					SLIDE_ENTRIES_TO_HIGHER_INDEX);
				if (rc)
					return rc;
			}
		}
		prio_idx--;
	}
	rsp->entry = free_mcam;
	return rc;
}

static void
npc_insert_into_flow_list(struct npc *npc, struct npc_prio_flow_entry *entry)
{
	struct npc_prio_flow_list_head *list;
	struct npc_prio_flow_entry *curr;

	list = &npc->prio_flow_list[entry->flow->priority];
	curr = TAILQ_FIRST(list);

	if (curr) {
		while (curr) {
			if (entry->flow->mcam_id > curr->flow->mcam_id)
				curr = TAILQ_NEXT(curr, next);
			else
				break;
		}
		if (curr)
			TAILQ_INSERT_BEFORE(curr, entry, next);
		else
			TAILQ_INSERT_TAIL(list, entry, next);
	} else {
		TAILQ_INSERT_HEAD(list, entry, next);
	}
}

static int
npc_allocate_mcam_entry(struct mbox *mbox, int prio,
			struct npc_mcam_alloc_entry_rsp *rsp_local,
			int ref_entry)
{
	struct npc_mcam_alloc_entry_rsp *rsp_cmd;
	struct npc_mcam_alloc_entry_req *req;
	struct npc_mcam_alloc_entry_rsp *rsp;
	int rc = -ENOSPC;

	req = mbox_alloc_msg_npc_mcam_alloc_entry(mbox);
	if (req == NULL)
		return rc;
	req->contig = 1;
	req->count = 1;
	req->priority = prio;
	req->ref_entry = ref_entry;

	rc = mbox_process_msg(mbox, (void *)&rsp_cmd);
	if (rc)
		return rc;

	if (!rsp_cmd->count)
		return -ENOSPC;

	mbox_memcpy(rsp_local, rsp_cmd, sizeof(*rsp));

	return 0;
}

static void
npc_find_mcam_ref_entry(struct roc_npc_flow *flow, struct npc *npc, int *prio,
			int *ref_entry, int dir)
{
	struct npc_prio_flow_entry *head, *tail;
	struct npc_prio_flow_list_head *list;
	int prio_idx = flow->priority;

	if (dir == NPC_MCAM_LOWER_PRIO) {
		while (prio_idx >= 0) {
			list = &npc->prio_flow_list[prio_idx];
			head = TAILQ_FIRST(list);
			if (head) {
				*prio = NPC_MCAM_LOWER_PRIO;
				*ref_entry = head->flow->mcam_id;
				return;
			}
			prio_idx--;
		}
	} else if (dir == NPC_MCAM_HIGHER_PRIO) {
		prio_idx = flow->priority;
		while (prio_idx <= npc->flow_max_priority - 1) {
			list = &npc->prio_flow_list[prio_idx];
			tail = TAILQ_LAST(list, npc_prio_flow_list_head);
			if (tail) {
				*prio = NPC_MCAM_HIGHER_PRIO;
				*ref_entry = tail->flow->mcam_id;
				return;
			}
			prio_idx++;
		}
	}
	*prio = NPC_MCAM_ANY_PRIO;
	*ref_entry = 0;
}

static int
npc_alloc_mcam_by_ref_entry(struct mbox *mbox, struct roc_npc_flow *flow,
			    struct npc *npc,
			    struct npc_mcam_alloc_entry_rsp *rsp_local)
{
	int prio, ref_entry = 0, rc = 0, dir = NPC_MCAM_LOWER_PRIO;
	bool retry_done = false;

retry:
	npc_find_mcam_ref_entry(flow, npc, &prio, &ref_entry, dir);
	rc = npc_allocate_mcam_entry(mbox, prio, rsp_local, ref_entry);
	if (rc && !retry_done) {
		plt_npc_dbg(
			"npc: Failed to allocate lower priority entry. Retrying for higher priority");

		dir = NPC_MCAM_HIGHER_PRIO;
		retry_done = true;
		goto retry;
	} else if (rc && retry_done) {
		return rc;
	}

	return 0;
}

int
npc_get_free_mcam_entry(struct mbox *mbox, struct roc_npc_flow *flow,
			struct npc *npc)
{
	struct npc_mcam_alloc_entry_rsp rsp_local;
	struct npc_prio_flow_entry *new_entry;
	int rc = 0;

	rc = npc_alloc_mcam_by_ref_entry(mbox, flow, npc, &rsp_local);

	if (rc)
		return rc;

	new_entry = plt_zmalloc(sizeof(*new_entry), 0);
	if (!new_entry)
		return -ENOSPC;

	new_entry->flow = flow;

	plt_npc_dbg("kernel allocated MCAM entry %d", rsp_local.entry);

	rc = npc_sort_mcams_by_user_prio_level(mbox, new_entry, npc,
					       &rsp_local);
	if (rc)
		goto err;

	plt_npc_dbg("allocated MCAM entry after sorting %d", rsp_local.entry);
	flow->mcam_id = rsp_local.entry;
	npc_insert_into_flow_list(npc, new_entry);

	return rsp_local.entry;
err:
	plt_free(new_entry);
	return rc;
}

void
npc_delete_prio_list_entry(struct npc *npc, struct roc_npc_flow *flow)
{
	struct npc_prio_flow_list_head *list;
	struct npc_prio_flow_entry *curr;

	list = &npc->prio_flow_list[flow->priority];
	curr = TAILQ_FIRST(list);

	if (!curr)
		return;

	while (curr) {
		if (flow->mcam_id == curr->flow->mcam_id) {
			TAILQ_REMOVE(list, curr, next);
			plt_free(curr);
			break;
		}
		curr = TAILQ_NEXT(curr, next);
	}
}
