/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include "mlx5dr_internal.h"

static bool mlx5dr_matcher_requires_col_tbl(uint8_t log_num_of_rules)
{
	/* Collision table concatenation is done only for large rule tables */
	return log_num_of_rules > MLX5DR_MATCHER_ASSURED_RULES_TH;
}

static uint8_t mlx5dr_matcher_rules_to_tbl_depth(uint8_t log_num_of_rules)
{
	if (mlx5dr_matcher_requires_col_tbl(log_num_of_rules))
		return MLX5DR_MATCHER_ASSURED_MAIN_TBL_DEPTH;

	/* For small rule tables we use a single deep table to assure insertion */
	return RTE_MIN(log_num_of_rules, MLX5DR_MATCHER_ASSURED_COL_TBL_DEPTH);
}

static int mlx5dr_matcher_create_end_ft(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_table *tbl = matcher->tbl;

	matcher->end_ft = mlx5dr_table_create_default_ft(tbl);
	if (!matcher->end_ft) {
		DR_LOG(ERR, "Failed to create matcher end flow table");
		return rte_errno;
	}
	return 0;
}

static void mlx5dr_matcher_destroy_end_ft(struct mlx5dr_matcher *matcher)
{
	mlx5dr_table_destroy_default_ft(matcher->tbl, matcher->end_ft);
}

static int mlx5dr_matcher_free_rtc_pointing(uint32_t fw_ft_type,
					    enum mlx5dr_table_type type,
					    struct mlx5dr_devx_obj *devx_obj)
{
	struct mlx5dr_cmd_ft_modify_attr ft_attr = {0};
	int ret;

	if (type != MLX5DR_TABLE_TYPE_FDB)
		return 0;

	ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
	ft_attr.type = fw_ft_type;
	ft_attr.rtc_id_0 = 0;
	ft_attr.rtc_id_1 = 0;

	ret = mlx5dr_cmd_flow_table_modify(devx_obj, &ft_attr);
	if (ret) {
		DR_LOG(ERR, "Failed to disconnect previous RTC");
		return ret;
	}

	return 0;
}

static int mlx5dr_matcher_connect(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_ft_modify_attr ft_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_matcher *prev = NULL;
	struct mlx5dr_matcher *next = NULL;
	struct mlx5dr_matcher *tmp_matcher;
	struct mlx5dr_devx_obj *ft;
	int ret;

	/* Find location in matcher list */
	if (LIST_EMPTY(&tbl->head)) {
		LIST_INSERT_HEAD(&tbl->head, matcher, next);
		goto connect;
	}

	LIST_FOREACH(tmp_matcher, &tbl->head, next) {
		if (tmp_matcher->attr.priority > matcher->attr.priority) {
			next = tmp_matcher;
			break;
		}
		prev = tmp_matcher;
	}

	if (next)
		LIST_INSERT_BEFORE(next, matcher, next);
	else
		LIST_INSERT_AFTER(prev, matcher, next);

connect:
	ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
	ft_attr.type = tbl->fw_ft_type;

	/* Connect to next */
	if (next) {
		if (next->match_ste.rtc_0)
			ft_attr.rtc_id_0 = next->match_ste.rtc_0->id;
		if (next->match_ste.rtc_1)
			ft_attr.rtc_id_1 = next->match_ste.rtc_1->id;

		ret = mlx5dr_cmd_flow_table_modify(matcher->end_ft, &ft_attr);
		if (ret) {
			DR_LOG(ERR, "Failed to connect new matcher to next RTC");
			goto remove_from_list;
		}
	}

	/* Connect to previous */
	ft = prev ? prev->end_ft : tbl->ft;

	if (matcher->match_ste.rtc_0)
		ft_attr.rtc_id_0 = matcher->match_ste.rtc_0->id;
	if (matcher->match_ste.rtc_1)
		ft_attr.rtc_id_1 = matcher->match_ste.rtc_1->id;

	ret = mlx5dr_cmd_flow_table_modify(ft, &ft_attr);
	if (ret) {
		DR_LOG(ERR, "Failed to connect new matcher to previous FT");
		goto remove_from_list;
	}

	return 0;

remove_from_list:
	LIST_REMOVE(matcher, next);
	return ret;
}

static int mlx5dr_matcher_disconnect(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_cmd_ft_modify_attr ft_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_matcher *tmp_matcher;
	struct mlx5dr_devx_obj *prev_ft;
	struct mlx5dr_matcher *next;
	int ret;

	prev_ft = matcher->tbl->ft;
	LIST_FOREACH(tmp_matcher, &tbl->head, next) {
		if (tmp_matcher == matcher)
			break;

		prev_ft = tmp_matcher->end_ft;
	}

	next = matcher->next.le_next;

	ft_attr.modify_fs = MLX5_IFC_MODIFY_FLOW_TABLE_RTC_ID;
	ft_attr.type = matcher->tbl->fw_ft_type;

	if (next) {
		/* Connect previous end FT to next RTC if exists */
		if (next->match_ste.rtc_0)
			ft_attr.rtc_id_0 = next->match_ste.rtc_0->id;
		if (next->match_ste.rtc_1)
			ft_attr.rtc_id_1 = next->match_ste.rtc_1->id;
	} else {
		/* Matcher is last, point prev end FT to default miss */
		mlx5dr_cmd_set_attr_connect_miss_tbl(tbl->ctx,
						     tbl->fw_ft_type,
						     tbl->type,
						     &ft_attr);
	}

	ret = mlx5dr_cmd_flow_table_modify(prev_ft, &ft_attr);
	if (ret) {
		DR_LOG(ERR, "Failed to disconnect matcher");
		return ret;
	}

	LIST_REMOVE(matcher, next);

	if (!next) {
		/* ft no longer points to any RTC, drop refcount */
		ret = mlx5dr_matcher_free_rtc_pointing(tbl->fw_ft_type,
						       tbl->type,
						       prev_ft);
		if (ret) {
			DR_LOG(ERR, "Failed to reset last RTC refcount");
			return ret;
		}
	}

	return 0;
}

static void mlx5dr_matcher_set_rtc_attr_sz(struct mlx5dr_matcher *matcher,
					   struct mlx5dr_cmd_rtc_create_attr *rtc_attr,
					   bool is_match_rtc,
					   bool is_mirror)
{
	enum mlx5dr_matcher_flow_src flow_src = matcher->attr.optimize_flow_src;
	struct mlx5dr_pool_chunk *ste = &matcher->action_ste.ste;

	if ((flow_src == MLX5DR_MATCHER_FLOW_SRC_VPORT && !is_mirror) ||
	    (flow_src == MLX5DR_MATCHER_FLOW_SRC_WIRE && is_mirror)) {
		/* Optimize FDB RTC */
		rtc_attr->log_size = 0;
		rtc_attr->log_depth = 0;
	} else {
		/* Keep original values */
		rtc_attr->log_size = is_match_rtc ? matcher->attr.table.sz_row_log : ste->order;
		rtc_attr->log_depth = is_match_rtc ? matcher->attr.table.sz_col_log : 0;
	}
}

static int mlx5dr_matcher_create_rtc(struct mlx5dr_matcher *matcher,
				     bool is_match_rtc)
{
	const char *rtc_type_str = is_match_rtc ? "match" : "action";
	struct mlx5dr_cmd_rtc_create_attr rtc_attr = {0};
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dr_action_default_stc *default_stc;
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_devx_obj **rtc_0, **rtc_1;
	struct mlx5dr_pool *ste_pool, *stc_pool;
	struct mlx5dr_devx_obj *devx_obj;
	struct mlx5dr_pool_chunk *ste;
	int ret;

	if (is_match_rtc) {
		rtc_0 = &matcher->match_ste.rtc_0;
		rtc_1 = &matcher->match_ste.rtc_1;
		ste_pool = matcher->match_ste.pool;
		ste = &matcher->match_ste.ste;
		ste->order = matcher->attr.table.sz_col_log +
			     matcher->attr.table.sz_row_log;
		rtc_attr.log_size = matcher->attr.table.sz_row_log;
		rtc_attr.log_depth = matcher->attr.table.sz_col_log;
		rtc_attr.update_index_mode = MLX5_IFC_RTC_STE_UPDATE_MODE_BY_HASH;
		/* The first match template is used since all share the same definer */
		rtc_attr.definer_id = mlx5dr_definer_get_id(matcher->mt[0]->definer);
		rtc_attr.is_jumbo = mlx5dr_definer_is_jumbo(matcher->mt[0]->definer);
		rtc_attr.miss_ft_id = matcher->end_ft->id;
		/* Match pool requires implicit allocation */
		ret = mlx5dr_pool_chunk_alloc(ste_pool, ste);
		if (ret) {
			DR_LOG(ERR, "Failed to allocate STE for %s RTC", rtc_type_str);
			return ret;
		}
	} else {
		rtc_0 = &matcher->action_ste.rtc_0;
		rtc_1 = &matcher->action_ste.rtc_1;
		ste_pool = matcher->action_ste.pool;
		ste = &matcher->action_ste.ste;
		ste->order = rte_log2_u32(matcher->action_ste.max_stes) +
			     matcher->attr.table.sz_row_log;
		rtc_attr.log_size = ste->order;
		rtc_attr.log_depth = 0;
		rtc_attr.update_index_mode = MLX5_IFC_RTC_STE_UPDATE_MODE_BY_OFFSET;
		/* The action STEs use the default always hit definer */
		rtc_attr.definer_id = ctx->caps->trivial_match_definer;
		rtc_attr.is_jumbo = false;
		rtc_attr.miss_ft_id = 0;
	}

	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(ste_pool, ste);

	rtc_attr.pd = ctx->pd_num;
	rtc_attr.ste_base = devx_obj->id;
	rtc_attr.ste_offset = ste->offset;
	rtc_attr.table_type = mlx5dr_table_get_res_fw_ft_type(tbl->type, false);
	mlx5dr_matcher_set_rtc_attr_sz(matcher, &rtc_attr, is_match_rtc, false);

	/* STC is a single resource (devx_obj), use any STC for the ID */
	stc_pool = ctx->stc_pool[tbl->type];
	default_stc = ctx->common_res[tbl->type].default_stc;
	devx_obj = mlx5dr_pool_chunk_get_base_devx_obj(stc_pool, &default_stc->default_hit);
	rtc_attr.stc_base = devx_obj->id;

	*rtc_0 = mlx5dr_cmd_rtc_create(ctx->ibv_ctx, &rtc_attr);
	if (!*rtc_0) {
		DR_LOG(ERR, "Failed to create matcher %s RTC", rtc_type_str);
		goto free_ste;
	}

	if (tbl->type == MLX5DR_TABLE_TYPE_FDB) {
		devx_obj = mlx5dr_pool_chunk_get_base_devx_obj_mirror(ste_pool, ste);
		rtc_attr.ste_base = devx_obj->id;
		rtc_attr.table_type = mlx5dr_table_get_res_fw_ft_type(tbl->type, true);

		devx_obj = mlx5dr_pool_chunk_get_base_devx_obj_mirror(stc_pool, &default_stc->default_hit);
		rtc_attr.stc_base = devx_obj->id;
		mlx5dr_matcher_set_rtc_attr_sz(matcher, &rtc_attr, is_match_rtc, true);

		*rtc_1 = mlx5dr_cmd_rtc_create(ctx->ibv_ctx, &rtc_attr);
		if (!*rtc_1) {
			DR_LOG(ERR, "Failed to create peer matcher %s RTC0", rtc_type_str);
			goto destroy_rtc_0;
		}
	}

	return 0;

destroy_rtc_0:
	mlx5dr_cmd_destroy_obj(*rtc_0);
free_ste:
	if (is_match_rtc)
		mlx5dr_pool_chunk_free(ste_pool, ste);
	return rte_errno;
}

static void mlx5dr_matcher_destroy_rtc(struct mlx5dr_matcher *matcher,
				       bool is_match_rtc)
{
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_devx_obj *rtc_0, *rtc_1;
	struct mlx5dr_pool_chunk *ste;
	struct mlx5dr_pool *ste_pool;

	if (is_match_rtc) {
		rtc_0 = matcher->match_ste.rtc_0;
		rtc_1 = matcher->match_ste.rtc_1;
		ste_pool = matcher->match_ste.pool;
		ste = &matcher->match_ste.ste;
	} else {
		rtc_0 = matcher->action_ste.rtc_0;
		rtc_1 = matcher->action_ste.rtc_1;
		ste_pool = matcher->action_ste.pool;
		ste = &matcher->action_ste.ste;
	}

	if (tbl->type == MLX5DR_TABLE_TYPE_FDB)
		mlx5dr_cmd_destroy_obj(rtc_1);

	mlx5dr_cmd_destroy_obj(rtc_0);
	if (is_match_rtc)
		mlx5dr_pool_chunk_free(ste_pool, ste);
}

static void mlx5dr_matcher_set_pool_attr(struct mlx5dr_pool_attr *attr,
					 struct mlx5dr_matcher *matcher)
{
	switch (matcher->attr.optimize_flow_src) {
	case MLX5DR_MATCHER_FLOW_SRC_VPORT:
		attr->opt_type = MLX5DR_POOL_OPTIMIZE_ORIG;
		break;
	case MLX5DR_MATCHER_FLOW_SRC_WIRE:
		attr->opt_type = MLX5DR_POOL_OPTIMIZE_MIRROR;
		break;
	default:
		break;
	}
}

static int mlx5dr_matcher_bind_at(struct mlx5dr_matcher *matcher)
{
	bool is_jumbo = mlx5dr_definer_is_jumbo(matcher->mt[0]->definer);
	struct mlx5dr_cmd_stc_modify_attr stc_attr = {0};
	struct mlx5dr_table *tbl = matcher->tbl;
	struct mlx5dr_pool_attr pool_attr = {0};
	struct mlx5dr_context *ctx = tbl->ctx;
	uint32_t required_stes;
	int i, ret;
	bool valid;

	for (i = 0; i < matcher->num_of_at; i++) {
		struct mlx5dr_action_template *at = matcher->at[i];

		/* Check if action combinabtion is valid */
		valid = mlx5dr_action_check_combo(at->action_type_arr, matcher->tbl->type);
		if (!valid) {
			DR_LOG(ERR, "Invalid combination in action template %d", i);
			return rte_errno;
		}

		/* Process action template to setters */
		ret = mlx5dr_action_template_process(at);
		if (ret) {
			DR_LOG(ERR, "Failed to process action template %d", i);
			return rte_errno;
		}

		required_stes = at->num_of_action_stes - (!is_jumbo || at->only_term);
		matcher->action_ste.max_stes = RTE_MAX(matcher->action_ste.max_stes, required_stes);

		/* Future: Optimize reparse */
	}

	/* There are no additioanl STEs required for matcher */
	if (!matcher->action_ste.max_stes)
		return 0;

	/* Allocate action STE mempool */
	pool_attr.table_type = tbl->type;
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STE;
	pool_attr.flags = MLX5DR_POOL_FLAGS_FOR_STE_ACTION_POOL;
	pool_attr.alloc_log_sz = rte_log2_u32(matcher->action_ste.max_stes) +
				 matcher->attr.table.sz_row_log;
	mlx5dr_matcher_set_pool_attr(&pool_attr, matcher);
	matcher->action_ste.pool = mlx5dr_pool_create(ctx, &pool_attr);
	if (!matcher->action_ste.pool) {
		DR_LOG(ERR, "Failed to create action ste pool");
		return rte_errno;
	}

	/* Allocate action RTC */
	ret = mlx5dr_matcher_create_rtc(matcher, false);
	if (ret) {
		DR_LOG(ERR, "Failed to create action RTC");
		goto free_ste_pool;
	}

	/* Allocate STC for jumps to STE */
	stc_attr.action_offset = MLX5DR_ACTION_OFFSET_HIT;
	stc_attr.action_type = MLX5_IFC_STC_ACTION_TYPE_JUMP_TO_STE_TABLE;
	stc_attr.ste_table.ste = matcher->action_ste.ste;
	stc_attr.ste_table.ste_pool = matcher->action_ste.pool;
	stc_attr.ste_table.match_definer_id = ctx->caps->trivial_match_definer;

	ret = mlx5dr_action_alloc_single_stc(ctx, &stc_attr, tbl->type,
					     &matcher->action_ste.stc);
	if (ret) {
		DR_LOG(ERR, "Failed to create action jump to table STC");
		goto free_rtc;
	}

	return 0;

free_rtc:
	mlx5dr_matcher_destroy_rtc(matcher, false);
free_ste_pool:
	mlx5dr_pool_destroy(matcher->action_ste.pool);
	return rte_errno;
}

static void mlx5dr_matcher_unbind_at(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_table *tbl = matcher->tbl;

	if (!matcher->action_ste.max_stes)
		return;

	mlx5dr_action_free_single_stc(tbl->ctx, tbl->type, &matcher->action_ste.stc);
	mlx5dr_matcher_destroy_rtc(matcher, false);
	mlx5dr_pool_destroy(matcher->action_ste.pool);
}

static int mlx5dr_matcher_bind_mt(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dr_pool_attr pool_attr = {0};
	int i, created = 0;
	int ret = -1;

	for (i = 0; i < matcher->num_of_mt; i++) {
		/* Get a definer for each match template */
		ret = mlx5dr_definer_get(ctx, matcher->mt[i]);
		if (ret)
			goto definer_put;

		created++;

		/* Verify all templates produce the same definer */
		if (i == 0)
			continue;

		ret = mlx5dr_definer_compare(matcher->mt[i]->definer,
					     matcher->mt[i - 1]->definer);
		if (ret) {
			DR_LOG(ERR, "Match templates cannot be used on the same matcher");
			rte_errno = ENOTSUP;
			goto definer_put;
		}
	}

	/* Create an STE pool per matcher*/
	pool_attr.pool_type = MLX5DR_POOL_TYPE_STE;
	pool_attr.flags = MLX5DR_POOL_FLAGS_FOR_MATCHER_STE_POOL;
	pool_attr.table_type = matcher->tbl->type;
	pool_attr.alloc_log_sz = matcher->attr.table.sz_col_log +
				 matcher->attr.table.sz_row_log;
	mlx5dr_matcher_set_pool_attr(&pool_attr, matcher);

	matcher->match_ste.pool = mlx5dr_pool_create(ctx, &pool_attr);
	if (!matcher->match_ste.pool) {
		DR_LOG(ERR, "Failed to allocate matcher STE pool");
		goto definer_put;
	}

	return 0;

definer_put:
	while (created--)
		mlx5dr_definer_put(matcher->mt[created]);

	return ret;
}

static void mlx5dr_matcher_unbind_mt(struct mlx5dr_matcher *matcher)
{
	int i;

	for (i = 0; i < matcher->num_of_mt; i++)
		mlx5dr_definer_put(matcher->mt[i]);

	mlx5dr_pool_destroy(matcher->match_ste.pool);
}

static int
mlx5dr_matcher_process_attr(struct mlx5dr_cmd_query_caps *caps,
			    struct mlx5dr_matcher *matcher,
			    bool is_root)
{
	struct mlx5dr_matcher_attr *attr = &matcher->attr;

	if (matcher->tbl->type != MLX5DR_TABLE_TYPE_FDB  && attr->optimize_flow_src) {
		DR_LOG(ERR, "NIC domain doesn't support flow_src");
		goto not_supported;
	}

	if (is_root) {
		if (attr->mode != MLX5DR_MATCHER_RESOURCE_MODE_RULE) {
			DR_LOG(ERR, "Root matcher supports only rule resource mode");
			goto not_supported;
		}
		if (attr->optimize_flow_src) {
			DR_LOG(ERR, "Root matcher can't specify FDB direction");
			goto not_supported;
		}
		return 0;
	}

	/* Convert number of rules to the required depth */
	if (attr->mode == MLX5DR_MATCHER_RESOURCE_MODE_RULE)
		attr->table.sz_col_log = mlx5dr_matcher_rules_to_tbl_depth(attr->rule.num_log);

	if (attr->table.sz_col_log > caps->rtc_log_depth_max) {
		DR_LOG(ERR, "Matcher depth exceeds limit %d", caps->rtc_log_depth_max);
		goto not_supported;
	}

	if (attr->table.sz_col_log + attr->table.sz_row_log > caps->ste_alloc_log_max) {
		DR_LOG(ERR, "Total matcher size exceeds limit %d", caps->ste_alloc_log_max);
		goto not_supported;
	}

	if (attr->table.sz_col_log + attr->table.sz_row_log < caps->ste_alloc_log_gran) {
		DR_LOG(ERR, "Total matcher size below limit %d", caps->ste_alloc_log_gran);
		goto not_supported;
	}

	return 0;

not_supported:
	rte_errno = EOPNOTSUPP;
	return rte_errno;
}

static int mlx5dr_matcher_create_and_connect(struct mlx5dr_matcher *matcher)
{
	int ret;

	/* Select and create the definers for current matcher */
	ret = mlx5dr_matcher_bind_mt(matcher);
	if (ret)
		return ret;

	/* Calculate and verify action combination */
	ret = mlx5dr_matcher_bind_at(matcher);
	if (ret)
		goto unbind_mt;

	/* Create matcher end flow table anchor */
	ret = mlx5dr_matcher_create_end_ft(matcher);
	if (ret)
		goto unbind_at;

	/* Allocate the RTC for the new matcher */
	ret = mlx5dr_matcher_create_rtc(matcher, true);
	if (ret)
		goto destroy_end_ft;

	/* Connect the matcher to the matcher list */
	ret = mlx5dr_matcher_connect(matcher);
	if (ret)
		goto destroy_rtc;

	return 0;

destroy_rtc:
	mlx5dr_matcher_destroy_rtc(matcher, true);
destroy_end_ft:
	mlx5dr_matcher_destroy_end_ft(matcher);
unbind_at:
	mlx5dr_matcher_unbind_at(matcher);
unbind_mt:
	mlx5dr_matcher_unbind_mt(matcher);
	return ret;
}

static void mlx5dr_matcher_destroy_and_disconnect(struct mlx5dr_matcher *matcher)
{
	mlx5dr_matcher_disconnect(matcher);
	mlx5dr_matcher_destroy_rtc(matcher, true);
	mlx5dr_matcher_destroy_end_ft(matcher);
	mlx5dr_matcher_unbind_at(matcher);
	mlx5dr_matcher_unbind_mt(matcher);
}

static int
mlx5dr_matcher_create_col_matcher(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dr_matcher *col_matcher;
	int ret;

	if (matcher->attr.mode != MLX5DR_MATCHER_RESOURCE_MODE_RULE)
		return 0;

	if (!mlx5dr_matcher_requires_col_tbl(matcher->attr.rule.num_log))
		return 0;

	col_matcher = simple_calloc(1, sizeof(*matcher));
	if (!col_matcher) {
		rte_errno = ENOMEM;
		return rte_errno;
	}

	col_matcher->tbl = matcher->tbl;
	col_matcher->num_of_mt = matcher->num_of_mt;
	memcpy(col_matcher->mt, matcher->mt, matcher->num_of_mt * sizeof(*matcher->mt));
	col_matcher->num_of_at = matcher->num_of_at;
	memcpy(col_matcher->at, matcher->at, matcher->num_of_at * sizeof(*matcher->at));

	col_matcher->attr.priority = matcher->attr.priority;
	col_matcher->attr.mode = MLX5DR_MATCHER_RESOURCE_MODE_HTABLE;
	col_matcher->attr.optimize_flow_src = matcher->attr.optimize_flow_src;
	col_matcher->attr.table.sz_row_log = matcher->attr.rule.num_log;
	col_matcher->attr.table.sz_col_log = MLX5DR_MATCHER_ASSURED_COL_TBL_DEPTH;
	if (col_matcher->attr.table.sz_row_log > MLX5DR_MATCHER_ASSURED_ROW_RATIO)
		col_matcher->attr.table.sz_row_log -= MLX5DR_MATCHER_ASSURED_ROW_RATIO;

	ret = mlx5dr_matcher_process_attr(ctx->caps, col_matcher, false);
	if (ret)
		goto free_col_matcher;

	ret = mlx5dr_matcher_create_and_connect(col_matcher);
	if (ret)
		goto free_col_matcher;

	matcher->col_matcher = col_matcher;

	return 0;

free_col_matcher:
	simple_free(col_matcher);
	DR_LOG(ERR, "Failed to create assured collision matcher");
	return ret;
}

static void
mlx5dr_matcher_destroy_col_matcher(struct mlx5dr_matcher *matcher)
{
	if (matcher->attr.mode != MLX5DR_MATCHER_RESOURCE_MODE_RULE)
		return;

	if (matcher->col_matcher) {
		mlx5dr_matcher_destroy_and_disconnect(matcher->col_matcher);
		simple_free(matcher->col_matcher);
	}
}

static int mlx5dr_matcher_init(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);

	/* Allocate matcher resource and connect to the packet pipe */
	ret = mlx5dr_matcher_create_and_connect(matcher);
	if (ret)
		goto unlock_err;

	/* Create additional matcher for collision handling */
	ret = mlx5dr_matcher_create_col_matcher(matcher);
	if (ret)
		goto destory_and_disconnect;

	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

destory_and_disconnect:
	mlx5dr_matcher_destroy_and_disconnect(matcher);
unlock_err:
	pthread_spin_unlock(&ctx->ctrl_lock);
	return ret;
}

static int mlx5dr_matcher_uninit(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;

	pthread_spin_lock(&ctx->ctrl_lock);
	mlx5dr_matcher_destroy_col_matcher(matcher);
	mlx5dr_matcher_destroy_and_disconnect(matcher);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;
}

static int mlx5dr_matcher_init_root(struct mlx5dr_matcher *matcher)
{
	enum mlx5dr_table_type type = matcher->tbl->type;
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	struct mlx5dv_flow_matcher_attr attr = {0};
	struct mlx5dv_flow_match_parameters *mask;
	struct mlx5_flow_attr flow_attr = {0};
	struct rte_flow_error rte_error;
	uint8_t match_criteria;
	int ret;

#ifdef HAVE_MLX5DV_FLOW_MATCHER_FT_TYPE
	attr.comp_mask = MLX5DV_FLOW_MATCHER_MASK_FT_TYPE;

	switch (type) {
	case MLX5DR_TABLE_TYPE_NIC_RX:
		attr.ft_type = MLX5DV_FLOW_TABLE_TYPE_NIC_RX;
		break;
	case MLX5DR_TABLE_TYPE_NIC_TX:
		attr.ft_type = MLX5DV_FLOW_TABLE_TYPE_NIC_TX;
		break;
	case MLX5DR_TABLE_TYPE_FDB:
		attr.ft_type = MLX5DV_FLOW_TABLE_TYPE_FDB;
		break;
	default:
		assert(0);
		break;
	}
#endif

	if (matcher->attr.priority > UINT16_MAX) {
		DR_LOG(ERR, "Root matcher priority exceeds allowed limit");
		rte_errno = EINVAL;
		return rte_errno;
	}

	ret = flow_hw_get_port_id_from_ctx(ctx, &flow_attr.port_id);
	if (ret) {
		DR_LOG(ERR, "Failed to get port id for dev %s", ctx->ibv_ctx->device->name);
		rte_errno = EINVAL;
		return rte_errno;
	}

	mask = simple_calloc(1, MLX5_ST_SZ_BYTES(fte_match_param) +
			     offsetof(struct mlx5dv_flow_match_parameters, match_buf));
	if (!mask) {
		rte_errno = ENOMEM;
		return rte_errno;
	}

	flow_attr.tbl_type = type;

	/* On root table matcher, only a single match template is supported */
	ret = flow_dv_translate_items_hws(matcher->mt[0]->items,
					  &flow_attr, mask->match_buf,
					  MLX5_SET_MATCHER_HS_M, NULL,
					  &match_criteria,
					  &rte_error);
	if (ret) {
		DR_LOG(ERR, "Failed to convert items to PRM [%s]", rte_error.message);
		goto free_mask;
	}

	mask->match_sz = MLX5_ST_SZ_BYTES(fte_match_param);
	attr.match_mask = mask;
	attr.match_criteria_enable = match_criteria;
	attr.type = IBV_FLOW_ATTR_NORMAL;
	attr.priority = matcher->attr.priority;

	matcher->dv_matcher =
		mlx5_glue->dv_create_flow_matcher_root(ctx->ibv_ctx, &attr);
	if (!matcher->dv_matcher) {
		DR_LOG(ERR, "Failed to create DV flow matcher");
		rte_errno = errno;
		goto free_mask;
	}

	simple_free(mask);

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_INSERT_HEAD(&matcher->tbl->head, matcher, next);
	pthread_spin_unlock(&ctx->ctrl_lock);

	return 0;

free_mask:
	simple_free(mask);
	return rte_errno;
}

static int mlx5dr_matcher_uninit_root(struct mlx5dr_matcher *matcher)
{
	struct mlx5dr_context *ctx = matcher->tbl->ctx;
	int ret;

	pthread_spin_lock(&ctx->ctrl_lock);
	LIST_REMOVE(matcher, next);
	pthread_spin_unlock(&ctx->ctrl_lock);

	ret = mlx5_glue->dv_destroy_flow_matcher_root(matcher->dv_matcher);
	if (ret) {
		DR_LOG(ERR, "Failed to Destroy DV flow matcher");
		rte_errno = errno;
	}

	return ret;
}

static int
mlx5dr_matcher_check_template(uint8_t num_of_mt, uint8_t num_of_at, bool is_root)
{
	uint8_t max_num_of_mt;

	max_num_of_mt = is_root ?
		MLX5DR_MATCHER_MAX_MT_ROOT :
		MLX5DR_MATCHER_MAX_MT;

	if (!num_of_mt || !num_of_at) {
		DR_LOG(ERR, "Number of action/match template cannot be zero");
		goto out_not_sup;
	}

	if (num_of_at > MLX5DR_MATCHER_MAX_AT) {
		DR_LOG(ERR, "Number of action templates exceeds limit");
		goto out_not_sup;
	}

	if (num_of_mt > max_num_of_mt) {
		DR_LOG(ERR, "Number of match templates exceeds limit");
		goto out_not_sup;
	}

	return 0;

out_not_sup:
	rte_errno = ENOTSUP;
	return rte_errno;
}

struct mlx5dr_matcher *
mlx5dr_matcher_create(struct mlx5dr_table *tbl,
		      struct mlx5dr_match_template *mt[],
		      uint8_t num_of_mt,
		      struct mlx5dr_action_template *at[],
		      uint8_t num_of_at,
		      struct mlx5dr_matcher_attr *attr)
{
	bool is_root = mlx5dr_table_is_root(tbl);
	struct mlx5dr_matcher *matcher;
	int ret;

	ret = mlx5dr_matcher_check_template(num_of_mt, num_of_at, is_root);
	if (ret)
		return NULL;

	matcher = simple_calloc(1, sizeof(*matcher));
	if (!matcher) {
		rte_errno = ENOMEM;
		return NULL;
	}

	matcher->tbl = tbl;
	matcher->attr = *attr;
	matcher->num_of_mt = num_of_mt;
	memcpy(matcher->mt, mt, num_of_mt * sizeof(*mt));
	matcher->num_of_at = num_of_at;
	memcpy(matcher->at, at, num_of_at * sizeof(*at));

	ret = mlx5dr_matcher_process_attr(tbl->ctx->caps, matcher, is_root);
	if (ret)
		goto free_matcher;

	if (is_root)
		ret = mlx5dr_matcher_init_root(matcher);
	else
		ret = mlx5dr_matcher_init(matcher);

	if (ret) {
		DR_LOG(ERR, "Failed to initialise matcher: %d", ret);
		goto free_matcher;
	}

	return matcher;

free_matcher:
	simple_free(matcher);
	return NULL;
}

int mlx5dr_matcher_destroy(struct mlx5dr_matcher *matcher)
{
	if (mlx5dr_table_is_root(matcher->tbl))
		mlx5dr_matcher_uninit_root(matcher);
	else
		mlx5dr_matcher_uninit(matcher);

	simple_free(matcher);
	return 0;
}

struct mlx5dr_match_template *
mlx5dr_match_template_create(const struct rte_flow_item items[],
			     enum mlx5dr_match_template_flags flags)
{
	struct mlx5dr_match_template *mt;
	struct rte_flow_error error;
	int ret, len;

	if (flags > MLX5DR_MATCH_TEMPLATE_FLAG_RELAXED_MATCH) {
		DR_LOG(ERR, "Unsupported match template flag provided");
		rte_errno = EINVAL;
		return NULL;
	}

	mt = simple_calloc(1, sizeof(*mt));
	if (!mt) {
		DR_LOG(ERR, "Failed to allocate match template");
		rte_errno = ENOMEM;
		return NULL;
	}

	mt->flags = flags;

	/* Duplicate the user given items */
	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, NULL, 0, items, &error);
	if (ret <= 0) {
		DR_LOG(ERR, "Unable to process items (%s): %s",
		       error.message ? error.message : "unspecified",
		       strerror(rte_errno));
		goto free_template;
	}

	len = RTE_ALIGN(ret, 16);
	mt->items = simple_calloc(1, len);
	if (!mt->items) {
		DR_LOG(ERR, "Failed to allocate item copy");
		rte_errno = ENOMEM;
		goto free_template;
	}

	ret = rte_flow_conv(RTE_FLOW_CONV_OP_PATTERN, mt->items, ret, items, &error);
	if (ret <= 0)
		goto free_dst;

	return mt;

free_dst:
	simple_free(mt->items);
free_template:
	simple_free(mt);
	return NULL;
}

int mlx5dr_match_template_destroy(struct mlx5dr_match_template *mt)
{
	assert(!mt->refcount);
	simple_free(mt->items);
	simple_free(mt);
	return 0;
}
