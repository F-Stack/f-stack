/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef MLX5DR_PAT_ARG_H_
#define MLX5DR_PAT_ARG_H_

/* Modify-header arg pool */
enum mlx5dr_arg_chunk_size {
	MLX5DR_ARG_CHUNK_SIZE_1,
	/* Keep MIN updated when changing */
	MLX5DR_ARG_CHUNK_SIZE_MIN = MLX5DR_ARG_CHUNK_SIZE_1,
	MLX5DR_ARG_CHUNK_SIZE_2,
	MLX5DR_ARG_CHUNK_SIZE_3,
	MLX5DR_ARG_CHUNK_SIZE_4,
	MLX5DR_ARG_CHUNK_SIZE_MAX,
};

enum {
	MLX5DR_MODIFY_ACTION_SIZE = 8,
	MLX5DR_ARG_DATA_SIZE = 64,
};

struct mlx5dr_pattern_cache {
	/* Protect pattern list */
	pthread_spinlock_t lock;
	LIST_HEAD(pattern_head, mlx5dr_pat_cached_pattern) head;
};

struct mlx5dr_pat_cached_pattern {
	enum mlx5dr_action_type type;
	struct {
		struct mlx5dr_devx_obj *pattern_obj;
		uint8_t *data;
		uint16_t num_of_actions;
	} mh_data;
	uint32_t refcount;
	LIST_ENTRY(mlx5dr_pat_cached_pattern) next;
};

enum mlx5dr_arg_chunk_size
mlx5dr_arg_get_arg_log_size(uint16_t num_of_actions);

uint32_t mlx5dr_arg_get_arg_size(uint16_t num_of_actions);

enum mlx5dr_arg_chunk_size
mlx5dr_arg_data_size_to_arg_log_size(uint16_t data_size);

uint32_t mlx5dr_arg_data_size_to_arg_size(uint16_t data_size);

int mlx5dr_pat_init_pattern_cache(struct mlx5dr_pattern_cache **cache);

void mlx5dr_pat_uninit_pattern_cache(struct mlx5dr_pattern_cache *cache);

int mlx5dr_pat_arg_create_modify_header(struct mlx5dr_context *ctx,
					struct mlx5dr_action *action,
					size_t pattern_sz,
					__be64 pattern[],
					uint32_t bulk_size);

void mlx5dr_pat_arg_destroy_modify_header(struct mlx5dr_context *ctx,
					  struct mlx5dr_action *action);

bool mlx5dr_arg_is_valid_arg_request_size(struct mlx5dr_context *ctx,
					  uint32_t arg_size);

void mlx5dr_arg_write(struct mlx5dr_send_engine *queue,
		      void *comp_data,
		      uint32_t arg_idx,
		      uint8_t *arg_data,
		      size_t data_size);

void mlx5dr_arg_decapl3_write(struct mlx5dr_send_engine *queue,
			      uint32_t arg_idx,
			      uint8_t *arg_data,
			      uint16_t num_of_actions);

int mlx5dr_arg_write_inline_arg_data(struct mlx5dr_context *ctx,
				     uint32_t arg_idx,
				     uint8_t *arg_data,
				     size_t data_size);
#endif /* MLX5DR_PAT_ARG_H_ */
