/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 NVIDIA Corporation & Affiliates
 */

#ifndef MLX5_CRYPTO_H_
#define MLX5_CRYPTO_H_

#include <stdbool.h>

#include <rte_cryptodev.h>
#include <cryptodev_pmd.h>

#include <mlx5_common_utils.h>
#include <mlx5_common_devx.h>
#include <mlx5_common_mr.h>

#define MLX5_CRYPTO_DEK_HTABLE_SZ (1 << 11)
#define MLX5_CRYPTO_KEY_LENGTH 80
#define MLX5_CRYPTO_UMR_WQE_STATIC_SIZE (sizeof(struct mlx5_wqe_cseg) +\
					sizeof(struct mlx5_wqe_umr_cseg) +\
					sizeof(struct mlx5_wqe_mkey_cseg) +\
					sizeof(struct mlx5_wqe_umr_bsf_seg))
#define MLX5_CRYPTO_KLM_SEGS_NUM(umr_wqe_sz) ((umr_wqe_sz -\
					MLX5_CRYPTO_UMR_WQE_STATIC_SIZE) /\
					MLX5_WSEG_SIZE)

struct mlx5_crypto_priv {
	TAILQ_ENTRY(mlx5_crypto_priv) next;
	struct mlx5_common_device *cdev; /* Backend mlx5 device. */
	struct rte_cryptodev *crypto_dev;
	struct mlx5_uar uar; /* User Access Region. */
	uint32_t max_segs_num; /* Maximum supported data segs. */
	struct mlx5_hlist *dek_hlist; /* Dek hash list. */
	struct rte_cryptodev_config dev_config;
	struct mlx5_devx_obj *login_obj;
	uint64_t keytag;
	uint16_t wqe_set_size;
	uint16_t umr_wqe_size;
	uint16_t umr_wqe_stride;
	uint16_t max_rdmar_ds;
	uint32_t is_wrapped_mode:1;
};

struct mlx5_crypto_qp {
	struct mlx5_crypto_priv *priv;
	struct mlx5_devx_cq cq_obj;
	struct mlx5_devx_qp qp_obj;
	struct rte_cryptodev_stats stats;
	struct rte_crypto_op **ops;
	struct mlx5_devx_obj **mkey; /* WQE's indirect mekys. */
	struct mlx5_mr_ctrl mr_ctrl;
	uint8_t *wqe;
	uint16_t entries_n;
	uint16_t pi;
	uint16_t ci;
	uint16_t db_pi;
};

struct mlx5_crypto_dek {
	struct mlx5_list_entry entry; /* Pointer to DEK hash list entry. */
	struct mlx5_devx_obj *obj; /* Pointer to DEK DevX object. */
	uint8_t data[MLX5_CRYPTO_KEY_LENGTH]; /* DEK key data. */
	uint32_t size; /* key+keytag size. */
} __rte_cache_aligned;

struct mlx5_crypto_devarg_params {
	bool login_devarg;
	struct mlx5_devx_crypto_login_attr login_attr;
	uint64_t keytag;
	uint32_t max_segs_num;
};

int
mlx5_crypto_dek_destroy(struct mlx5_crypto_priv *priv,
			struct mlx5_crypto_dek *dek);

struct mlx5_crypto_dek *
mlx5_crypto_dek_prepare(struct mlx5_crypto_priv *priv,
			struct rte_crypto_cipher_xform *cipher);

int
mlx5_crypto_dek_setup(struct mlx5_crypto_priv *priv);

void
mlx5_crypto_dek_unset(struct mlx5_crypto_priv *priv);

#endif /* MLX5_CRYPTO_H_ */
