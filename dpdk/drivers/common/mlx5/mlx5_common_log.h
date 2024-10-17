/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_MLX5_COMMON_LOG_H_
#define RTE_PMD_MLX5_COMMON_LOG_H_

#include "mlx5_common.h"


extern int mlx5_common_logtype;

#define MLX5_COMMON_LOG_PREFIX "mlx5_common"
/* Generic printf()-like logging macro with automatic line feed. */
#define DRV_LOG(level, ...) \
	PMD_DRV_LOG_(level, mlx5_common_logtype, MLX5_COMMON_LOG_PREFIX, \
		__VA_ARGS__ PMD_DRV_LOG_STRIP PMD_DRV_LOG_OPAREN, \
		PMD_DRV_LOG_CPAREN)

#endif /* RTE_PMD_MLX5_COMMON_LOG_H_ */
