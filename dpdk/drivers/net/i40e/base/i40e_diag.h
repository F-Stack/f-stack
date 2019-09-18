/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2018
 */

#ifndef _I40E_DIAG_H_
#define _I40E_DIAG_H_

#include "i40e_type.h"

enum i40e_lb_mode {
	I40E_LB_MODE_NONE       = 0x0,
	I40E_LB_MODE_PHY_LOCAL  = I40E_AQ_LB_PHY_LOCAL,
	I40E_LB_MODE_PHY_REMOTE = I40E_AQ_LB_PHY_REMOTE,
	I40E_LB_MODE_MAC_LOCAL  = I40E_AQ_LB_MAC_LOCAL,
};

struct i40e_diag_reg_test_info {
	u32 offset;	/* the base register */
	u32 mask;	/* bits that can be tested */
	u32 elements;	/* number of elements if array */
	u32 stride;	/* bytes between each element */
};

enum i40e_status_code i40e_diag_set_loopback(struct i40e_hw *hw,
					     enum i40e_lb_mode mode);
enum i40e_status_code i40e_diag_fw_alive_test(struct i40e_hw *hw);
enum i40e_status_code i40e_diag_reg_test(struct i40e_hw *hw);
enum i40e_status_code i40e_diag_eeprom_test(struct i40e_hw *hw);

#endif /* _I40E_DIAG_H_ */
