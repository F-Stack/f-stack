/* SPDX-License-Identifier: GPL-2.0 */
/*******************************************************************************

  Intel(R) Gigabit Ethernet Linux driver
  Copyright(c) 2007-2013 Intel Corporation.

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _E1000_I210_H_
#define _E1000_I210_H_

bool e1000_get_flash_presence_i210(struct e1000_hw *hw);
s32 e1000_update_flash_i210(struct e1000_hw *hw);
s32 e1000_update_nvm_checksum_i210(struct e1000_hw *hw);
s32 e1000_validate_nvm_checksum_i210(struct e1000_hw *hw);
s32 e1000_write_nvm_srwr_i210(struct e1000_hw *hw, u16 offset,
			      u16 words, u16 *data);
s32 e1000_read_nvm_srrd_i210(struct e1000_hw *hw, u16 offset,
			     u16 words, u16 *data);
s32 e1000_read_invm_version(struct e1000_hw *hw,
			    struct e1000_fw_version *invm_ver);
s32 e1000_acquire_swfw_sync_i210(struct e1000_hw *hw, u16 mask);
void e1000_release_swfw_sync_i210(struct e1000_hw *hw, u16 mask);
s32 e1000_read_xmdio_reg(struct e1000_hw *hw, u16 addr, u8 dev_addr,
			 u16 *data);
s32 e1000_write_xmdio_reg(struct e1000_hw *hw, u16 addr, u8 dev_addr,
			  u16 data);

#define E1000_STM_OPCODE		0xDB00
#define E1000_EEPROM_FLASH_SIZE_WORD	0x11

#define INVM_DWORD_TO_RECORD_TYPE(invm_dword) \
	(u8)((invm_dword) & 0x7)
#define INVM_DWORD_TO_WORD_ADDRESS(invm_dword) \
	(u8)(((invm_dword) & 0x0000FE00) >> 9)
#define INVM_DWORD_TO_WORD_DATA(invm_dword) \
	(u16)(((invm_dword) & 0xFFFF0000) >> 16)

enum E1000_INVM_STRUCTURE_TYPE {
	E1000_INVM_UNINITIALIZED_STRUCTURE		= 0x00,
	E1000_INVM_WORD_AUTOLOAD_STRUCTURE		= 0x01,
	E1000_INVM_CSR_AUTOLOAD_STRUCTURE		= 0x02,
	E1000_INVM_PHY_REGISTER_AUTOLOAD_STRUCTURE	= 0x03,
	E1000_INVM_RSA_KEY_SHA256_STRUCTURE		= 0x04,
	E1000_INVM_INVALIDATED_STRUCTURE		= 0x0F,
};

#define E1000_INVM_RSA_KEY_SHA256_DATA_SIZE_IN_DWORDS	8
#define E1000_INVM_CSR_AUTOLOAD_DATA_SIZE_IN_DWORDS	1
#define E1000_INVM_ULT_BYTES_SIZE	8
#define E1000_INVM_RECORD_SIZE_IN_BYTES	4
#define E1000_INVM_VER_FIELD_ONE	0x1FF8
#define E1000_INVM_VER_FIELD_TWO	0x7FE000
#define E1000_INVM_IMGTYPE_FIELD	0x1F800000

#define E1000_INVM_MAJOR_MASK	0x3F0
#define E1000_INVM_MINOR_MASK	0xF
#define E1000_INVM_MAJOR_SHIFT	4

#define ID_LED_DEFAULT_I210		((ID_LED_OFF1_ON2  << 8) | \
					 (ID_LED_DEF1_DEF2 <<  4) | \
					 (ID_LED_OFF1_OFF2))
#define ID_LED_DEFAULT_I210_SERDES	((ID_LED_DEF1_DEF2 << 8) | \
					 (ID_LED_DEF1_DEF2 <<  4) | \
					 (ID_LED_OFF1_ON2))

/* NVM offset defaults for I211 devices */
#define NVM_INIT_CTRL_2_DEFAULT_I211	0X7243
#define NVM_INIT_CTRL_4_DEFAULT_I211	0x00C1
#define NVM_LED_1_CFG_DEFAULT_I211	0x0184
#define NVM_LED_0_2_CFG_DEFAULT_I211	0x200C
#endif
