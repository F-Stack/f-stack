/* SPDX-License-Identifier: GPL-2.0 */
/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#ifndef _IXGBE_COMMON_H_
#define _IXGBE_COMMON_H_

#include "ixgbe_type.h"

u16 ixgbe_get_pcie_msix_count_generic(struct ixgbe_hw *hw);

s32 ixgbe_init_ops_generic(struct ixgbe_hw *hw);
s32 ixgbe_init_hw_generic(struct ixgbe_hw *hw);
s32 ixgbe_start_hw_generic(struct ixgbe_hw *hw);
s32 ixgbe_start_hw_gen2(struct ixgbe_hw *hw);
s32 ixgbe_clear_hw_cntrs_generic(struct ixgbe_hw *hw);
s32 ixgbe_read_pba_string_generic(struct ixgbe_hw *hw, u8 *pba_num,
				  u32 pba_num_size);
s32 ixgbe_get_mac_addr_generic(struct ixgbe_hw *hw, u8 *mac_addr);
s32 ixgbe_get_bus_info_generic(struct ixgbe_hw *hw);
void ixgbe_set_lan_id_multi_port_pcie(struct ixgbe_hw *hw);
s32 ixgbe_stop_adapter_generic(struct ixgbe_hw *hw);

s32 ixgbe_led_on_generic(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_led_off_generic(struct ixgbe_hw *hw, u32 index);

s32 ixgbe_init_eeprom_params_generic(struct ixgbe_hw *hw);
s32 ixgbe_write_eeprom_generic(struct ixgbe_hw *hw, u16 offset, u16 data);
s32 ixgbe_write_eeprom_buffer_bit_bang_generic(struct ixgbe_hw *hw, u16 offset,
					       u16 words, u16 *data);
s32 ixgbe_read_eerd_generic(struct ixgbe_hw *hw, u16 offset, u16 *data);
s32 ixgbe_read_eerd_buffer_generic(struct ixgbe_hw *hw, u16 offset,
				   u16 words, u16 *data);
s32 ixgbe_write_eewr_generic(struct ixgbe_hw *hw, u16 offset, u16 data);
s32 ixgbe_write_eewr_buffer_generic(struct ixgbe_hw *hw, u16 offset,
				    u16 words, u16 *data);
s32 ixgbe_read_eeprom_bit_bang_generic(struct ixgbe_hw *hw, u16 offset,
				       u16 *data);
s32 ixgbe_read_eeprom_buffer_bit_bang_generic(struct ixgbe_hw *hw, u16 offset,
					      u16 words, u16 *data);
u16 ixgbe_calc_eeprom_checksum_generic(struct ixgbe_hw *hw);
s32 ixgbe_validate_eeprom_checksum_generic(struct ixgbe_hw *hw,
					   u16 *checksum_val);
s32 ixgbe_update_eeprom_checksum_generic(struct ixgbe_hw *hw);
s32 ixgbe_poll_eerd_eewr_done(struct ixgbe_hw *hw, u32 ee_reg);

s32 ixgbe_set_rar_generic(struct ixgbe_hw *hw, u32 index, u8 *addr, u32 vmdq,
			  u32 enable_addr);
s32 ixgbe_clear_rar_generic(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_init_rx_addrs_generic(struct ixgbe_hw *hw);
s32 ixgbe_update_mc_addr_list_generic(struct ixgbe_hw *hw, u8 *mc_addr_list,
				      u32 mc_addr_count,
				      ixgbe_mc_addr_itr func, bool clear);
s32 ixgbe_update_uc_addr_list_generic(struct ixgbe_hw *hw, u8 *addr_list,
				      u32 addr_count, ixgbe_mc_addr_itr func);
s32 ixgbe_enable_mc_generic(struct ixgbe_hw *hw);
s32 ixgbe_disable_mc_generic(struct ixgbe_hw *hw);
s32 ixgbe_enable_rx_dma_generic(struct ixgbe_hw *hw, u32 regval);
s32 ixgbe_disable_sec_rx_path_generic(struct ixgbe_hw *hw);
s32 ixgbe_enable_sec_rx_path_generic(struct ixgbe_hw *hw);

s32 ixgbe_fc_enable_generic(struct ixgbe_hw *hw);
void ixgbe_fc_autoneg(struct ixgbe_hw *hw);

s32 ixgbe_validate_mac_addr(u8 *mac_addr);
s32 ixgbe_acquire_swfw_sync(struct ixgbe_hw *hw, u16 mask);
void ixgbe_release_swfw_sync(struct ixgbe_hw *hw, u16 mask);
s32 ixgbe_disable_pcie_master(struct ixgbe_hw *hw);

s32 ixgbe_blink_led_start_generic(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_blink_led_stop_generic(struct ixgbe_hw *hw, u32 index);

s32 ixgbe_get_san_mac_addr_generic(struct ixgbe_hw *hw, u8 *san_mac_addr);
s32 ixgbe_set_san_mac_addr_generic(struct ixgbe_hw *hw, u8 *san_mac_addr);

s32 ixgbe_set_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
s32 ixgbe_set_vmdq_san_mac_generic(struct ixgbe_hw *hw, u32 vmdq);
s32 ixgbe_clear_vmdq_generic(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
s32 ixgbe_insert_mac_addr_generic(struct ixgbe_hw *hw, u8 *addr, u32 vmdq);
s32 ixgbe_init_uta_tables_generic(struct ixgbe_hw *hw);
s32 ixgbe_set_vfta_generic(struct ixgbe_hw *hw, u32 vlan,
			 u32 vind, bool vlan_on);
s32 ixgbe_set_vlvf_generic(struct ixgbe_hw *hw, u32 vlan, u32 vind,
			   bool vlan_on, bool *vfta_changed);
s32 ixgbe_clear_vfta_generic(struct ixgbe_hw *hw);
s32 ixgbe_find_vlvf_slot(struct ixgbe_hw *hw, u32 vlan);

s32 ixgbe_check_mac_link_generic(struct ixgbe_hw *hw,
			       ixgbe_link_speed *speed,
			       bool *link_up, bool link_up_wait_to_complete);

s32 ixgbe_get_wwn_prefix_generic(struct ixgbe_hw *hw, u16 *wwnn_prefix,
				 u16 *wwpn_prefix);

s32 ixgbe_get_fcoe_boot_status_generic(struct ixgbe_hw *hw, u16 *bs);
void ixgbe_set_mac_anti_spoofing(struct ixgbe_hw *hw, bool enable, int pf);
void ixgbe_set_vlan_anti_spoofing(struct ixgbe_hw *hw, bool enable, int vf);
s32 ixgbe_get_device_caps_generic(struct ixgbe_hw *hw, u16 *device_caps);
void ixgbe_set_rxpba_generic(struct ixgbe_hw *hw, int num_pb, u32 headroom,
			     int strategy);
s32 ixgbe_set_fw_drv_ver_generic(struct ixgbe_hw *hw, u8 maj, u8 min,
				 u8 build, u8 ver);
void ixgbe_clear_tx_pending(struct ixgbe_hw *hw);

#define IXGBE_I2C_THERMAL_SENSOR_ADDR	0xF8
#define IXGBE_EMC_INTERNAL_DATA		0x00
#define IXGBE_EMC_INTERNAL_THERM_LIMIT	0x20
#define IXGBE_EMC_DIODE1_DATA		0x01
#define IXGBE_EMC_DIODE1_THERM_LIMIT	0x19
#define IXGBE_EMC_DIODE2_DATA		0x23
#define IXGBE_EMC_DIODE2_THERM_LIMIT	0x1A
#define IXGBE_EMC_DIODE3_DATA		0x2A
#define IXGBE_EMC_DIODE3_THERM_LIMIT	0x30

s32 ixgbe_get_thermal_sensor_data_generic(struct ixgbe_hw *hw);
s32 ixgbe_init_thermal_sensor_thresh_generic(struct ixgbe_hw *hw);
#endif /* IXGBE_COMMON */
