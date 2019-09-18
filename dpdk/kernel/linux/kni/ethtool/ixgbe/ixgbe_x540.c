// SPDX-License-Identifier: GPL-2.0
/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/

#include "ixgbe_x540.h"
#include "ixgbe_type.h"
#include "ixgbe_api.h"
#include "ixgbe_common.h"
#include "ixgbe_phy.h"

static s32 ixgbe_update_flash_X540(struct ixgbe_hw *hw);
static s32 ixgbe_poll_flash_update_done_X540(struct ixgbe_hw *hw);
static s32 ixgbe_get_swfw_sync_semaphore(struct ixgbe_hw *hw);
static void ixgbe_release_swfw_sync_semaphore(struct ixgbe_hw *hw);

/**
 *  ixgbe_init_ops_X540 - Inits func ptrs and MAC type
 *  @hw: pointer to hardware structure
 *
 *  Initialize the function pointers and assign the MAC type for X540.
 *  Does not touch the hardware.
 **/
s32 ixgbe_init_ops_X540(struct ixgbe_hw *hw)
{
	struct ixgbe_mac_info *mac = &hw->mac;
	struct ixgbe_phy_info *phy = &hw->phy;
	struct ixgbe_eeprom_info *eeprom = &hw->eeprom;
	s32 ret_val;

	ret_val = ixgbe_init_phy_ops_generic(hw);
	ret_val = ixgbe_init_ops_generic(hw);


	/* EEPROM */
	eeprom->ops.init_params = &ixgbe_init_eeprom_params_X540;
	eeprom->ops.read = &ixgbe_read_eerd_X540;
	eeprom->ops.read_buffer = &ixgbe_read_eerd_buffer_X540;
	eeprom->ops.write = &ixgbe_write_eewr_X540;
	eeprom->ops.write_buffer = &ixgbe_write_eewr_buffer_X540;
	eeprom->ops.update_checksum = &ixgbe_update_eeprom_checksum_X540;
	eeprom->ops.validate_checksum = &ixgbe_validate_eeprom_checksum_X540;
	eeprom->ops.calc_checksum = &ixgbe_calc_eeprom_checksum_X540;

	/* PHY */
	phy->ops.init = &ixgbe_init_phy_ops_generic;
	phy->ops.reset = NULL;

	/* MAC */
	mac->ops.reset_hw = &ixgbe_reset_hw_X540;
	mac->ops.get_media_type = &ixgbe_get_media_type_X540;
	mac->ops.get_supported_physical_layer =
				    &ixgbe_get_supported_physical_layer_X540;
	mac->ops.read_analog_reg8 = NULL;
	mac->ops.write_analog_reg8 = NULL;
	mac->ops.start_hw = &ixgbe_start_hw_X540;
	mac->ops.get_san_mac_addr = &ixgbe_get_san_mac_addr_generic;
	mac->ops.set_san_mac_addr = &ixgbe_set_san_mac_addr_generic;
	mac->ops.get_device_caps = &ixgbe_get_device_caps_generic;
	mac->ops.get_wwn_prefix = &ixgbe_get_wwn_prefix_generic;
	mac->ops.get_fcoe_boot_status = &ixgbe_get_fcoe_boot_status_generic;
	mac->ops.acquire_swfw_sync = &ixgbe_acquire_swfw_sync_X540;
	mac->ops.release_swfw_sync = &ixgbe_release_swfw_sync_X540;
	mac->ops.disable_sec_rx_path = &ixgbe_disable_sec_rx_path_generic;
	mac->ops.enable_sec_rx_path = &ixgbe_enable_sec_rx_path_generic;

	/* RAR, Multicast, VLAN */
	mac->ops.set_vmdq = &ixgbe_set_vmdq_generic;
	mac->ops.set_vmdq_san_mac = &ixgbe_set_vmdq_san_mac_generic;
	mac->ops.clear_vmdq = &ixgbe_clear_vmdq_generic;
	mac->ops.insert_mac_addr = &ixgbe_insert_mac_addr_generic;
	mac->rar_highwater = 1;
	mac->ops.set_vfta = &ixgbe_set_vfta_generic;
	mac->ops.set_vlvf = &ixgbe_set_vlvf_generic;
	mac->ops.clear_vfta = &ixgbe_clear_vfta_generic;
	mac->ops.init_uta_tables = &ixgbe_init_uta_tables_generic;
	mac->ops.set_mac_anti_spoofing = &ixgbe_set_mac_anti_spoofing;
	mac->ops.set_vlan_anti_spoofing = &ixgbe_set_vlan_anti_spoofing;

	/* Link */
	mac->ops.get_link_capabilities =
				&ixgbe_get_copper_link_capabilities_generic;
	mac->ops.setup_link = &ixgbe_setup_mac_link_X540;
	mac->ops.setup_rxpba = &ixgbe_set_rxpba_generic;
	mac->ops.check_link = &ixgbe_check_mac_link_generic;

	mac->mcft_size		= 128;
	mac->vft_size		= 128;
	mac->num_rar_entries	= 128;
	mac->rx_pb_size		= 384;
	mac->max_tx_queues	= 128;
	mac->max_rx_queues	= 128;
	mac->max_msix_vectors	= ixgbe_get_pcie_msix_count_generic(hw);

	/*
	 * FWSM register
	 * ARC supported; valid only if manageability features are
	 * enabled.
	 */
	mac->arc_subsystem_valid = (IXGBE_READ_REG(hw, IXGBE_FWSM) &
				   IXGBE_FWSM_MODE_MASK) ? true : false;

	//hw->mbx.ops.init_params = ixgbe_init_mbx_params_pf;

	/* LEDs */
	mac->ops.blink_led_start = ixgbe_blink_led_start_X540;
	mac->ops.blink_led_stop = ixgbe_blink_led_stop_X540;

	/* Manageability interface */
	mac->ops.set_fw_drv_ver = &ixgbe_set_fw_drv_ver_generic;

	return ret_val;
}

/**
 *  ixgbe_get_link_capabilities_X540 - Determines link capabilities
 *  @hw: pointer to hardware structure
 *  @speed: pointer to link speed
 *  @autoneg: true when autoneg or autotry is enabled
 *
 *  Determines the link capabilities by reading the AUTOC register.
 **/
s32 ixgbe_get_link_capabilities_X540(struct ixgbe_hw *hw,
				     ixgbe_link_speed *speed,
				     bool *autoneg)
{
	ixgbe_get_copper_link_capabilities_generic(hw, speed, autoneg);

	return 0;
}

/**
 *  ixgbe_get_media_type_X540 - Get media type
 *  @hw: pointer to hardware structure
 *
 *  Returns the media type (fiber, copper, backplane)
 **/
enum ixgbe_media_type ixgbe_get_media_type_X540(struct ixgbe_hw *hw)
{
	return ixgbe_media_type_copper;
}

/**
 *  ixgbe_setup_mac_link_X540 - Sets the auto advertised capabilities
 *  @hw: pointer to hardware structure
 *  @speed: new link speed
 *  @autoneg: true if autonegotiation enabled
 *  @autoneg_wait_to_complete: true when waiting for completion is needed
 **/
s32 ixgbe_setup_mac_link_X540(struct ixgbe_hw *hw,
			      ixgbe_link_speed speed, bool autoneg,
			      bool autoneg_wait_to_complete)
{
	return hw->phy.ops.setup_link_speed(hw, speed, autoneg,
					    autoneg_wait_to_complete);
}

/**
 *  ixgbe_reset_hw_X540 - Perform hardware reset
 *  @hw: pointer to hardware structure
 *
 *  Resets the hardware by resetting the transmit and receive units, masks
 *  and clears all interrupts, and perform a reset.
 **/
s32 ixgbe_reset_hw_X540(struct ixgbe_hw *hw)
{
	s32 status = 0;

	/*
	 * Userland DPDK takes the ownershiop of device
	 * Kernel driver here used as the simple path for ethtool only
	 * Won't real reset device anyway
	 */
#if 0
	u32 ctrl, i;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	status = hw->mac.ops.stop_adapter(hw);
	if (status != 0)
		goto reset_hw_out;

	/* flush pending Tx transactions */
	ixgbe_clear_tx_pending(hw);

mac_reset_top:
	ctrl = IXGBE_CTRL_RST;
	ctrl |= IXGBE_READ_REG(hw, IXGBE_CTRL);
	IXGBE_WRITE_REG(hw, IXGBE_CTRL, ctrl);
	IXGBE_WRITE_FLUSH(hw);

	/* Poll for reset bit to self-clear indicating reset is complete */
	for (i = 0; i < 10; i++) {
		udelay(1);
		ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
		if (!(ctrl & IXGBE_CTRL_RST_MASK))
			break;
	}

	if (ctrl & IXGBE_CTRL_RST_MASK) {
		status = IXGBE_ERR_RESET_FAILED;
		hw_dbg(hw, "Reset polling failed to complete.\n");
	}
	msleep(100);

	/*
	 * Double resets are required for recovery from certain error
	 * conditions.  Between resets, it is necessary to stall to allow time
	 * for any pending HW events to complete.
	 */
	if (hw->mac.flags & IXGBE_FLAGS_DOUBLE_RESET_REQUIRED) {
		hw->mac.flags &= ~IXGBE_FLAGS_DOUBLE_RESET_REQUIRED;
		goto mac_reset_top;
	}

	/* Set the Rx packet buffer size. */
	IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(0), 384 << IXGBE_RXPBSIZE_SHIFT);

#endif

	/* Store the permanent mac address */
	hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);

	/*
	 * Store MAC address from RAR0, clear receive address registers, and
	 * clear the multicast table.  Also reset num_rar_entries to 128,
	 * since we modify this value when programming the SAN MAC address.
	 */
	hw->mac.num_rar_entries = 128;
	hw->mac.ops.init_rx_addrs(hw);

	/* Store the permanent SAN mac address */
	hw->mac.ops.get_san_mac_addr(hw, hw->mac.san_addr);

	/* Add the SAN MAC address to the RAR only if it's a valid address */
	if (ixgbe_validate_mac_addr(hw->mac.san_addr) == 0) {
		hw->mac.ops.set_rar(hw, hw->mac.num_rar_entries - 1,
				    hw->mac.san_addr, 0, IXGBE_RAH_AV);

		/* Save the SAN MAC RAR index */
		hw->mac.san_mac_rar_index = hw->mac.num_rar_entries - 1;

		/* Reserve the last RAR for the SAN MAC address */
		hw->mac.num_rar_entries--;
	}

	/* Store the alternative WWNN/WWPN prefix */
	hw->mac.ops.get_wwn_prefix(hw, &hw->mac.wwnn_prefix,
				   &hw->mac.wwpn_prefix);

//reset_hw_out:
	return status;
}

/**
 *  ixgbe_start_hw_X540 - Prepare hardware for Tx/Rx
 *  @hw: pointer to hardware structure
 *
 *  Starts the hardware using the generic start_hw function
 *  and the generation start_hw function.
 *  Then performs revision-specific operations, if any.
 **/
s32 ixgbe_start_hw_X540(struct ixgbe_hw *hw)
{
	s32 ret_val = 0;

	ret_val = ixgbe_start_hw_generic(hw);
	if (ret_val != 0)
		goto out;

	ret_val = ixgbe_start_hw_gen2(hw);

out:
	return ret_val;
}

/**
 *  ixgbe_get_supported_physical_layer_X540 - Returns physical layer type
 *  @hw: pointer to hardware structure
 *
 *  Determines physical layer capabilities of the current configuration.
 **/
u32 ixgbe_get_supported_physical_layer_X540(struct ixgbe_hw *hw)
{
	u32 physical_layer = IXGBE_PHYSICAL_LAYER_UNKNOWN;
	u16 ext_ability = 0;

	hw->phy.ops.read_reg(hw, IXGBE_MDIO_PHY_EXT_ABILITY,
	IXGBE_MDIO_PMA_PMD_DEV_TYPE, &ext_ability);
	if (ext_ability & IXGBE_MDIO_PHY_10GBASET_ABILITY)
		physical_layer |= IXGBE_PHYSICAL_LAYER_10GBASE_T;
	if (ext_ability & IXGBE_MDIO_PHY_1000BASET_ABILITY)
		physical_layer |= IXGBE_PHYSICAL_LAYER_1000BASE_T;
	if (ext_ability & IXGBE_MDIO_PHY_100BASETX_ABILITY)
		physical_layer |= IXGBE_PHYSICAL_LAYER_100BASE_TX;

	return physical_layer;
}

/**
 *  ixgbe_init_eeprom_params_X540 - Initialize EEPROM params
 *  @hw: pointer to hardware structure
 *
 *  Initializes the EEPROM parameters ixgbe_eeprom_info within the
 *  ixgbe_hw struct in order to set up EEPROM access.
 **/
s32 ixgbe_init_eeprom_params_X540(struct ixgbe_hw *hw)
{
	struct ixgbe_eeprom_info *eeprom = &hw->eeprom;
	u32 eec;
	u16 eeprom_size;

	if (eeprom->type == ixgbe_eeprom_uninitialized) {
		eeprom->semaphore_delay = 10;
		eeprom->type = ixgbe_flash;

		eec = IXGBE_READ_REG(hw, IXGBE_EEC);
		eeprom_size = (u16)((eec & IXGBE_EEC_SIZE) >>
				    IXGBE_EEC_SIZE_SHIFT);
		eeprom->word_size = 1 << (eeprom_size +
					  IXGBE_EEPROM_WORD_SIZE_SHIFT);

		hw_dbg(hw, "Eeprom params: type = %d, size = %d\n",
			  eeprom->type, eeprom->word_size);
	}

	return 0;
}

/**
 *  ixgbe_read_eerd_X540- Read EEPROM word using EERD
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @data: word read from the EEPROM
 *
 *  Reads a 16 bit word from the EEPROM using the EERD register.
 **/
s32 ixgbe_read_eerd_X540(struct ixgbe_hw *hw, u16 offset, u16 *data)
{
	s32 status = 0;

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0)
		status = ixgbe_read_eerd_generic(hw, offset, data);
	else
		status = IXGBE_ERR_SWFW_SYNC;

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 *  ixgbe_read_eerd_buffer_X540- Read EEPROM word(s) using EERD
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to read
 *  @words: number of words
 *  @data: word(s) read from the EEPROM
 *
 *  Reads a 16 bit word(s) from the EEPROM using the EERD register.
 **/
s32 ixgbe_read_eerd_buffer_X540(struct ixgbe_hw *hw,
				u16 offset, u16 words, u16 *data)
{
	s32 status = 0;

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0)
		status = ixgbe_read_eerd_buffer_generic(hw, offset,
							words, data);
	else
		status = IXGBE_ERR_SWFW_SYNC;

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 *  ixgbe_write_eewr_X540 - Write EEPROM word using EEWR
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to write
 *  @data: word write to the EEPROM
 *
 *  Write a 16 bit word to the EEPROM using the EEWR register.
 **/
s32 ixgbe_write_eewr_X540(struct ixgbe_hw *hw, u16 offset, u16 data)
{
	s32 status = 0;

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0)
		status = ixgbe_write_eewr_generic(hw, offset, data);
	else
		status = IXGBE_ERR_SWFW_SYNC;

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 *  ixgbe_write_eewr_buffer_X540 - Write EEPROM word(s) using EEWR
 *  @hw: pointer to hardware structure
 *  @offset: offset of  word in the EEPROM to write
 *  @words: number of words
 *  @data: word(s) write to the EEPROM
 *
 *  Write a 16 bit word(s) to the EEPROM using the EEWR register.
 **/
s32 ixgbe_write_eewr_buffer_X540(struct ixgbe_hw *hw,
				 u16 offset, u16 words, u16 *data)
{
	s32 status = 0;

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0)
		status = ixgbe_write_eewr_buffer_generic(hw, offset,
							 words, data);
	else
		status = IXGBE_ERR_SWFW_SYNC;

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);
	return status;
}

/**
 *  ixgbe_calc_eeprom_checksum_X540 - Calculates and returns the checksum
 *
 *  This function does not use synchronization for EERD and EEWR. It can
 *  be used internally by function which utilize ixgbe_acquire_swfw_sync_X540.
 *
 *  @hw: pointer to hardware structure
 **/
u16 ixgbe_calc_eeprom_checksum_X540(struct ixgbe_hw *hw)
{
	u16 i;
	u16 j;
	u16 checksum = 0;
	u16 length = 0;
	u16 pointer = 0;
	u16 word = 0;

	/*
	 * Do not use hw->eeprom.ops.read because we do not want to take
	 * the synchronization semaphores here. Instead use
	 * ixgbe_read_eerd_generic
	 */

	/* Include 0x0-0x3F in the checksum */
	for (i = 0; i < IXGBE_EEPROM_CHECKSUM; i++) {
		if (ixgbe_read_eerd_generic(hw, i, &word) != 0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}
		checksum += word;
	}

	/*
	 * Include all data from pointers 0x3, 0x6-0xE.  This excludes the
	 * FW, PHY module, and PCIe Expansion/Option ROM pointers.
	 */
	for (i = IXGBE_PCIE_ANALOG_PTR; i < IXGBE_FW_PTR; i++) {
		if (i == IXGBE_PHY_PTR || i == IXGBE_OPTION_ROM_PTR)
			continue;

		if (ixgbe_read_eerd_generic(hw, i, &pointer) != 0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}

		/* Skip pointer section if the pointer is invalid. */
		if (pointer == 0xFFFF || pointer == 0 ||
		    pointer >= hw->eeprom.word_size)
			continue;

		if (ixgbe_read_eerd_generic(hw, pointer, &length) !=
		    0) {
			hw_dbg(hw, "EEPROM read failed\n");
			break;
		}

		/* Skip pointer section if length is invalid. */
		if (length == 0xFFFF || length == 0 ||
		    (pointer + length) >= hw->eeprom.word_size)
			continue;

		for (j = pointer+1; j <= pointer+length; j++) {
			if (ixgbe_read_eerd_generic(hw, j, &word) !=
			    0) {
				hw_dbg(hw, "EEPROM read failed\n");
				break;
			}
			checksum += word;
		}
	}

	checksum = (u16)IXGBE_EEPROM_SUM - checksum;

	return checksum;
}

/**
 *  ixgbe_validate_eeprom_checksum_X540 - Validate EEPROM checksum
 *  @hw: pointer to hardware structure
 *  @checksum_val: calculated checksum
 *
 *  Performs checksum calculation and validates the EEPROM checksum.  If the
 *  caller does not need checksum_val, the value can be NULL.
 **/
s32 ixgbe_validate_eeprom_checksum_X540(struct ixgbe_hw *hw,
					u16 *checksum_val)
{
	s32 status;
	u16 checksum;
	u16 read_checksum = 0;

	/*
	 * Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	status = hw->eeprom.ops.read(hw, 0, &checksum);

	if (status != 0) {
		hw_dbg(hw, "EEPROM read failed\n");
		goto out;
	}

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0) {
		checksum = hw->eeprom.ops.calc_checksum(hw);

		/*
		 * Do not use hw->eeprom.ops.read because we do not want to take
		 * the synchronization semaphores twice here.
		*/
		ixgbe_read_eerd_generic(hw, IXGBE_EEPROM_CHECKSUM,
					&read_checksum);

		/*
		 * Verify read checksum from EEPROM is the same as
		 * calculated checksum
		 */
		if (read_checksum != checksum)
			status = IXGBE_ERR_EEPROM_CHECKSUM;

		/* If the user cares, return the calculated checksum */
		if (checksum_val)
			*checksum_val = checksum;
	} else {
		status = IXGBE_ERR_SWFW_SYNC;
	}

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);
out:
	return status;
}

/**
 * ixgbe_update_eeprom_checksum_X540 - Updates the EEPROM checksum and flash
 * @hw: pointer to hardware structure
 *
 * After writing EEPROM to shadow RAM using EEWR register, software calculates
 * checksum and updates the EEPROM and instructs the hardware to update
 * the flash.
 **/
s32 ixgbe_update_eeprom_checksum_X540(struct ixgbe_hw *hw)
{
	s32 status;
	u16 checksum;

	/*
	 * Read the first word from the EEPROM. If this times out or fails, do
	 * not continue or we could be in for a very long wait while every
	 * EEPROM read fails
	 */
	status = hw->eeprom.ops.read(hw, 0, &checksum);

	if (status != 0)
		hw_dbg(hw, "EEPROM read failed\n");

	if (hw->mac.ops.acquire_swfw_sync(hw, IXGBE_GSSR_EEP_SM) ==
	    0) {
		checksum = hw->eeprom.ops.calc_checksum(hw);

		/*
		 * Do not use hw->eeprom.ops.write because we do not want to
		 * take the synchronization semaphores twice here.
		*/
		status = ixgbe_write_eewr_generic(hw, IXGBE_EEPROM_CHECKSUM,
						  checksum);

	if (status == 0)
		status = ixgbe_update_flash_X540(hw);
	else
		status = IXGBE_ERR_SWFW_SYNC;
	}

	hw->mac.ops.release_swfw_sync(hw, IXGBE_GSSR_EEP_SM);

	return status;
}

/**
 *  ixgbe_update_flash_X540 - Instruct HW to copy EEPROM to Flash device
 *  @hw: pointer to hardware structure
 *
 *  Set FLUP (bit 23) of the EEC register to instruct Hardware to copy
 *  EEPROM from shadow RAM to the flash device.
 **/
static s32 ixgbe_update_flash_X540(struct ixgbe_hw *hw)
{
	u32 flup;
	s32 status = IXGBE_ERR_EEPROM;

	status = ixgbe_poll_flash_update_done_X540(hw);
	if (status == IXGBE_ERR_EEPROM) {
		hw_dbg(hw, "Flash update time out\n");
		goto out;
	}

	flup = IXGBE_READ_REG(hw, IXGBE_EEC) | IXGBE_EEC_FLUP;
	IXGBE_WRITE_REG(hw, IXGBE_EEC, flup);

	status = ixgbe_poll_flash_update_done_X540(hw);
	if (status == 0)
		hw_dbg(hw, "Flash update complete\n");
	else
		hw_dbg(hw, "Flash update time out\n");

	if (hw->revision_id == 0) {
		flup = IXGBE_READ_REG(hw, IXGBE_EEC);

		if (flup & IXGBE_EEC_SEC1VAL) {
			flup |= IXGBE_EEC_FLUP;
			IXGBE_WRITE_REG(hw, IXGBE_EEC, flup);
		}

		status = ixgbe_poll_flash_update_done_X540(hw);
		if (status == 0)
			hw_dbg(hw, "Flash update complete\n");
		else
			hw_dbg(hw, "Flash update time out\n");
	}
out:
	return status;
}

/**
 *  ixgbe_poll_flash_update_done_X540 - Poll flash update status
 *  @hw: pointer to hardware structure
 *
 *  Polls the FLUDONE (bit 26) of the EEC Register to determine when the
 *  flash update is done.
 **/
static s32 ixgbe_poll_flash_update_done_X540(struct ixgbe_hw *hw)
{
	u32 i;
	u32 reg;
	s32 status = IXGBE_ERR_EEPROM;

	for (i = 0; i < IXGBE_FLUDONE_ATTEMPTS; i++) {
		reg = IXGBE_READ_REG(hw, IXGBE_EEC);
		if (reg & IXGBE_EEC_FLUDONE) {
			status = 0;
			break;
		}
		udelay(5);
	}
	return status;
}

/**
 *  ixgbe_acquire_swfw_sync_X540 - Acquire SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to acquire
 *
 *  Acquires the SWFW semaphore thought the SW_FW_SYNC register for
 *  the specified function (CSR, PHY0, PHY1, NVM, Flash)
 **/
s32 ixgbe_acquire_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask)
{
	u32 swfw_sync;
	u32 swmask = mask;
	u32 fwmask = mask << 5;
	u32 hwmask = 0;
	u32 timeout = 200;
	u32 i;
	s32 ret_val = 0;

	if (swmask == IXGBE_GSSR_EEP_SM)
		hwmask = IXGBE_GSSR_FLASH_SM;

	/* SW only mask doesn't have FW bit pair */
	if (swmask == IXGBE_GSSR_SW_MNG_SM)
		fwmask = 0;

	for (i = 0; i < timeout; i++) {
		/*
		 * SW NVM semaphore bit is used for access to all
		 * SW_FW_SYNC bits (not just NVM)
		 */
		if (ixgbe_get_swfw_sync_semaphore(hw)) {
			ret_val = IXGBE_ERR_SWFW_SYNC;
			goto out;
		}

		swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
		if (!(swfw_sync & (fwmask | swmask | hwmask))) {
			swfw_sync |= swmask;
			IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);
			ixgbe_release_swfw_sync_semaphore(hw);
			msleep(5);
			goto out;
		} else {
			/*
			 * Firmware currently using resource (fwmask), hardware
			 * currently using resource (hwmask), or other software
			 * thread currently using resource (swmask)
			 */
			ixgbe_release_swfw_sync_semaphore(hw);
			msleep(5);
		}
	}

	/* Failed to get SW only semaphore */
	if (swmask == IXGBE_GSSR_SW_MNG_SM) {
		ret_val = IXGBE_ERR_SWFW_SYNC;
		goto out;
	}

	/* If the resource is not released by the FW/HW the SW can assume that
	 * the FW/HW malfunctions. In that case the SW should sets the SW bit(s)
	 * of the requested resource(s) while ignoring the corresponding FW/HW
	 * bits in the SW_FW_SYNC register.
	 */
	swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
	if (swfw_sync & (fwmask | hwmask)) {
		if (ixgbe_get_swfw_sync_semaphore(hw)) {
			ret_val = IXGBE_ERR_SWFW_SYNC;
			goto out;
		}

		swfw_sync |= swmask;
		IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);
		ixgbe_release_swfw_sync_semaphore(hw);
		msleep(5);
	}

out:
	return ret_val;
}

/**
 *  ixgbe_release_swfw_sync_X540 - Release SWFW semaphore
 *  @hw: pointer to hardware structure
 *  @mask: Mask to specify which semaphore to release
 *
 *  Releases the SWFW semaphore through the SW_FW_SYNC register
 *  for the specified function (CSR, PHY0, PHY1, EVM, Flash)
 **/
void ixgbe_release_swfw_sync_X540(struct ixgbe_hw *hw, u16 mask)
{
	u32 swfw_sync;
	u32 swmask = mask;

	ixgbe_get_swfw_sync_semaphore(hw);

	swfw_sync = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
	swfw_sync &= ~swmask;
	IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swfw_sync);

	ixgbe_release_swfw_sync_semaphore(hw);
	msleep(5);
}

/**
 *  ixgbe_get_nvm_semaphore - Get hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  Sets the hardware semaphores so SW/FW can gain control of shared resources
 **/
static s32 ixgbe_get_swfw_sync_semaphore(struct ixgbe_hw *hw)
{
	s32 status = IXGBE_ERR_EEPROM;
	u32 timeout = 2000;
	u32 i;
	u32 swsm;

	/* Get SMBI software semaphore between device drivers first */
	for (i = 0; i < timeout; i++) {
		/*
		 * If the SMBI bit is 0 when we read it, then the bit will be
		 * set and we have the semaphore
		 */
		swsm = IXGBE_READ_REG(hw, IXGBE_SWSM);
		if (!(swsm & IXGBE_SWSM_SMBI)) {
			status = 0;
			break;
		}
		udelay(50);
	}

	/* Now get the semaphore between SW/FW through the REGSMP bit */
	if (status == 0) {
		for (i = 0; i < timeout; i++) {
			swsm = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
			if (!(swsm & IXGBE_SWFW_REGSMP))
				break;

			udelay(50);
		}

		/*
		 * Release semaphores and return error if SW NVM semaphore
		 * was not granted because we don't have access to the EEPROM
		 */
		if (i >= timeout) {
			hw_dbg(hw, "REGSMP Software NVM semaphore not "
				 "granted.\n");
			ixgbe_release_swfw_sync_semaphore(hw);
			status = IXGBE_ERR_EEPROM;
		}
	} else {
		hw_dbg(hw, "Software semaphore SMBI between device drivers "
			 "not granted.\n");
	}

	return status;
}

/**
 *  ixgbe_release_nvm_semaphore - Release hardware semaphore
 *  @hw: pointer to hardware structure
 *
 *  This function clears hardware semaphore bits.
 **/
static void ixgbe_release_swfw_sync_semaphore(struct ixgbe_hw *hw)
{
	u32 swsm;

	/* Release both semaphores by writing 0 to the bits REGSMP and SMBI */

	swsm = IXGBE_READ_REG(hw, IXGBE_SWSM);
	swsm &= ~IXGBE_SWSM_SMBI;
	IXGBE_WRITE_REG(hw, IXGBE_SWSM, swsm);

	swsm = IXGBE_READ_REG(hw, IXGBE_SWFW_SYNC);
	swsm &= ~IXGBE_SWFW_REGSMP;
	IXGBE_WRITE_REG(hw, IXGBE_SWFW_SYNC, swsm);

	IXGBE_WRITE_FLUSH(hw);
}

/**
 * ixgbe_blink_led_start_X540 - Blink LED based on index.
 * @hw: pointer to hardware structure
 * @index: led number to blink
 *
 * Devices that implement the version 2 interface:
 *   X540
 **/
s32 ixgbe_blink_led_start_X540(struct ixgbe_hw *hw, u32 index)
{
	u32 macc_reg;
	u32 ledctl_reg;
	ixgbe_link_speed speed;
	bool link_up;

	/*
	 * Link should be up in order for the blink bit in the LED control
	 * register to work. Force link and speed in the MAC if link is down.
	 * This will be reversed when we stop the blinking.
	 */
	hw->mac.ops.check_link(hw, &speed, &link_up, false);
	if (link_up == false) {
		macc_reg = IXGBE_READ_REG(hw, IXGBE_MACC);
		macc_reg |= IXGBE_MACC_FLU | IXGBE_MACC_FSV_10G | IXGBE_MACC_FS;
		IXGBE_WRITE_REG(hw, IXGBE_MACC, macc_reg);
	}
	/* Set the LED to LINK_UP + BLINK. */
	ledctl_reg = IXGBE_READ_REG(hw, IXGBE_LEDCTL);
	ledctl_reg &= ~IXGBE_LED_MODE_MASK(index);
	ledctl_reg |= IXGBE_LED_BLINK(index);
	IXGBE_WRITE_REG(hw, IXGBE_LEDCTL, ledctl_reg);
	IXGBE_WRITE_FLUSH(hw);

	return 0;
}

/**
 * ixgbe_blink_led_stop_X540 - Stop blinking LED based on index.
 * @hw: pointer to hardware structure
 * @index: led number to stop blinking
 *
 * Devices that implement the version 2 interface:
 *   X540
 **/
s32 ixgbe_blink_led_stop_X540(struct ixgbe_hw *hw, u32 index)
{
	u32 macc_reg;
	u32 ledctl_reg;

	/* Restore the LED to its default value. */
	ledctl_reg = IXGBE_READ_REG(hw, IXGBE_LEDCTL);
	ledctl_reg &= ~IXGBE_LED_MODE_MASK(index);
	ledctl_reg |= IXGBE_LED_LINK_ACTIVE << IXGBE_LED_MODE_SHIFT(index);
	ledctl_reg &= ~IXGBE_LED_BLINK(index);
	IXGBE_WRITE_REG(hw, IXGBE_LEDCTL, ledctl_reg);

	/* Unforce link and speed in the MAC. */
	macc_reg = IXGBE_READ_REG(hw, IXGBE_MACC);
	macc_reg &= ~(IXGBE_MACC_FLU | IXGBE_MACC_FSV_10G | IXGBE_MACC_FS);
	IXGBE_WRITE_REG(hw, IXGBE_MACC, macc_reg);
	IXGBE_WRITE_FLUSH(hw);

	return 0;
}
