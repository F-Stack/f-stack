/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation.
 */
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include <rte_io.h>
#include <rte_eal.h>
#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include "ntb.h"
#include "ntb_hw_intel.h"

enum xeon_ntb_bar {
	XEON_NTB_BAR23 = 2,
	XEON_NTB_BAR45 = 4,
};

static enum xeon_ntb_bar intel_ntb_bar[] = {
	XEON_NTB_BAR23,
	XEON_NTB_BAR45,
};

static inline int
is_gen3_ntb(const struct ntb_hw *hw)
{
	if (hw->pci_dev->id.device_id == NTB_INTEL_DEV_ID_B2B_SKX)
		return 1;

	return 0;
}

static inline int
is_gen4_ntb(const struct ntb_hw *hw)
{
	if (hw->pci_dev->id.device_id == NTB_INTEL_DEV_ID_B2B_ICX ||
	    hw->pci_dev->id.device_id == NTB_INTEL_DEV_ID_B2B_SPR)
		return 1;

	return 0;
}

static int
intel_ntb3_check_ppd(struct ntb_hw *hw)
{
	uint8_t reg_val;
	int ret;

	ret = rte_pci_read_config(hw->pci_dev, &reg_val,
				  sizeof(reg_val), XEON_PPD_OFFSET);
	if (ret < 0) {
		NTB_LOG(ERR, "Cannot get NTB PPD (PCIe port definition).");
		return -EIO;
	}

	/* Check connection topo type. Only support B2B. */
	switch (reg_val & XEON_PPD_CONN_MASK) {
	case XEON_PPD_CONN_B2B:
		NTB_LOG(INFO, "Topo B2B (back to back) is using.");
		break;
	case XEON_PPD_CONN_TRANSPARENT:
	case XEON_PPD_CONN_RP:
	default:
		NTB_LOG(ERR, "Not supported conn topo. Please use B2B.");
		return -EINVAL;
	}

	/* Check device type. */
	if (reg_val & XEON_PPD_DEV_DSD) {
		NTB_LOG(INFO, "DSD, Downstream Device.");
		hw->topo = NTB_TOPO_B2B_DSD;
	} else {
		NTB_LOG(INFO, "USD, Upstream device.");
		hw->topo = NTB_TOPO_B2B_USD;
	}

	/* Check if bar4 is split. Do not support split bar. */
	if (reg_val & XEON_PPD_SPLIT_BAR_MASK) {
		NTB_LOG(ERR, "Do not support split bar.");
		return -EINVAL;
	}

	return 0;
}

static int
intel_ntb4_check_ppd_for_ICX(struct ntb_hw *hw, uint32_t reg_val)
{
	/* Check connection topo type. Only support B2B. */
	switch (reg_val & XEON_GEN4_PPD_CONN_MASK) {
	case XEON_GEN4_PPD_CONN_B2B:
		NTB_LOG(INFO, "Topo B2B (back to back) is using.");
		break;
	default:
		NTB_LOG(ERR, "Not supported conn topo. Please use B2B.");
		return -EINVAL;
	}

	/* Check device type. */
	if (reg_val & XEON_GEN4_PPD_DEV_DSD) {
		NTB_LOG(INFO, "DSD, Downstream Device.");
		hw->topo = NTB_TOPO_B2B_DSD;
	} else {
		NTB_LOG(INFO, "USD, Upstream device.");
		hw->topo = NTB_TOPO_B2B_USD;
	}

	return 0;
}

static int
intel_ntb4_check_ppd_for_SPR(struct ntb_hw *hw, uint32_t reg_val)
{
	/* Check connection topo type. Only support B2B. */
	switch (reg_val & XEON_SPR_PPD_CONN_MASK) {
	case XEON_SPR_PPD_CONN_B2B:
		NTB_LOG(INFO, "Topo B2B (back to back) is using.");
		break;
	default:
		NTB_LOG(ERR, "Not supported conn topo. Please use B2B.");
		return -EINVAL;
	}

	/* Check device type. */
	if (reg_val & XEON_SPR_PPD_DEV_DSD) {
		NTB_LOG(INFO, "DSD, Downstream Device.");
		hw->topo = NTB_TOPO_B2B_DSD;
	} else {
		NTB_LOG(INFO, "USD, Upstream device.");
		hw->topo = NTB_TOPO_B2B_USD;
	}

	return 0;
}

static int
intel_ntb4_check_ppd(struct ntb_hw *hw)
{
	uint8_t revision_id;
	uint32_t reg_val;
	int ret;

	ret = rte_pci_read_config(hw->pci_dev, &revision_id,
				  NTB_PCI_DEV_REVISION_ID_LEN,
				  NTB_PCI_DEV_REVISION_ID_REG);
	if (ret != NTB_PCI_DEV_REVISION_ID_LEN) {
		NTB_LOG(ERR, "Cannot get NTB PCI Device Revision ID.");
		return -EIO;
	}

	reg_val = rte_read32(hw->hw_addr + XEON_GEN4_PPD1_OFFSET);

	/* Distinguish HW platform (ICX/SPR) via PCI Revision ID */
	if (revision_id > NTB_PCI_DEV_REVISION_ICX_MAX)
		ret = intel_ntb4_check_ppd_for_SPR(hw, reg_val);
	else if (revision_id >= NTB_PCI_DEV_REVISION_ICX_MIN)
		ret = intel_ntb4_check_ppd_for_ICX(hw, reg_val);
	else {
		NTB_LOG(ERR, "Invalid NTB PCI Device Revision ID.");
		return -EIO;
	}

	return ret;
}

static int
intel_ntb_dev_init(const struct rte_rawdev *dev)
{
	struct ntb_hw *hw = dev->dev_private;
	uint8_t bar;
	int ret, i;

	if (hw == NULL) {
		NTB_LOG(ERR, "Invalid device.");
		return -EINVAL;
	}

	hw->hw_addr = (char *)hw->pci_dev->mem_resource[0].addr;

	if (is_gen3_ntb(hw))
		ret = intel_ntb3_check_ppd(hw);
	else if (is_gen4_ntb(hw))
		/* PPD is in MMIO but not config space for NTB Gen4 */
		ret = intel_ntb4_check_ppd(hw);
	else {
		NTB_LOG(ERR, "Cannot init device for unsupported device.");
		return -ENOTSUP;
	}

	if (ret)
		return ret;

	hw->mw_cnt = XEON_MW_COUNT;
	hw->db_cnt = XEON_DB_COUNT;
	hw->spad_cnt = XEON_SPAD_COUNT;

	hw->mw_size = rte_zmalloc("ntb_mw_size",
				  hw->mw_cnt * sizeof(uint64_t), 0);
	if (hw->mw_size == NULL) {
		NTB_LOG(ERR, "Cannot allocate memory for mw size.");
		return -ENOMEM;
	}

	for (i = 0; i < hw->mw_cnt; i++) {
		bar = intel_ntb_bar[i];
		hw->mw_size[i] = hw->pci_dev->mem_resource[bar].len;
	}

	/* Reserve the last 2 spad registers for users. */
	for (i = 0; i < NTB_SPAD_USER_MAX_NUM; i++)
		hw->spad_user_list[i] = hw->spad_cnt;
	hw->spad_user_list[0] = hw->spad_cnt - 2;
	hw->spad_user_list[1] = hw->spad_cnt - 1;

	return 0;
}

static void *
intel_ntb_get_peer_mw_addr(const struct rte_rawdev *dev, int mw_idx)
{
	struct ntb_hw *hw = dev->dev_private;
	uint8_t bar;

	if (hw == NULL) {
		NTB_LOG(ERR, "Invalid device.");
		return 0;
	}

	if (mw_idx < 0 || mw_idx >= hw->mw_cnt) {
		NTB_LOG(ERR, "Invalid memory window index (0 - %u).",
			hw->mw_cnt - 1);
		return 0;
	}

	bar = intel_ntb_bar[mw_idx];

	return hw->pci_dev->mem_resource[bar].addr;
}

static int
intel_ntb_mw_set_trans(const struct rte_rawdev *dev, int mw_idx,
		       uint64_t addr, uint64_t size)
{
	struct ntb_hw *hw = dev->dev_private;
	void *xlat_addr, *limit_addr;
	uint64_t xlat_off, limit_off;
	uint64_t base, limit;
	uint8_t bar;

	if (hw == NULL) {
		NTB_LOG(ERR, "Invalid device.");
		return -EINVAL;
	}

	if (mw_idx < 0 || mw_idx >= hw->mw_cnt) {
		NTB_LOG(ERR, "Invalid memory window index (0 - %u).",
			hw->mw_cnt - 1);
		return -EINVAL;
	}

	bar = intel_ntb_bar[mw_idx];

	xlat_off = XEON_IMBAR1XBASE_OFFSET + mw_idx * XEON_BAR_INTERVAL_OFFSET;
	limit_off = XEON_IMBAR1XLMT_OFFSET + mw_idx * XEON_BAR_INTERVAL_OFFSET;
	xlat_addr = hw->hw_addr + xlat_off;
	limit_addr = hw->hw_addr + limit_off;

	/* Limit reg val should be EMBAR base address plus MW size. */
	base = addr;
	limit = hw->pci_dev->mem_resource[bar].phys_addr + size;
	rte_write64(base, xlat_addr);
	rte_write64(limit, limit_addr);

	if (is_gen3_ntb(hw)) {
		/* Setup the external point so that remote can access. */
		xlat_off = XEON_EMBAR1_OFFSET + 8 * mw_idx;
		xlat_addr = hw->hw_addr + xlat_off;
		limit_off = XEON_EMBAR1XLMT_OFFSET +
			    mw_idx * XEON_BAR_INTERVAL_OFFSET;
		limit_addr = hw->hw_addr + limit_off;
		base = rte_read64(xlat_addr);
		base &= ~0xf;
		limit = base + size;
		rte_write64(limit, limit_addr);
	} else if (is_gen4_ntb(hw)) {
		/* Set translate base address index register */
		xlat_off = XEON_GEN4_IM1XBASEIDX_OFFSET +
			   mw_idx * XEON_GEN4_XBASEIDX_INTERVAL;
		xlat_addr = hw->hw_addr + xlat_off;
		rte_write16(rte_log2_u64(size), xlat_addr);
	} else {
		NTB_LOG(ERR, "Cannot set translation of memory windows for unsupported device.");
		rte_write64(base, limit_addr);
		rte_write64(0, xlat_addr);
		return -ENOTSUP;
	}

	return 0;
}

static void *
intel_ntb_ioremap(const struct rte_rawdev *dev, uint64_t addr)
{
	struct ntb_hw *hw = dev->dev_private;
	void *mapped = NULL;
	void *base;
	int i;

	for (i = 0; i < hw->peer_used_mws; i++) {
		if (addr >= hw->peer_mw_base[i] &&
		    addr <= hw->peer_mw_base[i] + hw->mw_size[i]) {
			base = intel_ntb_get_peer_mw_addr(dev, i);
			mapped = (void *)(size_t)(addr - hw->peer_mw_base[i] +
				 (size_t)base);
			break;
		}
	}

	return mapped;
}

static int
intel_ntb_get_link_status(const struct rte_rawdev *dev)
{
	struct ntb_hw *hw = dev->dev_private;
	uint16_t reg_val, reg_off;
	int ret;

	if (hw == NULL) {
		NTB_LOG(ERR, "Invalid device.");
		return -EINVAL;
	}

	if (is_gen3_ntb(hw)) {
		reg_off = XEON_GEN3_LINK_STATUS_OFFSET;
		ret = rte_pci_read_config(hw->pci_dev, &reg_val,
					  sizeof(reg_val), reg_off);
		if (ret < 0) {
			NTB_LOG(ERR, "Unable to get link status.");
			return -EIO;
		}
	} else if (is_gen4_ntb(hw)) {
		reg_off = XEON_GEN4_LINK_STATUS_OFFSET;
		reg_val = rte_read16(hw->hw_addr + reg_off);
	} else {
		NTB_LOG(ERR, "Cannot get link status for unsupported device.");
		return -ENOTSUP;
	}

	hw->link_status = NTB_LNK_STA_ACTIVE(reg_val);

	if (hw->link_status) {
		hw->link_speed = NTB_LNK_STA_SPEED(reg_val);
		hw->link_width = NTB_LNK_STA_WIDTH(reg_val);
	} else {
		hw->link_speed = NTB_SPEED_NONE;
		hw->link_width = NTB_WIDTH_NONE;
	}

	return 0;
}

static int
intel_ntb_gen3_set_link(const struct ntb_hw *hw, bool up)
{
	uint32_t ntb_ctrl, reg_off;
	void *reg_addr;

	reg_off = XEON_NTBCNTL_OFFSET;
	reg_addr = hw->hw_addr + reg_off;
	ntb_ctrl = rte_read32(reg_addr);

	if (up) {
		ntb_ctrl &= ~(NTB_CTL_DISABLE | NTB_CTL_CFG_LOCK);
		ntb_ctrl |= NTB_CTL_P2S_BAR2_SNOOP | NTB_CTL_S2P_BAR2_SNOOP;
		ntb_ctrl |= NTB_CTL_P2S_BAR4_SNOOP | NTB_CTL_S2P_BAR4_SNOOP;
	} else {
		ntb_ctrl &= ~(NTB_CTL_P2S_BAR2_SNOOP | NTB_CTL_S2P_BAR2_SNOOP);
		ntb_ctrl &= ~(NTB_CTL_P2S_BAR4_SNOOP | NTB_CTL_S2P_BAR4_SNOOP);
		ntb_ctrl |= NTB_CTL_DISABLE | NTB_CTL_CFG_LOCK;
	}

	rte_write32(ntb_ctrl, reg_addr);

	return 0;
}

static int
intel_ntb_gen4_set_link(const struct ntb_hw *hw, bool up)
{
	uint32_t ntb_ctrl, ppd0;
	uint16_t link_ctrl;
	void *reg_addr;

	if (up) {
		reg_addr = hw->hw_addr + XEON_NTBCNTL_OFFSET;
		ntb_ctrl = NTB_CTL_P2S_BAR2_SNOOP | NTB_CTL_S2P_BAR2_SNOOP;
		ntb_ctrl |= NTB_CTL_P2S_BAR4_SNOOP | NTB_CTL_S2P_BAR4_SNOOP;
		rte_write32(ntb_ctrl, reg_addr);

		reg_addr = hw->hw_addr + XEON_GEN4_LINK_CTRL_OFFSET;
		link_ctrl = rte_read16(reg_addr);
		link_ctrl &= ~XEON_GEN4_LINK_CTRL_LINK_DIS;
		rte_write16(link_ctrl, reg_addr);

		/* start link training */
		reg_addr = hw->hw_addr + XEON_GEN4_PPD0_OFFSET;
		ppd0 = rte_read32(reg_addr);
		ppd0 |= XEON_GEN4_PPD_LINKTRN;
		rte_write32(ppd0, reg_addr);

		/* make sure link training has started */
		ppd0 = rte_read32(reg_addr);
		if (!(ppd0 & XEON_GEN4_PPD_LINKTRN)) {
			NTB_LOG(ERR, "Link is not training.");
			return -EINVAL;
		}
	} else {
		reg_addr = hw->hw_addr + XEON_NTBCNTL_OFFSET;
		ntb_ctrl = rte_read32(reg_addr);
		ntb_ctrl &= ~(NTB_CTL_P2S_BAR2_SNOOP | NTB_CTL_S2P_BAR2_SNOOP);
		ntb_ctrl &= ~(NTB_CTL_P2S_BAR4_SNOOP | NTB_CTL_S2P_BAR4_SNOOP);
		rte_write32(ntb_ctrl, reg_addr);

		reg_addr = hw->hw_addr + XEON_GEN4_LINK_CTRL_OFFSET;
		link_ctrl = rte_read16(reg_addr);
		link_ctrl |= XEON_GEN4_LINK_CTRL_LINK_DIS;
		rte_write16(link_ctrl, reg_addr);
	}

	return 0;
}

static int
intel_ntb_set_link(const struct rte_rawdev *dev, bool up)
{
	struct ntb_hw *hw = dev->dev_private;
	int ret = 0;

	if (is_gen3_ntb(hw))
		ret = intel_ntb_gen3_set_link(hw, up);
	else if (is_gen4_ntb(hw))
		ret = intel_ntb_gen4_set_link(hw, up);
	else {
		NTB_LOG(ERR, "Cannot set link for unsupported device.");
		ret = -ENOTSUP;
	}

	return ret;
}

static uint32_t
intel_ntb_spad_read(const struct rte_rawdev *dev, int spad, bool peer)
{
	struct ntb_hw *hw = dev->dev_private;
	uint32_t spad_v, reg_off;
	void *reg_addr;

	if (spad < 0 || spad >= hw->spad_cnt) {
		NTB_LOG(ERR, "Invalid spad reg index.");
		return 0;
	}

	/* When peer is true, read peer spad reg */
	if (is_gen3_ntb(hw))
		reg_off = peer ? XEON_GEN3_B2B_SPAD_OFFSET :
				XEON_IM_SPAD_OFFSET;
	else if (is_gen4_ntb(hw))
		reg_off = peer ? XEON_GEN4_B2B_SPAD_OFFSET :
				XEON_IM_SPAD_OFFSET;
	else {
		NTB_LOG(ERR, "Cannot read spad for unsupported device.");
		return -ENOTSUP;
	}
	reg_addr = hw->hw_addr + reg_off + (spad << 2);
	spad_v = rte_read32(reg_addr);

	return spad_v;
}

static int
intel_ntb_spad_write(const struct rte_rawdev *dev, int spad,
		     bool peer, uint32_t spad_v)
{
	struct ntb_hw *hw = dev->dev_private;
	uint32_t reg_off;
	void *reg_addr;

	if (spad < 0 || spad >= hw->spad_cnt) {
		NTB_LOG(ERR, "Invalid spad reg index.");
		return -EINVAL;
	}

	/* When peer is true, write peer spad reg */
	if (is_gen3_ntb(hw))
		reg_off = peer ? XEON_GEN3_B2B_SPAD_OFFSET :
				XEON_IM_SPAD_OFFSET;
	else if (is_gen4_ntb(hw))
		reg_off = peer ? XEON_GEN4_B2B_SPAD_OFFSET :
				XEON_IM_SPAD_OFFSET;
	else {
		NTB_LOG(ERR, "Cannot write spad for unsupported device.");
		return -ENOTSUP;
	}
	reg_addr = hw->hw_addr + reg_off + (spad << 2);

	rte_write32(spad_v, reg_addr);

	return 0;
}

static uint64_t
intel_ntb_db_read(const struct rte_rawdev *dev)
{
	struct ntb_hw *hw = dev->dev_private;
	uint64_t db_off, db_bits;
	void *db_addr;

	db_off = XEON_IM_INT_STATUS_OFFSET;
	db_addr = hw->hw_addr + db_off;

	db_bits = rte_read64(db_addr);

	return db_bits;
}

static int
intel_ntb_db_clear(const struct rte_rawdev *dev, uint64_t db_bits)
{
	struct ntb_hw *hw = dev->dev_private;
	uint64_t db_off;
	void *db_addr;

	db_off = XEON_IM_INT_STATUS_OFFSET;
	db_addr = hw->hw_addr + db_off;

	if (is_gen4_ntb(hw))
		rte_write16(XEON_GEN4_SLOTSTS_DLLSCS,
			    hw->hw_addr + XEON_GEN4_SLOTSTS);
	rte_write64(db_bits, db_addr);

	return 0;
}

static int
intel_ntb_db_set_mask(const struct rte_rawdev *dev, uint64_t db_mask)
{
	struct ntb_hw *hw = dev->dev_private;
	uint64_t db_m_off;
	void *db_m_addr;

	db_m_off = XEON_IM_INT_DISABLE_OFFSET;
	db_m_addr = hw->hw_addr + db_m_off;

	db_mask |= hw->db_mask;

	rte_write64(db_mask, db_m_addr);

	hw->db_mask = db_mask;

	return 0;
}

static int
intel_ntb_peer_db_set(const struct rte_rawdev *dev, uint8_t db_idx)
{
	struct ntb_hw *hw = dev->dev_private;
	uint32_t db_off;
	void *db_addr;

	if (((uint64_t)1 << db_idx) & ~hw->db_valid_mask) {
		NTB_LOG(ERR, "Invalid doorbell.");
		return -EINVAL;
	}

	db_off = XEON_IM_DOORBELL_OFFSET + db_idx * 4;
	db_addr = hw->hw_addr + db_off;

	rte_write32(1, db_addr);

	return 0;
}

static int
intel_ntb_vector_bind(const struct rte_rawdev *dev, uint8_t intr, uint8_t msix)
{
	struct ntb_hw *hw = dev->dev_private;
	uint8_t reg_off;
	void *reg_addr;

	if (intr >= hw->db_cnt) {
		NTB_LOG(ERR, "Invalid intr source.");
		return -EINVAL;
	}

	/* Bind intr source to msix vector */
	if (is_gen3_ntb(hw))
		reg_off = XEON_GEN3_INTVEC_OFFSET;
	else if (is_gen4_ntb(hw))
		reg_off = XEON_GEN4_INTVEC_OFFSET;
	else {
		NTB_LOG(ERR, "Cannot bind vectors for unsupported device.");
		return -ENOTSUP;
	}
	reg_addr = hw->hw_addr + reg_off + intr;

	rte_write8(msix, reg_addr);

	return 0;
}

/* operations for primary side of local ntb */
const struct ntb_dev_ops intel_ntb_ops = {
	.ntb_dev_init       = intel_ntb_dev_init,
	.get_peer_mw_addr   = intel_ntb_get_peer_mw_addr,
	.mw_set_trans       = intel_ntb_mw_set_trans,
	.ioremap            = intel_ntb_ioremap,
	.get_link_status    = intel_ntb_get_link_status,
	.set_link           = intel_ntb_set_link,
	.spad_read          = intel_ntb_spad_read,
	.spad_write         = intel_ntb_spad_write,
	.db_read            = intel_ntb_db_read,
	.db_clear           = intel_ntb_db_clear,
	.db_set_mask        = intel_ntb_db_set_mask,
	.peer_db_set        = intel_ntb_peer_db_set,
	.vector_bind        = intel_ntb_vector_bind,
};
