/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.
 *   Copyright(c) 2018 Synopsys, Inc. All rights reserved.
 */

#include "axgbe_ethdev.h"
#include "axgbe_common.h"
#include "axgbe_phy.h"
#include "axgbe_rxtx.h"

static uint32_t bitrev32(uint32_t x)
{
	x = (x >> 16) | (x << 16);
	x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
	x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
	x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
	x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
	return x;
}

/*MSB set bit from 32 to 1*/
static int get_lastbit_set(int x)
{
	int r = 32;

	if (!x)
		return 0;
	if (!(x & 0xffff0000)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000)) {
		x <<= 1;
		r -= 1;
	}
	return r;
}

static inline unsigned int axgbe_get_max_frame(struct axgbe_port *pdata)
{
	return pdata->eth_dev->data->mtu + RTE_ETHER_HDR_LEN +
		RTE_ETHER_CRC_LEN + RTE_VLAN_HLEN;
}

/* query busy bit */
static int mdio_complete(struct axgbe_port *pdata)
{
	if (!AXGMAC_IOREAD_BITS(pdata, MAC_MDIOSCCDR, BUSY))
		return 1;

	return 0;
}

static unsigned int axgbe_create_mdio_sca(int port, int reg)
{
	unsigned int mdio_sca, da;

	da = (reg & MII_ADDR_C45) ? reg >> 16 : 0;

	mdio_sca = 0;
	AXGMAC_SET_BITS(mdio_sca, MAC_MDIOSCAR, RA, reg);
	AXGMAC_SET_BITS(mdio_sca, MAC_MDIOSCAR, PA, port);
	AXGMAC_SET_BITS(mdio_sca, MAC_MDIOSCAR, DA, da);

	return mdio_sca;
}

static int axgbe_write_ext_mii_regs(struct axgbe_port *pdata, int addr,
				    int reg, u16 val)
{
	unsigned int mdio_sca, mdio_sccd;
	uint64_t timeout;

	mdio_sca = axgbe_create_mdio_sca(addr, reg);
	AXGMAC_IOWRITE(pdata, MAC_MDIOSCAR, mdio_sca);

	mdio_sccd = 0;
	AXGMAC_SET_BITS(mdio_sccd, MAC_MDIOSCCDR, DATA, val);
	AXGMAC_SET_BITS(mdio_sccd, MAC_MDIOSCCDR, CMD, 1);
	AXGMAC_SET_BITS(mdio_sccd, MAC_MDIOSCCDR, BUSY, 1);
	AXGMAC_IOWRITE(pdata, MAC_MDIOSCCDR, mdio_sccd);

	timeout = rte_get_timer_cycles() + rte_get_timer_hz();
	while (time_before(rte_get_timer_cycles(), timeout)) {
		rte_delay_us(100);
		if (mdio_complete(pdata))
			return 0;
	}

	PMD_DRV_LOG(ERR, "Mdio write operation timed out\n");
	return -ETIMEDOUT;
}

static int axgbe_read_ext_mii_regs(struct axgbe_port *pdata, int addr,
				   int reg)
{
	unsigned int mdio_sca, mdio_sccd;
	uint64_t timeout;

	mdio_sca = axgbe_create_mdio_sca(addr, reg);
	AXGMAC_IOWRITE(pdata, MAC_MDIOSCAR, mdio_sca);

	mdio_sccd = 0;
	AXGMAC_SET_BITS(mdio_sccd, MAC_MDIOSCCDR, CMD, 3);
	AXGMAC_SET_BITS(mdio_sccd, MAC_MDIOSCCDR, BUSY, 1);
	AXGMAC_IOWRITE(pdata, MAC_MDIOSCCDR, mdio_sccd);

	timeout = rte_get_timer_cycles() + rte_get_timer_hz();

	while (time_before(rte_get_timer_cycles(), timeout)) {
		rte_delay_us(100);
		if (mdio_complete(pdata))
			goto success;
	}

	PMD_DRV_LOG(ERR, "Mdio read operation timed out\n");
	return -ETIMEDOUT;

success:
	return AXGMAC_IOREAD_BITS(pdata, MAC_MDIOSCCDR, DATA);
}

static int axgbe_set_ext_mii_mode(struct axgbe_port *pdata, unsigned int port,
				  enum axgbe_mdio_mode mode)
{
	unsigned int reg_val = 0;

	switch (mode) {
	case AXGBE_MDIO_MODE_CL22:
		if (port > AXGMAC_MAX_C22_PORT)
			return -EINVAL;
		reg_val |= (1 << port);
		break;
	case AXGBE_MDIO_MODE_CL45:
		break;
	default:
		return -EINVAL;
	}
	AXGMAC_IOWRITE(pdata, MAC_MDIOCL22R, reg_val);

	return 0;
}

static int axgbe_read_mmd_regs_v2(struct axgbe_port *pdata,
				  int prtad __rte_unused, int mmd_reg)
{
	unsigned int mmd_address, index, offset;
	int mmd_data;

	if (mmd_reg & MII_ADDR_C45)
		mmd_address = mmd_reg & ~MII_ADDR_C45;
	else
		mmd_address = (pdata->mdio_mmd << 16) | (mmd_reg & 0xffff);

	/* The PCS registers are accessed using mmio. The underlying
	 * management interface uses indirect addressing to access the MMD
	 * register sets. This requires accessing of the PCS register in two
	 * phases, an address phase and a data phase.
	 *
	 * The mmio interface is based on 16-bit offsets and values. All
	 * register offsets must therefore be adjusted by left shifting the
	 * offset 1 bit and reading 16 bits of data.
	 */
	mmd_address <<= 1;
	index = mmd_address & ~pdata->xpcs_window_mask;
	offset = pdata->xpcs_window + (mmd_address & pdata->xpcs_window_mask);

	pthread_mutex_lock(&pdata->xpcs_mutex);

	XPCS32_IOWRITE(pdata, pdata->xpcs_window_sel_reg, index);
	mmd_data = XPCS16_IOREAD(pdata, offset);

	pthread_mutex_unlock(&pdata->xpcs_mutex);

	return mmd_data;
}

static void axgbe_write_mmd_regs_v2(struct axgbe_port *pdata,
				    int prtad __rte_unused,
				    int mmd_reg, int mmd_data)
{
	unsigned int mmd_address, index, offset;

	if (mmd_reg & MII_ADDR_C45)
		mmd_address = mmd_reg & ~MII_ADDR_C45;
	else
		mmd_address = (pdata->mdio_mmd << 16) | (mmd_reg & 0xffff);

	/* The PCS registers are accessed using mmio. The underlying
	 * management interface uses indirect addressing to access the MMD
	 * register sets. This requires accessing of the PCS register in two
	 * phases, an address phase and a data phase.
	 *
	 * The mmio interface is based on 16-bit offsets and values. All
	 * register offsets must therefore be adjusted by left shifting the
	 * offset 1 bit and writing 16 bits of data.
	 */
	mmd_address <<= 1;
	index = mmd_address & ~pdata->xpcs_window_mask;
	offset = pdata->xpcs_window + (mmd_address & pdata->xpcs_window_mask);

	pthread_mutex_lock(&pdata->xpcs_mutex);

	XPCS32_IOWRITE(pdata, pdata->xpcs_window_sel_reg, index);
	XPCS16_IOWRITE(pdata, offset, mmd_data);

	pthread_mutex_unlock(&pdata->xpcs_mutex);
}

static int axgbe_read_mmd_regs(struct axgbe_port *pdata, int prtad,
			       int mmd_reg)
{
	switch (pdata->vdata->xpcs_access) {
	case AXGBE_XPCS_ACCESS_V1:
		PMD_DRV_LOG(ERR, "PHY_Version 1 is not supported\n");
		return -1;
	case AXGBE_XPCS_ACCESS_V2:
	default:
		return axgbe_read_mmd_regs_v2(pdata, prtad, mmd_reg);
	}
}

static void axgbe_write_mmd_regs(struct axgbe_port *pdata, int prtad,
				 int mmd_reg, int mmd_data)
{
	switch (pdata->vdata->xpcs_access) {
	case AXGBE_XPCS_ACCESS_V1:
		PMD_DRV_LOG(ERR, "PHY_Version 1 is not supported\n");
		return;
	case AXGBE_XPCS_ACCESS_V2:
	default:
		return axgbe_write_mmd_regs_v2(pdata, prtad, mmd_reg, mmd_data);
	}
}

static int axgbe_set_speed(struct axgbe_port *pdata, int speed)
{
	unsigned int ss;

	switch (speed) {
	case SPEED_1000:
		ss = 0x03;
		break;
	case SPEED_2500:
		ss = 0x02;
		break;
	case SPEED_10000:
		ss = 0x00;
		break;
	default:
		return -EINVAL;
	}

	if (AXGMAC_IOREAD_BITS(pdata, MAC_TCR, SS) != ss)
		AXGMAC_IOWRITE_BITS(pdata, MAC_TCR, SS, ss);

	return 0;
}

static unsigned int axgbe_get_fc_queue_count(struct axgbe_port *pdata)
{
	unsigned int max_q_count = AXGMAC_MAX_FLOW_CONTROL_QUEUES;

	/* From MAC ver 30H the TFCR is per priority, instead of per queue */
	if (AXGMAC_GET_BITS(pdata->hw_feat.version, MAC_VR, SNPSVER) >= 0x30)
		return max_q_count;
	else
		return (RTE_MIN(pdata->tx_q_count, max_q_count));
}

static int axgbe_disable_tx_flow_control(struct axgbe_port *pdata)
{
	unsigned int reg, reg_val;
	unsigned int i, q_count;

	/* Clear MTL flow control */
	for (i = 0; i < pdata->rx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, EHFC, 0);

	/* Clear MAC flow control */
	q_count = axgbe_get_fc_queue_count(pdata);
	reg = MAC_Q0TFCR;
	for (i = 0; i < q_count; i++) {
		reg_val = AXGMAC_IOREAD(pdata, reg);
		AXGMAC_SET_BITS(reg_val, MAC_Q0TFCR, TFE, 0);
		AXGMAC_IOWRITE(pdata, reg, reg_val);

		reg += MAC_QTFCR_INC;
	}

	return 0;
}

static int axgbe_enable_tx_flow_control(struct axgbe_port *pdata)
{
	unsigned int reg, reg_val;
	unsigned int i, q_count;

	/* Set MTL flow control */
	for (i = 0; i < pdata->rx_q_count; i++) {
		unsigned int ehfc = 0;

		/* Flow control thresholds are established */
		if (pdata->rx_rfd[i])
			ehfc = 1;

		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, EHFC, ehfc);

		PMD_DRV_LOG(DEBUG, "flow control %s for RXq%u\n",
			    ehfc ? "enabled" : "disabled", i);
	}

	/* Set MAC flow control */
	q_count = axgbe_get_fc_queue_count(pdata);
	reg = MAC_Q0TFCR;
	for (i = 0; i < q_count; i++) {
		reg_val = AXGMAC_IOREAD(pdata, reg);

		/* Enable transmit flow control */
		AXGMAC_SET_BITS(reg_val, MAC_Q0TFCR, TFE, 1);
		/* Set pause time */
		AXGMAC_SET_BITS(reg_val, MAC_Q0TFCR, PT, 0xffff);

		AXGMAC_IOWRITE(pdata, reg, reg_val);

		reg += MAC_QTFCR_INC;
	}

	return 0;
}

static int axgbe_disable_rx_flow_control(struct axgbe_port *pdata)
{
	AXGMAC_IOWRITE_BITS(pdata, MAC_RFCR, RFE, 0);

	return 0;
}

static int axgbe_enable_rx_flow_control(struct axgbe_port *pdata)
{
	AXGMAC_IOWRITE_BITS(pdata, MAC_RFCR, RFE, 1);

	return 0;
}

static int axgbe_config_tx_flow_control(struct axgbe_port *pdata)
{
	if (pdata->tx_pause)
		axgbe_enable_tx_flow_control(pdata);
	else
		axgbe_disable_tx_flow_control(pdata);

	return 0;
}

static int axgbe_config_rx_flow_control(struct axgbe_port *pdata)
{
	if (pdata->rx_pause)
		axgbe_enable_rx_flow_control(pdata);
	else
		axgbe_disable_rx_flow_control(pdata);

	return 0;
}

static void axgbe_config_flow_control(struct axgbe_port *pdata)
{
	axgbe_config_tx_flow_control(pdata);
	axgbe_config_rx_flow_control(pdata);

	AXGMAC_IOWRITE_BITS(pdata, MAC_RFCR, PFCE, 0);
}

static void axgbe_queue_flow_control_threshold(struct axgbe_port *pdata,
					       unsigned int queue,
					       unsigned int q_fifo_size)
{
	unsigned int frame_fifo_size;
	unsigned int rfa, rfd;

	frame_fifo_size = AXGMAC_FLOW_CONTROL_ALIGN(axgbe_get_max_frame(pdata));

	/* This path deals with just maximum frame sizes which are
	 * limited to a jumbo frame of 9,000 (plus headers, etc.)
	 * so we can never exceed the maximum allowable RFA/RFD
	 * values.
	 */
	if (q_fifo_size <= 2048) {
		/* rx_rfd to zero to signal no flow control */
		pdata->rx_rfa[queue] = 0;
		pdata->rx_rfd[queue] = 0;
		return;
	}

	if (q_fifo_size <= 4096) {
		/* Between 2048 and 4096 */
		pdata->rx_rfa[queue] = 0;	/* Full - 1024 bytes */
		pdata->rx_rfd[queue] = 1;	/* Full - 1536 bytes */
		return;
	}

	if (q_fifo_size <= frame_fifo_size) {
		/* Between 4096 and max-frame */
		pdata->rx_rfa[queue] = 2;	/* Full - 2048 bytes */
		pdata->rx_rfd[queue] = 5;	/* Full - 3584 bytes */
		return;
	}

	if (q_fifo_size <= (frame_fifo_size * 3)) {
		/* Between max-frame and 3 max-frames,
		 * trigger if we get just over a frame of data and
		 * resume when we have just under half a frame left.
		 */
		rfa = q_fifo_size - frame_fifo_size;
		rfd = rfa + (frame_fifo_size / 2);
	} else {
		/* Above 3 max-frames - trigger when just over
		 * 2 frames of space available
		 */
		rfa = frame_fifo_size * 2;
		rfa += AXGMAC_FLOW_CONTROL_UNIT;
		rfd = rfa + frame_fifo_size;
	}

	pdata->rx_rfa[queue] = AXGMAC_FLOW_CONTROL_VALUE(rfa);
	pdata->rx_rfd[queue] = AXGMAC_FLOW_CONTROL_VALUE(rfd);
}

static void axgbe_calculate_flow_control_threshold(struct axgbe_port *pdata)
{
	unsigned int q_fifo_size;
	unsigned int i;

	for (i = 0; i < pdata->rx_q_count; i++) {
		q_fifo_size = (pdata->fifo + 1) * AXGMAC_FIFO_UNIT;

		axgbe_queue_flow_control_threshold(pdata, i, q_fifo_size);
	}
}

static void axgbe_config_flow_control_threshold(struct axgbe_port *pdata)
{
	unsigned int i;

	for (i = 0; i < pdata->rx_q_count; i++) {
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQFCR, RFA,
					pdata->rx_rfa[i]);
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQFCR, RFD,
					pdata->rx_rfd[i]);
	}
}

static int axgbe_enable_rx_vlan_stripping(struct axgbe_port *pdata)
{
	/* Put the VLAN tag in the Rx descriptor */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLRXS, 1);

	/* Don't check the VLAN type */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, DOVLTC, 1);

	/* Check only C-TAG (0x8100) packets */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, ERSVLM, 0);

	/* Don't consider an S-TAG (0x88A8) packet as a VLAN packet */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, ESVL, 0);

	/* Enable VLAN tag stripping */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLS, 0x3);
	return 0;
}

static int axgbe_disable_rx_vlan_stripping(struct axgbe_port *pdata)
{
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, EVLS, 0);
	return 0;
}

static int axgbe_enable_rx_vlan_filtering(struct axgbe_port *pdata)
{
	/* Enable VLAN filtering */
	AXGMAC_IOWRITE_BITS(pdata, MAC_PFR, VTFE, 1);

	/* Enable VLAN Hash Table filtering */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, VTHM, 1);

	/* Disable VLAN tag inverse matching */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, VTIM, 0);

	/* Only filter on the lower 12-bits of the VLAN tag */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, ETV, 1);

	/* In order for the VLAN Hash Table filtering to be effective,
	 * the VLAN tag identifier in the VLAN Tag Register must not
	 * be zero.  Set the VLAN tag identifier to "1" to enable the
	 * VLAN Hash Table filtering.  This implies that a VLAN tag of
	 * 1 will always pass filtering.
	 */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANTR, VL, 1);
	return 0;
}

static int axgbe_disable_rx_vlan_filtering(struct axgbe_port *pdata)
{
	/* Disable VLAN filtering */
	AXGMAC_IOWRITE_BITS(pdata, MAC_PFR, VTFE, 0);
	return 0;
}

static u32 axgbe_vid_crc32_le(__le16 vid_le)
{
	u32 poly = 0xedb88320;  /* CRCPOLY_LE */
	u32 crc = ~0;
	u32 temp = 0;
	unsigned char *data = (unsigned char *)&vid_le;
	unsigned char data_byte = 0;
	int i, bits;

	bits = get_lastbit_set(VLAN_VID_MASK);
	for (i = 0; i < bits; i++) {
		if ((i % 8) == 0)
			data_byte = data[i / 8];

		temp = ((crc & 1) ^ data_byte) & 1;
		crc >>= 1;
		data_byte >>= 1;

		if (temp)
			crc ^= poly;
	}
	return crc;
}

static int axgbe_update_vlan_hash_table(struct axgbe_port *pdata)
{
	u32 crc = 0;
	u16 vid;
	__le16 vid_le = 0;
	u16 vlan_hash_table = 0;
	unsigned int reg = 0;
	unsigned long vid_idx, vid_valid;

	/* Generate the VLAN Hash Table value */
	for (vid = 0; vid < VLAN_N_VID; vid++) {
		vid_idx = VLAN_TABLE_IDX(vid);
		vid_valid = pdata->active_vlans[vid_idx];
		vid_valid = (unsigned long)vid_valid >> (vid - (64 * vid_idx));
		if (vid_valid & 1)
			PMD_DRV_LOG(DEBUG,
				    "vid:%d pdata->active_vlans[%ld]=0x%lx\n",
				    vid, vid_idx, pdata->active_vlans[vid_idx]);
		else
			continue;

		vid_le = rte_cpu_to_le_16(vid);
		crc = bitrev32(~axgbe_vid_crc32_le(vid_le)) >> 28;
		vlan_hash_table |= (1 << crc);
		PMD_DRV_LOG(DEBUG, "crc = %d vlan_hash_table = 0x%x\n",
			    crc, vlan_hash_table);
	}
	/* Set the VLAN Hash Table filtering register */
	AXGMAC_IOWRITE_BITS(pdata, MAC_VLANHTR, VLHT, vlan_hash_table);
	reg = AXGMAC_IOREAD(pdata, MAC_VLANHTR);
	PMD_DRV_LOG(DEBUG, "vlan_hash_table reg val = 0x%x\n", reg);
	return 0;
}

static int __axgbe_exit(struct axgbe_port *pdata)
{
	unsigned int count = 2000;

	/* Issue a software reset */
	AXGMAC_IOWRITE_BITS(pdata, DMA_MR, SWR, 1);
	rte_delay_us(10);

	/* Poll Until Poll Condition */
	while (--count && AXGMAC_IOREAD_BITS(pdata, DMA_MR, SWR))
		rte_delay_us(500);

	if (!count)
		return -EBUSY;

	return 0;
}

static int axgbe_exit(struct axgbe_port *pdata)
{
	int ret;

	/* To guard against possible incorrectly generated interrupts,
	 * issue the software reset twice.
	 */
	ret = __axgbe_exit(pdata);
	if (ret)
		return ret;

	return __axgbe_exit(pdata);
}

static int axgbe_flush_tx_queues(struct axgbe_port *pdata)
{
	unsigned int i, count;

	if (AXGMAC_GET_BITS(pdata->hw_feat.version, MAC_VR, SNPSVER) < 0x21)
		return 0;

	for (i = 0; i < pdata->tx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, FTQ, 1);

	/* Poll Until Poll Condition */
	for (i = 0; i < pdata->tx_q_count; i++) {
		count = 2000;
		while (--count && AXGMAC_MTL_IOREAD_BITS(pdata, i,
							 MTL_Q_TQOMR, FTQ))
			rte_delay_us(500);

		if (!count)
			return -EBUSY;
	}

	return 0;
}

static void axgbe_config_dma_bus(struct axgbe_port *pdata)
{
	/* Set enhanced addressing mode */
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, EAME, 1);

	/* Out standing read/write requests*/
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, RD_OSR, 0x3f);
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, WR_OSR, 0x3f);

	/* Set the System Bus mode */
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, UNDEF, 1);
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, BLEN_32, 1);
	AXGMAC_IOWRITE_BITS(pdata, DMA_SBMR, AAL, 1);
}

static void axgbe_config_dma_cache(struct axgbe_port *pdata)
{
	unsigned int arcache, awcache, arwcache;

	arcache = 0;
	AXGMAC_SET_BITS(arcache, DMA_AXIARCR, DRC, 0xf);
	AXGMAC_SET_BITS(arcache, DMA_AXIARCR, TEC, 0xf);
	AXGMAC_SET_BITS(arcache, DMA_AXIARCR, THC, 0xf);
	AXGMAC_IOWRITE(pdata, DMA_AXIARCR, arcache);

	awcache = 0;
	AXGMAC_SET_BITS(awcache, DMA_AXIAWCR, DWC, 0xf);
	AXGMAC_SET_BITS(awcache, DMA_AXIAWCR, RPC, 0xf);
	AXGMAC_SET_BITS(awcache, DMA_AXIAWCR, RHC, 0xf);
	AXGMAC_SET_BITS(awcache, DMA_AXIAWCR, RDC, 0xf);
	AXGMAC_IOWRITE(pdata, DMA_AXIAWCR, awcache);

	arwcache = 0;
	AXGMAC_SET_BITS(arwcache, DMA_AXIAWRCR, TDWC, 0xf);
	AXGMAC_SET_BITS(arwcache, DMA_AXIAWRCR, RDRC, 0xf);
	AXGMAC_IOWRITE(pdata, DMA_AXIAWRCR, arwcache);
}

static void axgbe_config_edma_control(struct axgbe_port *pdata)
{
	AXGMAC_IOWRITE(pdata, EDMA_TX_CONTROL, 0x5);
	AXGMAC_IOWRITE(pdata, EDMA_RX_CONTROL, 0x5);
}

static int axgbe_config_osp_mode(struct axgbe_port *pdata)
{
	/* Force DMA to operate on second packet before closing descriptors
	 *  of first packet
	 */
	struct axgbe_tx_queue *txq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_tx_queues; i++) {
		txq = pdata->eth_dev->data->tx_queues[i];
		AXGMAC_DMA_IOWRITE_BITS(txq, DMA_CH_TCR, OSP,
					pdata->tx_osp_mode);
	}

	return 0;
}

static int axgbe_config_pblx8(struct axgbe_port *pdata)
{
	struct axgbe_tx_queue *txq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_tx_queues; i++) {
		txq = pdata->eth_dev->data->tx_queues[i];
		AXGMAC_DMA_IOWRITE_BITS(txq, DMA_CH_CR, PBLX8,
					pdata->pblx8);
	}
	return 0;
}

static int axgbe_config_tx_pbl_val(struct axgbe_port *pdata)
{
	struct axgbe_tx_queue *txq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_tx_queues; i++) {
		txq = pdata->eth_dev->data->tx_queues[i];
		AXGMAC_DMA_IOWRITE_BITS(txq, DMA_CH_TCR, PBL,
				pdata->tx_pbl);
	}

	return 0;
}

static int axgbe_config_rx_pbl_val(struct axgbe_port *pdata)
{
	struct axgbe_rx_queue *rxq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_rx_queues; i++) {
		rxq = pdata->eth_dev->data->rx_queues[i];
		AXGMAC_DMA_IOWRITE_BITS(rxq, DMA_CH_RCR, PBL,
				pdata->rx_pbl);
	}

	return 0;
}

static void axgbe_config_rx_buffer_size(struct axgbe_port *pdata)
{
	struct axgbe_rx_queue *rxq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_rx_queues; i++) {
		rxq = pdata->eth_dev->data->rx_queues[i];

		rxq->buf_size = rte_pktmbuf_data_room_size(rxq->mb_pool) -
			RTE_PKTMBUF_HEADROOM;
		rxq->buf_size = (rxq->buf_size + AXGBE_RX_BUF_ALIGN - 1) &
			~(AXGBE_RX_BUF_ALIGN - 1);

		if (rxq->buf_size > pdata->rx_buf_size)
			pdata->rx_buf_size = rxq->buf_size;

		AXGMAC_DMA_IOWRITE_BITS(rxq, DMA_CH_RCR, RBSZ,
					rxq->buf_size);
	}
}

static int axgbe_write_rss_reg(struct axgbe_port *pdata, unsigned int type,
			       unsigned int index, unsigned int val)
{
	unsigned int wait;

	if (AXGMAC_IOREAD_BITS(pdata, MAC_RSSAR, OB))
		return -EBUSY;

	AXGMAC_IOWRITE(pdata, MAC_RSSDR, val);

	AXGMAC_IOWRITE_BITS(pdata, MAC_RSSAR, RSSIA, index);
	AXGMAC_IOWRITE_BITS(pdata, MAC_RSSAR, ADDRT, type);
	AXGMAC_IOWRITE_BITS(pdata, MAC_RSSAR, CT, 0);
	AXGMAC_IOWRITE_BITS(pdata, MAC_RSSAR, OB, 1);

	wait = 1000;
	while (wait--) {
		if (!AXGMAC_IOREAD_BITS(pdata, MAC_RSSAR, OB))
			return 0;

		rte_delay_us(1500);
	}

	return -EBUSY;
}

int axgbe_write_rss_hash_key(struct axgbe_port *pdata)
{
	struct rte_eth_rss_conf *rss_conf;
	unsigned int key_regs = sizeof(pdata->rss_key) / sizeof(u32);
	unsigned int *key;
	int ret;

	rss_conf = &pdata->eth_dev->data->dev_conf.rx_adv_conf.rss_conf;

	if (!rss_conf->rss_key)
		key = (unsigned int *)&pdata->rss_key;
	else
		key = (unsigned int *)&rss_conf->rss_key;

	while (key_regs--) {
		ret = axgbe_write_rss_reg(pdata, AXGBE_RSS_HASH_KEY_TYPE,
					  key_regs, *key++);
		if (ret)
			return ret;
	}

	return 0;
}

int axgbe_write_rss_lookup_table(struct axgbe_port *pdata)
{
	unsigned int i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(pdata->rss_table); i++) {
		ret = axgbe_write_rss_reg(pdata,
					  AXGBE_RSS_LOOKUP_TABLE_TYPE, i,
					  pdata->rss_table[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int axgbe_enable_rss(struct axgbe_port *pdata)
{
	int ret;

	/* Program the hash key */
	ret = axgbe_write_rss_hash_key(pdata);
	if (ret)
		return ret;

	/* Program the lookup table */
	ret = axgbe_write_rss_lookup_table(pdata);
	if (ret)
		return ret;

	/* Set the RSS options */
	AXGMAC_IOWRITE(pdata, MAC_RSSCR, pdata->rss_options);

	/* Enable RSS */
	AXGMAC_IOWRITE_BITS(pdata, MAC_RSSCR, RSSE, 1);

	return 0;
}

static void axgbe_rss_options(struct axgbe_port *pdata)
{
	struct rte_eth_rss_conf *rss_conf;
	uint64_t rss_hf;

	rss_conf = &pdata->eth_dev->data->dev_conf.rx_adv_conf.rss_conf;
	pdata->rss_hf = rss_conf->rss_hf;
	rss_hf = rss_conf->rss_hf;

	if (rss_hf & (RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_IPV6))
		AXGMAC_SET_BITS(pdata->rss_options, MAC_RSSCR, IP2TE, 1);
	if (rss_hf & (RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV6_TCP))
		AXGMAC_SET_BITS(pdata->rss_options, MAC_RSSCR, TCP4TE, 1);
	if (rss_hf & (RTE_ETH_RSS_NONFRAG_IPV4_UDP | RTE_ETH_RSS_NONFRAG_IPV6_UDP))
		AXGMAC_SET_BITS(pdata->rss_options, MAC_RSSCR, UDP4TE, 1);
}

static int axgbe_config_rss(struct axgbe_port *pdata)
{
	uint32_t i;

	if (pdata->rss_enable) {
		/* Initialize RSS hash key and lookup table */
		uint32_t *key = (uint32_t *)pdata->rss_key;

		for (i = 0; i < sizeof(pdata->rss_key) / 4; i++)
			*key++ = (uint32_t)rte_rand();
		for (i = 0; i < AXGBE_RSS_MAX_TABLE_SIZE; i++)
			AXGMAC_SET_BITS(pdata->rss_table[i], MAC_RSSDR, DMCH,
					i % pdata->eth_dev->data->nb_rx_queues);
		axgbe_rss_options(pdata);
		if (axgbe_enable_rss(pdata)) {
			PMD_DRV_LOG(ERR, "Error in enabling RSS support\n");
			return -1;
		}
	} else {
		AXGMAC_IOWRITE_BITS(pdata, MAC_RSSCR, RSSE, 0);
	}

	return 0;
}

static void axgbe_enable_dma_interrupts(struct axgbe_port *pdata)
{
	struct axgbe_tx_queue *txq;
	unsigned int dma_ch_isr, dma_ch_ier;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_tx_queues; i++) {
		txq = pdata->eth_dev->data->tx_queues[i];

		/* Clear all the interrupts which are set */
		dma_ch_isr = AXGMAC_DMA_IOREAD(txq, DMA_CH_SR);
		AXGMAC_DMA_IOWRITE(txq, DMA_CH_SR, dma_ch_isr);

		/* Clear all interrupt enable bits */
		dma_ch_ier = 0;

		/* Enable following interrupts
		 *   NIE  - Normal Interrupt Summary Enable
		 *   AIE  - Abnormal Interrupt Summary Enable
		 *   FBEE - Fatal Bus Error Enable
		 */
		AXGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, NIE, 0);
		AXGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, AIE, 1);
		AXGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, FBEE, 1);

		/* Enable following Rx interrupts
		 *   RBUE - Receive Buffer Unavailable Enable
		 *   RIE  - Receive Interrupt Enable (unless using
		 *          per channel interrupts in edge triggered
		 *          mode)
		 */
		AXGMAC_SET_BITS(dma_ch_ier, DMA_CH_IER, RBUE, 0);

		AXGMAC_DMA_IOWRITE(txq, DMA_CH_IER, dma_ch_ier);
	}
}

static void wrapper_tx_desc_init(struct axgbe_port *pdata)
{
	struct axgbe_tx_queue *txq;
	unsigned int i;

	for (i = 0; i < pdata->eth_dev->data->nb_tx_queues; i++) {
		txq = pdata->eth_dev->data->tx_queues[i];
		txq->cur = 0;
		txq->dirty = 0;
		/* Update the total number of Tx descriptors */
		AXGMAC_DMA_IOWRITE(txq, DMA_CH_TDRLR, txq->nb_desc - 1);
		/* Update the starting address of descriptor ring */
		AXGMAC_DMA_IOWRITE(txq, DMA_CH_TDLR_HI,
					high32_value(txq->ring_phys_addr));
		AXGMAC_DMA_IOWRITE(txq, DMA_CH_TDLR_LO,
					low32_value(txq->ring_phys_addr));
	}
}

static int wrapper_rx_desc_init(struct axgbe_port *pdata)
{
	struct axgbe_rx_queue *rxq;
	struct rte_mbuf *mbuf;
	volatile union axgbe_rx_desc *desc;
	unsigned int i, j;

	for (i = 0; i < pdata->eth_dev->data->nb_rx_queues; i++) {
		rxq = pdata->eth_dev->data->rx_queues[i];

		/* Initialize software ring entries */
		rxq->mbuf_alloc = 0;
		rxq->cur = 0;
		rxq->dirty = 0;
		desc = AXGBE_GET_DESC_PT(rxq, 0);

		for (j = 0; j < rxq->nb_desc; j++) {
			mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
			if (mbuf == NULL) {
				PMD_DRV_LOG(ERR, "RX mbuf alloc failed queue_id = %u, idx = %d\n",
					    (unsigned int)rxq->queue_id, j);
				axgbe_dev_rx_queue_release(pdata->eth_dev, i);
				return -ENOMEM;
			}
			rxq->sw_ring[j] = mbuf;
			/* Mbuf populate */
			mbuf->next = NULL;
			mbuf->data_off = RTE_PKTMBUF_HEADROOM;
			mbuf->nb_segs = 1;
			mbuf->port = rxq->port_id;
			desc->read.baddr =
				rte_cpu_to_le_64(
					rte_mbuf_data_iova_default(mbuf));
			rte_wmb();
			AXGMAC_SET_BITS_LE(desc->read.desc3,
						RX_NORMAL_DESC3, OWN, 1);
			rte_wmb();
			rxq->mbuf_alloc++;
			desc++;
		}
		/* Update the total number of Rx descriptors */
		AXGMAC_DMA_IOWRITE(rxq, DMA_CH_RDRLR,
					rxq->nb_desc - 1);
		/* Update the starting address of descriptor ring */
		AXGMAC_DMA_IOWRITE(rxq, DMA_CH_RDLR_HI,
					high32_value(rxq->ring_phys_addr));
		AXGMAC_DMA_IOWRITE(rxq, DMA_CH_RDLR_LO,
					low32_value(rxq->ring_phys_addr));
		/* Update the Rx Descriptor Tail Pointer */
		AXGMAC_DMA_IOWRITE(rxq, DMA_CH_RDTR_LO,
				   low32_value(rxq->ring_phys_addr +
				   (rxq->nb_desc - 1) *
				   sizeof(union axgbe_rx_desc)));
	}
	return 0;
}

static void axgbe_config_mtl_mode(struct axgbe_port *pdata)
{
	unsigned int i;

	/* Set Tx to weighted round robin scheduling algorithm */
	AXGMAC_IOWRITE_BITS(pdata, MTL_OMR, ETSALG, MTL_ETSALG_WRR);

	/* Set Tx traffic classes to use WRR algorithm with equal weights */
	for (i = 0; i < pdata->hw_feat.tc_cnt; i++) {
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_TC_ETSCR, TSA,
				MTL_TSA_ETS);
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_TC_QWR, QW, 1);
	}

	/* Set Rx to strict priority algorithm */
	AXGMAC_IOWRITE_BITS(pdata, MTL_OMR, RAA, MTL_RAA_SP);
}

static int axgbe_config_tsf_mode(struct axgbe_port *pdata, unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->tx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TSF, val);

	return 0;
}

static int axgbe_config_rsf_mode(struct axgbe_port *pdata, unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->rx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RSF, val);

	return 0;
}

static int axgbe_config_tx_threshold(struct axgbe_port *pdata,
				     unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->tx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TTC, val);

	return 0;
}

static int axgbe_config_rx_threshold(struct axgbe_port *pdata,
				     unsigned int val)
{
	unsigned int i;

	for (i = 0; i < pdata->rx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RTC, val);

	return 0;
}

/* Distributing FIFO size */
static void axgbe_config_rx_fifo_size(struct axgbe_port *pdata)
{
	unsigned int fifo_size;
	unsigned int q_fifo_size;
	unsigned int p_fifo, i;

	fifo_size = RTE_MIN(pdata->rx_max_fifo_size,
			  pdata->hw_feat.rx_fifo_size);
	q_fifo_size = fifo_size / pdata->rx_q_count;

	/* Calculate the fifo setting by dividing the queue's fifo size
	 * by the fifo allocation increment (with 0 representing the
	 * base allocation increment so decrement the result
	 * by 1).
	 */
	p_fifo = q_fifo_size / AXGMAC_FIFO_UNIT;
	if (p_fifo)
		p_fifo--;

	for (i = 0; i < pdata->rx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_RQOMR, RQS, p_fifo);
	pdata->fifo = p_fifo;

	/*Calculate and config Flow control threshold*/
	axgbe_calculate_flow_control_threshold(pdata);
	axgbe_config_flow_control_threshold(pdata);

	PMD_DRV_LOG(DEBUG, "%d Rx hardware queues, %d byte fifo per queue\n",
		    pdata->rx_q_count, q_fifo_size);
}

static void axgbe_config_tx_fifo_size(struct axgbe_port *pdata)
{
	unsigned int fifo_size;
	unsigned int q_fifo_size;
	unsigned int p_fifo, i;

	fifo_size = RTE_MIN(pdata->tx_max_fifo_size,
				pdata->hw_feat.tx_fifo_size);
	q_fifo_size = fifo_size / pdata->tx_q_count;

	/* Calculate the fifo setting by dividing the queue's fifo size
	 * by the fifo allocation increment (with 0 representing the
	 * base allocation increment so decrement the result
	 * by 1).
	 */
	p_fifo = q_fifo_size / AXGMAC_FIFO_UNIT;
	if (p_fifo)
		p_fifo--;

	for (i = 0; i < pdata->tx_q_count; i++)
		AXGMAC_MTL_IOWRITE_BITS(pdata, i, MTL_Q_TQOMR, TQS, p_fifo);

	PMD_DRV_LOG(DEBUG, "%d Tx hardware queues, %d byte fifo per queue\n",
		    pdata->tx_q_count, q_fifo_size);
}

static void axgbe_config_queue_mapping(struct axgbe_port *pdata)
{
	unsigned int qptc, qptc_extra, queue;
	unsigned int i, j, reg, reg_val;

	/* Map the MTL Tx Queues to Traffic Classes
	 *   Note: Tx Queues >= Traffic Classes
	 */
	qptc = pdata->tx_q_count / pdata->hw_feat.tc_cnt;
	qptc_extra = pdata->tx_q_count % pdata->hw_feat.tc_cnt;

	for (i = 0, queue = 0; i < pdata->hw_feat.tc_cnt; i++) {
		for (j = 0; j < qptc; j++) {
			PMD_DRV_LOG(DEBUG, "TXq%u mapped to TC%u\n", queue, i);
			AXGMAC_MTL_IOWRITE_BITS(pdata, queue, MTL_Q_TQOMR,
						Q2TCMAP, i);
		}
		if (i < qptc_extra) {
			PMD_DRV_LOG(DEBUG, "TXq%u mapped to TC%u\n", queue, i);
			AXGMAC_MTL_IOWRITE_BITS(pdata, queue, MTL_Q_TQOMR,
						Q2TCMAP, i);
		}
	}

	if (pdata->rss_enable) {
		/* Select dynamic mapping of MTL Rx queue to DMA Rx channel */
		reg = MTL_RQDCM0R;
		reg_val = 0;
		for (i = 0; i < pdata->rx_q_count;) {
			reg_val |= (0x80 << ((i++ % MTL_RQDCM_Q_PER_REG) << 3));

			if ((i % MTL_RQDCM_Q_PER_REG) &&
			    (i != pdata->rx_q_count))
				continue;

			AXGMAC_IOWRITE(pdata, reg, reg_val);

			reg += MTL_RQDCM_INC;
			reg_val = 0;
		}
	}
}

static void axgbe_enable_mtl_interrupts(struct axgbe_port *pdata)
{
	unsigned int mtl_q_isr;
	unsigned int q_count, i;

	q_count = RTE_MAX(pdata->hw_feat.tx_q_cnt, pdata->hw_feat.rx_q_cnt);
	for (i = 0; i < q_count; i++) {
		/* Clear all the interrupts which are set */
		mtl_q_isr = AXGMAC_MTL_IOREAD(pdata, i, MTL_Q_ISR);
		AXGMAC_MTL_IOWRITE(pdata, i, MTL_Q_ISR, mtl_q_isr);

		/* No MTL interrupts to be enabled */
		AXGMAC_MTL_IOWRITE(pdata, i, MTL_Q_IER, 0);
	}
}

static uint32_t crc32_le(uint32_t crc, uint8_t *p, uint32_t len)
{
	int i;
	while (len--) {
		crc ^= *p++;
		for (i = 0; i < 8; i++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
	}
	return crc;
}

void axgbe_set_mac_hash_table(struct axgbe_port *pdata, u8 *addr, bool add)
{
	uint32_t crc, htable_index, htable_bitmask;

	crc = bitrev32(~crc32_le(~0, addr, RTE_ETHER_ADDR_LEN));
	crc >>= pdata->hash_table_shift;
	htable_index = crc >> 5;
	htable_bitmask = 1 << (crc & 0x1f);

	if (add) {
		pdata->uc_hash_table[htable_index] |= htable_bitmask;
		pdata->uc_hash_mac_addr++;
	} else {
		pdata->uc_hash_table[htable_index] &= ~htable_bitmask;
		pdata->uc_hash_mac_addr--;
	}
	PMD_DRV_LOG(DEBUG, "%s MAC hash table Bit %d at Index %#x\n",
		    add ? "set" : "clear", (crc & 0x1f), htable_index);

	AXGMAC_IOWRITE(pdata, MAC_HTR(htable_index),
		       pdata->uc_hash_table[htable_index]);
}

void axgbe_set_mac_addn_addr(struct axgbe_port *pdata, u8 *addr, uint32_t index)
{
	unsigned int mac_addr_hi, mac_addr_lo;
	u8 *mac_addr;

	mac_addr_lo = 0;
	mac_addr_hi = 0;

	if (addr) {
		mac_addr = (u8 *)&mac_addr_lo;
		mac_addr[0] = addr[0];
		mac_addr[1] = addr[1];
		mac_addr[2] = addr[2];
		mac_addr[3] = addr[3];
		mac_addr = (u8 *)&mac_addr_hi;
		mac_addr[0] = addr[4];
		mac_addr[1] = addr[5];

		/*Address Enable: Use this Addr for Perfect Filtering */
		AXGMAC_SET_BITS(mac_addr_hi, MAC_MACA1HR, AE, 1);
	}

	PMD_DRV_LOG(DEBUG, "%s mac address at %#x\n",
		    addr ? "set" : "clear", index);

	AXGMAC_IOWRITE(pdata, MAC_MACAHR(index), mac_addr_hi);
	AXGMAC_IOWRITE(pdata, MAC_MACALR(index), mac_addr_lo);
}

static int axgbe_set_mac_address(struct axgbe_port *pdata, u8 *addr)
{
	unsigned int mac_addr_hi, mac_addr_lo;

	mac_addr_hi = (addr[5] <<  8) | (addr[4] <<  0);
	mac_addr_lo = (addr[3] << 24) | (addr[2] << 16) |
		(addr[1] <<  8) | (addr[0] <<  0);

	AXGMAC_IOWRITE(pdata, MAC_MACA0HR, mac_addr_hi);
	AXGMAC_IOWRITE(pdata, MAC_MACA0LR, mac_addr_lo);

	return 0;
}

static void axgbe_config_mac_hash_table(struct axgbe_port *pdata)
{
	struct axgbe_hw_features *hw_feat = &pdata->hw_feat;

	pdata->hash_table_shift = 0;
	pdata->hash_table_count = 0;
	pdata->uc_hash_mac_addr = 0;
	memset(pdata->uc_hash_table, 0, sizeof(pdata->uc_hash_table));

	if (hw_feat->hash_table_size) {
		pdata->hash_table_shift = 26 - (hw_feat->hash_table_size >> 7);
		pdata->hash_table_count = hw_feat->hash_table_size / 32;
	}
}

static void axgbe_config_mac_address(struct axgbe_port *pdata)
{
	axgbe_set_mac_address(pdata, pdata->mac_addr.addr_bytes);
}

static void axgbe_config_jumbo_enable(struct axgbe_port *pdata)
{
	unsigned int val;

	val = (pdata->rx_buf_size > AXGMAC_STD_PACKET_MTU) ? 1 : 0;

	AXGMAC_IOWRITE_BITS(pdata, MAC_RCR, JE, val);
}

static void axgbe_config_mac_speed(struct axgbe_port *pdata)
{
	axgbe_set_speed(pdata, pdata->phy_speed);
}

static void axgbe_config_checksum_offload(struct axgbe_port *pdata)
{
	if (pdata->rx_csum_enable)
		AXGMAC_IOWRITE_BITS(pdata, MAC_RCR, IPC, 1);
	else
		AXGMAC_IOWRITE_BITS(pdata, MAC_RCR, IPC, 0);
}

static void axgbe_config_mmc(struct axgbe_port *pdata)
{
	struct axgbe_mmc_stats *stats = &pdata->mmc_stats;

	/* Reset stats */
	memset(stats, 0, sizeof(*stats));

	/* Set counters to reset on read */
	AXGMAC_IOWRITE_BITS(pdata, MMC_CR, ROR, 1);

	/* Reset the counters */
	AXGMAC_IOWRITE_BITS(pdata, MMC_CR, CR, 1);
}

static int axgbe_init(struct axgbe_port *pdata)
{
	int ret;

	/* Flush Tx queues */
	ret = axgbe_flush_tx_queues(pdata);
	if (ret)
		return ret;
	/* Initialize DMA related features */
	axgbe_config_dma_bus(pdata);
	axgbe_config_dma_cache(pdata);
	axgbe_config_edma_control(pdata);
	axgbe_config_osp_mode(pdata);
	axgbe_config_pblx8(pdata);
	axgbe_config_tx_pbl_val(pdata);
	axgbe_config_rx_pbl_val(pdata);
	axgbe_config_rx_buffer_size(pdata);
	axgbe_config_rss(pdata);
	wrapper_tx_desc_init(pdata);
	ret = wrapper_rx_desc_init(pdata);
	if (ret)
		return ret;
	axgbe_enable_dma_interrupts(pdata);

	/* Initialize MTL related features */
	axgbe_config_mtl_mode(pdata);
	axgbe_config_queue_mapping(pdata);
	axgbe_config_tsf_mode(pdata, pdata->tx_sf_mode);
	axgbe_config_rsf_mode(pdata, pdata->rx_sf_mode);
	axgbe_config_tx_threshold(pdata, pdata->tx_threshold);
	axgbe_config_rx_threshold(pdata, pdata->rx_threshold);
	axgbe_config_tx_fifo_size(pdata);
	axgbe_config_rx_fifo_size(pdata);

	axgbe_enable_mtl_interrupts(pdata);

	/* Initialize MAC related features */
	axgbe_config_mac_hash_table(pdata);
	axgbe_config_mac_address(pdata);
	axgbe_config_jumbo_enable(pdata);
	axgbe_config_flow_control(pdata);
	axgbe_config_mac_speed(pdata);
	axgbe_config_checksum_offload(pdata);
	axgbe_config_mmc(pdata);

	return 0;
}

void axgbe_init_function_ptrs_dev(struct axgbe_hw_if *hw_if)
{
	hw_if->exit = axgbe_exit;
	hw_if->config_flow_control = axgbe_config_flow_control;

	hw_if->init = axgbe_init;

	hw_if->read_mmd_regs = axgbe_read_mmd_regs;
	hw_if->write_mmd_regs = axgbe_write_mmd_regs;

	hw_if->set_speed = axgbe_set_speed;

	hw_if->set_ext_mii_mode = axgbe_set_ext_mii_mode;
	hw_if->read_ext_mii_regs = axgbe_read_ext_mii_regs;
	hw_if->write_ext_mii_regs = axgbe_write_ext_mii_regs;
	/* For FLOW ctrl */
	hw_if->config_tx_flow_control = axgbe_config_tx_flow_control;
	hw_if->config_rx_flow_control = axgbe_config_rx_flow_control;

	/*vlan*/
	hw_if->enable_rx_vlan_stripping = axgbe_enable_rx_vlan_stripping;
	hw_if->disable_rx_vlan_stripping = axgbe_disable_rx_vlan_stripping;
	hw_if->enable_rx_vlan_filtering = axgbe_enable_rx_vlan_filtering;
	hw_if->disable_rx_vlan_filtering = axgbe_disable_rx_vlan_filtering;
	hw_if->update_vlan_hash_table = axgbe_update_vlan_hash_table;
}
