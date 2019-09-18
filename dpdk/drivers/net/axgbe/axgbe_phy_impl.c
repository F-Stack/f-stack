/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright(c) 2018 Advanced Micro Devices, Inc. All rights reserved.
 *   Copyright(c) 2018 Synopsys, Inc. All rights reserved.
 */

#include "axgbe_ethdev.h"
#include "axgbe_common.h"
#include "axgbe_phy.h"

#define AXGBE_PHY_PORT_SPEED_100	BIT(0)
#define AXGBE_PHY_PORT_SPEED_1000	BIT(1)
#define AXGBE_PHY_PORT_SPEED_2500	BIT(2)
#define AXGBE_PHY_PORT_SPEED_10000	BIT(3)

#define AXGBE_MUTEX_RELEASE		0x80000000

#define AXGBE_SFP_DIRECT		7

/* I2C target addresses */
#define AXGBE_SFP_SERIAL_ID_ADDRESS	0x50
#define AXGBE_SFP_DIAG_INFO_ADDRESS	0x51
#define AXGBE_SFP_PHY_ADDRESS		0x56
#define AXGBE_GPIO_ADDRESS_PCA9555	0x20

/* SFP sideband signal indicators */
#define AXGBE_GPIO_NO_TX_FAULT		BIT(0)
#define AXGBE_GPIO_NO_RATE_SELECT	BIT(1)
#define AXGBE_GPIO_NO_MOD_ABSENT	BIT(2)
#define AXGBE_GPIO_NO_RX_LOS		BIT(3)

/* Rate-change complete wait/retry count */
#define AXGBE_RATECHANGE_COUNT		500

/* CDR delay values for KR support (in usec) */
#define AXGBE_CDR_DELAY_INIT		10000
#define AXGBE_CDR_DELAY_INC		10000
#define AXGBE_CDR_DELAY_MAX		100000

enum axgbe_port_mode {
	AXGBE_PORT_MODE_RSVD = 0,
	AXGBE_PORT_MODE_BACKPLANE,
	AXGBE_PORT_MODE_BACKPLANE_2500,
	AXGBE_PORT_MODE_1000BASE_T,
	AXGBE_PORT_MODE_1000BASE_X,
	AXGBE_PORT_MODE_NBASE_T,
	AXGBE_PORT_MODE_10GBASE_T,
	AXGBE_PORT_MODE_10GBASE_R,
	AXGBE_PORT_MODE_SFP,
	AXGBE_PORT_MODE_MAX,
};

enum axgbe_conn_type {
	AXGBE_CONN_TYPE_NONE = 0,
	AXGBE_CONN_TYPE_SFP,
	AXGBE_CONN_TYPE_MDIO,
	AXGBE_CONN_TYPE_RSVD1,
	AXGBE_CONN_TYPE_BACKPLANE,
	AXGBE_CONN_TYPE_MAX,
};

/* SFP/SFP+ related definitions */
enum axgbe_sfp_comm {
	AXGBE_SFP_COMM_DIRECT = 0,
	AXGBE_SFP_COMM_PCA9545,
};

enum axgbe_sfp_cable {
	AXGBE_SFP_CABLE_UNKNOWN = 0,
	AXGBE_SFP_CABLE_ACTIVE,
	AXGBE_SFP_CABLE_PASSIVE,
};

enum axgbe_sfp_base {
	AXGBE_SFP_BASE_UNKNOWN = 0,
	AXGBE_SFP_BASE_1000_T,
	AXGBE_SFP_BASE_1000_SX,
	AXGBE_SFP_BASE_1000_LX,
	AXGBE_SFP_BASE_1000_CX,
	AXGBE_SFP_BASE_10000_SR,
	AXGBE_SFP_BASE_10000_LR,
	AXGBE_SFP_BASE_10000_LRM,
	AXGBE_SFP_BASE_10000_ER,
	AXGBE_SFP_BASE_10000_CR,
};

enum axgbe_sfp_speed {
	AXGBE_SFP_SPEED_UNKNOWN = 0,
	AXGBE_SFP_SPEED_100_1000,
	AXGBE_SFP_SPEED_1000,
	AXGBE_SFP_SPEED_10000,
};

/* SFP Serial ID Base ID values relative to an offset of 0 */
#define AXGBE_SFP_BASE_ID			0
#define AXGBE_SFP_ID_SFP			0x03

#define AXGBE_SFP_BASE_EXT_ID			1
#define AXGBE_SFP_EXT_ID_SFP			0x04

#define AXGBE_SFP_BASE_10GBE_CC			3
#define AXGBE_SFP_BASE_10GBE_CC_SR		BIT(4)
#define AXGBE_SFP_BASE_10GBE_CC_LR		BIT(5)
#define AXGBE_SFP_BASE_10GBE_CC_LRM		BIT(6)
#define AXGBE_SFP_BASE_10GBE_CC_ER		BIT(7)

#define AXGBE_SFP_BASE_1GBE_CC			6
#define AXGBE_SFP_BASE_1GBE_CC_SX		BIT(0)
#define AXGBE_SFP_BASE_1GBE_CC_LX		BIT(1)
#define AXGBE_SFP_BASE_1GBE_CC_CX		BIT(2)
#define AXGBE_SFP_BASE_1GBE_CC_T		BIT(3)

#define AXGBE_SFP_BASE_CABLE			8
#define AXGBE_SFP_BASE_CABLE_PASSIVE		BIT(2)
#define AXGBE_SFP_BASE_CABLE_ACTIVE		BIT(3)

#define AXGBE_SFP_BASE_BR			12
#define AXGBE_SFP_BASE_BR_1GBE_MIN		0x0a
#define AXGBE_SFP_BASE_BR_1GBE_MAX		0x0d
#define AXGBE_SFP_BASE_BR_10GBE_MIN		0x64
#define AXGBE_SFP_BASE_BR_10GBE_MAX		0x68

#define AXGBE_SFP_BASE_CU_CABLE_LEN		18

#define AXGBE_SFP_BASE_VENDOR_NAME		20
#define AXGBE_SFP_BASE_VENDOR_NAME_LEN		16
#define AXGBE_SFP_BASE_VENDOR_PN		40
#define AXGBE_SFP_BASE_VENDOR_PN_LEN		16
#define AXGBE_SFP_BASE_VENDOR_REV		56
#define AXGBE_SFP_BASE_VENDOR_REV_LEN		4

#define AXGBE_SFP_BASE_CC			63

/* SFP Serial ID Extended ID values relative to an offset of 64 */
#define AXGBE_SFP_BASE_VENDOR_SN		4
#define AXGBE_SFP_BASE_VENDOR_SN_LEN		16

#define AXGBE_SFP_EXTD_DIAG			28
#define AXGBE_SFP_EXTD_DIAG_ADDR_CHANGE		BIT(2)

#define AXGBE_SFP_EXTD_SFF_8472			30

#define AXGBE_SFP_EXTD_CC			31

struct axgbe_sfp_eeprom {
	u8 base[64];
	u8 extd[32];
	u8 vendor[32];
};

#define AXGBE_BEL_FUSE_VENDOR	"BEL-FUSE"
#define AXGBE_BEL_FUSE_PARTNO	"1GBT-SFP06"

struct axgbe_sfp_ascii {
	union {
		char vendor[AXGBE_SFP_BASE_VENDOR_NAME_LEN + 1];
		char partno[AXGBE_SFP_BASE_VENDOR_PN_LEN + 1];
		char rev[AXGBE_SFP_BASE_VENDOR_REV_LEN + 1];
		char serno[AXGBE_SFP_BASE_VENDOR_SN_LEN + 1];
	} u;
};

/* MDIO PHY reset types */
enum axgbe_mdio_reset {
	AXGBE_MDIO_RESET_NONE = 0,
	AXGBE_MDIO_RESET_I2C_GPIO,
	AXGBE_MDIO_RESET_INT_GPIO,
	AXGBE_MDIO_RESET_MAX,
};

/* Re-driver related definitions */
enum axgbe_phy_redrv_if {
	AXGBE_PHY_REDRV_IF_MDIO = 0,
	AXGBE_PHY_REDRV_IF_I2C,
	AXGBE_PHY_REDRV_IF_MAX,
};

enum axgbe_phy_redrv_model {
	AXGBE_PHY_REDRV_MODEL_4223 = 0,
	AXGBE_PHY_REDRV_MODEL_4227,
	AXGBE_PHY_REDRV_MODEL_MAX,
};

enum axgbe_phy_redrv_mode {
	AXGBE_PHY_REDRV_MODE_CX = 5,
	AXGBE_PHY_REDRV_MODE_SR = 9,
};

#define AXGBE_PHY_REDRV_MODE_REG	0x12b0

/* PHY related configuration information */
struct axgbe_phy_data {
	enum axgbe_port_mode port_mode;

	unsigned int port_id;

	unsigned int port_speeds;

	enum axgbe_conn_type conn_type;

	enum axgbe_mode cur_mode;
	enum axgbe_mode start_mode;

	unsigned int rrc_count;

	unsigned int mdio_addr;

	unsigned int comm_owned;

	/* SFP Support */
	enum axgbe_sfp_comm sfp_comm;
	unsigned int sfp_mux_address;
	unsigned int sfp_mux_channel;

	unsigned int sfp_gpio_address;
	unsigned int sfp_gpio_mask;
	unsigned int sfp_gpio_rx_los;
	unsigned int sfp_gpio_tx_fault;
	unsigned int sfp_gpio_mod_absent;
	unsigned int sfp_gpio_rate_select;

	unsigned int sfp_rx_los;
	unsigned int sfp_tx_fault;
	unsigned int sfp_mod_absent;
	unsigned int sfp_diags;
	unsigned int sfp_changed;
	unsigned int sfp_phy_avail;
	unsigned int sfp_cable_len;
	enum axgbe_sfp_base sfp_base;
	enum axgbe_sfp_cable sfp_cable;
	enum axgbe_sfp_speed sfp_speed;
	struct axgbe_sfp_eeprom sfp_eeprom;

	/* External PHY support */
	enum axgbe_mdio_mode phydev_mode;
	enum axgbe_mdio_reset mdio_reset;
	unsigned int mdio_reset_addr;
	unsigned int mdio_reset_gpio;

	/* Re-driver support */
	unsigned int redrv;
	unsigned int redrv_if;
	unsigned int redrv_addr;
	unsigned int redrv_lane;
	unsigned int redrv_model;

	/* KR AN support */
	unsigned int phy_cdr_notrack;
	unsigned int phy_cdr_delay;
};

static enum axgbe_an_mode axgbe_phy_an_mode(struct axgbe_port *pdata);

static int axgbe_phy_i2c_xfer(struct axgbe_port *pdata,
			      struct axgbe_i2c_op *i2c_op)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	/* Be sure we own the bus */
	if (!phy_data->comm_owned)
		return -EIO;

	return pdata->i2c_if.i2c_xfer(pdata, i2c_op);
}

static int axgbe_phy_redrv_write(struct axgbe_port *pdata, unsigned int reg,
				 unsigned int val)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_i2c_op i2c_op;
	uint16_t *redrv_val;
	u8 redrv_data[5], csum;
	unsigned int i, retry;
	int ret;

	/* High byte of register contains read/write indicator */
	redrv_data[0] = ((reg >> 8) & 0xff) << 1;
	redrv_data[1] = reg & 0xff;
	redrv_val = (uint16_t *)&redrv_data[2];
	*redrv_val = rte_cpu_to_be_16(val);

	/* Calculate 1 byte checksum */
	csum = 0;
	for (i = 0; i < 4; i++) {
		csum += redrv_data[i];
		if (redrv_data[i] > csum)
			csum++;
	}
	redrv_data[4] = ~csum;

	retry = 1;
again1:
	i2c_op.cmd = AXGBE_I2C_CMD_WRITE;
	i2c_op.target = phy_data->redrv_addr;
	i2c_op.len = sizeof(redrv_data);
	i2c_op.buf = redrv_data;
	ret = axgbe_phy_i2c_xfer(pdata, &i2c_op);
	if (ret) {
		if ((ret == -EAGAIN) && retry--)
			goto again1;

		return ret;
	}

	retry = 1;
again2:
	i2c_op.cmd = AXGBE_I2C_CMD_READ;
	i2c_op.target = phy_data->redrv_addr;
	i2c_op.len = 1;
	i2c_op.buf = redrv_data;
	ret = axgbe_phy_i2c_xfer(pdata, &i2c_op);
	if (ret) {
		if ((ret == -EAGAIN) && retry--)
			goto again2;

		return ret;
	}

	if (redrv_data[0] != 0xff) {
		PMD_DRV_LOG(ERR, "Redriver write checksum error\n");
		ret = -EIO;
	}

	return ret;
}

static int axgbe_phy_i2c_read(struct axgbe_port *pdata, unsigned int target,
			      void *reg, unsigned int reg_len,
			      void *val, unsigned int val_len)
{
	struct axgbe_i2c_op i2c_op;
	int retry, ret;

	retry = 1;
again1:
	/* Set the specified register to read */
	i2c_op.cmd = AXGBE_I2C_CMD_WRITE;
	i2c_op.target = target;
	i2c_op.len = reg_len;
	i2c_op.buf = reg;
	ret = axgbe_phy_i2c_xfer(pdata, &i2c_op);
	if (ret) {
		if ((ret == -EAGAIN) && retry--)
			goto again1;

		return ret;
	}

	retry = 1;
again2:
	/* Read the specfied register */
	i2c_op.cmd = AXGBE_I2C_CMD_READ;
	i2c_op.target = target;
	i2c_op.len = val_len;
	i2c_op.buf = val;
	ret = axgbe_phy_i2c_xfer(pdata, &i2c_op);
	if ((ret == -EAGAIN) && retry--)
		goto again2;

	return ret;
}

static int axgbe_phy_sfp_put_mux(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_i2c_op i2c_op;
	uint8_t mux_channel;

	if (phy_data->sfp_comm == AXGBE_SFP_COMM_DIRECT)
		return 0;

	/* Select no mux channels */
	mux_channel = 0;
	i2c_op.cmd = AXGBE_I2C_CMD_WRITE;
	i2c_op.target = phy_data->sfp_mux_address;
	i2c_op.len = sizeof(mux_channel);
	i2c_op.buf = &mux_channel;

	return axgbe_phy_i2c_xfer(pdata, &i2c_op);
}

static int axgbe_phy_sfp_get_mux(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_i2c_op i2c_op;
	u8 mux_channel;

	if (phy_data->sfp_comm == AXGBE_SFP_COMM_DIRECT)
		return 0;

	/* Select desired mux channel */
	mux_channel = 1 << phy_data->sfp_mux_channel;
	i2c_op.cmd = AXGBE_I2C_CMD_WRITE;
	i2c_op.target = phy_data->sfp_mux_address;
	i2c_op.len = sizeof(mux_channel);
	i2c_op.buf = &mux_channel;

	return axgbe_phy_i2c_xfer(pdata, &i2c_op);
}

static void axgbe_phy_put_comm_ownership(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	phy_data->comm_owned = 0;

	pthread_mutex_unlock(&pdata->phy_mutex);
}

static int axgbe_phy_get_comm_ownership(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	uint64_t timeout;
	unsigned int mutex_id;

	if (phy_data->comm_owned)
		return 0;

	/* The I2C and MDIO/GPIO bus is multiplexed between multiple devices,
	 * the driver needs to take the software mutex and then the hardware
	 * mutexes before being able to use the busses.
	 */
	pthread_mutex_lock(&pdata->phy_mutex);

	/* Clear the mutexes */
	XP_IOWRITE(pdata, XP_I2C_MUTEX, AXGBE_MUTEX_RELEASE);
	XP_IOWRITE(pdata, XP_MDIO_MUTEX, AXGBE_MUTEX_RELEASE);

	/* Mutex formats are the same for I2C and MDIO/GPIO */
	mutex_id = 0;
	XP_SET_BITS(mutex_id, XP_I2C_MUTEX, ID, phy_data->port_id);
	XP_SET_BITS(mutex_id, XP_I2C_MUTEX, ACTIVE, 1);

	timeout = rte_get_timer_cycles() + (rte_get_timer_hz() * 5);
	while (time_before(rte_get_timer_cycles(), timeout)) {
		/* Must be all zeroes in order to obtain the mutex */
		if (XP_IOREAD(pdata, XP_I2C_MUTEX) ||
		    XP_IOREAD(pdata, XP_MDIO_MUTEX)) {
			rte_delay_us(100);
			continue;
		}

		/* Obtain the mutex */
		XP_IOWRITE(pdata, XP_I2C_MUTEX, mutex_id);
		XP_IOWRITE(pdata, XP_MDIO_MUTEX, mutex_id);

		phy_data->comm_owned = 1;
		return 0;
	}

	pthread_mutex_unlock(&pdata->phy_mutex);

	PMD_DRV_LOG(ERR, "unable to obtain hardware mutexes\n");

	return -ETIMEDOUT;
}

static void axgbe_phy_sfp_phy_settings(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	if (phy_data->sfp_mod_absent) {
		pdata->phy.speed = SPEED_UNKNOWN;
		pdata->phy.duplex = DUPLEX_UNKNOWN;
		pdata->phy.autoneg = AUTONEG_ENABLE;
		pdata->phy.advertising = pdata->phy.supported;
	}

	pdata->phy.advertising &= ~ADVERTISED_Autoneg;
	pdata->phy.advertising &= ~ADVERTISED_TP;
	pdata->phy.advertising &= ~ADVERTISED_FIBRE;
	pdata->phy.advertising &= ~ADVERTISED_100baseT_Full;
	pdata->phy.advertising &= ~ADVERTISED_1000baseT_Full;
	pdata->phy.advertising &= ~ADVERTISED_10000baseT_Full;
	pdata->phy.advertising &= ~ADVERTISED_10000baseR_FEC;

	switch (phy_data->sfp_base) {
	case AXGBE_SFP_BASE_1000_T:
	case AXGBE_SFP_BASE_1000_SX:
	case AXGBE_SFP_BASE_1000_LX:
	case AXGBE_SFP_BASE_1000_CX:
		pdata->phy.speed = SPEED_UNKNOWN;
		pdata->phy.duplex = DUPLEX_UNKNOWN;
		pdata->phy.autoneg = AUTONEG_ENABLE;
		pdata->phy.advertising |= ADVERTISED_Autoneg;
		break;
	case AXGBE_SFP_BASE_10000_SR:
	case AXGBE_SFP_BASE_10000_LR:
	case AXGBE_SFP_BASE_10000_LRM:
	case AXGBE_SFP_BASE_10000_ER:
	case AXGBE_SFP_BASE_10000_CR:
	default:
		pdata->phy.speed = SPEED_10000;
		pdata->phy.duplex = DUPLEX_FULL;
		pdata->phy.autoneg = AUTONEG_DISABLE;
		break;
	}

	switch (phy_data->sfp_base) {
	case AXGBE_SFP_BASE_1000_T:
	case AXGBE_SFP_BASE_1000_CX:
	case AXGBE_SFP_BASE_10000_CR:
		pdata->phy.advertising |= ADVERTISED_TP;
		break;
	default:
		pdata->phy.advertising |= ADVERTISED_FIBRE;
	}

	switch (phy_data->sfp_speed) {
	case AXGBE_SFP_SPEED_100_1000:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100)
			pdata->phy.advertising |= ADVERTISED_100baseT_Full;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000)
			pdata->phy.advertising |= ADVERTISED_1000baseT_Full;
		break;
	case AXGBE_SFP_SPEED_1000:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000)
			pdata->phy.advertising |= ADVERTISED_1000baseT_Full;
		break;
	case AXGBE_SFP_SPEED_10000:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000)
			pdata->phy.advertising |= ADVERTISED_10000baseT_Full;
		break;
	default:
		/* Choose the fastest supported speed */
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000)
			pdata->phy.advertising |= ADVERTISED_10000baseT_Full;
		else if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000)
			pdata->phy.advertising |= ADVERTISED_1000baseT_Full;
		else if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100)
			pdata->phy.advertising |= ADVERTISED_100baseT_Full;
	}
}

static bool axgbe_phy_sfp_bit_rate(struct axgbe_sfp_eeprom *sfp_eeprom,
				   enum axgbe_sfp_speed sfp_speed)
{
	u8 *sfp_base, min, max;

	sfp_base = sfp_eeprom->base;

	switch (sfp_speed) {
	case AXGBE_SFP_SPEED_1000:
		min = AXGBE_SFP_BASE_BR_1GBE_MIN;
		max = AXGBE_SFP_BASE_BR_1GBE_MAX;
		break;
	case AXGBE_SFP_SPEED_10000:
		min = AXGBE_SFP_BASE_BR_10GBE_MIN;
		max = AXGBE_SFP_BASE_BR_10GBE_MAX;
		break;
	default:
		return false;
	}

	return ((sfp_base[AXGBE_SFP_BASE_BR] >= min) &&
		(sfp_base[AXGBE_SFP_BASE_BR] <= max));
}

static void axgbe_phy_sfp_external_phy(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	if (!phy_data->sfp_changed)
		return;

	phy_data->sfp_phy_avail = 0;

	if (phy_data->sfp_base != AXGBE_SFP_BASE_1000_T)
		return;
}

static bool axgbe_phy_belfuse_parse_quirks(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_sfp_eeprom *sfp_eeprom = &phy_data->sfp_eeprom;

	if (memcmp(&sfp_eeprom->base[AXGBE_SFP_BASE_VENDOR_NAME],
		   AXGBE_BEL_FUSE_VENDOR, strlen(AXGBE_BEL_FUSE_VENDOR)))
		return false;

	if (!memcmp(&sfp_eeprom->base[AXGBE_SFP_BASE_VENDOR_PN],
		    AXGBE_BEL_FUSE_PARTNO, strlen(AXGBE_BEL_FUSE_PARTNO))) {
		phy_data->sfp_base = AXGBE_SFP_BASE_1000_SX;
		phy_data->sfp_cable = AXGBE_SFP_CABLE_ACTIVE;
		phy_data->sfp_speed = AXGBE_SFP_SPEED_1000;
		return true;
	}

	return false;
}

static bool axgbe_phy_sfp_parse_quirks(struct axgbe_port *pdata)
{
	if (axgbe_phy_belfuse_parse_quirks(pdata))
		return true;

	return false;
}

static void axgbe_phy_sfp_parse_eeprom(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_sfp_eeprom *sfp_eeprom = &phy_data->sfp_eeprom;
	uint8_t *sfp_base;

	sfp_base = sfp_eeprom->base;

	if (sfp_base[AXGBE_SFP_BASE_ID] != AXGBE_SFP_ID_SFP)
		return;

	if (sfp_base[AXGBE_SFP_BASE_EXT_ID] != AXGBE_SFP_EXT_ID_SFP)
		return;

	if (axgbe_phy_sfp_parse_quirks(pdata))
		return;

	/* Assume ACTIVE cable unless told it is PASSIVE */
	if (sfp_base[AXGBE_SFP_BASE_CABLE] & AXGBE_SFP_BASE_CABLE_PASSIVE) {
		phy_data->sfp_cable = AXGBE_SFP_CABLE_PASSIVE;
		phy_data->sfp_cable_len = sfp_base[AXGBE_SFP_BASE_CU_CABLE_LEN];
	} else {
		phy_data->sfp_cable = AXGBE_SFP_CABLE_ACTIVE;
	}

	/* Determine the type of SFP */
	if (sfp_base[AXGBE_SFP_BASE_10GBE_CC] & AXGBE_SFP_BASE_10GBE_CC_SR)
		phy_data->sfp_base = AXGBE_SFP_BASE_10000_SR;
	else if (sfp_base[AXGBE_SFP_BASE_10GBE_CC] & AXGBE_SFP_BASE_10GBE_CC_LR)
		phy_data->sfp_base = AXGBE_SFP_BASE_10000_LR;
	else if (sfp_base[AXGBE_SFP_BASE_10GBE_CC] &
		 AXGBE_SFP_BASE_10GBE_CC_LRM)
		phy_data->sfp_base = AXGBE_SFP_BASE_10000_LRM;
	else if (sfp_base[AXGBE_SFP_BASE_10GBE_CC] & AXGBE_SFP_BASE_10GBE_CC_ER)
		phy_data->sfp_base = AXGBE_SFP_BASE_10000_ER;
	else if (sfp_base[AXGBE_SFP_BASE_1GBE_CC] & AXGBE_SFP_BASE_1GBE_CC_SX)
		phy_data->sfp_base = AXGBE_SFP_BASE_1000_SX;
	else if (sfp_base[AXGBE_SFP_BASE_1GBE_CC] & AXGBE_SFP_BASE_1GBE_CC_LX)
		phy_data->sfp_base = AXGBE_SFP_BASE_1000_LX;
	else if (sfp_base[AXGBE_SFP_BASE_1GBE_CC] & AXGBE_SFP_BASE_1GBE_CC_CX)
		phy_data->sfp_base = AXGBE_SFP_BASE_1000_CX;
	else if (sfp_base[AXGBE_SFP_BASE_1GBE_CC] & AXGBE_SFP_BASE_1GBE_CC_T)
		phy_data->sfp_base = AXGBE_SFP_BASE_1000_T;
	else if ((phy_data->sfp_cable == AXGBE_SFP_CABLE_PASSIVE) &&
		 axgbe_phy_sfp_bit_rate(sfp_eeprom, AXGBE_SFP_SPEED_10000))
		phy_data->sfp_base = AXGBE_SFP_BASE_10000_CR;

	switch (phy_data->sfp_base) {
	case AXGBE_SFP_BASE_1000_T:
		phy_data->sfp_speed = AXGBE_SFP_SPEED_100_1000;
		break;
	case AXGBE_SFP_BASE_1000_SX:
	case AXGBE_SFP_BASE_1000_LX:
	case AXGBE_SFP_BASE_1000_CX:
		phy_data->sfp_speed = AXGBE_SFP_SPEED_1000;
		break;
	case AXGBE_SFP_BASE_10000_SR:
	case AXGBE_SFP_BASE_10000_LR:
	case AXGBE_SFP_BASE_10000_LRM:
	case AXGBE_SFP_BASE_10000_ER:
	case AXGBE_SFP_BASE_10000_CR:
		phy_data->sfp_speed = AXGBE_SFP_SPEED_10000;
		break;
	default:
		break;
	}
}

static bool axgbe_phy_sfp_verify_eeprom(uint8_t cc_in, uint8_t *buf,
					unsigned int len)
{
	uint8_t cc;

	for (cc = 0; len; buf++, len--)
		cc += *buf;

	return (cc == cc_in) ? true : false;
}

static int axgbe_phy_sfp_read_eeprom(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	struct axgbe_sfp_eeprom sfp_eeprom;
	uint8_t eeprom_addr;
	int ret;

	ret = axgbe_phy_sfp_get_mux(pdata);
	if (ret) {
		PMD_DRV_LOG(ERR, "I2C error setting SFP MUX\n");
		return ret;
	}

	/* Read the SFP serial ID eeprom */
	eeprom_addr = 0;
	ret = axgbe_phy_i2c_read(pdata, AXGBE_SFP_SERIAL_ID_ADDRESS,
				 &eeprom_addr, sizeof(eeprom_addr),
				 &sfp_eeprom, sizeof(sfp_eeprom));
	if (ret) {
		PMD_DRV_LOG(ERR, "I2C error reading SFP EEPROM\n");
		goto put;
	}

	/* Validate the contents read */
	if (!axgbe_phy_sfp_verify_eeprom(sfp_eeprom.base[AXGBE_SFP_BASE_CC],
					 sfp_eeprom.base,
					 sizeof(sfp_eeprom.base) - 1)) {
		ret = -EINVAL;
		goto put;
	}

	if (!axgbe_phy_sfp_verify_eeprom(sfp_eeprom.extd[AXGBE_SFP_EXTD_CC],
					 sfp_eeprom.extd,
					 sizeof(sfp_eeprom.extd) - 1)) {
		ret = -EINVAL;
		goto put;
	}

	/* Check for an added or changed SFP */
	if (memcmp(&phy_data->sfp_eeprom, &sfp_eeprom, sizeof(sfp_eeprom))) {
		phy_data->sfp_changed = 1;
		memcpy(&phy_data->sfp_eeprom, &sfp_eeprom, sizeof(sfp_eeprom));

		if (sfp_eeprom.extd[AXGBE_SFP_EXTD_SFF_8472]) {
			uint8_t diag_type;
			diag_type = sfp_eeprom.extd[AXGBE_SFP_EXTD_DIAG];

			if (!(diag_type & AXGBE_SFP_EXTD_DIAG_ADDR_CHANGE))
				phy_data->sfp_diags = 1;
		}
	} else {
		phy_data->sfp_changed = 0;
	}

put:
	axgbe_phy_sfp_put_mux(pdata);

	return ret;
}

static void axgbe_phy_sfp_signals(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int gpio_input;
	u8 gpio_reg, gpio_ports[2];
	int ret;

	/* Read the input port registers */
	gpio_reg = 0;
	ret = axgbe_phy_i2c_read(pdata, phy_data->sfp_gpio_address,
				 &gpio_reg, sizeof(gpio_reg),
				 gpio_ports, sizeof(gpio_ports));
	if (ret) {
		PMD_DRV_LOG(ERR, "I2C error reading SFP GPIOs\n");
		return;
	}

	gpio_input = (gpio_ports[1] << 8) | gpio_ports[0];

	if (phy_data->sfp_gpio_mask & AXGBE_GPIO_NO_MOD_ABSENT) {
		/* No GPIO, just assume the module is present for now */
		phy_data->sfp_mod_absent = 0;
	} else {
		if (!(gpio_input & (1 << phy_data->sfp_gpio_mod_absent)))
			phy_data->sfp_mod_absent = 0;
	}

	if (!(phy_data->sfp_gpio_mask & AXGBE_GPIO_NO_RX_LOS) &&
	    (gpio_input & (1 << phy_data->sfp_gpio_rx_los)))
		phy_data->sfp_rx_los = 1;

	if (!(phy_data->sfp_gpio_mask & AXGBE_GPIO_NO_TX_FAULT) &&
	    (gpio_input & (1 << phy_data->sfp_gpio_tx_fault)))
		phy_data->sfp_tx_fault = 1;
}

static void axgbe_phy_sfp_mod_absent(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	phy_data->sfp_mod_absent = 1;
	phy_data->sfp_phy_avail = 0;
	memset(&phy_data->sfp_eeprom, 0, sizeof(phy_data->sfp_eeprom));
}

static void axgbe_phy_sfp_reset(struct axgbe_phy_data *phy_data)
{
	phy_data->sfp_rx_los = 0;
	phy_data->sfp_tx_fault = 0;
	phy_data->sfp_mod_absent = 1;
	phy_data->sfp_diags = 0;
	phy_data->sfp_base = AXGBE_SFP_BASE_UNKNOWN;
	phy_data->sfp_cable = AXGBE_SFP_CABLE_UNKNOWN;
	phy_data->sfp_speed = AXGBE_SFP_SPEED_UNKNOWN;
}

static void axgbe_phy_sfp_detect(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	int ret;

	/* Reset the SFP signals and info */
	axgbe_phy_sfp_reset(phy_data);

	ret = axgbe_phy_get_comm_ownership(pdata);
	if (ret)
		return;

	/* Read the SFP signals and check for module presence */
	axgbe_phy_sfp_signals(pdata);
	if (phy_data->sfp_mod_absent) {
		axgbe_phy_sfp_mod_absent(pdata);
		goto put;
	}

	ret = axgbe_phy_sfp_read_eeprom(pdata);
	if (ret) {
		/* Treat any error as if there isn't an SFP plugged in */
		axgbe_phy_sfp_reset(phy_data);
		axgbe_phy_sfp_mod_absent(pdata);
		goto put;
	}

	axgbe_phy_sfp_parse_eeprom(pdata);
	axgbe_phy_sfp_external_phy(pdata);

put:
	axgbe_phy_sfp_phy_settings(pdata);
	axgbe_phy_put_comm_ownership(pdata);
}

static void axgbe_phy_phydev_flowctrl(struct axgbe_port *pdata)
{
	pdata->phy.tx_pause = 0;
	pdata->phy.rx_pause = 0;
}

static enum axgbe_mode axgbe_phy_an73_redrv_outcome(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	enum axgbe_mode mode;
	unsigned int ad_reg, lp_reg;

	pdata->phy.lp_advertising |= ADVERTISED_Autoneg;
	pdata->phy.lp_advertising |= ADVERTISED_Backplane;

	/* Use external PHY to determine flow control */
	if (pdata->phy.pause_autoneg)
		axgbe_phy_phydev_flowctrl(pdata);

	/* Compare Advertisement and Link Partner register 2 */
	ad_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_ADVERTISE + 1);
	lp_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_LPA + 1);
	if (lp_reg & 0x80)
		pdata->phy.lp_advertising |= ADVERTISED_10000baseKR_Full;
	if (lp_reg & 0x20)
		pdata->phy.lp_advertising |= ADVERTISED_1000baseKX_Full;

	ad_reg &= lp_reg;
	if (ad_reg & 0x80) {
		switch (phy_data->port_mode) {
		case AXGBE_PORT_MODE_BACKPLANE:
			mode = AXGBE_MODE_KR;
			break;
		default:
			mode = AXGBE_MODE_SFI;
			break;
		}
	} else if (ad_reg & 0x20) {
		switch (phy_data->port_mode) {
		case AXGBE_PORT_MODE_BACKPLANE:
			mode = AXGBE_MODE_KX_1000;
			break;
		case AXGBE_PORT_MODE_1000BASE_X:
			mode = AXGBE_MODE_X;
			break;
		case AXGBE_PORT_MODE_SFP:
			switch (phy_data->sfp_base) {
			case AXGBE_SFP_BASE_1000_T:
				mode = AXGBE_MODE_SGMII_1000;
				break;
			case AXGBE_SFP_BASE_1000_SX:
			case AXGBE_SFP_BASE_1000_LX:
			case AXGBE_SFP_BASE_1000_CX:
			default:
				mode = AXGBE_MODE_X;
				break;
			}
			break;
		default:
			mode = AXGBE_MODE_SGMII_1000;
			break;
		}
	} else {
		mode = AXGBE_MODE_UNKNOWN;
	}

	/* Compare Advertisement and Link Partner register 3 */
	ad_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_ADVERTISE + 2);
	lp_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_LPA + 2);
	if (lp_reg & 0xc000)
		pdata->phy.lp_advertising |= ADVERTISED_10000baseR_FEC;

	return mode;
}

static enum axgbe_mode axgbe_phy_an73_outcome(struct axgbe_port *pdata)
{
	enum axgbe_mode mode;
	unsigned int ad_reg, lp_reg;

	pdata->phy.lp_advertising |= ADVERTISED_Autoneg;
	pdata->phy.lp_advertising |= ADVERTISED_Backplane;

	/* Compare Advertisement and Link Partner register 1 */
	ad_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_ADVERTISE);
	lp_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_LPA);
	if (lp_reg & 0x400)
		pdata->phy.lp_advertising |= ADVERTISED_Pause;
	if (lp_reg & 0x800)
		pdata->phy.lp_advertising |= ADVERTISED_Asym_Pause;

	if (pdata->phy.pause_autoneg) {
		/* Set flow control based on auto-negotiation result */
		pdata->phy.tx_pause = 0;
		pdata->phy.rx_pause = 0;

		if (ad_reg & lp_reg & 0x400) {
			pdata->phy.tx_pause = 1;
			pdata->phy.rx_pause = 1;
		} else if (ad_reg & lp_reg & 0x800) {
			if (ad_reg & 0x400)
				pdata->phy.rx_pause = 1;
			else if (lp_reg & 0x400)
				pdata->phy.tx_pause = 1;
		}
	}

	/* Compare Advertisement and Link Partner register 2 */
	ad_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_ADVERTISE + 1);
	lp_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_LPA + 1);
	if (lp_reg & 0x80)
		pdata->phy.lp_advertising |= ADVERTISED_10000baseKR_Full;
	if (lp_reg & 0x20)
		pdata->phy.lp_advertising |= ADVERTISED_1000baseKX_Full;

	ad_reg &= lp_reg;
	if (ad_reg & 0x80)
		mode = AXGBE_MODE_KR;
	else if (ad_reg & 0x20)
		mode = AXGBE_MODE_KX_1000;
	else
		mode = AXGBE_MODE_UNKNOWN;

	/* Compare Advertisement and Link Partner register 3 */
	ad_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_ADVERTISE + 2);
	lp_reg = XMDIO_READ(pdata, MDIO_MMD_AN, MDIO_AN_LPA + 2);
	if (lp_reg & 0xc000)
		pdata->phy.lp_advertising |= ADVERTISED_10000baseR_FEC;

	return mode;
}

static enum axgbe_mode axgbe_phy_an_outcome(struct axgbe_port *pdata)
{
	switch (pdata->an_mode) {
	case AXGBE_AN_MODE_CL73:
		return axgbe_phy_an73_outcome(pdata);
	case AXGBE_AN_MODE_CL73_REDRV:
		return axgbe_phy_an73_redrv_outcome(pdata);
	case AXGBE_AN_MODE_CL37:
	case AXGBE_AN_MODE_CL37_SGMII:
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static unsigned int axgbe_phy_an_advertising(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int advertising;

	/* Without a re-driver, just return current advertising */
	if (!phy_data->redrv)
		return pdata->phy.advertising;

	/* With the KR re-driver we need to advertise a single speed */
	advertising = pdata->phy.advertising;
	advertising &= ~ADVERTISED_1000baseKX_Full;
	advertising &= ~ADVERTISED_10000baseKR_Full;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		advertising |= ADVERTISED_10000baseKR_Full;
		break;
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		advertising |= ADVERTISED_1000baseKX_Full;
		break;
	case AXGBE_PORT_MODE_1000BASE_T:
	case AXGBE_PORT_MODE_1000BASE_X:
	case AXGBE_PORT_MODE_NBASE_T:
		advertising |= ADVERTISED_1000baseKX_Full;
		break;
	case AXGBE_PORT_MODE_10GBASE_T:
		PMD_DRV_LOG(ERR, "10GBASE_T mode is not supported\n");
		break;
	case AXGBE_PORT_MODE_10GBASE_R:
		advertising |= ADVERTISED_10000baseKR_Full;
		break;
	case AXGBE_PORT_MODE_SFP:
		switch (phy_data->sfp_base) {
		case AXGBE_SFP_BASE_1000_T:
		case AXGBE_SFP_BASE_1000_SX:
		case AXGBE_SFP_BASE_1000_LX:
		case AXGBE_SFP_BASE_1000_CX:
			advertising |= ADVERTISED_1000baseKX_Full;
			break;
		default:
			advertising |= ADVERTISED_10000baseKR_Full;
			break;
		}
		break;
	default:
		advertising |= ADVERTISED_10000baseKR_Full;
		break;
	}

	return advertising;
}

static int axgbe_phy_an_config(struct axgbe_port *pdata __rte_unused)
{
	return 0;
	/* Dummy API since there is no case to support
	 * external phy devices registred through kerenl apis
	 */
}

static enum axgbe_an_mode axgbe_phy_an_sfp_mode(struct axgbe_phy_data *phy_data)
{
	switch (phy_data->sfp_base) {
	case AXGBE_SFP_BASE_1000_T:
		return AXGBE_AN_MODE_CL37_SGMII;
	case AXGBE_SFP_BASE_1000_SX:
	case AXGBE_SFP_BASE_1000_LX:
	case AXGBE_SFP_BASE_1000_CX:
		return AXGBE_AN_MODE_CL37;
	default:
		return AXGBE_AN_MODE_NONE;
	}
}

static enum axgbe_an_mode axgbe_phy_an_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	/* A KR re-driver will always require CL73 AN */
	if (phy_data->redrv)
		return AXGBE_AN_MODE_CL73_REDRV;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		return AXGBE_AN_MODE_CL73;
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		return AXGBE_AN_MODE_NONE;
	case AXGBE_PORT_MODE_1000BASE_T:
		return AXGBE_AN_MODE_CL37_SGMII;
	case AXGBE_PORT_MODE_1000BASE_X:
		return AXGBE_AN_MODE_CL37;
	case AXGBE_PORT_MODE_NBASE_T:
		return AXGBE_AN_MODE_CL37_SGMII;
	case AXGBE_PORT_MODE_10GBASE_T:
		return AXGBE_AN_MODE_CL73;
	case AXGBE_PORT_MODE_10GBASE_R:
		return AXGBE_AN_MODE_NONE;
	case AXGBE_PORT_MODE_SFP:
		return axgbe_phy_an_sfp_mode(phy_data);
	default:
		return AXGBE_AN_MODE_NONE;
	}
}

static int axgbe_phy_set_redrv_mode_mdio(struct axgbe_port *pdata,
					 enum axgbe_phy_redrv_mode mode)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	u16 redrv_reg, redrv_val;

	redrv_reg = AXGBE_PHY_REDRV_MODE_REG + (phy_data->redrv_lane * 0x1000);
	redrv_val = (u16)mode;

	return pdata->hw_if.write_ext_mii_regs(pdata, phy_data->redrv_addr,
					       redrv_reg, redrv_val);
}

static int axgbe_phy_set_redrv_mode_i2c(struct axgbe_port *pdata,
					enum axgbe_phy_redrv_mode mode)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int redrv_reg;
	int ret;

	/* Calculate the register to write */
	redrv_reg = AXGBE_PHY_REDRV_MODE_REG + (phy_data->redrv_lane * 0x1000);

	ret = axgbe_phy_redrv_write(pdata, redrv_reg, mode);

	return ret;
}

static void axgbe_phy_set_redrv_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	enum axgbe_phy_redrv_mode mode;
	int ret;

	if (!phy_data->redrv)
		return;

	mode = AXGBE_PHY_REDRV_MODE_CX;
	if ((phy_data->port_mode == AXGBE_PORT_MODE_SFP) &&
	    (phy_data->sfp_base != AXGBE_SFP_BASE_1000_CX) &&
	    (phy_data->sfp_base != AXGBE_SFP_BASE_10000_CR))
		mode = AXGBE_PHY_REDRV_MODE_SR;

	ret = axgbe_phy_get_comm_ownership(pdata);
	if (ret)
		return;

	if (phy_data->redrv_if)
		axgbe_phy_set_redrv_mode_i2c(pdata, mode);
	else
		axgbe_phy_set_redrv_mode_mdio(pdata, mode);

	axgbe_phy_put_comm_ownership(pdata);
}

static void axgbe_phy_start_ratechange(struct axgbe_port *pdata)
{
	if (!XP_IOREAD_BITS(pdata, XP_DRIVER_INT_RO, STATUS))
		return;
}

static void axgbe_phy_complete_ratechange(struct axgbe_port *pdata)
{
	unsigned int wait;

	/* Wait for command to complete */
	wait = AXGBE_RATECHANGE_COUNT;
	while (wait--) {
		if (!XP_IOREAD_BITS(pdata, XP_DRIVER_INT_RO, STATUS))
			return;

		rte_delay_us(1500);
	}
}

static void axgbe_phy_rrc(struct axgbe_port *pdata)
{
	unsigned int s0;

	axgbe_phy_start_ratechange(pdata);

	/* Receiver Reset Cycle */
	s0 = 0;
	XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, COMMAND, 5);
	XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 0);

	/* Call FW to make the change */
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_0, s0);
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_1, 0);
	XP_IOWRITE_BITS(pdata, XP_DRIVER_INT_REQ, REQUEST, 1);

	axgbe_phy_complete_ratechange(pdata);
}

static void axgbe_phy_power_off(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	axgbe_phy_start_ratechange(pdata);

	/* Call FW to make the change */
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_0, 0);
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_1, 0);
	XP_IOWRITE_BITS(pdata, XP_DRIVER_INT_REQ, REQUEST, 1);
	axgbe_phy_complete_ratechange(pdata);
	phy_data->cur_mode = AXGBE_MODE_UNKNOWN;
}

static void axgbe_phy_sfi_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int s0;

	axgbe_phy_set_redrv_mode(pdata);

	axgbe_phy_start_ratechange(pdata);

	/* 10G/SFI */
	s0 = 0;
	XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, COMMAND, 3);
	if (phy_data->sfp_cable != AXGBE_SFP_CABLE_PASSIVE) {
		XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 0);
	} else {
		if (phy_data->sfp_cable_len <= 1)
			XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 1);
		else if (phy_data->sfp_cable_len <= 3)
			XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 2);
		else
			XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 3);
	}

	/* Call FW to make the change */
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_0, s0);
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_1, 0);
	XP_IOWRITE_BITS(pdata, XP_DRIVER_INT_REQ, REQUEST, 1);
	axgbe_phy_complete_ratechange(pdata);
	phy_data->cur_mode = AXGBE_MODE_SFI;
}

static void axgbe_phy_kr_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int s0;

	axgbe_phy_set_redrv_mode(pdata);

	axgbe_phy_start_ratechange(pdata);

	/* 10G/KR */
	s0 = 0;
	XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, COMMAND, 4);
	XP_SET_BITS(s0, XP_DRIVER_SCRATCH_0, SUB_COMMAND, 0);

	/* Call FW to make the change */
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_0, s0);
	XP_IOWRITE(pdata, XP_DRIVER_SCRATCH_1, 0);
	XP_IOWRITE_BITS(pdata, XP_DRIVER_INT_REQ, REQUEST, 1);
	axgbe_phy_complete_ratechange(pdata);
	phy_data->cur_mode = AXGBE_MODE_KR;
}

static enum axgbe_mode axgbe_phy_cur_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	return phy_data->cur_mode;
}

static enum axgbe_mode axgbe_phy_switch_baset_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	/* No switching if not 10GBase-T */
	if (phy_data->port_mode != AXGBE_PORT_MODE_10GBASE_T)
		return axgbe_phy_cur_mode(pdata);

	switch (axgbe_phy_cur_mode(pdata)) {
	case AXGBE_MODE_SGMII_100:
	case AXGBE_MODE_SGMII_1000:
		return AXGBE_MODE_KR;
	case AXGBE_MODE_KR:
	default:
		return AXGBE_MODE_SGMII_1000;
	}
}

static enum axgbe_mode axgbe_phy_switch_bp_2500_mode(struct axgbe_port *pdata
						     __rte_unused)
{
	return AXGBE_MODE_KX_2500;
}

static enum axgbe_mode axgbe_phy_switch_bp_mode(struct axgbe_port *pdata)
{
	/* If we are in KR switch to KX, and vice-versa */
	switch (axgbe_phy_cur_mode(pdata)) {
	case AXGBE_MODE_KX_1000:
		return AXGBE_MODE_KR;
	case AXGBE_MODE_KR:
	default:
		return AXGBE_MODE_KX_1000;
	}
}

static enum axgbe_mode axgbe_phy_switch_mode(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		return axgbe_phy_switch_bp_mode(pdata);
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		return axgbe_phy_switch_bp_2500_mode(pdata);
	case AXGBE_PORT_MODE_1000BASE_T:
	case AXGBE_PORT_MODE_NBASE_T:
	case AXGBE_PORT_MODE_10GBASE_T:
		return axgbe_phy_switch_baset_mode(pdata);
	case AXGBE_PORT_MODE_1000BASE_X:
	case AXGBE_PORT_MODE_10GBASE_R:
	case AXGBE_PORT_MODE_SFP:
		/* No switching, so just return current mode */
		return axgbe_phy_cur_mode(pdata);
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_basex_mode(struct axgbe_phy_data *phy_data
						__rte_unused,
						int speed)
{
	switch (speed) {
	case SPEED_1000:
		return AXGBE_MODE_X;
	case SPEED_10000:
		return AXGBE_MODE_KR;
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_baset_mode(struct axgbe_phy_data *phy_data
						__rte_unused,
						int speed)
{
	switch (speed) {
	case SPEED_100:
		return AXGBE_MODE_SGMII_100;
	case SPEED_1000:
		return AXGBE_MODE_SGMII_1000;
	case SPEED_10000:
		return AXGBE_MODE_KR;
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_sfp_mode(struct axgbe_phy_data *phy_data,
					      int speed)
{
	switch (speed) {
	case SPEED_100:
		return AXGBE_MODE_SGMII_100;
	case SPEED_1000:
		if (phy_data->sfp_base == AXGBE_SFP_BASE_1000_T)
			return AXGBE_MODE_SGMII_1000;
		else
			return AXGBE_MODE_X;
	case SPEED_10000:
	case SPEED_UNKNOWN:
		return AXGBE_MODE_SFI;
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_bp_2500_mode(int speed)
{
	switch (speed) {
	case SPEED_2500:
		return AXGBE_MODE_KX_2500;
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_bp_mode(int speed)
{
	switch (speed) {
	case SPEED_1000:
		return AXGBE_MODE_KX_1000;
	case SPEED_10000:
		return AXGBE_MODE_KR;
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static enum axgbe_mode axgbe_phy_get_mode(struct axgbe_port *pdata,
					  int speed)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		return axgbe_phy_get_bp_mode(speed);
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		return axgbe_phy_get_bp_2500_mode(speed);
	case AXGBE_PORT_MODE_1000BASE_T:
	case AXGBE_PORT_MODE_NBASE_T:
	case AXGBE_PORT_MODE_10GBASE_T:
		return axgbe_phy_get_baset_mode(phy_data, speed);
	case AXGBE_PORT_MODE_1000BASE_X:
	case AXGBE_PORT_MODE_10GBASE_R:
		return axgbe_phy_get_basex_mode(phy_data, speed);
	case AXGBE_PORT_MODE_SFP:
		return axgbe_phy_get_sfp_mode(phy_data, speed);
	default:
		return AXGBE_MODE_UNKNOWN;
	}
}

static void axgbe_phy_set_mode(struct axgbe_port *pdata, enum axgbe_mode mode)
{
	switch (mode) {
	case AXGBE_MODE_KR:
		axgbe_phy_kr_mode(pdata);
		break;
	case AXGBE_MODE_SFI:
		axgbe_phy_sfi_mode(pdata);
		break;
	default:
		break;
	}
}

static bool axgbe_phy_check_mode(struct axgbe_port *pdata,
				 enum axgbe_mode mode, u32 advert)
{
	if (pdata->phy.autoneg == AUTONEG_ENABLE) {
		if (pdata->phy.advertising & advert)
			return true;
	} else {
		enum axgbe_mode cur_mode;

		cur_mode = axgbe_phy_get_mode(pdata, pdata->phy.speed);
		if (cur_mode == mode)
			return true;
	}

	return false;
}

static bool axgbe_phy_use_basex_mode(struct axgbe_port *pdata,
				     enum axgbe_mode mode)
{
	switch (mode) {
	case AXGBE_MODE_X:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_1000baseT_Full);
	case AXGBE_MODE_KR:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_10000baseT_Full);
	default:
		return false;
	}
}

static bool axgbe_phy_use_baset_mode(struct axgbe_port *pdata,
				     enum axgbe_mode mode)
{
	switch (mode) {
	case AXGBE_MODE_SGMII_100:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_100baseT_Full);
	case AXGBE_MODE_SGMII_1000:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_1000baseT_Full);
	case AXGBE_MODE_KR:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_10000baseT_Full);
	default:
		return false;
	}
}

static bool axgbe_phy_use_sfp_mode(struct axgbe_port *pdata,
				   enum axgbe_mode mode)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (mode) {
	case AXGBE_MODE_X:
		if (phy_data->sfp_base == AXGBE_SFP_BASE_1000_T)
			return false;
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_1000baseT_Full);
	case AXGBE_MODE_SGMII_100:
		if (phy_data->sfp_base != AXGBE_SFP_BASE_1000_T)
			return false;
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_100baseT_Full);
	case AXGBE_MODE_SGMII_1000:
		if (phy_data->sfp_base != AXGBE_SFP_BASE_1000_T)
			return false;
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_1000baseT_Full);
	case AXGBE_MODE_SFI:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_10000baseT_Full);
	default:
		return false;
	}
}

static bool axgbe_phy_use_bp_2500_mode(struct axgbe_port *pdata,
				       enum axgbe_mode mode)
{
	switch (mode) {
	case AXGBE_MODE_KX_2500:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_2500baseX_Full);
	default:
		return false;
	}
}

static bool axgbe_phy_use_bp_mode(struct axgbe_port *pdata,
				  enum axgbe_mode mode)
{
	switch (mode) {
	case AXGBE_MODE_KX_1000:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_1000baseKX_Full);
	case AXGBE_MODE_KR:
		return axgbe_phy_check_mode(pdata, mode,
					    ADVERTISED_10000baseKR_Full);
	default:
		return false;
	}
}

static bool axgbe_phy_use_mode(struct axgbe_port *pdata, enum axgbe_mode mode)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		return axgbe_phy_use_bp_mode(pdata, mode);
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		return axgbe_phy_use_bp_2500_mode(pdata, mode);
	case AXGBE_PORT_MODE_1000BASE_T:
	case AXGBE_PORT_MODE_NBASE_T:
	case AXGBE_PORT_MODE_10GBASE_T:
		return axgbe_phy_use_baset_mode(pdata, mode);
	case AXGBE_PORT_MODE_1000BASE_X:
	case AXGBE_PORT_MODE_10GBASE_R:
		return axgbe_phy_use_basex_mode(pdata, mode);
	case AXGBE_PORT_MODE_SFP:
		return axgbe_phy_use_sfp_mode(pdata, mode);
	default:
		return false;
	}
}

static int axgbe_phy_link_status(struct axgbe_port *pdata, int *an_restart)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int reg;

	*an_restart = 0;

	if (phy_data->port_mode == AXGBE_PORT_MODE_SFP) {
		/* Check SFP signals */
		axgbe_phy_sfp_detect(pdata);

		if (phy_data->sfp_changed) {
			*an_restart = 1;
			return 0;
		}

		if (phy_data->sfp_mod_absent || phy_data->sfp_rx_los)
			return 0;
	}

	/* Link status is latched low, so read once to clear
	 * and then read again to get current state
	 */
	reg = XMDIO_READ(pdata, MDIO_MMD_PCS, MDIO_STAT1);
	reg = XMDIO_READ(pdata, MDIO_MMD_PCS, MDIO_STAT1);
	if (reg & MDIO_STAT1_LSTATUS)
		return 1;

	/* No link, attempt a receiver reset cycle */
	if (phy_data->rrc_count++) {
		phy_data->rrc_count = 0;
		axgbe_phy_rrc(pdata);
	}

	return 0;
}

static void axgbe_phy_sfp_gpio_setup(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int reg;

	reg = XP_IOREAD(pdata, XP_PROP_3);

	phy_data->sfp_gpio_address = AXGBE_GPIO_ADDRESS_PCA9555 +
		XP_GET_BITS(reg, XP_PROP_3, GPIO_ADDR);

	phy_data->sfp_gpio_mask = XP_GET_BITS(reg, XP_PROP_3, GPIO_MASK);

	phy_data->sfp_gpio_rx_los = XP_GET_BITS(reg, XP_PROP_3,
						GPIO_RX_LOS);
	phy_data->sfp_gpio_tx_fault = XP_GET_BITS(reg, XP_PROP_3,
						  GPIO_TX_FAULT);
	phy_data->sfp_gpio_mod_absent = XP_GET_BITS(reg, XP_PROP_3,
						    GPIO_MOD_ABS);
	phy_data->sfp_gpio_rate_select = XP_GET_BITS(reg, XP_PROP_3,
						     GPIO_RATE_SELECT);
}

static void axgbe_phy_sfp_comm_setup(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int reg, mux_addr_hi, mux_addr_lo;

	reg = XP_IOREAD(pdata, XP_PROP_4);

	mux_addr_hi = XP_GET_BITS(reg, XP_PROP_4, MUX_ADDR_HI);
	mux_addr_lo = XP_GET_BITS(reg, XP_PROP_4, MUX_ADDR_LO);
	if (mux_addr_lo == AXGBE_SFP_DIRECT)
		return;

	phy_data->sfp_comm = AXGBE_SFP_COMM_PCA9545;
	phy_data->sfp_mux_address = (mux_addr_hi << 2) + mux_addr_lo;
	phy_data->sfp_mux_channel = XP_GET_BITS(reg, XP_PROP_4, MUX_CHAN);
}

static void axgbe_phy_sfp_setup(struct axgbe_port *pdata)
{
	axgbe_phy_sfp_comm_setup(pdata);
	axgbe_phy_sfp_gpio_setup(pdata);
}

static bool axgbe_phy_redrv_error(struct axgbe_phy_data *phy_data)
{
	if (!phy_data->redrv)
		return false;

	if (phy_data->redrv_if >= AXGBE_PHY_REDRV_IF_MAX)
		return true;

	switch (phy_data->redrv_model) {
	case AXGBE_PHY_REDRV_MODEL_4223:
		if (phy_data->redrv_lane > 3)
			return true;
		break;
	case AXGBE_PHY_REDRV_MODEL_4227:
		if (phy_data->redrv_lane > 1)
			return true;
		break;
	default:
		return true;
	}

	return false;
}

static int axgbe_phy_mdio_reset_setup(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	unsigned int reg;

	if (phy_data->conn_type != AXGBE_CONN_TYPE_MDIO)
		return 0;
	reg = XP_IOREAD(pdata, XP_PROP_3);
	phy_data->mdio_reset = XP_GET_BITS(reg, XP_PROP_3, MDIO_RESET);
	switch (phy_data->mdio_reset) {
	case AXGBE_MDIO_RESET_NONE:
	case AXGBE_MDIO_RESET_I2C_GPIO:
	case AXGBE_MDIO_RESET_INT_GPIO:
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported MDIO reset (%#x)\n",
			    phy_data->mdio_reset);
		return -EINVAL;
	}
	if (phy_data->mdio_reset == AXGBE_MDIO_RESET_I2C_GPIO) {
		phy_data->mdio_reset_addr = AXGBE_GPIO_ADDRESS_PCA9555 +
			XP_GET_BITS(reg, XP_PROP_3,
				    MDIO_RESET_I2C_ADDR);
		phy_data->mdio_reset_gpio = XP_GET_BITS(reg, XP_PROP_3,
							MDIO_RESET_I2C_GPIO);
	} else if (phy_data->mdio_reset == AXGBE_MDIO_RESET_INT_GPIO) {
		phy_data->mdio_reset_gpio = XP_GET_BITS(reg, XP_PROP_3,
							MDIO_RESET_INT_GPIO);
	}

	return 0;
}

static bool axgbe_phy_port_mode_mismatch(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
		if ((phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000))
			return false;
		break;
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_2500)
			return false;
		break;
	case AXGBE_PORT_MODE_1000BASE_T:
		if ((phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000))
			return false;
		break;
	case AXGBE_PORT_MODE_1000BASE_X:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000)
			return false;
		break;
	case AXGBE_PORT_MODE_NBASE_T:
		if ((phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_2500))
			return false;
		break;
	case AXGBE_PORT_MODE_10GBASE_T:
		if ((phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000))
			return false;
		break;
	case AXGBE_PORT_MODE_10GBASE_R:
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000)
			return false;
		break;
	case AXGBE_PORT_MODE_SFP:
		if ((phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) ||
		    (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000))
			return false;
		break;
	default:
		break;
	}

	return true;
}

static bool axgbe_phy_conn_type_mismatch(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_BACKPLANE:
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		if (phy_data->conn_type == AXGBE_CONN_TYPE_BACKPLANE)
			return false;
		break;
	case AXGBE_PORT_MODE_1000BASE_T:
	case AXGBE_PORT_MODE_1000BASE_X:
	case AXGBE_PORT_MODE_NBASE_T:
	case AXGBE_PORT_MODE_10GBASE_T:
	case AXGBE_PORT_MODE_10GBASE_R:
		if (phy_data->conn_type == AXGBE_CONN_TYPE_MDIO)
			return false;
		break;
	case AXGBE_PORT_MODE_SFP:
		if (phy_data->conn_type == AXGBE_CONN_TYPE_SFP)
			return false;
		break;
	default:
		break;
	}

	return true;
}

static bool axgbe_phy_port_enabled(struct axgbe_port *pdata)
{
	unsigned int reg;

	reg = XP_IOREAD(pdata, XP_PROP_0);
	if (!XP_GET_BITS(reg, XP_PROP_0, PORT_SPEEDS))
		return false;
	if (!XP_GET_BITS(reg, XP_PROP_0, CONN_TYPE))
		return false;

	return true;
}

static void axgbe_phy_cdr_track(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	if (!pdata->vdata->an_cdr_workaround)
		return;

	if (!phy_data->phy_cdr_notrack)
		return;

	rte_delay_us(phy_data->phy_cdr_delay + 400);

	XMDIO_WRITE_BITS(pdata, MDIO_MMD_PMAPMD, MDIO_VEND2_PMA_CDR_CONTROL,
			 AXGBE_PMA_CDR_TRACK_EN_MASK,
			 AXGBE_PMA_CDR_TRACK_EN_ON);

	phy_data->phy_cdr_notrack = 0;
}

static void axgbe_phy_cdr_notrack(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	if (!pdata->vdata->an_cdr_workaround)
		return;

	if (phy_data->phy_cdr_notrack)
		return;

	XMDIO_WRITE_BITS(pdata, MDIO_MMD_PMAPMD, MDIO_VEND2_PMA_CDR_CONTROL,
			 AXGBE_PMA_CDR_TRACK_EN_MASK,
			 AXGBE_PMA_CDR_TRACK_EN_OFF);

	axgbe_phy_rrc(pdata);

	phy_data->phy_cdr_notrack = 1;
}

static void axgbe_phy_kr_training_post(struct axgbe_port *pdata)
{
	if (!pdata->cdr_track_early)
		axgbe_phy_cdr_track(pdata);
}

static void axgbe_phy_kr_training_pre(struct axgbe_port *pdata)
{
	if (pdata->cdr_track_early)
		axgbe_phy_cdr_track(pdata);
}

static void axgbe_phy_an_post(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (pdata->an_mode) {
	case AXGBE_AN_MODE_CL73:
	case AXGBE_AN_MODE_CL73_REDRV:
		if (phy_data->cur_mode != AXGBE_MODE_KR)
			break;

		axgbe_phy_cdr_track(pdata);

		switch (pdata->an_result) {
		case AXGBE_AN_READY:
		case AXGBE_AN_COMPLETE:
			break;
		default:
			if (phy_data->phy_cdr_delay < AXGBE_CDR_DELAY_MAX)
				phy_data->phy_cdr_delay += AXGBE_CDR_DELAY_INC;
			break;
		}
		break;
	default:
		break;
	}
}

static void axgbe_phy_an_pre(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	switch (pdata->an_mode) {
	case AXGBE_AN_MODE_CL73:
	case AXGBE_AN_MODE_CL73_REDRV:
		if (phy_data->cur_mode != AXGBE_MODE_KR)
			break;

		axgbe_phy_cdr_notrack(pdata);
		break;
	default:
		break;
	}
}

static void axgbe_phy_stop(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;

	/* Reset SFP data */
	axgbe_phy_sfp_reset(phy_data);
	axgbe_phy_sfp_mod_absent(pdata);

	/* Reset CDR support */
	axgbe_phy_cdr_track(pdata);

	/* Power off the PHY */
	axgbe_phy_power_off(pdata);

	/* Stop the I2C controller */
	pdata->i2c_if.i2c_stop(pdata);
}

static int axgbe_phy_start(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	int ret;

	/* Start the I2C controller */
	ret = pdata->i2c_if.i2c_start(pdata);
	if (ret)
		return ret;

	/* Start in highest supported mode */
	axgbe_phy_set_mode(pdata, phy_data->start_mode);

	/* Reset CDR support */
	axgbe_phy_cdr_track(pdata);

	/* After starting the I2C controller, we can check for an SFP */
	switch (phy_data->port_mode) {
	case AXGBE_PORT_MODE_SFP:
		axgbe_phy_sfp_detect(pdata);
		break;
	default:
		break;
	}

	return ret;
}

static int axgbe_phy_reset(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data = pdata->phy_data;
	enum axgbe_mode cur_mode;

	/* Reset by power cycling the PHY */
	cur_mode = phy_data->cur_mode;
	axgbe_phy_power_off(pdata);
	/* First time reset is done with passed unknown mode*/
	axgbe_phy_set_mode(pdata, cur_mode);
	return 0;
}

static int axgbe_phy_init(struct axgbe_port *pdata)
{
	struct axgbe_phy_data *phy_data;
	unsigned int reg;
	int ret;

	/* Check if enabled */
	if (!axgbe_phy_port_enabled(pdata)) {
		PMD_DRV_LOG(ERR, "device is not enabled\n");
		return -ENODEV;
	}

	/* Initialize the I2C controller */
	ret = pdata->i2c_if.i2c_init(pdata);
	if (ret)
		return ret;

	phy_data = rte_zmalloc("phy_data memory", sizeof(*phy_data), 0);
	if (!phy_data) {
		PMD_DRV_LOG(ERR, "phy_data allocation failed\n");
		return -ENOMEM;
	}
	pdata->phy_data = phy_data;

	reg = XP_IOREAD(pdata, XP_PROP_0);
	phy_data->port_mode = XP_GET_BITS(reg, XP_PROP_0, PORT_MODE);
	phy_data->port_id = XP_GET_BITS(reg, XP_PROP_0, PORT_ID);
	phy_data->port_speeds = XP_GET_BITS(reg, XP_PROP_0, PORT_SPEEDS);
	phy_data->conn_type = XP_GET_BITS(reg, XP_PROP_0, CONN_TYPE);
	phy_data->mdio_addr = XP_GET_BITS(reg, XP_PROP_0, MDIO_ADDR);

	reg = XP_IOREAD(pdata, XP_PROP_4);
	phy_data->redrv = XP_GET_BITS(reg, XP_PROP_4, REDRV_PRESENT);
	phy_data->redrv_if = XP_GET_BITS(reg, XP_PROP_4, REDRV_IF);
	phy_data->redrv_addr = XP_GET_BITS(reg, XP_PROP_4, REDRV_ADDR);
	phy_data->redrv_lane = XP_GET_BITS(reg, XP_PROP_4, REDRV_LANE);
	phy_data->redrv_model = XP_GET_BITS(reg, XP_PROP_4, REDRV_MODEL);

	/* Validate the connection requested */
	if (axgbe_phy_conn_type_mismatch(pdata)) {
		PMD_DRV_LOG(ERR, "phy mode/connection mismatch (%#x/%#x)\n",
			    phy_data->port_mode, phy_data->conn_type);
		return -EINVAL;
	}

	/* Validate the mode requested */
	if (axgbe_phy_port_mode_mismatch(pdata)) {
		PMD_DRV_LOG(ERR, "phy mode/speed mismatch (%#x/%#x)\n",
			    phy_data->port_mode, phy_data->port_speeds);
		return -EINVAL;
	}

	/* Check for and validate MDIO reset support */
	ret = axgbe_phy_mdio_reset_setup(pdata);
	if (ret)
		return ret;

	/* Validate the re-driver information */
	if (axgbe_phy_redrv_error(phy_data)) {
		PMD_DRV_LOG(ERR, "phy re-driver settings error\n");
		return -EINVAL;
	}
	pdata->kr_redrv = phy_data->redrv;

	/* Indicate current mode is unknown */
	phy_data->cur_mode = AXGBE_MODE_UNKNOWN;

	/* Initialize supported features */
	pdata->phy.supported = 0;

	switch (phy_data->port_mode) {
		/* Backplane support */
	case AXGBE_PORT_MODE_BACKPLANE:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_Backplane;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) {
			pdata->phy.supported |= SUPPORTED_1000baseKX_Full;
			phy_data->start_mode = AXGBE_MODE_KX_1000;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000) {
			pdata->phy.supported |= SUPPORTED_10000baseKR_Full;
			if (pdata->fec_ability & MDIO_PMA_10GBR_FECABLE_ABLE)
				pdata->phy.supported |=
					SUPPORTED_10000baseR_FEC;
			phy_data->start_mode = AXGBE_MODE_KR;
		}

		phy_data->phydev_mode = AXGBE_MDIO_MODE_NONE;
		break;
	case AXGBE_PORT_MODE_BACKPLANE_2500:
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_Backplane;
		pdata->phy.supported |= SUPPORTED_2500baseX_Full;
		phy_data->start_mode = AXGBE_MODE_KX_2500;

		phy_data->phydev_mode = AXGBE_MDIO_MODE_NONE;
		break;

		/* MDIO 1GBase-T support */
	case AXGBE_PORT_MODE_1000BASE_T:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_TP;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) {
			pdata->phy.supported |= SUPPORTED_100baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_100;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) {
			pdata->phy.supported |= SUPPORTED_1000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_1000;
		}

		phy_data->phydev_mode = AXGBE_MDIO_MODE_CL22;
		break;

		/* MDIO Base-X support */
	case AXGBE_PORT_MODE_1000BASE_X:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_FIBRE;
		pdata->phy.supported |= SUPPORTED_1000baseT_Full;
		phy_data->start_mode = AXGBE_MODE_X;

		phy_data->phydev_mode = AXGBE_MDIO_MODE_CL22;
		break;

		/* MDIO NBase-T support */
	case AXGBE_PORT_MODE_NBASE_T:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_TP;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) {
			pdata->phy.supported |= SUPPORTED_100baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_100;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) {
			pdata->phy.supported |= SUPPORTED_1000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_1000;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_2500) {
			pdata->phy.supported |= SUPPORTED_2500baseX_Full;
			phy_data->start_mode = AXGBE_MODE_KX_2500;
		}

		phy_data->phydev_mode = AXGBE_MDIO_MODE_CL45;
		break;

		/* 10GBase-T support */
	case AXGBE_PORT_MODE_10GBASE_T:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_TP;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) {
			pdata->phy.supported |= SUPPORTED_100baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_100;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) {
			pdata->phy.supported |= SUPPORTED_1000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_1000;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000) {
			pdata->phy.supported |= SUPPORTED_10000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_KR;
		}

		phy_data->phydev_mode = AXGBE_MDIO_MODE_NONE;
		break;

		/* 10GBase-R support */
	case AXGBE_PORT_MODE_10GBASE_R:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_TP;
		pdata->phy.supported |= SUPPORTED_10000baseT_Full;
		if (pdata->fec_ability & MDIO_PMA_10GBR_FECABLE_ABLE)
			pdata->phy.supported |= SUPPORTED_10000baseR_FEC;
		phy_data->start_mode = AXGBE_MODE_SFI;

		phy_data->phydev_mode = AXGBE_MDIO_MODE_NONE;
		break;

		/* SFP support */
	case AXGBE_PORT_MODE_SFP:
		pdata->phy.supported |= SUPPORTED_Autoneg;
		pdata->phy.supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
		pdata->phy.supported |= SUPPORTED_TP;
		pdata->phy.supported |= SUPPORTED_FIBRE;
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_100) {
			pdata->phy.supported |= SUPPORTED_100baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_100;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_1000) {
			pdata->phy.supported |= SUPPORTED_1000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SGMII_1000;
		}
		if (phy_data->port_speeds & AXGBE_PHY_PORT_SPEED_10000) {
			pdata->phy.supported |= SUPPORTED_10000baseT_Full;
			phy_data->start_mode = AXGBE_MODE_SFI;
			if (pdata->fec_ability & MDIO_PMA_10GBR_FECABLE_ABLE)
				pdata->phy.supported |=
					SUPPORTED_10000baseR_FEC;
		}

		phy_data->phydev_mode = AXGBE_MDIO_MODE_CL22;

		axgbe_phy_sfp_setup(pdata);
		break;
	default:
		return -EINVAL;
	}

	if ((phy_data->conn_type & AXGBE_CONN_TYPE_MDIO) &&
	    (phy_data->phydev_mode != AXGBE_MDIO_MODE_NONE)) {
		ret = pdata->hw_if.set_ext_mii_mode(pdata, phy_data->mdio_addr,
						    phy_data->phydev_mode);
		if (ret) {
			PMD_DRV_LOG(ERR, "mdio port/clause not compatible (%d/%u)\n",
				    phy_data->mdio_addr, phy_data->phydev_mode);
			return -EINVAL;
		}
	}

	if (phy_data->redrv && !phy_data->redrv_if) {
		ret = pdata->hw_if.set_ext_mii_mode(pdata, phy_data->redrv_addr,
						    AXGBE_MDIO_MODE_CL22);
		if (ret) {
			PMD_DRV_LOG(ERR, "redriver mdio port not compatible (%u)\n",
				    phy_data->redrv_addr);
			return -EINVAL;
		}
	}

	phy_data->phy_cdr_delay = AXGBE_CDR_DELAY_INIT;
	return 0;
}
void axgbe_init_function_ptrs_phy_v2(struct axgbe_phy_if *phy_if)
{
	struct axgbe_phy_impl_if *phy_impl = &phy_if->phy_impl;

	phy_impl->init			= axgbe_phy_init;
	phy_impl->reset			= axgbe_phy_reset;
	phy_impl->start			= axgbe_phy_start;
	phy_impl->stop			= axgbe_phy_stop;
	phy_impl->link_status		= axgbe_phy_link_status;
	phy_impl->use_mode		= axgbe_phy_use_mode;
	phy_impl->set_mode		= axgbe_phy_set_mode;
	phy_impl->get_mode		= axgbe_phy_get_mode;
	phy_impl->switch_mode		= axgbe_phy_switch_mode;
	phy_impl->cur_mode		= axgbe_phy_cur_mode;
	phy_impl->an_mode		= axgbe_phy_an_mode;
	phy_impl->an_config		= axgbe_phy_an_config;
	phy_impl->an_advertising	= axgbe_phy_an_advertising;
	phy_impl->an_outcome		= axgbe_phy_an_outcome;

	phy_impl->an_pre		= axgbe_phy_an_pre;
	phy_impl->an_post		= axgbe_phy_an_post;

	phy_impl->kr_training_pre	= axgbe_phy_kr_training_pre;
	phy_impl->kr_training_post	= axgbe_phy_kr_training_post;
}
