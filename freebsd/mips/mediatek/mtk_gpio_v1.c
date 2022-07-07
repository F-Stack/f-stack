/*-
 * Copyright 2016 Stanislav Galabov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/gpio.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <mips/mediatek/mtk_soc.h>

#include <dev/gpio/gpiobusvar.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus.h>
#include <dev/ofw/ofw_bus_subr.h>

#include <dt-bindings/interrupt-controller/irq.h>

#include "gpio_if.h"
#include "pic_if.h"

#define MTK_GPIO_PINS 32

enum mtk_gpio_regs {
	GPIO_PIOINT = 0,
	GPIO_PIOEDGE,
	GPIO_PIORENA,
	GPIO_PIOFENA,
	GPIO_PIODATA,
	GPIO_PIODIR,
	GPIO_PIOPOL,
	GPIO_PIOSET,
	GPIO_PIORESET,
	GPIO_PIOTOG,
	GPIO_PIOMAX
};

struct mtk_gpio_pin_irqsrc {
	struct intr_irqsrc	isrc;
	u_int			irq;
};

struct mtk_gpio_pin {
	uint32_t			pin_caps;
	uint32_t			pin_flags;
	enum intr_trigger		intr_trigger;
	enum intr_polarity		intr_polarity;
	char				pin_name[GPIOMAXNAME];
	struct mtk_gpio_pin_irqsrc	pin_irqsrc;
};

struct mtk_gpio_softc {
	device_t		dev;
	device_t		busdev;
	struct resource		*res[2];
	struct mtx		mtx;
	struct mtk_gpio_pin	pins[MTK_GPIO_PINS];
	void			*intrhand;

	uint8_t		regs[GPIO_PIOMAX];
	uint32_t		num_pins;
	uint8_t			do_remap;
};

#define PIC_INTR_ISRC(sc, irq)	(&(sc)->pins[(irq)].pin_irqsrc.isrc)

static struct resource_spec mtk_gpio_spec[] = {
	{ SYS_RES_MEMORY, 0, RF_ACTIVE },
	{ SYS_RES_IRQ,    0, RF_ACTIVE | RF_SHAREABLE },
	{ -1, 0 }
};

static int mtk_gpio_probe(device_t dev);
static int mtk_gpio_attach(device_t dev);
static int mtk_gpio_detach(device_t dev);
static int mtk_gpio_intr(void *arg);

#define MTK_GPIO_LOCK(sc)		mtx_lock_spin(&(sc)->mtx)
#define MTK_GPIO_UNLOCK(sc)		mtx_unlock_spin(&(sc)->mtx)
#define MTK_GPIO_LOCK_INIT(sc)		\
    mtx_init(&(sc)->mtx, device_get_nameunit((sc)->dev),	\
    "mtk_gpio", MTX_SPIN)
#define MTK_GPIO_LOCK_DESTROY(sc)	mtx_destroy(&(sc)->mtx)

#define MTK_WRITE_4(sc, reg, val)	\
    bus_write_4((sc)->res[0], (sc)->regs[(reg)], (val))
#define MTK_READ_4(sc, reg)		\
    bus_read_4((sc)->res[0], (sc)->regs[(reg)])

static struct ofw_compat_data compat_data[] = {
	{ "ralink,rt2880-gpio",		1 },
	{ "ralink,rt3050-gpio",		1 },
	{ "ralink,rt3352-gpio",		1 },
	{ "ralink,rt3883-gpio",		1 },
	{ "ralink,rt5350-gpio",		1 },
	{ "ralink,mt7620a-gpio",	1 },
	{ NULL,				0 }
};

static int
mtk_gpio_probe(device_t dev)
{
	phandle_t node;

	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	node = ofw_bus_get_node(dev);
	if (!OF_hasprop(node, "gpio-controller"))
		return (ENXIO);

	device_set_desc(dev, "MTK GPIO Controller (v1)");

	return (BUS_PROBE_DEFAULT);
}

static int
mtk_pic_register_isrcs(struct mtk_gpio_softc *sc)
{
	int error;
	uint32_t irq;
	struct intr_irqsrc *isrc;
	const char *name;

	name = device_get_nameunit(sc->dev);
	for (irq = 0; irq < sc->num_pins; irq++) {
		sc->pins[irq].pin_irqsrc.irq = irq;
		isrc = PIC_INTR_ISRC(sc, irq);
		error = intr_isrc_register(isrc, sc->dev, 0, "%s", name);
		if (error != 0) {
			/* XXX call intr_isrc_deregister */
			device_printf(sc->dev, "%s failed", __func__);
			return (error);
		}
	}

	return (0);
}

static int
mtk_gpio_pin_set_direction(struct mtk_gpio_softc *sc, uint32_t pin,
    uint32_t dir)
{
	uint32_t regval, mask = (1u << pin);

	if (!(sc->pins[pin].pin_caps & dir))
		return (EINVAL);

	regval = MTK_READ_4(sc, GPIO_PIODIR);
	if (dir == GPIO_PIN_INPUT)
		regval &= ~mask;
	else
		regval |= mask;
	MTK_WRITE_4(sc, GPIO_PIODIR, regval);

	sc->pins[pin].pin_flags &= ~(GPIO_PIN_INPUT | GPIO_PIN_OUTPUT);
	sc->pins[pin].pin_flags |= dir;

	return (0);
}

static int
mtk_gpio_pin_set_invert(struct mtk_gpio_softc *sc, uint32_t pin, uint32_t val)
{
	uint32_t regval, mask = (1u << pin);

	regval = MTK_READ_4(sc, GPIO_PIOPOL);
	if (val)
		regval |= mask;
	else
		regval &= ~mask;
	MTK_WRITE_4(sc, GPIO_PIOPOL, regval);
	sc->pins[pin].pin_flags &= ~(GPIO_PIN_INVIN | GPIO_PIN_INVOUT);
	sc->pins[pin].pin_flags |= val;

	return (0);
}

static void
mtk_gpio_pin_probe(struct mtk_gpio_softc *sc, uint32_t pin)
{
	uint32_t mask = (1u << pin);
	uint32_t val;

	/* Clear cached gpio config */
	sc->pins[pin].pin_flags = 0;

	val = MTK_READ_4(sc, GPIO_PIORENA) |
	    MTK_READ_4(sc, GPIO_PIOFENA);
	if (val & mask) {
		/* Pin is in interrupt mode */
		sc->pins[pin].intr_trigger = INTR_TRIGGER_EDGE;
		val = MTK_READ_4(sc, GPIO_PIORENA);
		if (val & mask)
			sc->pins[pin].intr_polarity = INTR_POLARITY_HIGH;
		else
			sc->pins[pin].intr_polarity = INTR_POLARITY_LOW;
	}

	val = MTK_READ_4(sc, GPIO_PIODIR);
	if (val & mask)
		sc->pins[pin].pin_flags |= GPIO_PIN_OUTPUT;
	else
		sc->pins[pin].pin_flags |= GPIO_PIN_INPUT;

	val = MTK_READ_4(sc, GPIO_PIOPOL);
	if (val & mask) {
		if (sc->pins[pin].pin_flags & GPIO_PIN_INPUT) {
			sc->pins[pin].pin_flags |= GPIO_PIN_INVIN;
		} else {
			sc->pins[pin].pin_flags |= GPIO_PIN_INVOUT;
		}
	}
}

static int
mtk_gpio_attach(device_t dev)
{
	struct mtk_gpio_softc *sc;
	phandle_t node;
	uint32_t i, num_pins;

	sc = device_get_softc(dev);
	sc->dev = dev;

	if (bus_alloc_resources(dev, mtk_gpio_spec, sc->res)) {
		device_printf(dev, "could not allocate resources for device\n");
		return (ENXIO);
	}

	MTK_GPIO_LOCK_INIT(sc);

	node = ofw_bus_get_node(dev);

	if (OF_hasprop(node, "clocks"))
		mtk_soc_start_clock(dev);
	if (OF_hasprop(node, "resets"))
		mtk_soc_reset_device(dev);

	if (OF_getprop(node, "ralink,register-map", sc->regs,
	    GPIO_PIOMAX) <= 0) {
		device_printf(dev, "Failed to read register map\n");
		return (ENXIO);
	}

	if (OF_hasprop(node, "ralink,num-gpios") && (OF_getencprop(node,
	    "ralink,num-gpios", &num_pins, sizeof(num_pins)) >= 0))
		sc->num_pins = num_pins;
	else
		sc->num_pins = MTK_GPIO_PINS;

	for (i = 0; i < sc->num_pins; i++) {
		sc->pins[i].pin_caps |= GPIO_PIN_INPUT | GPIO_PIN_OUTPUT |
		    GPIO_PIN_INVIN | GPIO_PIN_INVOUT |
		    GPIO_INTR_EDGE_RISING | GPIO_INTR_EDGE_FALLING;
		sc->pins[i].intr_polarity = INTR_POLARITY_HIGH;
		sc->pins[i].intr_trigger = INTR_TRIGGER_EDGE;

		snprintf(sc->pins[i].pin_name, GPIOMAXNAME - 1, "gpio%c%d",
		    device_get_unit(dev) + 'a', i);
		sc->pins[i].pin_name[GPIOMAXNAME - 1] = '\0';

		mtk_gpio_pin_probe(sc, i);
	}

	if (mtk_pic_register_isrcs(sc) != 0) {
		device_printf(dev, "could not register PIC ISRCs\n");
		goto fail;
	}

	if (intr_pic_register(dev, OF_xref_from_node(node)) == NULL) {
		device_printf(dev, "could not register PIC\n");
		goto fail;
	}

	if (bus_setup_intr(dev, sc->res[1], INTR_TYPE_MISC | INTR_MPSAFE,
	    mtk_gpio_intr, NULL, sc, &sc->intrhand) != 0)
		goto fail_pic;

	sc->busdev = gpiobus_attach_bus(dev);
	if (sc->busdev == NULL)
		goto fail_pic;

	return (0);
fail_pic:
	intr_pic_deregister(dev, OF_xref_from_node(node));
fail:
	if(sc->intrhand != NULL)
		bus_teardown_intr(dev, sc->res[1], sc->intrhand);
	bus_release_resources(dev, mtk_gpio_spec, sc->res);
	MTK_GPIO_LOCK_DESTROY(sc);
	return (ENXIO);
}

static int
mtk_gpio_detach(device_t dev)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);
	phandle_t node;

	node = ofw_bus_get_node(dev);
	intr_pic_deregister(dev, OF_xref_from_node(node));
	if (sc->intrhand != NULL)
		bus_teardown_intr(dev, sc->res[1], sc->intrhand);
	bus_release_resources(dev, mtk_gpio_spec, sc->res);
	MTK_GPIO_LOCK_DESTROY(sc);
	return (0);
}

static device_t
mtk_gpio_get_bus(device_t dev)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);

	return (sc->busdev);
}

static int
mtk_gpio_pin_max(device_t dev, int *maxpin)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);

	*maxpin = sc->num_pins - 1;

	return (0);
}

static int
mtk_gpio_pin_getcaps(device_t dev, uint32_t pin, uint32_t *caps)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	*caps = sc->pins[pin].pin_caps;
	MTK_GPIO_UNLOCK(sc);

	return (0);
}

static int
mtk_gpio_pin_getflags(device_t dev, uint32_t pin, uint32_t *flags)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	*flags = sc->pins[pin].pin_flags;
	MTK_GPIO_UNLOCK(sc);

	return (0);
}

static int
mtk_gpio_pin_getname(device_t dev, uint32_t pin, char *name)
{
	struct mtk_gpio_softc *sc = device_get_softc(dev);

	if (pin >= sc->num_pins)
		return (EINVAL);

	strncpy(name, sc->pins[pin].pin_name, GPIOMAXNAME - 1);
	name[GPIOMAXNAME - 1] = '\0';

	return (0);
}

static int
mtk_gpio_pin_setflags(device_t dev, uint32_t pin, uint32_t flags)
{
	struct mtk_gpio_softc *sc;
	int retval;

	sc = device_get_softc(dev);

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	retval = mtk_gpio_pin_set_direction(sc, pin,
	    flags & (GPIO_PIN_INPUT | GPIO_PIN_OUTPUT));
	if (retval == 0)
		retval = mtk_gpio_pin_set_invert(sc, pin,
		    flags & (GPIO_PIN_INVIN | GPIO_PIN_INVOUT));
	MTK_GPIO_UNLOCK(sc);

	return (retval);
}

static int
mtk_gpio_pin_set(device_t dev, uint32_t pin, unsigned int value)
{
	struct mtk_gpio_softc *sc;
	int ret;

	sc = device_get_softc(dev);
	ret = 0;

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	if (value)
		MTK_WRITE_4(sc, GPIO_PIOSET, (1u << pin));
	else
		MTK_WRITE_4(sc, GPIO_PIORESET, (1u << pin));
	MTK_GPIO_UNLOCK(sc);

	return (ret);
}

static int
mtk_gpio_pin_get(device_t dev, uint32_t pin, unsigned int *val)
{
	struct mtk_gpio_softc *sc;
	uint32_t data;
	int ret;

	sc = device_get_softc(dev);
	ret = 0;

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	data = MTK_READ_4(sc, GPIO_PIODATA);
	*val = (data & (1u << pin)) ? 1 : 0;
	MTK_GPIO_UNLOCK(sc);

	return (ret);
}

static int
mtk_gpio_pin_toggle(device_t dev, uint32_t pin)
{
	struct mtk_gpio_softc *sc;
	int ret;

	sc = device_get_softc(dev);
	ret = 0;

	if (pin >= sc->num_pins)
		return (EINVAL);

	MTK_GPIO_LOCK(sc);
	if (!(sc->pins[pin].pin_flags & GPIO_PIN_OUTPUT)) {
		ret = EINVAL;
		goto out;
	}
	MTK_WRITE_4(sc, GPIO_PIOTOG, (1u << pin));

out:
	MTK_GPIO_UNLOCK(sc);

	return (ret);
}

static int
mtk_gpio_pic_map_fdt(struct mtk_gpio_softc *sc,
    struct intr_map_data_fdt *daf, u_int *irqp, uint32_t *modep)
{
	u_int irq;

	if (daf->ncells != 1) {
		device_printf(sc->dev, "Invalid #interrupt-cells\n");
		return (EINVAL);
	}

	irq = daf->cells[0];

	if (irq >= sc->num_pins) {
		device_printf(sc->dev, "Invalid interrupt number %u\n", irq);
		return (EINVAL);
	}

	*irqp = irq;
	if (modep != NULL)
		*modep = GPIO_INTR_EDGE_BOTH;

	return (0);
}

static int
mtk_gpio_pic_map_gpio(struct mtk_gpio_softc *sc,
    struct intr_map_data_gpio *dag, u_int *irqp, uint32_t *modep)
{
	u_int irq;

	irq = dag->gpio_pin_num;
	if (irq >= sc->num_pins) {
		device_printf(sc->dev, "Invalid interrupt number %u\n", irq);
		return (EINVAL);
	}

	*irqp = irq;
	if (modep != NULL)
		*modep = dag->gpio_intr_mode;

	return (0);
}

static int
mtk_gpio_pic_map_intr(device_t dev, struct intr_map_data *data,
    struct intr_irqsrc **isrcp)
{
	int error;
	u_int irq;
	struct mtk_gpio_softc *sc;

	sc = device_get_softc(dev);
	switch (data->type) {
	case INTR_MAP_DATA_FDT:
		error = (mtk_gpio_pic_map_fdt(sc,
		    (struct intr_map_data_fdt *)data, &irq, NULL));
		break;
	case INTR_MAP_DATA_GPIO:
		error = (mtk_gpio_pic_map_gpio(sc,
		    (struct intr_map_data_gpio *)data, &irq, NULL));
		break;
	default:
		error = EINVAL;
		break;
	}

	if (error != 0) {
		device_printf(dev, "Invalid map type\n");
		return (error);
	}

	*isrcp = PIC_INTR_ISRC(sc, irq);
	return (0);
}

static void
mtk_gpio_pic_enable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct mtk_gpio_softc *sc;
	struct mtk_gpio_pin_irqsrc *pisrc;
	uint32_t pin, mask, val;

	sc = device_get_softc(dev);

	pisrc = (struct mtk_gpio_pin_irqsrc *)isrc;
	pin = pisrc->irq;
	mask = 1u << pin;

	MTK_GPIO_LOCK(sc);

	if (sc->pins[pin].intr_polarity == INTR_POLARITY_LOW) {
		val = MTK_READ_4(sc, GPIO_PIORENA) & ~mask;
		MTK_WRITE_4(sc, GPIO_PIORENA, val);
		val = MTK_READ_4(sc, GPIO_PIOFENA) | mask;
		MTK_WRITE_4(sc, GPIO_PIOFENA, val);
	} else {
		val = MTK_READ_4(sc, GPIO_PIOFENA) & ~mask;
		MTK_WRITE_4(sc, GPIO_PIOFENA, val);
		val = MTK_READ_4(sc, GPIO_PIORENA) | mask;
		MTK_WRITE_4(sc, GPIO_PIORENA, val);
	}

	MTK_GPIO_UNLOCK(sc);
}

static void
mtk_gpio_pic_disable_intr(device_t dev, struct intr_irqsrc *isrc)
{
	struct mtk_gpio_softc *sc;
	struct mtk_gpio_pin_irqsrc *pisrc;
	uint32_t pin, mask, val;

	sc = device_get_softc(dev);

	pisrc = (struct mtk_gpio_pin_irqsrc *)isrc;
	pin = pisrc->irq;
	mask = 1u << pin;

	MTK_GPIO_LOCK(sc);

	val = MTK_READ_4(sc, GPIO_PIORENA) & ~mask;
	MTK_WRITE_4(sc, GPIO_PIORENA, val);
	val = MTK_READ_4(sc, GPIO_PIOFENA) & ~mask;
	MTK_WRITE_4(sc, GPIO_PIOFENA, val);

	MTK_GPIO_UNLOCK(sc);
}

static void
mtk_gpio_pic_pre_ithread(device_t dev, struct intr_irqsrc *isrc)
{

	mtk_gpio_pic_disable_intr(dev, isrc);
}

static void
mtk_gpio_pic_post_ithread(device_t dev, struct intr_irqsrc *isrc)
{

	mtk_gpio_pic_enable_intr(dev, isrc);
}

static void
mtk_gpio_pic_post_filter(device_t dev, struct intr_irqsrc *isrc)
{
	struct mtk_gpio_softc *sc;
	struct mtk_gpio_pin_irqsrc *pisrc;

	pisrc = (struct mtk_gpio_pin_irqsrc *)isrc;
	sc = device_get_softc(dev);
	MTK_GPIO_LOCK(sc);
	MTK_WRITE_4(sc, GPIO_PIOINT, 1u << pisrc->irq);
	MTK_GPIO_UNLOCK(sc);
}

static int
mtk_gpio_pic_setup_intr(device_t dev, struct intr_irqsrc *isrc,
    struct resource *res, struct intr_map_data *data)
{
	struct mtk_gpio_softc *sc;
	uint32_t val;
	int error;
	uint32_t mode;
	u_int irq;

	if (data == NULL)
		return (ENOTSUP);

	sc = device_get_softc(dev);

	switch (data->type) {
	case INTR_MAP_DATA_FDT:
		error = mtk_gpio_pic_map_fdt(sc,
		    (struct intr_map_data_fdt *)data, &irq, &mode);
		break;
	case INTR_MAP_DATA_GPIO:
		error = mtk_gpio_pic_map_gpio(sc,
		    (struct intr_map_data_gpio *)data, &irq, &mode);
		break;
	default:
		error = ENOTSUP;
		break;
	}

	if (error != 0)
		return (error);

	MTK_GPIO_LOCK(sc);
	if (mode == GPIO_INTR_EDGE_BOTH || mode == GPIO_INTR_EDGE_RISING) {
		val = MTK_READ_4(sc, GPIO_PIORENA) | (1u << irq);
		MTK_WRITE_4(sc, GPIO_PIORENA, val);
	}
	if (mode == GPIO_INTR_EDGE_BOTH || mode == GPIO_INTR_EDGE_FALLING) {
		val = MTK_READ_4(sc, GPIO_PIOFENA) | (1u << irq);
		MTK_WRITE_4(sc, GPIO_PIOFENA, val);
	}
	MTK_GPIO_UNLOCK(sc);
	return (0);
}

static int
mtk_gpio_intr(void *arg)
{
	struct mtk_gpio_softc *sc;
	uint32_t i, interrupts;

	sc = arg;
	interrupts = MTK_READ_4(sc, GPIO_PIOINT);
	MTK_WRITE_4(sc, GPIO_PIOINT, interrupts);

	for (i = 0; interrupts != 0; i++, interrupts >>= 1) {
		if ((interrupts & 0x1) == 0)
			continue;
		if (intr_isrc_dispatch(PIC_INTR_ISRC(sc, i),
		    curthread->td_intr_frame) != 0) {
			device_printf(sc->dev, "spurious interrupt %d\n", i);
		}
	}

	return (FILTER_HANDLED);
}

static phandle_t
mtk_gpio_get_node(device_t bus, device_t dev)
{

	/* We only have one child, the GPIO bus, which needs our own node. */
	return (ofw_bus_get_node(bus));
}

static device_method_t mtk_gpio_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		mtk_gpio_probe),
	DEVMETHOD(device_attach,	mtk_gpio_attach),
	DEVMETHOD(device_detach,	mtk_gpio_detach),

	/* GPIO protocol */
	DEVMETHOD(gpio_get_bus,		mtk_gpio_get_bus),
	DEVMETHOD(gpio_pin_max,		mtk_gpio_pin_max),
	DEVMETHOD(gpio_pin_getname,	mtk_gpio_pin_getname),
	DEVMETHOD(gpio_pin_getflags,	mtk_gpio_pin_getflags),
	DEVMETHOD(gpio_pin_getcaps,	mtk_gpio_pin_getcaps),
	DEVMETHOD(gpio_pin_setflags,	mtk_gpio_pin_setflags),
	DEVMETHOD(gpio_pin_get,		mtk_gpio_pin_get),
	DEVMETHOD(gpio_pin_set,		mtk_gpio_pin_set),
	DEVMETHOD(gpio_pin_toggle,	mtk_gpio_pin_toggle),

	/* Interrupt controller interface */
	DEVMETHOD(pic_disable_intr,	mtk_gpio_pic_disable_intr),
	DEVMETHOD(pic_enable_intr,	mtk_gpio_pic_enable_intr),
	DEVMETHOD(pic_map_intr,		mtk_gpio_pic_map_intr),
	DEVMETHOD(pic_setup_intr,	mtk_gpio_pic_setup_intr),
	DEVMETHOD(pic_post_filter,	mtk_gpio_pic_post_filter),
	DEVMETHOD(pic_post_ithread,	mtk_gpio_pic_post_ithread),
	DEVMETHOD(pic_pre_ithread,	mtk_gpio_pic_pre_ithread),

	/* ofw_bus interface */
	DEVMETHOD(ofw_bus_get_node,	mtk_gpio_get_node),

	DEVMETHOD_END
};

static driver_t mtk_gpio_driver = {
	"gpio",
	mtk_gpio_methods,
	sizeof(struct mtk_gpio_softc),
};

static devclass_t mtk_gpio_devclass;

EARLY_DRIVER_MODULE(mtk_gpio_v1, simplebus, mtk_gpio_driver,
    mtk_gpio_devclass, 0, 0, BUS_PASS_INTERRUPT + BUS_PASS_ORDER_LATE);
