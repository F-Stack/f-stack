/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009, Oleksandr Tymoshenko <gonzo@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/condvar.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>

#include <dev/usb/usb_core.h>
#include <dev/usb/usb_busdma.h>
#include <dev/usb/usb_process.h>
#include <dev/usb/usb_util.h>

#include <dev/usb/usb_controller.h>
#include <dev/usb/usb_bus.h>
#include <dev/usb/controller/ohci.h>
#include <dev/usb/controller/ohcireg.h>

#include <mips/atheros/ar71xxreg.h> /* for stuff in ar71xx_cpudef.h */
#include <mips/atheros/ar71xx_cpudef.h>

static int ar71xx_ohci_attach(device_t dev);
static int ar71xx_ohci_detach(device_t dev);
static int ar71xx_ohci_probe(device_t dev);

struct ar71xx_ohci_softc
{
	struct ohci_softc sc_ohci;
};

static int
ar71xx_ohci_probe(device_t dev)
{
	device_set_desc(dev, "AR71XX integrated OHCI controller");
	return (BUS_PROBE_DEFAULT);
}

static void
ar71xx_ohci_intr(void *arg)
{

	/* XXX TODO: should really see if this was our interrupt.. */
	ar71xx_device_flush_ddr(AR71XX_CPU_DDR_FLUSH_USB);
	ohci_interrupt(arg);
}

static int
ar71xx_ohci_attach(device_t dev)
{
	struct ar71xx_ohci_softc *sc = device_get_softc(dev);
	int err;
	int rid;

	/* initialise some bus fields */
	sc->sc_ohci.sc_bus.parent = dev;
	sc->sc_ohci.sc_bus.devices = sc->sc_ohci.sc_devices;
	sc->sc_ohci.sc_bus.devices_max = OHCI_MAX_DEVICES;
	sc->sc_ohci.sc_bus.dma_bits = 32;

	/* get all DMA memory */
	if (usb_bus_mem_alloc_all(&sc->sc_ohci.sc_bus,
	    USB_GET_DMA_TAG(dev), &ohci_iterate_hw_softc)) {
		return (ENOMEM);
	}

	sc->sc_ohci.sc_dev = dev;

	rid = 0;
	sc->sc_ohci.sc_io_res = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->sc_ohci.sc_io_res == NULL) {
		err = ENOMEM;
		goto error;
	}
	sc->sc_ohci.sc_io_tag = rman_get_bustag(sc->sc_ohci.sc_io_res);
	sc->sc_ohci.sc_io_hdl = rman_get_bushandle(sc->sc_ohci.sc_io_res);
	sc->sc_ohci.sc_io_size = rman_get_size(sc->sc_ohci.sc_io_res);

	rid = 0;
	sc->sc_ohci.sc_irq_res = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_ACTIVE);
	if (sc->sc_ohci.sc_irq_res == NULL) {
		err = ENOMEM;
		goto error;
	}
	sc->sc_ohci.sc_bus.bdev = device_add_child(dev, "usbus", -1);
	if (sc->sc_ohci.sc_bus.bdev == NULL) {
		err = ENOMEM;
		goto error;
	}
	device_set_ivars(sc->sc_ohci.sc_bus.bdev, &sc->sc_ohci.sc_bus);

	err = bus_setup_intr(dev, sc->sc_ohci.sc_irq_res,
	    INTR_TYPE_BIO | INTR_MPSAFE, NULL,
	    ar71xx_ohci_intr, sc, &sc->sc_ohci.sc_intr_hdl);
	if (err) {
		err = ENXIO;
		goto error;
	}

	strlcpy(sc->sc_ohci.sc_vendor, "Atheros", sizeof(sc->sc_ohci.sc_vendor));

	bus_space_write_4(sc->sc_ohci.sc_io_tag, sc->sc_ohci.sc_io_hdl, OHCI_CONTROL, 0);

	err = ohci_init(&sc->sc_ohci);
	if (!err)
		err = device_probe_and_attach(sc->sc_ohci.sc_bus.bdev);

	if (err)
		goto error;
	return (0);

error:
	if (err) {
		ar71xx_ohci_detach(dev);
		return (err);
	}
	return (err);
}

static int
ar71xx_ohci_detach(device_t dev)
{
	struct ar71xx_ohci_softc *sc = device_get_softc(dev);

	/* during module unload there are lots of children leftover */
	device_delete_children(dev);

	/*
	 * Put the controller into reset, then disable clocks and do
	 * the MI tear down.  We have to disable the clocks/hardware
	 * after we do the rest of the teardown.  We also disable the
	 * clocks in the opposite order we acquire them, but that
	 * doesn't seem to be absolutely necessary.  We free up the
	 * clocks after we disable them, so the system could, in
	 * theory, reuse them.
	 */
	bus_space_write_4(sc->sc_ohci.sc_io_tag, sc->sc_ohci.sc_io_hdl,
	    OHCI_CONTROL, 0);

	if (sc->sc_ohci.sc_intr_hdl) {
		bus_teardown_intr(dev, sc->sc_ohci.sc_irq_res, sc->sc_ohci.sc_intr_hdl);
		sc->sc_ohci.sc_intr_hdl = NULL;
	}

	if (sc->sc_ohci.sc_irq_res && sc->sc_ohci.sc_intr_hdl) {
		/*
		 * only call ohci_detach() after ohci_init()
		 */
		ohci_detach(&sc->sc_ohci);

		bus_release_resource(dev, SYS_RES_IRQ, 0, sc->sc_ohci.sc_irq_res);
		sc->sc_ohci.sc_irq_res = NULL;
	}
	if (sc->sc_ohci.sc_io_res) {
		bus_release_resource(dev, SYS_RES_MEMORY, 0, sc->sc_ohci.sc_io_res);
		sc->sc_ohci.sc_io_res = NULL;
		sc->sc_ohci.sc_io_tag = 0;
		sc->sc_ohci.sc_io_hdl = 0;
	}
	usb_bus_mem_free_all(&sc->sc_ohci.sc_bus, &ohci_iterate_hw_softc);

	return (0);
}

static device_method_t ohci_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, ar71xx_ohci_probe),
	DEVMETHOD(device_attach, ar71xx_ohci_attach),
	DEVMETHOD(device_detach, ar71xx_ohci_detach),
	DEVMETHOD(device_suspend, bus_generic_suspend),
	DEVMETHOD(device_resume, bus_generic_resume),
	DEVMETHOD(device_shutdown, bus_generic_shutdown),

	DEVMETHOD_END
};

static driver_t ohci_driver = {
	.name = "ohci",
	.methods = ohci_methods,
	.size = sizeof(struct ar71xx_ohci_softc),
};

static devclass_t ohci_devclass;

DRIVER_MODULE(ohci, apb, ohci_driver, ohci_devclass, 0, 0);
