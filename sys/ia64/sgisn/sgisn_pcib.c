/*-
 * Copyright (c) 2010 Marcel Moolenaar
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/pcpu.h>
#include <sys/rman.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcib_private.h>

#include "pcib_if.h"

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/pci_cfgreg.h>
#include <machine/resource.h>
#include <machine/sal.h>
#include <machine/sgisn.h>

static struct sgisn_fwdev sgisn_dev;
static struct sgisn_fwirq sgisn_irq;

struct sgisn_pcib_softc {
	device_t	sc_dev;
	void		*sc_promaddr;
	u_int		sc_domain;
	u_int		sc_busnr;
};

static int sgisn_pcib_attach(device_t);
static int sgisn_pcib_probe(device_t);

static int sgisn_pcib_activate_resource(device_t, device_t, int, int,
    struct resource *);
static int sgisn_pcib_read_ivar(device_t, device_t, int, uintptr_t *);
static int sgisn_pcib_write_ivar(device_t, device_t, int, uintptr_t);

static int sgisn_pcib_maxslots(device_t);
static uint32_t sgisn_pcib_cfgread(device_t, u_int, u_int, u_int, u_int, int);
static void sgisn_pcib_cfgwrite(device_t, u_int, u_int, u_int, u_int, uint32_t,
    int);

#if 0
static int sgisn_pcib_scan(struct sgisn_pcib_softc *, u_int, u_int);
#endif

/*
 * Bus interface definitions.
 */
static device_method_t sgisn_pcib_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		sgisn_pcib_probe),
	DEVMETHOD(device_attach,	sgisn_pcib_attach),

	/* Bus interface */
        DEVMETHOD(bus_read_ivar,	sgisn_pcib_read_ivar),
        DEVMETHOD(bus_write_ivar,	sgisn_pcib_write_ivar),
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_alloc_resource,	bus_generic_alloc_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_release_resource),
	DEVMETHOD(bus_activate_resource, sgisn_pcib_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	/* pcib interface */
	DEVMETHOD(pcib_maxslots,	sgisn_pcib_maxslots),
	DEVMETHOD(pcib_read_config,	sgisn_pcib_cfgread),
	DEVMETHOD(pcib_write_config,	sgisn_pcib_cfgwrite),
	DEVMETHOD(pcib_route_interrupt,	pcib_route_interrupt),

	{ 0, 0 }
};

static driver_t sgisn_pcib_driver = {
	"pcib",
	sgisn_pcib_methods,
	sizeof(struct sgisn_pcib_softc),
};

devclass_t pcib_devclass;

DRIVER_MODULE(pcib, shub, sgisn_pcib_driver, pcib_devclass, 0, 0);

static int
sgisn_pcib_maxslots(device_t dev)
{

	return (PCI_SLOTMAX);
}

static uint32_t
sgisn_pcib_cfgread(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, int bytes)
{
	struct sgisn_pcib_softc *sc;
	uint32_t val;

	sc = device_get_softc(dev);

	val = pci_cfgregread((sc->sc_domain << 8) | bus, slot, func, reg,
	    bytes);
	return (val);
}

static void
sgisn_pcib_cfgwrite(device_t dev, u_int bus, u_int slot, u_int func,
    u_int reg, uint32_t val, int bytes)
{
	struct sgisn_pcib_softc *sc;

	sc = device_get_softc(dev);

	pci_cfgregwrite((sc->sc_domain << 8) | bus, slot, func, reg, val,
	    bytes);
}

static int
sgisn_pcib_activate_resource(device_t dev, device_t child, int type, int rid,
    struct resource *res)
{
	struct ia64_sal_result r;
	struct sgisn_pcib_softc *sc;
	device_t parent;
	void *vaddr;
	uintptr_t func, slot;
	vm_paddr_t paddr;
	u_long base;
	int bar, error;
 
	parent = device_get_parent(child);

	error = BUS_READ_IVAR(parent, child, PCI_IVAR_SLOT, &slot);
	if (!error)
		error = BUS_READ_IVAR(parent, child, PCI_IVAR_FUNCTION, &func);
	if (error)
		return (error);

	sc = device_get_softc(dev);

	r = ia64_sal_entry(SAL_SGISN_IODEV_INFO, sc->sc_domain, sc->sc_busnr,
	    (slot << 3) | func, ia64_tpa((uintptr_t)&sgisn_dev),
	    ia64_tpa((uintptr_t)&sgisn_irq), 0, 0);
	if (r.sal_status != 0)
		return (ENXIO);

	paddr = rman_get_start(res);

	if (type == SYS_RES_IRQ) {
		/* For now, only warn when there's a mismatch. */
		if (paddr != sgisn_irq.irq_nr)
			device_printf(dev, "interrupt mismatch: (actual=%u)\n",
			    sgisn_irq.irq_nr);

	printf("XXX: %s: %u, %u, %u, %u, %u, %#lx\n", __func__,
	    sgisn_irq.irq_tgt_nasid, sgisn_irq.irq_tgt_slice,
	    sgisn_irq.irq_cpuid, sgisn_irq.irq_nr, sgisn_irq.irq_pin,
	    sgisn_irq.irq_tgt_xtaddr);
	printf("\t%u, %p, %p, %u, %#x, %#x, %u\n", sgisn_irq.irq_br_type,
	    sgisn_irq.irq_bridge, sgisn_irq.irq_io_info, sgisn_irq.irq_last,
	    sgisn_irq.irq_cookie, sgisn_irq.irq_flags, sgisn_irq.irq_refcnt);

#if 0
		r = ia64_sal_entry(SAL_SGISN_INTERRUPT, 1 /*alloc*/,
		    sgisn_irq.irq_tgt_nasid,
		    (sgisn_irq.irq_bridge >> 24) & 15
		    ia64_tpa((uintptr_t)&sgisn_irq),
		    paddr,
		    sgisn_irq.irq_tgt_nasid,
		    sgisn_irq.irq_tgt_slice);
		if (r.status != 0)
			return (ENXIO);
#endif

		goto out;
	}

	bar = PCI_RID2BAR(rid);
	if (bar < 0 || bar > PCIR_MAX_BAR_0)
		return (EINVAL);
	base = sgisn_dev.dev_bar[bar];
	if (base != paddr)
		device_printf(dev, "PCI bus address %#lx mapped to CPU "
		    "address %#lx\n", paddr, base);

	/* I/O port space is presented as memory mapped I/O. */
	rman_set_bustag(res, IA64_BUS_SPACE_MEM);
	vaddr = pmap_mapdev(base, rman_get_size(res));
	rman_set_bushandle(res, (bus_space_handle_t) vaddr);
	if (type == SYS_RES_MEMORY)
		rman_set_virtual(res, vaddr);

 out:
	return (rman_activate_resource(res));
}

static int
sgisn_pcib_probe(device_t dev)
{
	device_t parent;
	uintptr_t bus, seg;

	parent = device_get_parent(dev);
	if (parent == NULL)
		return (ENXIO);

	if (BUS_READ_IVAR(parent, dev, SHUB_IVAR_PCISEG, &seg) ||
	    BUS_READ_IVAR(parent, dev, SHUB_IVAR_PCIBUS, &bus))
		return (ENXIO);

	device_set_desc(dev, "SGI PCI-X host controller");
	return (BUS_PROBE_DEFAULT);
}

static int
sgisn_pcib_attach(device_t dev)
{
	struct sgisn_pcib_softc *sc;
	device_t parent;
	uintptr_t bus, seg;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;

	parent = device_get_parent(dev);
	BUS_READ_IVAR(parent, dev, SHUB_IVAR_PCIBUS, &bus);
	sc->sc_busnr = bus;
	BUS_READ_IVAR(parent, dev, SHUB_IVAR_PCISEG, &seg);
	sc->sc_domain = seg;

#if 0
	sgisn_pcib_scan(sc, sc->sc_busnr, sgisn_pcib_maxslots(dev));
#endif

	device_add_child(dev, "pci", -1);
	return (bus_generic_attach(dev));
}

static int
sgisn_pcib_read_ivar(device_t dev, device_t child, int which, uintptr_t *res)
{
	struct sgisn_pcib_softc *sc = device_get_softc(dev);

	switch (which) {
	case PCIB_IVAR_BUS:
		*res = sc->sc_busnr;
		return (0);
	case PCIB_IVAR_DOMAIN:
		*res = sc->sc_domain;
		return (0);
	}
	return (ENOENT);
}

static int
sgisn_pcib_write_ivar(device_t dev, device_t child, int which, uintptr_t value)
{
	struct sgisn_pcib_softc *sc = device_get_softc(dev);

	switch (which) {
	case PCIB_IVAR_BUS:
		sc->sc_busnr = value;
		return (0);
	}
	return (ENOENT);
}

#if 0
static int
sgisn_pcib_scan(struct sgisn_pcib_softc *sc, u_int bus, u_int maxslot)
{
	static struct sgisn_fwdev dev;
	static struct sgisn_fwirq irq;
	struct ia64_sal_result r;
	u_int devfn, func, maxfunc, slot;
	uint8_t hdrtype;

	for (slot = 0; slot <= maxslot; slot++) {
		maxfunc = 0;
		for (func = 0; func <= maxfunc; func++) {
			hdrtype = sgisn_pcib_cfgread(sc->sc_dev, bus, slot,
			    func, PCIR_HDRTYPE, 1);

			if ((hdrtype & PCIM_HDRTYPE) > PCI_MAXHDRTYPE)
				continue;

			if (func == 0 && (hdrtype & PCIM_MFDEV))
				maxfunc = PCI_FUNCMAX;

			printf("XXX: %s: %u:%u:%u:%u: ", __func__,
			    sc->sc_domain, bus, slot, func);

			devfn = (slot << 3) | func;
			r = ia64_sal_entry(SAL_SGISN_IODEV_INFO, sc->sc_domain,
			    bus, devfn, ia64_tpa((uintptr_t)&dev),
			    ia64_tpa((uintptr_t)&irq), 0, 0);

			if (r.sal_status != 0) {
				printf("status %#lx\n", r.sal_status);
				continue;
			}

			printf("handle=%#lx\n", dev.dev_handle);
			printf("  BAR: %#lx, %#lx, %#lx, %#lx, %#lx, %#lx\n",
			    dev.dev_bar[0], dev.dev_bar[1], dev.dev_bar[2],
			    dev.dev_bar[3], dev.dev_bar[4], dev.dev_bar[5]);
			printf("  ROM: %#lx\n", dev.dev_rom);

			printf("  IRT: nodeid=%#x, slice=%#x, cpuid=%#x\n",
			    irq.irq_nasid, irq.irq_slice, irq.irq_cpuid);
			printf("  IRQ: nr=%#x, pin=%#x, xtaddr=%#lx\n",
			    irq.irq_no, irq.irq_pin, irq.irq_xtaddr);
		}
	}

	return (0);
}
#endif
