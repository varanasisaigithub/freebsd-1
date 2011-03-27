/*-
 * Copyright (c) 2011 Marcel Moolenaar
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

#include <vm/vm.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/md_var.h>
#include <machine/resource.h>
#include <machine/sal.h>
#include <machine/sgisn.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/actables.h>
#include <dev/acpica/acpivar.h>

// XXX static struct sgisn_hub sgisn_hub;

struct sgisn_shub_softc {
	struct sgisn_hub	sc_prom_hub;
	device_t	sc_dev;
	void		*sc_promaddr;
	u_int		sc_domain;
	u_int		sc_busnr;
};

static int sgisn_shub_attach(device_t);
static void sgisn_shub_identify(driver_t *, device_t);
static int sgisn_shub_probe(device_t);

static int sgisn_shub_activate_resource(device_t, device_t, int, int,
    struct resource *);
static int sgisn_shub_read_ivar(device_t, device_t, int, uintptr_t *);
static int sgisn_shub_write_ivar(device_t, device_t, int, uintptr_t);

/*
 * Bus interface definitions.
 */
static device_method_t sgisn_shub_methods[] = {
	/* Device interface */
	DEVMETHOD(device_identify,	sgisn_shub_identify),
	DEVMETHOD(device_probe,		sgisn_shub_probe),
	DEVMETHOD(device_attach,	sgisn_shub_attach),

	/* Bus interface */
        DEVMETHOD(bus_read_ivar,	sgisn_shub_read_ivar),
        DEVMETHOD(bus_write_ivar,	sgisn_shub_write_ivar),
	DEVMETHOD(bus_print_child,	bus_generic_print_child),
	DEVMETHOD(bus_alloc_resource,	bus_generic_alloc_resource),
	DEVMETHOD(bus_release_resource,	bus_generic_release_resource),
	DEVMETHOD(bus_activate_resource, sgisn_shub_activate_resource),
	DEVMETHOD(bus_deactivate_resource, bus_generic_deactivate_resource),
	DEVMETHOD(bus_setup_intr,	bus_generic_setup_intr),
	DEVMETHOD(bus_teardown_intr,	bus_generic_teardown_intr),

	{ 0, 0 }
};

static devclass_t sgisn_shub_devclass;
static char sgisn_shub_name[] = "shub";

static driver_t sgisn_shub_driver = {
	sgisn_shub_name,
	sgisn_shub_methods,
	sizeof(struct sgisn_shub_softc),
};


DRIVER_MODULE(shub, nexus, sgisn_shub_driver, sgisn_shub_devclass, 0, 0);

static int
sgisn_shub_activate_resource(device_t dev, device_t child, int type, int rid,
    struct resource *res)
{
#if 0
	struct ia64_sal_result r;
	struct sgisn_shub_softc *sc;
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

		r = ia64_sal_entry(SAL_SGISN_INTERRUPT, 1 /*alloc*/,
		    sgisn_irq.irq_tgt_nasid,
		    (sgisn_irq.irq_bridge >> 24) & 15
		    ia64_tpa((uintptr_t)&sgisn_irq),
		    paddr,
		    sgisn_irq.irq_tgt_nasid,
		    sgisn_irq.irq_tgt_slice);
		if (r.status != 0)
			return (ENXIO);

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
#endif

	return (EDOOFUS);
}

static void
sgisn_shub_dump_sn_info(struct ia64_sal_result *r)
{

	printf("XXX: SHub type: %lu (0=SHub1, 1=SHub2)\n",
	    r->sal_result[0] & 0xff);
	printf("XXX: Max nodes in system: %u\n",
	    1 << ((r->sal_result[0] >> 8) & 0xff));
	printf("XXX: Max nodes in sharing domain: %u\n",
	    1 << ((r->sal_result[0] >> 16) & 0xff));
	printf("XXX: Partition ID: %lu\n", (r->sal_result[0] >> 24) & 0xff);
	printf("XXX: Coherency ID: %lu\n", (r->sal_result[0] >> 32) & 0xff);
	printf("XXX: Region size: %lu\n", (r->sal_result[0] >> 40) & 0xff);

	printf("XXX: NasID mask: %#lx\n", r->sal_result[1] & 0xffff);
	printf("XXX: NasID bit position: %lu\n",
	    (r->sal_result[1] >> 16) & 0xff);

}

static void
sgisn_shub_srat_parse(ACPI_SUBTABLE_HEADER *entry, void *arg)
{
	ACPI_SRAT_CPU_AFFINITY *cpu;
	ACPI_SRAT_MEM_AFFINITY *mem;
	device_t bus, dev;
	uint32_t domain;

	bus = arg;

	/*
	 * Use all possible entry types for learning about domains.
	 * This probably is highly redundant and could possible be
	 * wrong, but it seems more harmful to miss a domain than
	 * anything else.
	 */
	domain = 0;
	switch (entry->Type) {
	case ACPI_SRAT_TYPE_CPU_AFFINITY:
		cpu = (ACPI_SRAT_CPU_AFFINITY *)(void *)entry;
		domain = cpu->ProximityDomainLo |
		    cpu->ProximityDomainHi[0] << 8 |
		    cpu->ProximityDomainHi[1] << 16 |
		    cpu->ProximityDomainHi[2] << 24;
		break;
	case ACPI_SRAT_TYPE_MEMORY_AFFINITY:
		mem = (ACPI_SRAT_MEM_AFFINITY *)(void *)entry;
		domain = mem->ProximityDomain;
		break;
	default:
		return;
	}

	/*
	 * We're done if we've already seen the domain.
	 */
	dev = devclass_get_device(sgisn_shub_devclass, domain);
	if (dev != NULL)
		return;

	if (bootverbose)
		printf("%s: found now domain %u\n", sgisn_shub_name, domain);

	/*
	 * First encounter of this domain. Add a SHub device with a unit
	 * number equal to the domain number. Order the SHub devices by
	 * unit (and thus domain) number.
	 */
	dev = BUS_ADD_CHILD(bus, domain, sgisn_shub_name, domain);
}

static void
sgisn_shub_identify(driver_t *drv, device_t bus)
{
	struct ia64_sal_result r;
	ACPI_TABLE_HEADER *tbl;
	void *ptr;

	KASSERT(drv == &sgisn_shub_driver, ("%s: driver mismatch", __func__));

	/*
	 * The presence of SHub ASICs is conditional upon the platform
	 * (SGI Altix SN). Check that first...
	 */
	r = ia64_sal_entry(SAL_SGISN_SN_INFO, 0, 0, 0, 0, 0, 0, 0);
	if (r.sal_status != 0)
		return;

	if (bootverbose)
		sgisn_shub_dump_sn_info(&r);

	/*
	 * The number of SHub ASICs is determined by the number of nodes
	 * in the SRAT table.
	 */
	tbl = ptr = acpi_find_table(ACPI_SIG_SRAT);
	if (tbl == NULL) {
		printf("WARNING: no SRAT table found...\n");
		return;
	}

	acpi_walk_subtables((uint8_t *)ptr + sizeof(ACPI_TABLE_SRAT),
	    (uint8_t *)ptr + tbl->Length, sgisn_shub_srat_parse, bus);
}

static int
sgisn_shub_probe(device_t dev)
{
	struct sgisn_shub_softc *sc;

	sc = device_get_softc(dev);

	device_set_desc(dev, "SGI SHub ASIC ");
	return (BUS_PROBE_DEFAULT);
}

static int
sgisn_shub_attach(device_t dev)
{
	struct sgisn_shub_softc *sc;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;

	device_add_child(dev, "pci", -1);
	return (bus_generic_attach(dev));
}

static int
sgisn_shub_read_ivar(device_t dev, device_t child, int which, uintptr_t *res)
{
// XXX	struct sgisn_shub_softc *sc = device_get_softc(dev);

	return (ENOENT);
}

static int
sgisn_shub_write_ivar(device_t dev, device_t child, int which, uintptr_t value)
{
// XXX	struct sgisn_shub_softc *sc = device_get_softc(dev);

	return (ENOENT);
}
