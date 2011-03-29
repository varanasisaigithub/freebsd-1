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
 *
 * $FreeBSD$
 */
#ifndef _MACHINE_SGISN_H_
#define _MACHINE_SGISN_H_

/* SAL functions */
#define	SAL_SGISN_KLCONFIG_ADDR		0x02000005
#define	SAL_SGISN_SAPIC_INFO		0x0200001d
#define	SAL_SGISN_SN_INFO		0x0200001e
#define	SAL_SGISN_PUTC			0x02000021
#define	SAL_SGISN_GETC			0x02000022
#define	SAL_SGISN_POLL			0x02000026
#define	SAL_SGISN_TXBUF			0x02000028
#define	SAL_SGISN_IOHUB_INFO		0x02000055
#define	SAL_SGISN_IOBUS_INFO		0x02000056
#define	SAL_SGISN_IODEV_INFO		0x02000057
#define	SAL_SGISN_FEATURE_GET_PROM	0x02000065
#define	SAL_SGISN_FEATURE_SET_OS	0x02000066

#define	SGISN_GEOID_MODULE(id)		(((id) >> 0) & 0xffffffffu)
#define	SGISN_GEOID_TYPE(id)		(((id) >> 32) & 0xff)
#define	SGISN_GEOID_SLAB(id)		(((id) >> 40) & 0xff)
#define	SGISN_GEOID_ADDIT(id)		(((id) >> 48) & 0xffff);
#define	SGISN_GEOID_CPU_SLICE(id)	((SGISN_GEOID_ADDIT(id) >> 0) & 0xff)
#define	SGISN_GEOID_DEV_BUS(id)		((SGISN_GEOID_ADDIT(id) >> 0) & 0xff)
#define	SGISN_GEOID_DEV_SLOT(id)	((SGISN_GEOID_ADDIT(id) >> 8) & 0xff)
#define	SGISN_GEOID_MEM_BUS(id)		((SGISN_GEOID_ADDIT(id) >> 0) & 0xff)
#define	SGISN_GEOID_MEM_SLOT(id)	((SGISN_GEOID_ADDIT(id) >> 8) & 0xff)

#define	SGISN_GEO_TYPE_INVALID	0
#define	SGISN_GEO_TYPE_MODULE	1
#define	SGISN_GEO_TYPE_NODE	2
#define	SGISN_GEO_TYPE_RTR	3
#define	SGISN_GEO_TYPE_IOC	4
#define	SGISN_GEO_TYPE_DEV	5	/* PCI device */
#define	SGISN_GEO_TYPE_CPU	6
#define	SGISN_GEO_TYPE_MEM	7

#define	SGISN_HUB_NITTES	8
#define	SGISN_HUB_NWIDGETS	16

#define	SHUB_IVAR_PCIBUS	1
#define	SHUB_IVAR_PCISEG	2

struct sgisn_fwhub;

struct sgisn_widget {
	uint32_t		wgt_hwmfg;
	uint32_t		wgt_hwrev;
	uint32_t		wgt_hwpn;
	uint8_t			wgt_port;
	uint8_t			_pad[3];
	struct sgisn_fwhub	*wgt_hub;
	uint64_t		wgt_funcs;
	uint64_t		wgt_vertex;
};

struct sgisn_fwbus {
	uint32_t		bus_asic;
	uint32_t		bus_xid;
	uint32_t		bus_busnr;
	uint32_t		bus_segment;
	uint64_t		bus_ioport_addr;
	uint64_t		bus_memio_addr;
	uint64_t		bus_base;
	struct sgisn_widget	*bus_wgt_info;
};

struct sgisn_fwhub {
	uint64_t		hub_geoid;
	uint16_t		hub_nasid;
	uint16_t		hub_peer_nasid;
	uint32_t		_pad;
	void 			*hub_widgets;
	uint64_t		hub_dma_itte[SGISN_HUB_NITTES];
	struct sgisn_widget	hub_widget[SGISN_HUB_NWIDGETS];

	void	*hdi_nodepda;
	void	*hdi_node_vertex;

	uint32_t		hub_pci_maxseg;
	uint32_t		hub_pci_maxbus;
};

struct sgisn_fwirq {
	uint64_t		_obsolete;
	uint16_t		irq_tgt_nasid;
	uint16_t		_pad1;
	uint32_t		irq_tgt_slice;
	uint32_t		irq_cpuid;
	uint32_t		irq_nr;
	uint32_t		irq_pin;
	uint64_t		irq_tgt_xtaddr;
	uint32_t		irq_br_type;
	uint32_t		_pad2;
	void			*irq_bridge;	/* Originating */
	void			*irq_io_info;
	uint32_t		irq_last;
	uint32_t		irq_cookie;
	uint32_t		irq_flags;
	uint32_t		irq_refcnt;
};

struct sgisn_fwdev {
	uint64_t		dev_bar[6];
	uint64_t		dev_romaddr;
	uint64_t		dev_handle;
	struct sgisn_fwbus	*dev_bus_softc;
	struct sgisn_fwdev	*dev_parent;
	void			*dev_os_devptr;
	struct sgisn_fwirq	*dev_irq;
};

#endif /* !_MACHINE_SGISN_H_ */
