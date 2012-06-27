/*-
 * Copyright (c) 2010-2012 Citrix Inc.
 * Copyright (c) 2009-2012 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2004-2006 Kip Macy
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>

#include <net/bpf.h>

#include <net/if_types.h>
#include <net/if.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <machine/frame.h>
#include <machine/vmparam.h>

#include <sys/bus.h>
#include <sys/rman.h>
#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <machine/atomic.h>

#include <machine/intr_machdep.h>

#include <dev/hyperv/include/hyperv.h>
#include "hv_net_vsc.h"
#include "hv_rndis.h"

/* Short for Hyper-V network interface */
#define NETVSC_DEVNAME    "hn"

/*
 * It looks like offset 0 of buf is reserved to hold the softc pointer.
 * The sc pointer evidently not needed, and is not presently populated.
 * The packet offset is where the netvsc_packet starts in the buffer.
 */
#define HV_NV_SC_PTR_OFFSET_IN_BUF         0
#define HV_NV_PACKET_OFFSET_IN_BUF         16


/*
 * Data types
 * XXXKYS: Rename the device and driver structures
 */
struct net_device_context {
	/* points back to our device context */
	struct hv_device  *device_ctx;
/*	struct net_device_stats stats;	*/
};

/*
 * XXXKYS: May want to combine this with netvsc_driver_object
 */
struct netvsc_driver_context {
	netvsc_driver_object    drv_obj;
	uint32_t		drv_inited;
};

/* Now sx spin lock, as mutexes do not play well with semaphores */
#define SN_LOCK_INIT(_sc, _name) \
	    sx_init_flags(&(_sc)->hn_lock, _name, SX_NOADAPTIVE)
#define SN_LOCK(_sc)		sx_xlock(&(_sc)->hn_lock)
#define SN_LOCK_ASSERT(_sc)	sx_assert(&(_sc)->hn_lock, SA_XLOCKED)
#define SN_UNLOCK(_sc)		sx_xunlock(&(_sc)->hn_lock)
#define SN_LOCK_DESTROY(_sc)	sx_destroy(&(_sc)->hn_lock)


/*
 * Globals
 */

int hv_promisc_mode = 0;    /* normal mode by default */


/* The one and only one */
static struct netvsc_driver_context g_netvsc_drv;

/*
 * Forward declarations
 */
static void hn_stop(hn_softc_t *sc);
static void hn_ifinit_locked(hn_softc_t *sc);
static void hn_ifinit(void *xsc);
static int  hn_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data);
static int  hn_start_locked(struct ifnet *ifp);
static void hn_start(struct ifnet *ifp);

static void netvsc_xmit_completion(void *context);

/*
 * NetVsc driver initialization
 */
static int
netvsc_drv_init(void)
{
	netvsc_driver_object *driver = &g_netvsc_drv.drv_obj;

        hv_rndis_filter_init(driver);

	return (0);
}

/*
 * NetVsc global initialization entry point
 */
static void
netvsc_init(void)
{
	printf("Netvsc initializing... ");

	/*
	 * XXXKYS: cleanup initialization
	 */
	if (!cold && !g_netvsc_drv.drv_inited) {
		g_netvsc_drv.drv_inited = 1;
		netvsc_drv_init();
	} else {
		printf("Already initialized!\n");
	}
}

/* {F8615163-DF3E-46c5-913F-F2D2F965ED0E} */
static const hv_guid g_net_vsc_device_type = {
	.data = {0x63, 0x51, 0x61, 0xF8, 0x3E, 0xDF, 0xc5, 0x46,
		0x91, 0x3F, 0xF2, 0xD2, 0xF9, 0x65, 0xED, 0x0E}
};

/*
 * Standard probe entry point.
 *
 */
static int
netvsc_probe(device_t dev)
{
	const char *p;

	p = vmbus_get_type(dev);
	if (!memcmp(p, &g_net_vsc_device_type.data, sizeof(hv_guid))) {
		device_set_desc(dev, "Synthetic Network Interface");
		printf("Netvsc probe... DONE \n");

		return (0);
	}

	return (ENXIO);
}

/*
 * Standard attach entry point.
 *
 * Called when the driver is loaded.  It allocates needed resources,
 * and initializes the "hardware" and software.
 */
static int
netvsc_attach(device_t dev)
{
	struct hv_device *device_ctx = vmbus_get_devctx(dev);
	netvsc_device_info device_info;
	hn_softc_t *sc;
	int unit = device_get_unit(dev);
	struct ifnet *ifp;
	int ret;

	netvsc_init();

	sc = device_get_softc(dev);
	if (sc == NULL) {
		return (ENOMEM);
	}

	bzero(sc, sizeof(hn_softc_t));
	sc->hn_unit = unit;
	sc->hn_dev = dev;

	SN_LOCK_INIT(sc, "NetVSCLock");

	sc->hn_dev_obj = device_ctx;

	ifp = sc->hn_ifp = sc->arpcom.ac_ifp = if_alloc(IFT_ETHER);
	ifp->if_softc = sc;

	if_initname(ifp, device_get_name(dev), device_get_unit(dev));
	ifp->if_dunit = unit;
	ifp->if_dname = NETVSC_DEVNAME;

	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	ifp->if_ioctl = hn_ioctl;
	ifp->if_start = hn_start;
	ifp->if_init = hn_ifinit;
	/* needed by hv_rf_on_device_add() code */
	ifp->if_mtu = ETHERMTU;
	IFQ_SET_MAXLEN(&ifp->if_snd, 512);
	ifp->if_snd.ifq_drv_maxlen = 511;
	IFQ_SET_READY(&ifp->if_snd);

	ret = hv_rf_on_device_add(device_ctx, &device_info);
	if (ret != 0) {
		if_free(ifp);

		return (ret);
	}
	if (device_info.link_state == 0) {
		sc->hn_carrier = 1;
	}

	ether_ifattach(ifp, device_info.mac_addr);

	return (0);
}

/*
 *
 */
static int
netvsc_detach(device_t dev)
{
	struct hv_device *hv_device = vmbus_get_devctx(dev); 

	printf("netvsc_detach\n");

	/*
	 * XXXKYS:  Need to clean up all our
	 * driver state; this is the driver
	 * unloading.
	 */

	/*
	 * XXXKYS:  Need to stop outgoing traffic and unregister
	 * the netdevice.
	 */

	hv_rf_on_device_remove(hv_device);

	return (0);
}

/*
 *
 */
static int
netvsc_shutdown(device_t dev)
{
	return (0);
}

/*
 * Send completion processing
 *
 * Note:  It looks like offset 0 of buf is reserved to hold the softc
 * pointer.  The sc pointer is not currently needed in this function, and
 * it is not presently populated by the TX function.
 */
static void
netvsc_xmit_completion(void *context)
{
	netvsc_packet *packet = (netvsc_packet *)context;
	struct mbuf *mb;
	uint8_t *buf;

	mb = (struct mbuf *)packet->compl.send.send_completion_tid;
	buf = ((uint8_t *)packet) - HV_NV_PACKET_OFFSET_IN_BUF;

	free(buf, M_DEVBUF);

	if (mb != NULL) {
		m_freem(mb);
	}
}

/*
 * Start a transmit
 */
static int
hn_start_locked(struct ifnet *ifp)
{
	hn_softc_t *sc = ifp->if_softc;
	netvsc_driver_object *net_drv_obj = &g_netvsc_drv.drv_obj;
	struct hv_device *device_ctx = vmbus_get_devctx(sc->hn_dev);
	uint8_t *buf;
	netvsc_packet *packet;
	struct mbuf *m_head, *m;
	int i;
	int num_frags;
	int len;
	int xlen;
	int retries = 0;
	int ret = 0;

	while (!IFQ_DRV_IS_EMPTY(&sc->hn_ifp->if_snd)) {
		IFQ_DRV_DEQUEUE(&sc->hn_ifp->if_snd, m_head);
		if (m_head == NULL) {
			break;
		}

		len = 0;
		num_frags = 0;
		xlen = 0;

		/* Walk the mbuf list computing total length and num frags */
		for (m = m_head; m != NULL; m = m->m_next) {
			if (m->m_len != 0) {
				num_frags++;
				len += m->m_len;
			}
		}

		/*
		 * Reserve the number of pages requested.  Currently,
		 * one page is reserved for the message in the RNDIS
		 * filter packet
		 */
		num_frags += net_drv_obj->additional_request_page_buf_cnt;

		if (num_frags > NETVSC_PACKET_MAXPAGE) {
			/* Exceeds # page_buffers in netvsc_packet */
			return (EINVAL);
		}

		/*
		 * Allocate a buffer with space for a netvsc packet plus a
		 * couple of reserved areas.  First comes a (currently 16
		 * bytes, currently unused) reserved data area.  Second is
		 * the netvsc_packet, which includes (currently 4) page
		 * buffers.  Third is an area reserved for an
		 * rndis_filter_packet struct.
		 * Changed malloc to M_NOWAIT to avoid sleep under spin lock.
		 * No longer reserving extra space for page buffers, as they
		 * are already part of the netvsc_packet.
		 */
		buf = malloc(HV_NV_PACKET_OFFSET_IN_BUF +
		    sizeof(netvsc_packet) + net_drv_obj->request_ext_size,
		    M_DEVBUF, M_ZERO | M_NOWAIT);
		if (buf == NULL) {
			return (ENOMEM);
		}

		packet = (netvsc_packet *)(buf + HV_NV_PACKET_OFFSET_IN_BUF);
		*(vm_offset_t *)buf = HV_NV_SC_PTR_OFFSET_IN_BUF;

		/*
		 * extension points to the area reserved for the
		 * rndis_filter_packet, which is placed just after
		 * the netvsc_packet.
		 */
		packet->extension = packet + 1;

		/* Set up the rndis header */
		packet->page_buf_count = num_frags;

		/* Initialize it from the mbuf */
		packet->tot_data_buf_len = len;

		/*
		 * Fill the page buffers with mbuf info starting at index
		 * additional_request_page_buf_cnt.
		 */
		i = net_drv_obj->additional_request_page_buf_cnt;
		for (m = m_head; m != NULL; m = m->m_next) {
			if (m->m_len) {
				vm_offset_t paddr =
				    vtophys(mtod(m, vm_offset_t));
				packet->page_buffers[i].pfn =
				    paddr >> PAGE_SHIFT;
				packet->page_buffers[i].offset =
				    paddr & (PAGE_SIZE - 1);
				packet->page_buffers[i].length = m->m_len;
				i++;
			}
		}

		/* Set the completion routine */
		packet->compl.send.on_send_completion = netvsc_xmit_completion;
		packet->compl.send.send_completion_context = packet;
		packet->compl.send.send_completion_tid = (uint64_t)m_head;

retry_send:
		/* Removed critical_enter(), does not appear necessary */
		ret = hv_rf_on_send(device_ctx, packet);

		if (ret == 0) {
			ifp->if_opackets++;
			if (ifp->if_bpf) {
				bpf_mtap(ifp->if_bpf, m_head);
			}
		} else {
			retries++;
			if (retries < 4) {
				goto retry_send;
			}

			IF_PREPEND(&ifp->if_snd, m_head);
			ifp->if_drv_flags |= IFF_DRV_OACTIVE;

			/*
			 * Null it since the caller will free it instead of
			 * the completion routine
			 */
			packet->compl.send.send_completion_tid = 0;

			/*
			 * Release the resources since we will not get any
			 * send completion
			 */
			netvsc_xmit_completion(packet);
		}
	}

	return (ret);
}

/*
 * Link up/down notification
 */
void
netvsc_linkstatus_callback(struct hv_device *device_obj, uint32_t status)
{
	hn_softc_t *sc = device_get_softc(device_obj->device);

	if (sc == NULL) {
		return;
	}

	if (status == 1) {
		sc->hn_carrier = 1;
	} else {
		sc->hn_carrier = 0;
	}
}

/*
 * RX Callback.  Called when we receive a data packet from the "wire" on the
 * specified device
 *
 * Fixme:  This is no longer used as a callback
 */
int
netvsc_recv_callback(struct hv_device *device_ctx, netvsc_packet *packet)
{
	hn_softc_t *sc = (hn_softc_t *)device_get_softc(device_ctx->device);
	struct mbuf *m_new;
	struct ifnet *ifp = sc->hn_ifp;
	int i;

	if (sc == NULL) {
		return (0); /* TODO: KYS how can this be! */
	}
	
	ifp = sc->arpcom.ac_ifp;

	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING)) {
		return (0);
	}
	if (packet->tot_data_buf_len > MCLBYTES) {
		return (0);
	}

	MGETHDR(m_new, M_DONTWAIT, MT_DATA);
	if (m_new == NULL) {
		return (0);
	}
	MCLGET(m_new, M_DONTWAIT);
	if ((m_new->m_flags & M_EXT) == 0) {
		m_freem(m_new);
		return (0);
	}

	/*
	 * Copy the received packet to one or more mbufs. 
	 * The copy is required since the memory pointed to by netvsc_packet
	 * cannot be deallocated
	 */
	for (i=0; i < packet->page_buf_count; i++) {
		/* Shift virtual page number to form virtual page address */
		uint8_t *vaddr = (uint8_t *)
		    (packet->page_buffers[i].pfn << PAGE_SHIFT);

		m_append(m_new, packet->page_buffers[i].length,
		    vaddr + packet->page_buffers[i].offset);
	}

	m_new->m_pkthdr.len = m_new->m_len = packet->tot_data_buf_len -
	    ETHER_CRC_LEN;
	m_new->m_pkthdr.rcvif = ifp;

	/*
	 * Note:  Moved RX completion back to hv_nv_on_receive() so all
	 * messages (not just data messages) will trigger a response.
	 */

	ifp->if_ipackets++;
	/* Fixme:  Is the lock held? */
/*	SN_UNLOCK(sc);	*/
	(*ifp->if_input)(ifp, m_new);
/*	SN_LOCK(sc);	*/

	return (0);
}

/*
 * Standard ioctl entry point.  Called when the user wants to configure
 * the interface.
 */
static int
hn_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	hn_softc_t *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *) data;

	int mask, error = 0;

	switch(cmd) {
	case SIOCSIFADDR:
	case SIOCGIFADDR:
		error = ether_ioctl(ifp, cmd, data);
		break;
	case SIOCSIFMTU:
		ifp->if_mtu = ifr->ifr_mtu;
		hn_ifinit(sc);
		break;
	case SIOCSIFFLAGS:
		SN_LOCK(sc);
		if (ifp->if_flags & IFF_UP) {
			/*
			 * If only the state of the PROMISC flag changed,
			 * then just use the 'set promisc mode' command
			 * instead of reinitializing the entire NIC. Doing
			 * a full re-init means reloading the firmware and
			 * waiting for it to start up, which may take a
			 * second or two.
			 */
#ifdef notyet
			/* Fixme:  Promiscuous mode? */
			/* No promiscuous mode with Xen */
			if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
			    ifp->if_flags & IFF_PROMISC &&
			    !(sc->hn_if_flags & IFF_PROMISC)) {
				/* do something here for Hyper-V */
				;
/*				XN_SETBIT(sc, XN_RX_MODE,		*/
/*					  XN_RXMODE_RX_PROMISC);	*/
			} else if (ifp->if_drv_flags & IFF_DRV_RUNNING &&
				   !(ifp->if_flags & IFF_PROMISC) &&
				   sc->hn_if_flags & IFF_PROMISC) {
				/* do something here for Hyper-V */
				;
/*				XN_CLRBIT(sc, XN_RX_MODE,		*/
/*					  XN_RXMODE_RX_PROMISC);	*/
			} else
#endif
				hn_ifinit_locked(sc);
		} else {
			if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
				hn_stop(sc);
			}
		}
		sc->hn_if_flags = ifp->if_flags;
		SN_UNLOCK(sc);
		error = 0;
		break;
	case SIOCSIFCAP:
		mask = ifr->ifr_reqcap ^ ifp->if_capenable;
		if (mask & IFCAP_HWCSUM) {
			if (IFCAP_HWCSUM & ifp->if_capenable) {
				ifp->if_capenable &= ~IFCAP_HWCSUM;
			} else {
				ifp->if_capenable |= IFCAP_HWCSUM;
			}
		}
		error = 0;
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
#ifdef notyet
		/* Fixme:  Multicast mode? */
		if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
			SN_LOCK(sc);
			netvsc_setmulti(sc);
			SN_UNLOCK(sc);
			error = 0;
		}
#endif
		/* FALLTHROUGH */
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
		error = EINVAL;
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}
    
	return (error);
}

/*
 *
 */
static void
hn_stop(hn_softc_t *sc)
{
	struct ifnet *ifp;
	int ret;
	struct hv_device *device_ctx = vmbus_get_devctx(sc->hn_dev);

	SN_LOCK_ASSERT(sc);
	ifp = sc->hn_ifp;

	printf(" Closing Device ...\n");

	ifp->if_drv_flags &= ~(IFF_DRV_RUNNING | IFF_DRV_OACTIVE);
	sc->hn_initdone = 0;

	ret = hv_rf_on_close(device_ctx);
}

/*
 * FreeBSD transmit entry point
 */
static void
hn_start(struct ifnet *ifp)
{
	hn_softc_t *sc;

	sc = ifp->if_softc;
	SN_LOCK(sc);
	hn_start_locked(ifp);
	SN_UNLOCK(sc);
}

/*
 *
 */
static void
hn_ifinit_locked(hn_softc_t *sc)
{
	struct ifnet *ifp;
	struct hv_device *device_ctx = vmbus_get_devctx(sc->hn_dev);
	int ret;

	SN_LOCK_ASSERT(sc);

	ifp = sc->hn_ifp;

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		return;
	}

	hv_promisc_mode = 1;

	ret = hv_rf_on_open(device_ctx);
	if (ret != 0) {
		return;
	} else {
		sc->hn_initdone = 1;
	}
	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
}

/*
 *
 */
static void
hn_ifinit(void *xsc)
{
	hn_softc_t *sc = xsc;

	SN_LOCK(sc);
	hn_ifinit_locked(sc);
	SN_UNLOCK(sc);
}

#ifdef LATER
/*
 *
 */
static void
hn_watchdog(struct ifnet *ifp)
{
	hn_softc_t *sc;
	sc = ifp->if_softc;

	printf("hn%d: watchdog timeout -- resetting\n", sc->hn_unit);
	hn_ifinit(sc);    /*???*/
	ifp->if_oerrors++;
}
#endif

static device_method_t netvsc_methods[] = {
        /* Device interface */
        DEVMETHOD(device_probe,         netvsc_probe),
        DEVMETHOD(device_attach,        netvsc_attach),
        DEVMETHOD(device_detach,        netvsc_detach),
        DEVMETHOD(device_shutdown,      netvsc_shutdown),

        { 0, 0 }
};

static driver_t netvsc_driver = {
        NETVSC_DEVNAME,
        netvsc_methods,
        sizeof(hn_softc_t)
};

static devclass_t netvsc_devclass;

DRIVER_MODULE(hn, vmbus, netvsc_driver, netvsc_devclass, 0, 0);
MODULE_VERSION(hn, 1);
MODULE_DEPEND(hn, vmbus, 1, 1, 1);
SYSINIT(netvsc_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1, netvsc_init,
     NULL);

