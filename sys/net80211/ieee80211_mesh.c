/*- 
 * Copyright (c) 2009 The FreeBSD Foundation 
 * All rights reserved. 
 * 
 * This software was developed by Rui Paulo under sponsorship from the                 
 * FreeBSD Foundation. 
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
#ifdef __FreeBSD__
__FBSDID("$FreeBSD$");
#endif

/*
 * IEEE 802.11s Mesh Point (MBSS) support.
 */
#include "opt_inet.h"
#include "opt_wlan.h"

#include <sys/param.h>
#include <sys/systm.h> 
#include <sys/mbuf.h>   
#include <sys/malloc.h>
#include <sys/kernel.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_media.h>
#include <net/if_llc.h>
#include <net/ethernet.h>

#include <net/bpf.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_mesh.h>
#include <net80211/ieee80211_input.h>

static void	mesh_vattach(struct ieee80211vap *);
static int	mesh_newstate(struct ieee80211vap *, enum ieee80211_state, int);
static int	mesh_input(struct ieee80211_node *, struct mbuf *, int, int,
		    uint32_t);
static void	mesh_recv_mgmt(struct ieee80211_node *, struct mbuf *, int,
		    int, int, uint32_t);

void
ieee80211_mesh_attach(struct ieee80211com *ic)
{
	ic->ic_vattach[IEEE80211_M_MBSS] = mesh_vattach;
}

void
ieee80211_mesh_detach(struct ieee80211com *ic)
{
}

static void
mesh_vdetach(struct ieee80211vap *vap)
{
}

static void
mesh_vattach(struct ieee80211vap *vap)
{
	vap->iv_newstate = mesh_newstate;
	vap->iv_input = mesh_input;
	vap->iv_opdetach = mesh_vdetach;
	vap->iv_recv_mgmt = mesh_recv_mgmt;
}

/*
 * IEEE80211_M_MBSS vap state machine handler.
 */
static int
mesh_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate, int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	enum ieee80211_state ostate;

	IEEE80211_LOCK_ASSERT(ic);

        ostate = vap->iv_state;
        IEEE80211_DPRINTF(vap, IEEE80211_MSG_STATE, "%s: %s -> %s (%d)\n",
            __func__, ieee80211_state_name[ostate],
            ieee80211_state_name[nstate], arg);
        vap->iv_state = nstate;                 /* state transition */
        if (ostate != IEEE80211_S_SCAN)
                ieee80211_cancel_scan(vap);     /* background scan */
	ni = vap->iv_bss;			/* NB: no reference held */
	switch (nstate) {
	case IEEE80211_S_INIT:
		if (ostate == IEEE80211_S_SCAN)
			ieee80211_cancel_scan(vap);
		if (ostate != IEEE80211_S_INIT) {
			/* NB: optimize INIT -> INIT case */
			ieee80211_reset_bss(vap);
		}
		break;
	case IEEE80211_S_SCAN:
		switch (ostate) {
		case IEEE80211_S_INIT:
		}
	case IEEE80211_S_AUTH:
	case IEEE80211_S_ASSOC:
	case IEEE80211_S_CAC:
	case IEEE80211_S_RUN:
	case IEEE80211_S_CSA:
	case IEEE80211_S_SLEEP:
	default:
		break;
	}

	return 0;
}

static int
mesh_input(struct ieee80211_node *ni, struct mbuf *m, int rssi, int noise,
    uint32_t rstamp)
{

	return 0;
}


static void
mesh_recv_mgmt(struct ieee80211_node *ni, struct mbuf *m0, int subtype,
    int rssi, int noise, uint32_t rstamp)
{
	/*struct ieee80211vap *vap = ni->ni_vap;
	struct ieee80211com *ic = ni->ni_ic;*/
	struct ieee80211_frame *wh;
	uint8_t *frm, *efrm;

	wh = mtod(m0, struct ieee80211_frame *);
	frm = (uint8_t *)&wh[1];
	efrm = mtod(m0, uint8_t *) + m0->m_len;
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
	case IEEE80211_FC0_SUBTYPE_BEACON:
	{
		struct ieee80211_scanparams scan;

		/* Parse beacons to discover mesh neighbours */
		if (ieee80211_parse_beacon(ni, m0, &scan) != 0)
			return;
		break;
	}
	default:
		break;
	}

}


static int
mesh_ioctl_get80211(struct ieee80211vap *vap, struct ieee80211req *ireq)
{
	int error;
	uint8_t tmpmeshid[IEEE80211_NWID_LEN];

	error = 0;
	switch (ireq->i_type) {
	case IEEE80211_IOC_MESH_ID:
		if (vap->iv_opmode != IEEE80211_M_MBSS)
			return EINVAL;
		ireq->i_len = vap->iv_meshidlen;
		memcpy(meshid, vap->iv_meshid, ireq->i_len);
		error = copyout(tmpmeshid, ireq->i_data, ireq->i_len);
		break;
	default:
		return ENOSYS;
	}

	return error;
}
IEEE80211_IOCTL_GET(mesh, mesh_ioctl_get80211);

static int
mesh_ioctl_set80211(struct ieee80211vap *vap, struct ieee80211req *ireq)
{
	int error;
	uint8_t tmpmeshid[IEEE80211_NWID_LEN];

	error = 0;
	switch (ireq->i_type) {
	case IEEE80211_IOC_MESH_ID:
		if (ireq->i_val != 0 || ireq->i_len > IEEE80211_NWID_LEN)
			return EINVAL;
		error = copyin(ireq->i_data, tmpmeshid, ireq->i_len);
		if (error)
			break;
		memset(vap->iv_meshid, 0, IEEE80211_NWID_LEN);
		vap->iv_meshidlen = ireq->i_len;
		memcpy(vap->iv_meshid, tmpmeshid, ireq->i_len);
		break;
	default:
		return ENOSYS;
	}

	return error;
}
IEEE80211_IOCTL_SET(mesh, mesh_ioctl_set80211);
