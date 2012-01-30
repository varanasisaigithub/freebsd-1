/*****************************************************************************
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The following copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2010-2011, Citrix, Inc.
 *
 * Ported from lis21 code drop
 *
 * HyperV channel timesync code
 *
 *****************************************************************************/

/*
 * Copyright (c) 2009, Microsoft Corporation - All rights reserved.
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 */

/* HYPER-V Time Sync IC defs */
#define ICTIMESYNCFLAG_PROBE 			0
#define ICTIMESYNCFLAG_SYNC 			1
#define ICTIMESYNCFLAG_SAMPLE 			2

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <sys/bus.h>
#include <sys/mutex.h>
#include <sys/timetc.h>

#include <hv_osd.h>
#include <hv_ic.h>
#include <hv_vmbus_packet_format.h>
#include <hv_channel_messages.h>
#include <hv_channel_mgmt.h>
#include <hv_vmbus_var.h>
#include <hv_vmbus_api.h>
#include <hv_vmbus.h>
#include <hv_logging.h>
#include <hv_channel.h>

#include "hv_timesync_ic.h"

static void adj_guesttime(winfiletime_t hosttime, UINT8 flags);

void
timesync_channel_cb(void *context) {
	VMBUS_CHANNEL *channel = context;
	uint8_t *buf;
	uint32_t buflen, recvlen;
	uint64_t requestid;
	struct icmsg_hdr *icmsghdrp;
	struct icmsg_negotiate *negop;
	struct ictimesync_data *timedatap;

	DPRINT_ENTER(VMBUS);

	buflen = PAGE_SIZE;

	buf = malloc(buflen, M_DEVBUF, M_NOWAIT);

	if (buf != NULL) {

		VmbusChannelRecvPacket(channel, buf, buflen, &recvlen, &requestid);

		if (recvlen > 0) {

			DPRINT_DBG(VMBUS,
				"timesync packet: recvlen=%d, requestid=%ld",
				recvlen, requestid);

			icmsghdrp = (struct icmsg_hdr *)
					 &buf[sizeof(struct vmbuspipe_hdr)];

			if (icmsghdrp->icmsgtype == ICMSGTYPE_NEGOTIATE) {
				icmsghdrp->icmsgsize = 0x10;
				negop = (struct icmsg_negotiate *)
					 &buf[sizeof(struct vmbuspipe_hdr) +
					      sizeof(struct icmsg_hdr)];
				if (negop->icframe_vercnt == 2 &&
					negop->icversion_data[1].major == 3) {
					negop->icversion_data[0].major = 3;
					negop->icversion_data[0].minor = 0;
					negop->icversion_data[1].major = 3;
					negop->icversion_data[1].minor = 0;
				} else {
					negop->icversion_data[0].major = 1;
					negop->icversion_data[0].minor = 0;
					negop->icversion_data[1].major = 1;
					negop->icversion_data[1].minor = 0;
				}
				negop->icframe_vercnt = 1;
				negop->icmsg_vercnt = 1;
			} else {
				timedatap = (struct ictimesync_data *)
					&buf[sizeof(struct vmbuspipe_hdr) +
					     sizeof(struct icmsg_hdr)];
				adj_guesttime(timedatap->parenttime,
						timedatap->flags);
			}

			icmsghdrp->icflags = ICMSGHDRFLAG_TRANSACTION |
						ICMSGHDRFLAG_RESPONSE;

			VmbusChannelSendPacket(channel, buf, recvlen, requestid,
				VmbusPacketTypeDataInBand, 0);

			free(buf, M_DEVBUF);

		} else {
			// memory allocation error
		}

	}
	DPRINT_EXIT(VMBUS);
}

#define WLTIMEDELTA 116444736000000000L  /* in 100ns unit */
#define ADJ_THRESHOLD 500*1000           /* in nanoseconds */
#define NANO_SEC  1000000000L            /* 10^ 9 nanosecs = 1 sec */

static void
adj_guesttime(winfiletime_t hosttime, UINT8 flags) {
	struct timespec ts, host_ts;
	int64_t tns, host_tns, terr, tmp, tsec;
	int32_t err_sign;
	static int32_t scnt = 50;

	nanotime(&ts);
	tns = ts.tv_sec * NANO_SEC + ts.tv_nsec;
	host_tns = (hosttime - WLTIMEDELTA) * 100;
	terr = host_tns - tns;

	tmp = host_tns;
	tsec = tmp / NANO_SEC;
	host_ts.tv_nsec = (long) (tmp - (tsec * NANO_SEC));
	host_ts.tv_sec = tsec;

	terr = (terr >= 0) ? terr : -terr;

	/* force time sync with host after reboot, restore, etc. */
	if ((flags & ICTIMESYNCFLAG_SYNC) != 0) {
		mtx_lock(&Giant);
		tc_setclock(&host_ts);
		resettodr();
		mtx_unlock(&Giant);
		return;
	}

	if ((flags & ICTIMESYNCFLAG_SAMPLE) != 0) {
		terr = host_tns - tns;

		if (terr >= 0) {
			err_sign = 1;
		} else {
			err_sign = -1;
			terr = -terr;
		}

		if (scnt > 0) {
			scnt--;
			mtx_lock(&Giant);
			tc_setclock(&host_ts);
			resettodr();
			mtx_unlock(&Giant);
			return;
		}
	}
}

