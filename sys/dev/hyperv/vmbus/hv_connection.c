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
 * HyperV vmbus connection functionality
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
 *   K. Y. Srinivasan <kys@microsoft.com>
 */

#include <sys/types.h>
#include <machine/bus.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>


#include "../include/hyperv.h"
#include "vmbus_priv.h"

//
// Globals
//

VMBUS_CONNECTION gVmbusConnection =
	{ .ConnectState = Disconnected,
	  .NextGpadlHandle = 0xE1E10, };

/*++

 Name:
 VmbusConnect()

 Description:
 Sends a connect request on the partition service connection

 --*/
int
VmbusConnect(void) {
	int ret = 0;
	VMBUS_CHANNEL_MSGINFO *msgInfo = NULL;
	VMBUS_CHANNEL_INITIATE_CONTACT *msg;


	// Make sure we are not connecting or connected
	if (gVmbusConnection.ConnectState != Disconnected) {
		return -1;
	}

	// Initialize the vmbus connection
	gVmbusConnection.ConnectState = Connecting;
	gVmbusConnection.WorkQueue = work_queue_create("vmbusQ");
	sema_init(&gVmbusConnection.control_sema, 1, "control_sema");

	TAILQ_INIT(&gVmbusConnection.channel_msg_anchor);
	mtx_init(&gVmbusConnection.ChannelMsgLock, "vmbus channel msg",
		NULL, MTX_SPIN);

	TAILQ_INIT(&gVmbusConnection.channel_anchor);
	mtx_init(&gVmbusConnection.ChannelLock, "vmbus channel",
		NULL, MTX_SPIN);

	// Set up the vmbus event connection for channel interrupt abstraction
	// stuff
	gVmbusConnection.InterruptPage = contigmalloc(PAGE_SIZE, M_DEVBUF,
					 M_NOWAIT | M_ZERO, 0UL, BUS_SPACE_MAXADDR,
					 PAGE_SIZE, 0);

	if (gVmbusConnection.InterruptPage == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	gVmbusConnection.RecvInterruptPage = gVmbusConnection.InterruptPage;
	gVmbusConnection.SendInterruptPage =
		((uint8_t *) gVmbusConnection.InterruptPage + (PAGE_SIZE >> 1));

	// Set up the monitor notification facility. The 1st page for
	// parent->child and the 2nd page for child->parent
	gVmbusConnection.MonitorPages = contigmalloc(2*PAGE_SIZE, M_DEVBUF,
					 M_NOWAIT | M_ZERO,
					 0UL, BUS_SPACE_MAXADDR,
					 PAGE_SIZE, 0);

	if (gVmbusConnection.MonitorPages == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	msgInfo = (VMBUS_CHANNEL_MSGINFO*)
			malloc(sizeof(VMBUS_CHANNEL_MSGINFO) +
				sizeof(VMBUS_CHANNEL_INITIATE_CONTACT),
				M_DEVBUF, M_NOWAIT | M_ZERO);

	if (msgInfo == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	sema_init(&msgInfo->wait_sema, 0, "Msg Info Sema");
	msg = (VMBUS_CHANNEL_INITIATE_CONTACT*) msgInfo->Msg;

	msg->Header.MessageType = ChannelMessageInitiateContact;
	msg->VMBusVersionRequested = VMBUS_REVISION_NUMBER;
	msg->InterruptPage = get_phys_addr(gVmbusConnection.InterruptPage);
	msg->MonitorPage1 = get_phys_addr(gVmbusConnection.MonitorPages);
	msg->MonitorPage2 =
		get_phys_addr(((uint8_t *) gVmbusConnection.MonitorPages
					+ PAGE_SIZE));

	// Add to list before we send the request since we may receive the
	// response before returning from this routine
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, msgInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);


	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_INITIATE_CONTACT));
	if (ret != 0) {
		mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
		TAILQ_REMOVE(&gVmbusConnection.channel_msg_anchor, msgInfo, MsgListEntry);
		mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);
		goto Cleanup;
	}

	// Wait for the connection response
	ret = sema_timedwait(&msgInfo->wait_sema, 500); //KYS 5 seconds


	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_REMOVE(&gVmbusConnection.channel_msg_anchor, msgInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

	// Check if successful
	if (msgInfo->Response.VersionResponse.VersionSupported) {
		gVmbusConnection.ConnectState = Connected;
	} else {
		ret = -ECONNREFUSED;
		goto Cleanup;
	}

	sema_destroy(&msgInfo->wait_sema);
	free(msgInfo, M_DEVBUF);

	return 0;

Cleanup:

	gVmbusConnection.ConnectState = Disconnected;

	work_queue_close(gVmbusConnection.WorkQueue);
	sema_destroy(&gVmbusConnection.control_sema);
	mtx_destroy(&gVmbusConnection.ChannelLock);
	mtx_destroy(&gVmbusConnection.ChannelMsgLock);

	if (gVmbusConnection.InterruptPage) {
		contigfree(gVmbusConnection.InterruptPage, PAGE_SIZE, M_DEVBUF);
		gVmbusConnection.InterruptPage = NULL;
	}

	if (gVmbusConnection.MonitorPages) {
		contigfree(gVmbusConnection.MonitorPages, 2 * PAGE_SIZE, M_DEVBUF);
		gVmbusConnection.MonitorPages = NULL;
	}

	if (msgInfo) {
		sema_destroy(&msgInfo->wait_sema);
		free(msgInfo, M_DEVBUF);
	}


	return ret;
}

/*++

 Name:
 VmbusDisconnect()

 Description:
 Sends a disconnect request on the partition service connection

 --*/
int
VmbusDisconnect(void) {
	int ret = 0;
	VMBUS_CHANNEL_UNLOAD *msg;

	msg = malloc(sizeof(VMBUS_CHANNEL_UNLOAD), M_DEVBUF, M_NOWAIT | M_ZERO);

	if (!msg)
		return -ENOMEM;

	msg->MessageType = ChannelMessageUnload;

	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_UNLOAD));

	KASSERT(ret == 0, ("Message Post Failed\n"));

	contigfree(gVmbusConnection.InterruptPage, PAGE_SIZE, M_DEVBUF);

	mtx_destroy(&gVmbusConnection.ChannelMsgLock);

	work_queue_close(gVmbusConnection.WorkQueue);
	sema_destroy(&gVmbusConnection.control_sema);

	gVmbusConnection.ConnectState = Disconnected;

	free(msg, M_DEVBUF);

	return ret;
}


/*++

 Name:
 GetChannelFromRelId()

 Description:
 Get the channel object given its child relative id (ie channel id)

 XXX Consider optimization where relids are stored in a fixed size array
 and channels are accessed without the need to take this lock or search the list.
 --*/
VMBUS_CHANNEL*
GetChannelFromRelId(uint32_t relId) {
	VMBUS_CHANNEL* channel;
	VMBUS_CHANNEL* foundChannel = NULL;

	mtx_lock_spin(&gVmbusConnection.ChannelLock);
	TAILQ_FOREACH(channel, &gVmbusConnection.channel_anchor, ListEntry) {

		if (channel->OfferMsg.ChildRelId == relId) {
			foundChannel = channel;
			break;
		}
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelLock);

	return foundChannel;
}

/*++

 Name:
 VmbusProcessChannelEvent()

 Description:
 Process a channel event notification

 --*/
static void
VmbusProcessChannelEvent(uint32_t relid) 
{

	VMBUS_CHANNEL* channel;

	/*
	 * Find the channel based on this relid and invokes
	 * the channel callback to process the event
	 */

	channel = GetChannelFromRelId(relid);

	if (!channel) {
		return;
	}
	/*
	 * To deal with the race condition where we might
	 * receive a packet while the relevant driver is 
	 * being unloaded, dispatch the callback while 
	 * holding the channel lock. The unloading driver
	 * will acquire the same channel lock to set the
	 * callback to NULL. This closes the window.
	 */

	mtx_lock_spin(&channel->InboundLock);
	if (channel->OnChannelCallback != NULL)
		channel->OnChannelCallback(channel->ChannelCallbackContext);

	mtx_unlock_spin(&channel->InboundLock);

}

/*++

 Name:
vmbus_on_events()

 Description:
 Handler for events

 --*/
void
vmbus_on_events(void *arg) 
{
	int dword;
	//int maxdword = PAGE_SIZE >> 3; // receive size is 1/2 page and divide that by 4 bytes
	int maxdword = MAX_NUM_CHANNELS_SUPPORTED >> 5;
	int bit;
	int relid;
	uint32_t* recvInterruptPage = gVmbusConnection.RecvInterruptPage;

	// Check events
	if (recvInterruptPage) {
		for (dword = 0; dword < maxdword; dword++) {
			if (recvInterruptPage[dword]) {
				for (bit = 0; bit < 32; bit++) {
					if (synch_test_and_clear_bit(bit,
						(uint32_t *)&recvInterruptPage[dword])) {
						relid = (dword << 5) + bit;

						if (relid == 0) {
							/* 
							 * Special case -
							 * vmbus channel protocol msg.
							 */
							continue;
						} else {
							VmbusProcessChannelEvent(relid);

						}
					}
				}
			}
		}
	}

	return;
}

/*++

 Name:
 VmbusPostMessage()

 Description:
 Send a msg on the vmbus's message connection

 --*/
int VmbusPostMessage(void *buffer, size_t bufferLen) {
	int ret = 0;
	HV_CONNECTION_ID connId;
	int retries = 0;

	while (retries < 3) {
		connId.Asuint32_t = 0;
		connId.u.Id = VMBUS_MESSAGE_CONNECTION_ID;
		ret = HvPostMessage(connId, 1, buffer, bufferLen);
		if (ret != HV_STATUS_INSUFFICIENT_BUFFERS)
                        return ret;
		retries++;
		DELAY(100); //KYS We should use a blocking wait call.
	}

	return ret;
}

/*++

 Name:
 VmbusSetEvent()

 Description:
 Send an event notification to the parent

 --*/
int
VmbusSetEvent(uint32_t childRelId) {
	int ret = 0;


	// Each uint32_t represents 32 channels
	synch_set_bit(childRelId & 31,
		(((uint32_t *)gVmbusConnection.SendInterruptPage + (childRelId >> 5))));
	ret = HvSignalEvent();

	return ret;
}

