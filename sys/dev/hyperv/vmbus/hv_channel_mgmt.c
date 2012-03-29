/*-
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
 * HyperV channel code
 *
 */

/*-
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


#include <sys/param.h>
#include <sys/mbuf.h>

#include "../include/hyperv.h"
#include "vmbus_priv.h"

//
// Data types
//

typedef void (*PFN_CHANNEL_MESSAGE_HANDLER)(VMBUS_CHANNEL_MESSAGE_HEADER* msg);

typedef struct _VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY {
	VMBUS_CHANNEL_MESSAGE_TYPE messageType;
	PFN_CHANNEL_MESSAGE_HANDLER messageHandler;
} VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY;

/*
 *
 * Implementation of the work abstraction.
 */

static void work_item_callback(void *work, int pending) 

{
	struct work_item *w = (struct work_item *)work;

	/*
	 * Serialize work execution.
	 */

	sema_wait(&w->wq->work_sema);

	w->callback(w->context);

	sema_post(&w->wq->work_sema);

	free(w, M_DEVBUF);
}

struct work_queue *work_queue_create(char* name)
{
	static unsigned int qid = 0;
	char qname[64];
	int pri;
	struct work_queue *wq;

	wq = malloc(sizeof(struct work_queue), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!wq) {
		printf("Failed to create WorkQueue\n");
		return (NULL);
	}

	/*
	 * XXXKYS: We use work abstraction to handle messages
	 * coming from the host and these are typically offers.
	 * Some FreeBsd drivers appear to have a concurrency issue
	 * where probe/attach needs to be serialized. We ensure that
	 * by having only one thread process work elements in a 
	 * specific queue by serializing work execution.
	 *
	 */
	sema_init(&wq->work_sema, 1, "work_sema");
	if (strcmp(name, "vmbusQ") == 0) {
		pri = PI_DISK;
	} else {
		pri = PI_NET;
	}

	sprintf(qname, "hv_%s_%u", name, qid);

	/*
	 * Fixme:  FreeBSD 8.2 has a different prototype for
	 * taskqueue_create(), and for certain other taskqueue functions.
	 * We need to research the implications of these changes.
	 * Fixme:  Not sure when the changes were introduced.
	 */
	wq->queue = taskqueue_create(qname, M_NOWAIT, taskqueue_thread_enqueue,
		&wq->queue
#if __FreeBSD_version < 800000
		, &wq->proc
#endif
		);

	if (wq->queue == NULL) {
		sema_destroy(&wq->work_sema);
		free(wq, M_DEVBUF);
		return (NULL);
	}

	if (taskqueue_start_threads(&wq->queue, 1, pri, "%s taskq", qname)) {
		taskqueue_free(wq->queue);
		sema_destroy(&wq->work_sema);
		free(wq, M_DEVBUF);
		return (NULL);
	}

	qid++;

	return (wq);
}

void work_queue_close(struct work_queue *wq)
{
	/*
	 * XXXKYS: Need to drain the taskqueue
	 * before we close the work_queue.
	 */
//KYS	taskqueue_drain(wq->tq, );
	taskqueue_free(wq->queue);
	sema_destroy(&wq->work_sema);
	free(wq, M_DEVBUF);
}

int queue_work_item(struct work_queue *wq, void (*callback)(void *), void *context)
{
	struct work_item *w = malloc(sizeof(struct work_item), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!w) {
		printf("Failed to create WorkItem\n");
		return (-ENOMEM);
	}

	w->callback = callback;
	w->context = context;
	w->wq = wq;

	TASK_INIT(&w->work, 0, work_item_callback, w);

	return (taskqueue_enqueue(wq->queue, &w->work));
}

//
// Internal routines
//

static void
VmbusChannelOnOffer(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);
static void
VmbusChannelOnOpenResult(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelOnOfferRescind(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelOnGpadlCreated(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelOnGpadlTorndown(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelOnOffersDelivered(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelOnVersionResponse(PVMBUS_CHANNEL_MESSAGE_HEADER hdr);

static void
VmbusChannelProcessOffer(void *context);


// Channel message dispatch table
VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY gChannelMessageTable[ChannelMessageCount] = {
	{ ChannelMessageInvalid, NULL },
	{ ChannelMessageOfferChannel, VmbusChannelOnOffer },
	{ ChannelMessageRescindChannelOffer, VmbusChannelOnOfferRescind },
	{ ChannelMessageRequestOffers, NULL },
	{ ChannelMessageAllOffersDelivered,VmbusChannelOnOffersDelivered },
	{ ChannelMessageOpenChannel,NULL },
	{ ChannelMessageOpenChannelResult,VmbusChannelOnOpenResult },
	{ ChannelMessageCloseChannel, NULL },
	{ ChannelMessageGpadlHeader, NULL },
	{ ChannelMessageGpadlBody, NULL },
	{ ChannelMessageGpadlCreated, VmbusChannelOnGpadlCreated },
	{ ChannelMessageGpadlTeardown, NULL },
	{ ChannelMessageGpadlTorndown, VmbusChannelOnGpadlTorndown },
	{ ChannelMessageRelIdReleased, NULL },
	{ ChannelMessageInitiateContact, NULL },
	{ ChannelMessageVersionResponse, VmbusChannelOnVersionResponse },
	{ ChannelMessageUnload, NULL }, };


/*++

 Name:
 VmbusChannelProcessRescindOffer()

 Description:
 Rescind the offer by initiating a device removal

 --*/
static void
VmbusChannelProcessRescindOffer(void *context) 
{
	VMBUS_CHANNEL* channel = (VMBUS_CHANNEL*) context;

	vmbus_child_device_unregister(channel->device);

}

/*++

 Name:
 AllocVmbusChannel()

 Description:
 Allocate and initialize a vmbus channel object

 --*/
VMBUS_CHANNEL*
AllocVmbusChannel(void) {
	VMBUS_CHANNEL* channel;

	channel = (VMBUS_CHANNEL*) malloc(sizeof(VMBUS_CHANNEL), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!channel) {
		return NULL;
	}

	mtx_init(&channel->InboundLock, "channel inbound", NULL, MTX_SPIN);

	channel->ControlWQ = work_queue_create("control");
	if (!channel->ControlWQ) {
		mtx_destroy(&channel->InboundLock);
		free(channel, M_DEVBUF);
		return NULL;
	}

	return channel;
}

/*++

 Name:
 ReleaseVmbusChannel()

 Description:
 Release the vmbus channel object itself

 --*/
static inline void
ReleaseVmbusChannel(void* Context) {
	VMBUS_CHANNEL* channel = (VMBUS_CHANNEL*) Context;

	work_queue_close(channel->ControlWQ);
	free(channel, M_DEVBUF);
}

/*++

 Name:
 FreeVmbusChannel()

 Description:
 Release the resources used by the vmbus channel object

 --*/
void
FreeVmbusChannel(VMBUS_CHANNEL* Channel) {
	mtx_destroy(&Channel->InboundLock);

	// We have to release the channel's workqueue/thread in the vmbus's workqueue/thread context
	// ie we can't destroy ourselves.
	queue_work_item(gVmbusConnection.WorkQueue, ReleaseVmbusChannel,
		(void*) Channel);
}


/*++

 Name:
 VmbusChannelProcessOffer()

 Description:
 Process the offer by creating a channel/device associated with this offer

 --*/
static void
VmbusChannelProcessOffer(void *context) {
	int ret = 0;
	VMBUS_CHANNEL* newChannel = (VMBUS_CHANNEL*) context;
	bool fNew = true;
	VMBUS_CHANNEL* channel;

	// Make sure this is a new offer
	mtx_lock_spin(&gVmbusConnection.ChannelLock);

	LIST_FOREACH(channel, &gVmbusConnection.channel_anchor, ListEntry) {

		if (!memcmp(&channel->OfferMsg.Offer.InterfaceType,
			&newChannel->OfferMsg.Offer.InterfaceType, sizeof(GUID))
			&& !memcmp(&channel->OfferMsg.Offer.InterfaceInstance,
				&newChannel->OfferMsg.Offer.InterfaceInstance,
				sizeof(GUID))) {
			fNew = false;
			break;
		}
	}

	if (fNew) {
		LIST_INSERT_HEAD(&gVmbusConnection.channel_anchor, newChannel, ListEntry);
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelLock);

	if (!fNew) {
		FreeVmbusChannel(newChannel);
		return;
	}

	// Start the process of binding this offer to the driver
	// We need to set the device field before calling VmbusChildDeviceAdd()
	newChannel->device = vmbus_child_device_create(
		newChannel->OfferMsg.Offer.InterfaceType,
		newChannel->OfferMsg.Offer.InterfaceInstance, newChannel);

	// todo - the CHANNEL_OPEN_STATE flag should not be set below but in the "open" channel
	//			request. The ret != 0 logic below doesn't take into account that a channel
	//          may have been opened successfully

	// Add the new device to the bus. This will kick off device-driver binding
	// which eventually invokes the device driver's AddDevice() method.
	ret = vmbus_child_device_register(newChannel->device);
	if (ret != 0) {
		mtx_lock_spin(&gVmbusConnection.ChannelLock);
		LIST_REMOVE(newChannel, ListEntry);
		mtx_unlock_spin(&gVmbusConnection.ChannelLock);

		FreeVmbusChannel(newChannel);
	} else {
		// This state is used to indicate a successful open 
		// so that when we do close the channel normally,
		// we can cleanup properly
		newChannel->State = CHANNEL_OPEN_STATE;

	} 
}


/*++

 Name:
 VmbusChannelOnOffer()

 Description:
 Handler for channel offers from vmbus in parent partition. We ignore all offers except
 network and storage offers. For each network and storage offers, we create a channel object
 and queue a work item to the channel object to process the offer synchronously

 --*/
static void
VmbusChannelOnOffer(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_OFFER_CHANNEL* offer = (VMBUS_CHANNEL_OFFER_CHANNEL*) hdr;
	VMBUS_CHANNEL* newChannel;

	GUID *guidType;
	GUID *guidInstance;

	guidType = &offer->Offer.InterfaceType;
	guidInstance = &offer->Offer.InterfaceInstance;


	// Allocate the channel object and save this offer.
	newChannel = AllocVmbusChannel();
	if (!newChannel)
		return;


	memcpy(&newChannel->OfferMsg, offer,
		sizeof(VMBUS_CHANNEL_OFFER_CHANNEL));
	newChannel->MonitorGroup = (uint8_t) offer->MonitorId / 32;
	newChannel->MonitorBit = (uint8_t) offer->MonitorId % 32;

	// TODO: Make sure the offer comes from our parent partition
	queue_work_item(newChannel->ControlWQ, VmbusChannelProcessOffer,
		newChannel);

}

/*++

 Name:
 VmbusChannelOnOfferRescind()

 Description:
 Rescind offer handler. We queue a work item to process this offer
 synchronously

 --*/
static void
VmbusChannelOnOfferRescind(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_RESCIND_OFFER* rescind =
		(VMBUS_CHANNEL_RESCIND_OFFER*) hdr;
	VMBUS_CHANNEL* channel;

	channel = GetChannelFromRelId(rescind->ChildRelId);
	if (channel == NULL) 
		return;

	queue_work_item(channel->ControlWQ,
		VmbusChannelProcessRescindOffer, channel);

}

/*++

 Name:
 VmbusChannelOnOffersDelivered()

 Description:
 This is invoked when all offers have been delivered.
 Nothing to do here.

 --*/
static void
VmbusChannelOnOffersDelivered(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
}

/*++

 Name:
 VmbusChannelOnOpenResult()

 Description:
 Open result handler. This is invoked when we received a response
 to our channel open request. Find the matching request, copy the
 response and signal the requesting thread.

 --*/
static void
VmbusChannelOnOpenResult(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_OPEN_RESULT* result = (VMBUS_CHANNEL_OPEN_RESULT*) hdr;
	VMBUS_CHANNEL_MSGINFO* msgInfo;
	VMBUS_CHANNEL_MESSAGE_HEADER* requestHeader;
	VMBUS_CHANNEL_OPEN_CHANNEL* openMsg;


	// Find the open msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	LIST_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (VMBUS_CHANNEL_MESSAGE_HEADER*) msgInfo->Msg;

		if (requestHeader->MessageType == ChannelMessageOpenChannel) {
			openMsg = (VMBUS_CHANNEL_OPEN_CHANNEL*) msgInfo->Msg;
			if (openMsg->ChildRelId == result->ChildRelId
				&& openMsg->OpenId == result->OpenId) {
				memcpy(&msgInfo->Response.OpenResult, result,
					sizeof(VMBUS_CHANNEL_OPEN_RESULT));
				sema_post(&msgInfo->wait_sema);
				break;
			}
		}
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

}

/*++

 Name:
 VmbusChannelOnGpadlCreated()

 Description:
 GPADL created handler. This is invoked when we received a response
 to our gpadl create request. Find the matching request, copy the
 response and signal the requesting thread.

 --*/
static void
VmbusChannelOnGpadlCreated(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_GPADL_CREATED *gpadlCreated =
		(VMBUS_CHANNEL_GPADL_CREATED*) hdr;
	VMBUS_CHANNEL_MSGINFO *msgInfo;
	VMBUS_CHANNEL_MESSAGE_HEADER *requestHeader;
	VMBUS_CHANNEL_GPADL_HEADER *gpadlHeader;


	// Find the establish msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	LIST_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (VMBUS_CHANNEL_MESSAGE_HEADER*) msgInfo->Msg;

		if (requestHeader->MessageType == ChannelMessageGpadlHeader) {
			gpadlHeader =
				(VMBUS_CHANNEL_GPADL_HEADER*) requestHeader;

			if ((gpadlCreated->ChildRelId == gpadlHeader->ChildRelId)
				&& (gpadlCreated->Gpadl == gpadlHeader->Gpadl)) {
				memcpy(&msgInfo->Response.GpadlCreated,
					gpadlCreated,
					sizeof(VMBUS_CHANNEL_GPADL_CREATED));
				sema_post(&msgInfo->wait_sema);
				break;
			}
		}
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

}

/*++

 Name:
 VmbusChannelOnGpadlTorndown()

 Description:
 GPADL torndown handler. This is invoked when we received a response
 to our gpadl teardown request. Find the matching request, copy the
 response and signal the requesting thread.

 --*/
static void
VmbusChannelOnGpadlTorndown(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_GPADL_TORNDOWN* gpadlTorndown =
		(VMBUS_CHANNEL_GPADL_TORNDOWN*) hdr;
	VMBUS_CHANNEL_MSGINFO* msgInfo;
	VMBUS_CHANNEL_MESSAGE_HEADER *requestHeader;
	VMBUS_CHANNEL_GPADL_TEARDOWN *gpadlTeardown;


	// Find the open msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	LIST_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (VMBUS_CHANNEL_MESSAGE_HEADER*) msgInfo->Msg;

		if (requestHeader->MessageType == ChannelMessageGpadlTeardown) {
			gpadlTeardown =
				(VMBUS_CHANNEL_GPADL_TEARDOWN*) requestHeader;

			if (gpadlTorndown->Gpadl == gpadlTeardown->Gpadl) {
				memcpy(&msgInfo->Response.GpadlTorndown,
					gpadlTorndown,
					sizeof(VMBUS_CHANNEL_GPADL_TORNDOWN));
				sema_post(&msgInfo->wait_sema);
				break;
			}
		}
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

}

/*++

 Name:
 VmbusChannelOnVersionResponse()

 Description:
 Version response handler. This is invoked when we received a response
 to our initiate contact request. Find the matching request, copy the
 response and signal the requesting thread.

 --*/
static void
VmbusChannelOnVersionResponse(PVMBUS_CHANNEL_MESSAGE_HEADER hdr) {
	VMBUS_CHANNEL_MSGINFO *msgInfo;
	VMBUS_CHANNEL_MESSAGE_HEADER *requestHeader;
	VMBUS_CHANNEL_INITIATE_CONTACT *initiate;
	VMBUS_CHANNEL_VERSION_RESPONSE *versionResponse =
		(VMBUS_CHANNEL_VERSION_RESPONSE*) hdr;


	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	LIST_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (VMBUS_CHANNEL_MESSAGE_HEADER*) msgInfo->Msg;

		if (requestHeader->MessageType
			== ChannelMessageInitiateContact) {
			initiate =
				(VMBUS_CHANNEL_INITIATE_CONTACT*) requestHeader;
			memcpy(&msgInfo->Response.VersionResponse,
				versionResponse,
				sizeof(VMBUS_CHANNEL_VERSION_RESPONSE));
			sema_post(&msgInfo->wait_sema);
		}
	}
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

}

/*++

 Name:
 VmbusOnChannelMessage()

 Description:
 Handler for channel protocol messages.
 This is invoked in the vmbus worker thread context.

 --*/
void
VmbusOnChannelMessage(void *Context) {
	HV_MESSAGE *msg = (HV_MESSAGE*) Context;
	VMBUS_CHANNEL_MESSAGE_HEADER* hdr;
	int size;


	hdr = (VMBUS_CHANNEL_MESSAGE_HEADER*) msg->u.Payload;
	size = msg->Header.PayloadSize;


	if (hdr->MessageType >= ChannelMessageCount) {
		free(msg, M_DEVBUF);
		return;
	}

	if (gChannelMessageTable[hdr->MessageType].messageHandler) {
		gChannelMessageTable[hdr->MessageType].messageHandler(hdr);
	}

	// Free the msg that was allocated in VmbusOnMsgDPC()
	free(msg, M_DEVBUF);
}

/*++

 Name:
 VmbusChannelRequestOffers()

 Description:
 Send a request to get all our pending offers.

 --*/
int
VmbusChannelRequestOffers(void) {
	int ret = 0;
	VMBUS_CHANNEL_MESSAGE_HEADER* msg;
	VMBUS_CHANNEL_MSGINFO* msgInfo;

	msgInfo = (VMBUS_CHANNEL_MSGINFO *)
	        malloc(sizeof(VMBUS_CHANNEL_MSGINFO) +
	          sizeof(VMBUS_CHANNEL_MESSAGE_HEADER), M_DEVBUF, M_NOWAIT);

	if (!msgInfo) {
		printf("VMBUS: Request Offers malloc failed\n");
		return -ENOMEM;
	}

	msg = (VMBUS_CHANNEL_MESSAGE_HEADER*) msgInfo->Msg;
	msg->MessageType = ChannelMessageRequestOffers;

	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_MESSAGE_HEADER));
	if (ret != 0) 
		printf("VMBUS: Request Offers PostMessage failed\n");

	if (msgInfo)
		free(msgInfo, M_DEVBUF);

	return ret;
}

/*++

 Name:
 VmbusChannelReleaseUnattachedChannels()

 Description:
 Release channels that are unattached/unconnected ie (no drivers associated)

 --*/
void
VmbusChannelReleaseUnattachedChannels(void) 
{
	VMBUS_CHANNEL *channel;

	mtx_lock_spin(&gVmbusConnection.ChannelLock);

	while (!LIST_EMPTY(&gVmbusConnection.channel_anchor)) {
		channel = LIST_FIRST(&gVmbusConnection.channel_anchor);
		LIST_REMOVE(channel, ListEntry);

		vmbus_child_device_unregister(channel->device);
		FreeVmbusChannel(channel);

	}
	mtx_unlock_spin(&gVmbusConnection.ChannelLock);
}
