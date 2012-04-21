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

#include <dev/hyperv/include/hyperv.h>
#include "vmbus_priv.h"

//
// Data types
//

typedef void (*PFN_CHANNEL_MESSAGE_HANDLER)(hv_vmbus_channel_message_header* msg);

typedef struct _VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY {
	hv_vmbus_channel_message_type messageType;
	PFN_CHANNEL_MESSAGE_HANDLER messageHandler;
} VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY;

/*
 *
 * Implementation of the work abstraction.
 */

static void work_item_callback(void *work, int pending) 

{
	struct hv_work_item *w = (struct hv_work_item *)work;

	/*
	 * Serialize work execution.
	 */
	if (w->wq->work_sema != NULL) {
		sema_wait(w->wq->work_sema);
	}

	w->callback(w->context);

	if (w->wq->work_sema != NULL) {
		sema_post(w->wq->work_sema);
	} 

	free(w, M_DEVBUF);
}

struct hv_work_queue *hv_work_queue_create(char* name)
{
	static unsigned int qid = 0;
	char qname[64];
	int pri;
	struct hv_work_queue *wq;

	wq = malloc(sizeof(struct hv_work_queue), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!wq) {
		printf("Failed to create WorkQueue\n");
		return (NULL);
	}

	/*
	 * We use work abstraction to handle messages
	 * coming from the host and these are typically offers.
	 * Some FreeBsd drivers appear to have a concurrency issue
	 * where probe/attach needs to be serialized. We ensure that
	 * by having only one thread process work elements in a 
	 * specific queue by serializing work execution.
	 *
	 */
	if (strcmp(name, "vmbusQ") == 0) {
		pri = PI_DISK;
	} else {					/* control */
		pri = PI_NET;
		/*
		 * Initialize semaphore for this queue by pointing
		 * to the globale semaphore used for synchronizing all
		 * control messages.
		 */
		wq->work_sema = &gVmbusConnection.control_sema;
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
		free(wq, M_DEVBUF);
		return (NULL);
	}

	if (taskqueue_start_threads(&wq->queue, 1, pri, "%s taskq", qname)) {
		taskqueue_free(wq->queue);
		free(wq, M_DEVBUF);
		return (NULL);
	}

	qid++;

	return (wq);
}

void hv_work_queue_close(struct hv_work_queue *wq)
{
	/*
	 * XXXKYS: Need to drain the taskqueue
	 * before we close the hv_work_queue.
	 */
//KYS	taskqueue_drain(wq->tq, );
	taskqueue_free(wq->queue);
	free(wq, M_DEVBUF);
}

int hv_queue_work_item(struct hv_work_queue *wq, void (*callback)(void *), void *context)
{
	struct hv_work_item *w = malloc(sizeof(struct hv_work_item), M_DEVBUF, M_NOWAIT | M_ZERO);
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
VmbusChannelOnOffer(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnOpenResult(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnOfferRescind(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnGpadlCreated(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnGpadlTorndown(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnOffersDelivered(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelOnVersionResponse(hv_vmbus_channel_message_header * hdr);

static void
VmbusChannelProcessOffer(void *context);


// Channel message dispatch table
VMBUS_CHANNEL_MESSAGE_TABLE_ENTRY gChannelMessageTable[HV_CHANNEL_MESSAGE_COUNT] = {
	{ HV_CHANNEL_MESSAGE_INVALID, NULL },
	{ HV_CHANNEL_MESSAGE_OFFER_CHANNEL, VmbusChannelOnOffer },
	{ HV_CHANNEL_MESSAGE_RESCIND_CHANNEL_OFFER, VmbusChannelOnOfferRescind },
	{ HV_CHANNEL_MESSAGE_REQUEST_OFFERS, NULL },
	{ HV_CHANNEL_MESSAGE_ALL_OFFERS_DELIVERED,VmbusChannelOnOffersDelivered },
	{ HV_CHANNEL_MESSAGE_OPEN_CHANNEL,NULL },
	{ HV_CHANNEL_MESSAGE_OPEN_CHANNEL_RESULT,VmbusChannelOnOpenResult },
	{ HV_CHANNEL_MESSAGE_CLOSE_CHANNEL, NULL },
	{ HV_CHANNEL_MESSAGEL_GPADL_HEADER, NULL },
	{ HV_CHANNEL_MESSAGE_GPADL_BODY, NULL },
	{ HV_CHANNEL_MESSAGE_GPADL_CREATED, VmbusChannelOnGpadlCreated },
	{ HV_CHANNEL_MESSAGE_GPADL_TEARDOWN, NULL },
	{ HV_CHANNEL_MESSAGE_GPADL_TORNDOWN, VmbusChannelOnGpadlTorndown },
	{ HV_CHANNEL_MESSAGE_REL_ID_RELEASED, NULL },
	{ HV_CHANNEL_MESSAGE_INITIATED_CONTACT, NULL },
	{ HV_CHANNEL_MESSAGE_VERSION_RESPONSE, VmbusChannelOnVersionResponse },
	{ HV_CHANNEL_MESSAGE_UNLOAD, NULL }, };


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

	mtx_init(&channel->InboundLock, "channel inbound", NULL, MTX_DEF);

	channel->ControlWQ = hv_work_queue_create("control");
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

	hv_work_queue_close(channel->ControlWQ);
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
	hv_queue_work_item(gVmbusConnection.WorkQueue, ReleaseVmbusChannel,
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
	VMBUS_CHANNEL* channel = NULL;

	// Make sure this is a new offer
	mtx_lock_spin(&gVmbusConnection.ChannelLock);

	TAILQ_FOREACH(channel, &gVmbusConnection.channel_anchor, ListEntry) {

		if (!memcmp(&channel->OfferMsg.offer.interface_type,
			&newChannel->OfferMsg.offer.interface_type, sizeof(hv_guid))
			&& !memcmp(&channel->OfferMsg.offer.interface_instance,
				&newChannel->OfferMsg.offer.interface_instance,
				sizeof(hv_guid))) {
			fNew = false;
			break;
		}
	}

	if (fNew) {
		/* Insert at tail */
		TAILQ_INSERT_TAIL(&gVmbusConnection.channel_anchor, newChannel, ListEntry);

	}
	mtx_unlock_spin(&gVmbusConnection.ChannelLock);

	if (!fNew) {
		FreeVmbusChannel(newChannel);
		return;
	}

	// Start the process of binding this offer to the driver
	// We need to set the device field before calling VmbusChildDeviceAdd()
	newChannel->device = vmbus_child_device_create(
		newChannel->OfferMsg.offer.interface_type,
		newChannel->OfferMsg.offer.interface_instance, newChannel);

	// todo - the HV_CHANNEL_OPEN_STATE flag should not be set below but in the "open" channel
	//			request. The ret != 0 logic below doesn't take into account that a channel
	//          may have been opened successfully

	// Add the new device to the bus. This will kick off device-driver binding
	// which eventually invokes the device driver's AddDevice() method.
	ret = vmbus_child_device_register(newChannel->device);
	if (ret != 0) {
		mtx_lock_spin(&gVmbusConnection.ChannelLock);
		TAILQ_REMOVE(&gVmbusConnection.channel_anchor, newChannel, ListEntry);
		mtx_unlock_spin(&gVmbusConnection.ChannelLock);

		FreeVmbusChannel(newChannel);
	} else {
		// This state is used to indicate a successful open 
		// so that when we do close the channel normally,
		// we can cleanup properly
		newChannel->State = HV_CHANNEL_OPEN_STATE;

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
VmbusChannelOnOffer(hv_vmbus_channel_message_header * hdr) {
	hv_vmbus_channel_offer_channel* offer = (hv_vmbus_channel_offer_channel*) hdr;
	VMBUS_CHANNEL* newChannel;

	hv_guid *guidType;
	hv_guid *guidInstance;

	guidType = &offer->offer.interface_type;
	guidInstance = &offer->offer.interface_instance;


	// Allocate the channel object and save this offer.
	newChannel = AllocVmbusChannel();
	if (!newChannel)
		return;


	memcpy(&newChannel->OfferMsg, offer,
		sizeof(hv_vmbus_channel_offer_channel));
	newChannel->MonitorGroup = (uint8_t) offer->monitor_id / 32;
	newChannel->MonitorBit = (uint8_t) offer->monitor_id % 32;

	// TODO: Make sure the offer comes from our parent partition
	hv_queue_work_item(newChannel->ControlWQ, VmbusChannelProcessOffer,
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
VmbusChannelOnOfferRescind(hv_vmbus_channel_message_header * hdr) {
	hv_vmbus_channel_rescind_offer* rescind =
		(hv_vmbus_channel_rescind_offer*) hdr;
	VMBUS_CHANNEL* channel;

	channel = GetChannelFromRelId(rescind->child_rel_id);
	if (channel == NULL) 
		return;

	hv_queue_work_item(channel->ControlWQ,
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
VmbusChannelOnOffersDelivered(hv_vmbus_channel_message_header * hdr) {
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
VmbusChannelOnOpenResult(hv_vmbus_channel_message_header * hdr) {
	hv_vmbus_channel_open_result* result = (hv_vmbus_channel_open_result*) hdr;
	VMBUS_CHANNEL_MSGINFO* msgInfo;
	hv_vmbus_channel_message_header* requestHeader;
	hv_vmbus_channel_open_channel* openMsg;


	// Find the open msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	TAILQ_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (hv_vmbus_channel_message_header*) msgInfo->Msg;

		if (requestHeader->message_type == HV_CHANNEL_MESSAGE_OPEN_CHANNEL) {
			openMsg = (hv_vmbus_channel_open_channel*) msgInfo->Msg;
			if (openMsg->child_rel_id == result->child_rel_id
				&& openMsg->open_id == result->open_id) {
				memcpy(&msgInfo->Response.OpenResult, result,
					sizeof(hv_vmbus_channel_open_result));
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
VmbusChannelOnGpadlCreated(hv_vmbus_channel_message_header * hdr) {
	hv_vmbus_channel_gpadl_created *gpadlCreated =
		(hv_vmbus_channel_gpadl_created*) hdr;
	VMBUS_CHANNEL_MSGINFO *msgInfo;
	hv_vmbus_channel_message_header *requestHeader;
	hv_vmbus_channel_gpadl_header *gpadlHeader;


	// Find the establish msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	TAILQ_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (hv_vmbus_channel_message_header*) msgInfo->Msg;

		if (requestHeader->message_type == HV_CHANNEL_MESSAGEL_GPADL_HEADER) {
			gpadlHeader =
				(hv_vmbus_channel_gpadl_header*) requestHeader;

			if ((gpadlCreated->child_rel_id == gpadlHeader->child_rel_id)
				&& (gpadlCreated->gpadl == gpadlHeader->gpadl)) {
				memcpy(&msgInfo->Response.GpadlCreated,
					gpadlCreated,
					sizeof(hv_vmbus_channel_gpadl_created));
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
VmbusChannelOnGpadlTorndown(hv_vmbus_channel_message_header * hdr) {
	hv_vmbus_channel_gpadl_torndown* gpadlTorndown =
		(hv_vmbus_channel_gpadl_torndown*) hdr;
	VMBUS_CHANNEL_MSGINFO* msgInfo;
	hv_vmbus_channel_message_header *requestHeader;
	hv_vmbus_channel_gpadl_teardown *gpadlTeardown;


	// Find the open msg, copy the result and signal/unblock the wait event
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	TAILQ_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (hv_vmbus_channel_message_header*) msgInfo->Msg;

		if (requestHeader->message_type == HV_CHANNEL_MESSAGE_GPADL_TEARDOWN) {
			gpadlTeardown =
				(hv_vmbus_channel_gpadl_teardown*) requestHeader;

			if (gpadlTorndown->gpadl == gpadlTeardown->gpadl) {
				memcpy(&msgInfo->Response.GpadlTorndown,
					gpadlTorndown,
					sizeof(hv_vmbus_channel_gpadl_torndown));
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
VmbusChannelOnVersionResponse(hv_vmbus_channel_message_header * hdr) {
	VMBUS_CHANNEL_MSGINFO *msgInfo;
	hv_vmbus_channel_message_header *requestHeader;
	hv_vmbus_channel_initiate_contact *initiate;
	hv_vmbus_channel_version_response *versionResponse =
		(hv_vmbus_channel_version_response*) hdr;


	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);

	TAILQ_FOREACH(msgInfo, &gVmbusConnection.channel_msg_anchor, MsgListEntry) {
		requestHeader = (hv_vmbus_channel_message_header*) msgInfo->Msg;

		if (requestHeader->message_type
			== HV_CHANNEL_MESSAGE_INITIATED_CONTACT) {
			initiate =
				(hv_vmbus_channel_initiate_contact*) requestHeader;
			memcpy(&msgInfo->Response.VersionResponse,
				versionResponse,
				sizeof(hv_vmbus_channel_version_response));
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
	hv_vmbus_channel_message_header* hdr;
	int size;


	hdr = (hv_vmbus_channel_message_header*) msg->u.Payload;
	size = msg->header.PayloadSize;


	if (hdr->message_type >= HV_CHANNEL_MESSAGE_COUNT) {
		free(msg, M_DEVBUF);
		return;
	}

	if (gChannelMessageTable[hdr->message_type].messageHandler) {
		gChannelMessageTable[hdr->message_type].messageHandler(hdr);
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
	hv_vmbus_channel_message_header* msg;
	VMBUS_CHANNEL_MSGINFO* msgInfo;

	msgInfo = (VMBUS_CHANNEL_MSGINFO *)
	        malloc(sizeof(VMBUS_CHANNEL_MSGINFO) +
	          sizeof(hv_vmbus_channel_message_header), M_DEVBUF, M_NOWAIT);

	if (!msgInfo) {
		printf("VMBUS: Request Offers malloc failed\n");
		return -ENOMEM;
	}

	msg = (hv_vmbus_channel_message_header*) msgInfo->Msg;
	msg->message_type = HV_CHANNEL_MESSAGE_REQUEST_OFFERS;

	ret = VmbusPostMessage(msg, sizeof(hv_vmbus_channel_message_header));
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

	while (!TAILQ_EMPTY(&gVmbusConnection.channel_anchor)) {
		channel = TAILQ_FIRST(&gVmbusConnection.channel_anchor);
		TAILQ_REMOVE(&gVmbusConnection.channel_anchor, channel, ListEntry);

		vmbus_child_device_unregister(channel->device);
		FreeVmbusChannel(channel);

	}
	mtx_unlock_spin(&gVmbusConnection.ChannelLock);
}
