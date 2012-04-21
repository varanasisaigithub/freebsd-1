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
 * Hyperv channel code
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
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include "../include/hyperv.h"
#include "vmbus_priv.h"

static int
VmbusChannelCreateGpadlHeader(void *Kbuffer, // must be phys and virt contiguous
	uint32_t Size,	 // page-size multiple
	VMBUS_CHANNEL_MSGINFO **msgInfo, uint32_t *MessageCount);


static void
VmbusChannelSetEvent(VMBUS_CHANNEL *Channel);

/*++

 Name:
 VmbusChannelSetEvent()

 Description:
 Trigger an event notification on the specified channel.

 --*/
static void
VmbusChannelSetEvent(VMBUS_CHANNEL *Channel) 
{
	HV_MONITOR_PAGE *monitorPage;


	if (Channel->OfferMsg.monitor_allocated) {
		// Each uint32_t represents 32 channels
		synch_set_bit((Channel->OfferMsg.child_rel_id & 31),
			((uint32_t *)gVmbusConnection.send_interrupt_page +
			((Channel->OfferMsg.child_rel_id >> 5))));

		monitorPage = (HV_MONITOR_PAGE *) gVmbusConnection.MonitorPages;
		monitorPage++; // Get the child to parent monitor page

		synch_set_bit(Channel->MonitorBit,
			(uint32_t *)&monitorPage->TriggerGroup[Channel->MonitorGroup].Pending);
	} else {
		VmbusSetEvent(Channel->OfferMsg.child_rel_id);
	}

}

/*++;

 Name:
 VmbusChannelGetDebugInfo()

 Description:
 Retrieve various channel debug info

 --*/
void
hv_vmbus_channel_get_debug_info(VMBUS_CHANNEL *Channel,
	VMBUS_CHANNEL_DEBUG_INFO *DebugInfo) 
{

	HV_MONITOR_PAGE *monitorPage;
	uint8_t monitorGroup = (uint8_t) Channel->OfferMsg.monitor_id / 32;
	uint8_t monitorOffset = (uint8_t) Channel->OfferMsg.monitor_id % 32;
	//uint32_t monitorBit	= 1 << monitorOffset;

	DebugInfo->RelId = Channel->OfferMsg.child_rel_id;
	DebugInfo->State = Channel->State;
	memcpy(&DebugInfo->InterfaceType,
		&Channel->OfferMsg.offer.interface_type, sizeof(hv_guid));
	memcpy(&DebugInfo->InterfaceInstance,
		&Channel->OfferMsg.offer.interface_instance, sizeof(hv_guid));

	monitorPage = (HV_MONITOR_PAGE*) gVmbusConnection.MonitorPages;

	DebugInfo->monitor_id = Channel->OfferMsg.monitor_id;

	DebugInfo->ServerMonitorPending =
		monitorPage->TriggerGroup[monitorGroup].Pending;
	DebugInfo->ServerMonitorLatency =
		monitorPage->Latency[monitorGroup][monitorOffset];
	DebugInfo->ServerMonitorConnectionId =
		monitorPage->Parameter[monitorGroup][monitorOffset].ConnectionId.u.Id;

	monitorPage++;

	DebugInfo->ClientMonitorPending =
		monitorPage->TriggerGroup[monitorGroup].Pending;
	DebugInfo->ClientMonitorLatency =
		monitorPage->Latency[monitorGroup][monitorOffset];
	DebugInfo->ClientMonitorConnectionId =
		monitorPage->Parameter[monitorGroup][monitorOffset].ConnectionId.u.Id;

	RingBufferGetDebugInfo(&Channel->Inbound, &DebugInfo->Inbound);
	RingBufferGetDebugInfo(&Channel->Outbound, &DebugInfo->Outbound);
}

void
GetChannelInfo(struct hv_device *dev, struct hv_devinfo *p)
{
	VMBUS_CHANNEL_DEBUG_INFO di;

	if (dev->channel) {
		hv_vmbus_channel_get_debug_info(dev->channel, &di);

		p->channel_id = di.RelId;
		p->channel_state = di.State;
		memcpy(&p->channel_type, &di.InterfaceType, sizeof(hv_guid));
		memcpy(&p->channel_instance, &di.InterfaceInstance,
			sizeof(hv_guid));

		p->monitor_id = di.monitor_id;

		p->server_monitor_pending = di.ServerMonitorPending;
		p->server_monitor_latency = di.ServerMonitorLatency;
		p->server_monitor_connection_id = di.ServerMonitorConnectionId;

		p->client_monitor_pending = di.ClientMonitorPending;
		p->client_monitor_latency = di.ClientMonitorLatency;
		p->client_monitor_connection_id = di.ClientMonitorConnectionId;

		p->in_bound.interrupt_mask = di.Inbound.Currentinterrupt_mask;
		p->in_bound.read_index = di.Inbound.CurrentReadIndex;
		p->in_bound.write_index = di.Inbound.CurrentWriteIndex;
		p->in_bound.bytes_avail_to_read = di.Inbound.BytesAvailToRead;
		p->in_bound.bytes_avail_to_write = di.Inbound.BytesAvailToWrite;

		p->out_bound.interrupt_mask = di.Outbound.Currentinterrupt_mask;
		p->out_bound.read_index = di.Outbound.CurrentReadIndex;
		p->out_bound.write_index = di.Outbound.CurrentWriteIndex;
		p->out_bound.bytes_avail_to_read = di.Outbound.BytesAvailToRead;
		p->out_bound.bytes_avail_to_write = di.Outbound.BytesAvailToWrite;
	}
}

/*++;

 Name:
 VmbusChannelOpen()

 Description:
 Open the specified channel.

 --*/
int
hv_vmbus_channel_open(VMBUS_CHANNEL *NewChannel, uint32_t SendRingBufferSize,
	uint32_t RecvRingBufferSize, void *user_data, uint32_t UserDataLen,
	hv_vmbus_pfn_channel_callback pfnOnChannelCallback, void *Context) 
{

	int ret = 0;
	hv_vmbus_channel_open_channel* openMsg;
	VMBUS_CHANNEL_MSGINFO* openInfo;
	void *in, *out;


	NewChannel->OnChannelCallback = pfnOnChannelCallback;
	NewChannel->ChannelCallbackContext = Context;

	// Allocate the ring buffer
	out = contigmalloc((SendRingBufferSize + RecvRingBufferSize),
			M_DEVBUF, M_ZERO, 0UL, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);
			
	if (!out)
		return -ENOMEM;

	in = ((uint8_t *)out + SendRingBufferSize);

	NewChannel->RingBufferPages = out;
	NewChannel->RingBufferPageCount = (SendRingBufferSize
		+ RecvRingBufferSize) >> PAGE_SHIFT;

	RingBufferInit(&NewChannel->Outbound, out, SendRingBufferSize);

	RingBufferInit(&NewChannel->Inbound, in, RecvRingBufferSize);

	// Establish the gpadl for the ring buffer

	NewChannel->ring_buffer_gpadl_handle = 0;

	ret = hv_vmbus_channel_establish_gpadl(NewChannel,
		NewChannel->Outbound.ring_buffer,
		SendRingBufferSize + RecvRingBufferSize,
		&NewChannel->ring_buffer_gpadl_handle);


	// Create and init the channel open message 
	openInfo = (VMBUS_CHANNEL_MSGINFO*)malloc(
		   sizeof(VMBUS_CHANNEL_MSGINFO) +
		   sizeof(hv_vmbus_channel_open_channel), M_DEVBUF, M_NOWAIT);

	if (!openInfo)
		return -ENOMEM;

	sema_init(&openInfo->wait_sema, 0, "Open Info Sema");

	openMsg = (hv_vmbus_channel_open_channel*) openInfo->Msg;
	openMsg->header.message_type = HV_CHANNEL_MESSAGE_OPEN_CHANNEL;
	openMsg->open_id = NewChannel->OfferMsg.child_rel_id; // FIXME
	openMsg->child_rel_id = NewChannel->OfferMsg.child_rel_id;
	openMsg->ring_buffer_gpadl_handle = NewChannel->ring_buffer_gpadl_handle;
	openMsg->downstream_ring_buffer_page_offset = SendRingBufferSize
		>> PAGE_SHIFT;
	openMsg->server_context_area_gpadl_handle = 0; // TODO

	if (UserDataLen) {
		memcpy(openMsg->user_data, user_data, UserDataLen);
	}

	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, openInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);


	ret = VmbusPostMessage(openMsg, sizeof(hv_vmbus_channel_open_channel));

	if (ret != 0)
		goto Cleanup;

	ret = sema_timedwait(&openInfo->wait_sema, 500); //KYS 5 seconds 
	
	if (ret)
		goto Cleanup;

	if (openInfo->Response.OpenResult.status == 0) {
		printf("channel <%p> open success!!", NewChannel);
	} else {
		printf("channel <%p> open failed - %d!!",
			NewChannel, openInfo->Response.OpenResult.status);
	}

Cleanup:
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_REMOVE(&gVmbusConnection.channel_msg_anchor, openInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);
	sema_destroy(&openInfo->wait_sema);
	free(openInfo, M_DEVBUF);

	return ret;
}


/*
 Name:
 VmbusChannelCreateGpadlHeader()

 Description:
 Creates a gpadl for the specified buffer

 --*/

static int
VmbusChannelCreateGpadlHeader(void *Kbuffer,
	uint32_t Size,	// page-size multiple
	VMBUS_CHANNEL_MSGINFO **MsgInfo, uint32_t *MessageCount) 
{
	int i;
	int pageCount;
	unsigned long long pfn;
	hv_vmbus_channel_gpadl_header* gpaHeader;
	hv_vmbus_channel_gpadl_body* gpadlBody;
	VMBUS_CHANNEL_MSGINFO* msgHeader;
	VMBUS_CHANNEL_MSGINFO* msgBody;
	uint32_t msgSize;

	int pfnSum, pfnCount, pfnLeft, pfnCurr, pfnSize;


	pageCount = Size >> PAGE_SHIFT;
	pfn = hv_get_phys_addr(Kbuffer) >> PAGE_SHIFT;

	// do we need a gpadl body msg
	pfnSize = MAX_SIZE_CHANNEL_MESSAGE - sizeof(hv_vmbus_channel_gpadl_header)
		- sizeof(hv_gpa_range);
	pfnCount = pfnSize / sizeof(uint64_t);

	if (pageCount > pfnCount) { // we need a gpadl body
		// fill in the header
		msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
			+ sizeof(hv_vmbus_channel_gpadl_header) + sizeof(hv_gpa_range)
			+ pfnCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		TAILQ_INIT(&msgHeader->sub_msg_list_anchor);
		msgHeader->MessageSize = msgSize;

		gpaHeader = (hv_vmbus_channel_gpadl_header*) msgHeader->Msg;
		gpaHeader->range_count = 1;
		gpaHeader->range_buf_len = sizeof(hv_gpa_range)
			+ pageCount * sizeof(uint64_t);
		gpaHeader->range[0].byte_offset = 0;
		gpaHeader->range[0].byte_count = Size;
		for (i = 0; i < pfnCount; i++) {
			gpaHeader->range[0].pfn_array[i] = pfn + i;
		}
		*MsgInfo = msgHeader;
		*MessageCount = 1;

		pfnSum = pfnCount;
		pfnLeft = pageCount - pfnCount;

		// how many pfns can we fit
		pfnSize = MAX_SIZE_CHANNEL_MESSAGE
			- sizeof(hv_vmbus_channel_gpadl_body);
		pfnCount = pfnSize / sizeof(uint64_t);

		// fill in the body
		while (pfnLeft) {
			if (pfnLeft > pfnCount) {
				pfnCurr = pfnCount;
			} else {
				pfnCurr = pfnLeft;
			}

			msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
				+ sizeof(hv_vmbus_channel_gpadl_body)
				+ pfnCurr * sizeof(uint64_t);
			msgBody = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
			msgBody->MessageSize = msgSize;
			(*MessageCount)++;
			gpadlBody = (hv_vmbus_channel_gpadl_body*) msgBody->Msg;

			// FIXME: Gpadl is uint32_t and we are using a pointer which could be 64-bit
			//gpadlBody->gpadl = kbuffer;
			for (i = 0; i < pfnCurr; i++) {
				gpadlBody->pfn[i] = pfn + pfnSum + i;
			}

			TAILQ_INSERT_TAIL(&msgHeader->sub_msg_list_anchor, msgBody, MsgListEntry);
			pfnSum += pfnCurr;
			pfnLeft -= pfnCurr;
		}
	} else {
		// everything fits in a header
		msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
			+ sizeof(hv_vmbus_channel_gpadl_header) + sizeof(hv_gpa_range)
			+ pageCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		msgHeader->MessageSize = msgSize;

		gpaHeader = (hv_vmbus_channel_gpadl_header*) msgHeader->Msg;
		gpaHeader->range_count = 1;
		gpaHeader->range_buf_len = sizeof(hv_gpa_range)
			+ pageCount * sizeof(uint64_t);
		gpaHeader->range[0].byte_offset = 0;
		gpaHeader->range[0].byte_count = Size;
		for (i = 0; i < pageCount; i++) {
			gpaHeader->range[0].pfn_array[i] = pfn + i;
		}

		*MsgInfo = msgHeader;
		*MessageCount = 1;
	}

	return 0;
}

/*++;

 Name:
 VmbusChannelEstablishGpadl()

 Description:
 Estabish a GPADL for the specified buffer

 --*/
int
hv_vmbus_channel_establish_gpadl(VMBUS_CHANNEL *Channel, void *Kbuffer,
	uint32_t Size,	 // page-size multiple
	uint32_t *GpadlHandle) 

{
	int ret = 0;
	hv_vmbus_channel_gpadl_header* gpadlMsg;
	hv_vmbus_channel_gpadl_body* gpadlBody;

	VMBUS_CHANNEL_MSGINFO *msgInfo;
	VMBUS_CHANNEL_MSGINFO *subMsgInfo;

	uint32_t msgCount;
	struct _VMBUS_CHANNEL_MSGINFO *curr;
	uint32_t nextGpadlHandle;

	/* Fixme:  NetScaler */
	int retrycnt = 0;

	/* Fixme:  NetScaler:  Used in error message only */
	int mcnt = 0;

	nextGpadlHandle = gVmbusConnection.NextGpadlHandle;
	atomic_add_int((int*) &gVmbusConnection.NextGpadlHandle, 1);

	VmbusChannelCreateGpadlHeader(Kbuffer, Size, &msgInfo, &msgCount);

	/*
	 * XXXKYS: Deal with allocation failures in 
	 * VmbusChannelCreateGpadlHeader()
	 */

	sema_init(&msgInfo->wait_sema, 0, "Open Info Sema");
	gpadlMsg = (hv_vmbus_channel_gpadl_header*) msgInfo->Msg;
	gpadlMsg->header.message_type = HV_CHANNEL_MESSAGEL_GPADL_HEADER;
	gpadlMsg->child_rel_id = Channel->OfferMsg.child_rel_id;
	gpadlMsg->gpadl = nextGpadlHandle;


	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, msgInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);


	ret = VmbusPostMessage(gpadlMsg,
		msgInfo->MessageSize - (uint32_t) sizeof(VMBUS_CHANNEL_MSGINFO));
	if (ret != 0) {
		goto Cleanup;
	}

	mcnt = 1;
	if (msgCount > 1) {
		TAILQ_FOREACH(curr, &msgInfo->sub_msg_list_anchor, MsgListEntry)
		{
			mcnt++;
			subMsgInfo = curr;
			gpadlBody = (hv_vmbus_channel_gpadl_body*) subMsgInfo->Msg;

			gpadlBody->header.message_type = HV_CHANNEL_MESSAGE_GPADL_BODY;
			gpadlBody->gpadl = nextGpadlHandle;

			retry: ret =
				VmbusPostMessage(
					gpadlBody,
					subMsgInfo->MessageSize
						- (uint32_t) sizeof(VMBUS_CHANNEL_MSGINFO));
			/* Fixme:  NetScaler */
			if (ret != 0) {
				if ((ret == HV_STATUS_INSUFFICIENT_BUFFERS)
					&& (retrycnt < 5)) {
					printf(
						"Failed to send GPADL body (%d): %x, retry: %d\n",
						mcnt, (unsigned int) ret,
						retrycnt);
					DELAY(5000);
					retrycnt++;
					goto retry;
				}
			}
		}
	}

	ret = sema_timedwait(&msgInfo->wait_sema, 500); //KYS 5 seconds
	if (ret)
		goto Cleanup;


	*GpadlHandle = gpadlMsg->gpadl;

Cleanup:

	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_REMOVE(&gVmbusConnection.channel_msg_anchor, msgInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

	sema_destroy(&msgInfo->wait_sema);
	free(msgInfo, M_DEVBUF);

	return ret;
}

/*++;

 Name:
 VmbusChannelTeardownGpadl()

 Description:
 Teardown the specified GPADL handle

 --*/
int
hv_vmbus_channel_teardown_gpdal(VMBUS_CHANNEL *Channel, uint32_t GpadlHandle) 
{
	int ret = 0;
	hv_vmbus_channel_gpadl_teardown *msg;
	VMBUS_CHANNEL_MSGINFO* info;


	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(hv_vmbus_channel_gpadl_teardown),
				M_DEVBUF, M_NOWAIT);

	if (!info) {
		ret = -ENOMEM;
		goto cleanup;
	}

	sema_init(&info->wait_sema, 0, "Open Info Sema");

	msg = (hv_vmbus_channel_gpadl_teardown*) info->Msg;

	msg->header.message_type = HV_CHANNEL_MESSAGE_GPADL_TEARDOWN;
	msg->child_rel_id = Channel->OfferMsg.child_rel_id;
	msg->gpadl = GpadlHandle;

	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, info, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

	ret = VmbusPostMessage(msg, sizeof(hv_vmbus_channel_gpadl_teardown));
	if (ret != 0) 
		goto cleanup;
	

	ret = sema_timedwait(&info->wait_sema, 500); //KYS 5 seconds

cleanup:

	// Received a torndown response
	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_REMOVE(&gVmbusConnection.channel_msg_anchor, info, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);
	sema_destroy(&info->wait_sema);
	free(info, M_DEVBUF);

	return ret;
}

/*++

 Name:
 VmbusChannelClose()

 Description:
 Close the specified channel

 --*/
void
hv_vmbus_channel_close(VMBUS_CHANNEL *Channel) 
{
	int ret = 0;
	hv_vmbus_channel_close_channel* msg;
	VMBUS_CHANNEL_MSGINFO* info;

	mtx_lock(&Channel->InboundLock);
	Channel->OnChannelCallback = NULL;
	mtx_unlock(&Channel->InboundLock);

	// Send a closing message
	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(hv_vmbus_channel_close_channel),
				M_DEVBUF, M_NOWAIT);

	KASSERT(info != NULL, ("malloc failed")); //KYS: eliminate this error

	msg = (hv_vmbus_channel_close_channel*) info->Msg;
	msg->header.message_type = HV_CHANNEL_MESSAGE_CLOSE_CHANNEL;
	msg->child_rel_id = Channel->OfferMsg.child_rel_id;

	ret = VmbusPostMessage(msg, sizeof(hv_vmbus_channel_close_channel));
	if (ret != 0) {
		// TODO:
	}

	// Tear down the gpadl for the channel's ring buffer
	if (Channel->ring_buffer_gpadl_handle) {
		hv_vmbus_channel_teardown_gpdal(Channel,
			Channel->ring_buffer_gpadl_handle);
	}

	// TODO: Send a msg to release the childRelId

	// Cleanup the ring buffers for this channel
	RingBufferCleanup(&Channel->Outbound);
	RingBufferCleanup(&Channel->Inbound);

	contigfree(Channel->RingBufferPages, Channel->RingBufferPageCount, M_DEVBUF);

	free(info, M_DEVBUF);

	// If we are closing the channel during an error path in opening the channel, don't free the channel
	// since the caller will free the channel
	if (Channel->State == HV_CHANNEL_OPEN_STATE) {
		mtx_lock_spin(&gVmbusConnection.ChannelLock);
		TAILQ_REMOVE(&gVmbusConnection.channel_anchor, Channel, ListEntry);
		mtx_unlock_spin(&gVmbusConnection.ChannelLock);

		FreeVmbusChannel(Channel);
	}

}

/*++

 Name:
 VmbusChannelSendPacket()

 Description:
 Send the specified buffer on the given channel

 --*/
int
hv_vmbus_channel_send_packet(VMBUS_CHANNEL *Channel, void *Buffer,
	uint32_t BufferLen, uint64_t RequestId, hv_vmbus_packet_type Type,
	uint32_t Flags) 
{
	
	int ret = 0;
	hv_vm_packet_descriptor desc;
	uint32_t packetLen = sizeof(hv_vm_packet_descriptor) + BufferLen;
	uint32_t packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;


	// Setup the descriptor
	desc.type = Type;	//HV_VMBUS_PACKET_TYPE_DATA_IN_BAND;
	desc.flags = Flags;	//HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = sizeof(hv_vm_packet_descriptor) >> 3; // in 8-bytes granularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = RequestId;

	bufferList[0].Data = &desc;
	bufferList[0].length = sizeof(hv_vm_packet_descriptor);

	bufferList[1].Data = Buffer;
	bufferList[1].length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferinterrupt_mask(&Channel->Outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 VmbusChannelSendPacketPageBuffer()

 Description:
 Send a range of single-page buffer packets using a GPADL Direct packet type.

 --*/
int
hv_vmbus_channel_send_packet_pagebuffer(VMBUS_CHANNEL *Channel,
	PAGE_BUFFER PageBuffers[], uint32_t PageCount, void *Buffer,
	uint32_t BufferLen, uint64_t RequestId) 
{
	
	int ret = 0;
	int i = 0;
	VMBUS_CHANNEL_PACKET_PAGE_BUFFER desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;

        if (PageCount > HV_MAX_PAGE_BUFFER_COUNT)
                return -EINVAL;

	// Adjust the size down since VMBUS_CHANNEL_PACKET_PAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_PAGE_BUFFER)
		- ((HV_MAX_PAGE_BUFFER_COUNT - PageCount) * sizeof(PAGE_BUFFER));
	packetLen = descSize + BufferLen;
	packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.Type = HV_VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT;
	desc.Flags = HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = descSize >> 3; // in 8-bytes grandularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = RequestId;
	desc.range_count = PageCount;

	for (i = 0; i < PageCount; i++) {
		desc.range[i].length = PageBuffers[i].length;
		desc.range[i].offset = PageBuffers[i].offset;
		desc.range[i].pfn = PageBuffers[i].pfn;
	}

	bufferList[0].Data = &desc;
	bufferList[0].length = descSize;

	bufferList[1].Data = Buffer;
	bufferList[1].length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferinterrupt_mask(&Channel->Outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 VmbusChannelSendPacketMultiPageBuffer()

 Description:
 Send a multi-page buffer packet using a GPADL Direct packet type.

 --*/
int
hv_vmbus_channel_send_packet_multipagebuffer(VMBUS_CHANNEL *Channel,
	hv_vmbus_multipage_buffer *MultiPageBuffer, void *Buffer, uint32_t BufferLen,
	uint64_t RequestId) 
{
	
	int ret = 0;
	VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;
	uint32_t pfnCount =
		HV_NUM_PAGES_SPANNED(MultiPageBuffer->offset, MultiPageBuffer->length);


	if ((pfnCount < 0) || (pfnCount > HV_MAX_MULTIPAGE_BUFFER_COUNT))
		return -EINVAL;

	// Adjust the size down since VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER)
		- ((HV_MAX_MULTIPAGE_BUFFER_COUNT - pfnCount) * sizeof(uint64_t));
	packetLen = descSize + BufferLen;
	packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.Type = HV_VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT;
	desc.Flags = HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = descSize >> 3; // in 8-bytes grandularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = RequestId;
	desc.range_count = 1;

	desc.range.length = MultiPageBuffer->length;
	desc.range.offset = MultiPageBuffer->offset;

	memcpy(desc.range.pfn_array, MultiPageBuffer->pfn_array,
		pfnCount*sizeof(uint64_t));

	bufferList[0].Data = &desc;
	bufferList[0].length = descSize;

	bufferList[1].Data = Buffer;
	bufferList[1].length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferinterrupt_mask(&Channel->Outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 VmbusChannelRecvPacket()

 Description:
 Retrieve the user packet on the specified channel

 --*/
int
hv_vmbus_channel_recv_packet(VMBUS_CHANNEL *Channel, void *Buffer,
	uint32_t BufferLen, uint32_t *BufferActualLen, uint64_t *RequestId) 
{

	hv_vm_packet_descriptor desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;

	*BufferActualLen = 0;
	*RequestId = 0;

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(hv_vm_packet_descriptor));
	if (ret != 0) 
		return 0;


	packetLen = desc.length8 << 3;
	userLen = packetLen - (desc.data_offset8 << 3);

	*BufferActualLen = userLen;

	if (userLen > BufferLen)
		return -EINVAL;

	*RequestId = desc.transaction_id;

	// Copy over the packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, userLen,
		(desc.data_offset8 << 3));
	return 0;
}

/*++

 Name:
 VmbusChannelRecvPacketRaw()

 Description:
 Retrieve the raw packet on the specified channel

 --*/
int
hv_vmbus_channel_recv_packet_raw(VMBUS_CHANNEL *Channel, void *Buffer,
	uint32_t BufferLen, uint32_t *BufferActualLen, uint64_t *RequestId) 
{
	
	hv_vm_packet_descriptor desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;
	*BufferActualLen = 0;
	*RequestId = 0;

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(hv_vm_packet_descriptor));

	if (ret != 0)
		return 0;

	packetLen = desc.length8 << 3;
	userLen = packetLen - (desc.data_offset8 << 3);

	*BufferActualLen = packetLen;

	if (packetLen > BufferLen)
		return -ENOBUFS;


	*RequestId = desc.transaction_id;

	// Copy over the entire packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, packetLen, 0);

	return 0;
}
