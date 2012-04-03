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


	if (Channel->OfferMsg.MonitorAllocated) {
		// Each uint32_t represents 32 channels
		synch_set_bit((Channel->OfferMsg.ChildRelId & 31),
			((uint32_t *)gVmbusConnection.SendInterruptPage +
			((Channel->OfferMsg.ChildRelId >> 5))));

		monitorPage = (HV_MONITOR_PAGE*) gVmbusConnection.MonitorPages;
		monitorPage++; // Get the child to parent monitor page

		synch_set_bit(Channel->MonitorBit,
			(uint32_t *)&monitorPage->TriggerGroup[Channel->MonitorGroup].Pending);
	} else {
		VmbusSetEvent(Channel->OfferMsg.ChildRelId);
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
	uint8_t monitorGroup = (uint8_t) Channel->OfferMsg.MonitorId / 32;
	uint8_t monitorOffset = (uint8_t) Channel->OfferMsg.MonitorId % 32;
	//uint32_t monitorBit	= 1 << monitorOffset;

	DebugInfo->RelId = Channel->OfferMsg.ChildRelId;
	DebugInfo->State = Channel->State;
	memcpy(&DebugInfo->InterfaceType,
		&Channel->OfferMsg.Offer.InterfaceType, sizeof(GUID));
	memcpy(&DebugInfo->InterfaceInstance,
		&Channel->OfferMsg.Offer.InterfaceInstance, sizeof(GUID));

	monitorPage = (HV_MONITOR_PAGE*) gVmbusConnection.MonitorPages;

	DebugInfo->MonitorId = Channel->OfferMsg.MonitorId;

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

		p->ChannelId = di.RelId;
		p->ChannelState = di.State;
		memcpy(&p->ChannelType, &di.InterfaceType, sizeof(GUID));
		memcpy(&p->ChannelInstance, &di.InterfaceInstance,
			sizeof(GUID));

		p->MonitorId = di.MonitorId;

		p->ServerMonitorPending = di.ServerMonitorPending;
		p->ServerMonitorLatency = di.ServerMonitorLatency;
		p->ServerMonitorConnectionId = di.ServerMonitorConnectionId;

		p->ClientMonitorPending = di.ClientMonitorPending;
		p->ClientMonitorLatency = di.ClientMonitorLatency;
		p->ClientMonitorConnectionId = di.ClientMonitorConnectionId;

		p->Inbound.InterruptMask = di.Inbound.CurrentInterruptMask;
		p->Inbound.ReadIndex = di.Inbound.CurrentReadIndex;
		p->Inbound.WriteIndex = di.Inbound.CurrentWriteIndex;
		p->Inbound.BytesAvailToRead = di.Inbound.BytesAvailToRead;
		p->Inbound.BytesAvailToWrite = di.Inbound.BytesAvailToWrite;

		p->Outbound.InterruptMask = di.Outbound.CurrentInterruptMask;
		p->Outbound.ReadIndex = di.Outbound.CurrentReadIndex;
		p->Outbound.WriteIndex = di.Outbound.CurrentWriteIndex;
		p->Outbound.BytesAvailToRead = di.Outbound.BytesAvailToRead;
		p->Outbound.BytesAvailToWrite = di.Outbound.BytesAvailToWrite;
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
	uint32_t RecvRingBufferSize, void *UserData, uint32_t UserDataLen,
	PFN_CHANNEL_CALLBACK pfnOnChannelCallback, void *Context) 
{

	int ret = 0;
	VMBUS_CHANNEL_OPEN_CHANNEL* openMsg;
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

	NewChannel->RingBufferGpadlHandle = 0;

	ret = hv_vmbus_channel_establish_gpadl(NewChannel,
		NewChannel->Outbound.RingBuffer,
		SendRingBufferSize + RecvRingBufferSize,
		&NewChannel->RingBufferGpadlHandle);


	// Create and init the channel open message 
	openInfo = (VMBUS_CHANNEL_MSGINFO*)malloc(
		   sizeof(VMBUS_CHANNEL_MSGINFO) +
		   sizeof(VMBUS_CHANNEL_OPEN_CHANNEL), M_DEVBUF, M_NOWAIT);

	if (!openInfo)
		return -ENOMEM;

	sema_init(&openInfo->wait_sema, 0, "Open Info Sema");

	openMsg = (VMBUS_CHANNEL_OPEN_CHANNEL*) openInfo->Msg;
	openMsg->Header.MessageType = ChannelMessageOpenChannel;
	openMsg->OpenId = NewChannel->OfferMsg.ChildRelId; // FIXME
	openMsg->ChildRelId = NewChannel->OfferMsg.ChildRelId;
	openMsg->RingBufferGpadlHandle = NewChannel->RingBufferGpadlHandle;
	openMsg->DownstreamRingBufferPageOffset = SendRingBufferSize
		>> PAGE_SHIFT;
	openMsg->ServerContextAreaGpadlHandle = 0; // TODO

	if (UserDataLen) {
		memcpy(openMsg->UserData, UserData, UserDataLen);
	}

	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, openInfo, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);


	ret = VmbusPostMessage(openMsg, sizeof(VMBUS_CHANNEL_OPEN_CHANNEL));

	if (ret != 0)
		goto Cleanup;

	ret = sema_timedwait(&openInfo->wait_sema, 500); //KYS 5 seconds 
	
	if (ret)
		goto Cleanup;

	if (openInfo->Response.OpenResult.Status == 0) {
		printf("channel <%p> open success!!", NewChannel);
	} else {
		printf("channel <%p> open failed - %d!!",
			NewChannel, openInfo->Response.OpenResult.Status);
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
	VMBUS_CHANNEL_GPADL_HEADER* gpaHeader;
	VMBUS_CHANNEL_GPADL_BODY* gpadlBody;
	VMBUS_CHANNEL_MSGINFO* msgHeader;
	VMBUS_CHANNEL_MSGINFO* msgBody;
	uint32_t msgSize;

	int pfnSum, pfnCount, pfnLeft, pfnCurr, pfnSize;


	pageCount = Size >> PAGE_SHIFT;
	pfn = get_phys_addr(Kbuffer) >> PAGE_SHIFT;

	// do we need a gpadl body msg
	pfnSize = MAX_SIZE_CHANNEL_MESSAGE - sizeof(VMBUS_CHANNEL_GPADL_HEADER)
		- sizeof(GPA_RANGE);
	pfnCount = pfnSize / sizeof(uint64_t);

	if (pageCount > pfnCount) { // we need a gpadl body
		// fill in the header
		msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
			+ sizeof(VMBUS_CHANNEL_GPADL_HEADER) + sizeof(GPA_RANGE)
			+ pfnCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		TAILQ_INIT(&msgHeader->sub_msg_list_anchor);
		msgHeader->MessageSize = msgSize;

		gpaHeader = (VMBUS_CHANNEL_GPADL_HEADER*) msgHeader->Msg;
		gpaHeader->RangeCount = 1;
		gpaHeader->RangeBufLen = sizeof(GPA_RANGE)
			+ pageCount * sizeof(uint64_t);
		gpaHeader->Range[0].ByteOffset = 0;
		gpaHeader->Range[0].ByteCount = Size;
		for (i = 0; i < pfnCount; i++) {
			gpaHeader->Range[0].PfnArray[i] = pfn + i;
		}
		*MsgInfo = msgHeader;
		*MessageCount = 1;

		pfnSum = pfnCount;
		pfnLeft = pageCount - pfnCount;

		// how many pfns can we fit
		pfnSize = MAX_SIZE_CHANNEL_MESSAGE
			- sizeof(VMBUS_CHANNEL_GPADL_BODY);
		pfnCount = pfnSize / sizeof(uint64_t);

		// fill in the body
		while (pfnLeft) {
			if (pfnLeft > pfnCount) {
				pfnCurr = pfnCount;
			} else {
				pfnCurr = pfnLeft;
			}

			msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
				+ sizeof(VMBUS_CHANNEL_GPADL_BODY)
				+ pfnCurr * sizeof(uint64_t);
			msgBody = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
			msgBody->MessageSize = msgSize;
			(*MessageCount)++;
			gpadlBody = (VMBUS_CHANNEL_GPADL_BODY*) msgBody->Msg;

			// FIXME: Gpadl is uint32_t and we are using a pointer which could be 64-bit
			//gpadlBody->Gpadl = kbuffer;
			for (i = 0; i < pfnCurr; i++) {
				gpadlBody->Pfn[i] = pfn + pfnSum + i;
			}

			TAILQ_INSERT_TAIL(&msgHeader->sub_msg_list_anchor, msgBody, MsgListEntry);
			pfnSum += pfnCurr;
			pfnLeft -= pfnCurr;
		}
	} else {
		// everything fits in a header
		msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
			+ sizeof(VMBUS_CHANNEL_GPADL_HEADER) + sizeof(GPA_RANGE)
			+ pageCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		msgHeader->MessageSize = msgSize;

		gpaHeader = (VMBUS_CHANNEL_GPADL_HEADER*) msgHeader->Msg;
		gpaHeader->RangeCount = 1;
		gpaHeader->RangeBufLen = sizeof(GPA_RANGE)
			+ pageCount * sizeof(uint64_t);
		gpaHeader->Range[0].ByteOffset = 0;
		gpaHeader->Range[0].ByteCount = Size;
		for (i = 0; i < pageCount; i++) {
			gpaHeader->Range[0].PfnArray[i] = pfn + i;
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
	VMBUS_CHANNEL_GPADL_HEADER* gpadlMsg;
	VMBUS_CHANNEL_GPADL_BODY* gpadlBody;

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
	gpadlMsg = (VMBUS_CHANNEL_GPADL_HEADER*) msgInfo->Msg;
	gpadlMsg->Header.MessageType = ChannelMessageGpadlHeader;
	gpadlMsg->ChildRelId = Channel->OfferMsg.ChildRelId;
	gpadlMsg->Gpadl = nextGpadlHandle;


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
			gpadlBody = (VMBUS_CHANNEL_GPADL_BODY*) subMsgInfo->Msg;

			gpadlBody->Header.MessageType = ChannelMessageGpadlBody;
			gpadlBody->Gpadl = nextGpadlHandle;

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


	*GpadlHandle = gpadlMsg->Gpadl;

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
	VMBUS_CHANNEL_GPADL_TEARDOWN *msg;
	VMBUS_CHANNEL_MSGINFO* info;


	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(VMBUS_CHANNEL_GPADL_TEARDOWN),
				M_DEVBUF, M_NOWAIT);

	if (!info) {
		ret = -ENOMEM;
		goto cleanup;
	}

	sema_init(&info->wait_sema, 0, "Open Info Sema");

	msg = (VMBUS_CHANNEL_GPADL_TEARDOWN*) info->Msg;

	msg->Header.MessageType = ChannelMessageGpadlTeardown;
	msg->ChildRelId = Channel->OfferMsg.ChildRelId;
	msg->Gpadl = GpadlHandle;

	mtx_lock_spin(&gVmbusConnection.ChannelMsgLock);
	TAILQ_INSERT_TAIL(&gVmbusConnection.channel_msg_anchor, info, MsgListEntry);
	mtx_unlock_spin(&gVmbusConnection.ChannelMsgLock);

	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_GPADL_TEARDOWN));
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
	VMBUS_CHANNEL_CLOSE_CHANNEL* msg;
	VMBUS_CHANNEL_MSGINFO* info;

	mtx_lock(&Channel->InboundLock);
	Channel->OnChannelCallback = NULL;
	mtx_unlock(&Channel->InboundLock);

	// Send a closing message
	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(VMBUS_CHANNEL_CLOSE_CHANNEL),
				M_DEVBUF, M_NOWAIT);

	KASSERT(info != NULL, ("malloc failed")); //KYS: eliminate this error

	msg = (VMBUS_CHANNEL_CLOSE_CHANNEL*) info->Msg;
	msg->Header.MessageType = ChannelMessageCloseChannel;
	msg->ChildRelId = Channel->OfferMsg.ChildRelId;

	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_CLOSE_CHANNEL));
	if (ret != 0) {
		// TODO:
	}

	// Tear down the gpadl for the channel's ring buffer
	if (Channel->RingBufferGpadlHandle) {
		hv_vmbus_channel_teardown_gpdal(Channel,
			Channel->RingBufferGpadlHandle);
	}

	// TODO: Send a msg to release the childRelId

	// Cleanup the ring buffers for this channel
	RingBufferCleanup(&Channel->Outbound);
	RingBufferCleanup(&Channel->Inbound);

	contigfree(Channel->RingBufferPages, Channel->RingBufferPageCount, M_DEVBUF);

	free(info, M_DEVBUF);

	// If we are closing the channel during an error path in opening the channel, don't free the channel
	// since the caller will free the channel
	if (Channel->State == CHANNEL_OPEN_STATE) {
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
	uint32_t BufferLen, uint64_t RequestId, VMBUS_PACKET_TYPE Type,
	uint32_t Flags) 
{
	
	int ret = 0;
	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen = sizeof(VMPACKET_DESCRIPTOR) + BufferLen;
	uint32_t packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;


	// Setup the descriptor
	desc.Type = Type;	//VmbusPacketTypeDataInBand;
	desc.Flags = Flags;	//VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.DataOffset8 = sizeof(VMPACKET_DESCRIPTOR) >> 3; // in 8-bytes granularity
	desc.Length8 = (uint16_t) (packetLenAligned >> 3);
	desc.TransactionId = RequestId;

	bufferList[0].Data = &desc;
	bufferList[0].Length = sizeof(VMPACKET_DESCRIPTOR);

	bufferList[1].Data = Buffer;
	bufferList[1].Length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].Length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferInterruptMask(&Channel->Outbound)) {
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

        if (PageCount > MAX_PAGE_BUFFER_COUNT)
                return -EINVAL;

	// Adjust the size down since VMBUS_CHANNEL_PACKET_PAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_PAGE_BUFFER)
		- ((MAX_PAGE_BUFFER_COUNT - PageCount) * sizeof(PAGE_BUFFER));
	packetLen = descSize + BufferLen;
	packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.Type = VmbusPacketTypeDataUsingGpaDirect;
	desc.Flags = VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.DataOffset8 = descSize >> 3; // in 8-bytes grandularity
	desc.Length8 = (uint16_t) (packetLenAligned >> 3);
	desc.TransactionId = RequestId;
	desc.RangeCount = PageCount;

	for (i = 0; i < PageCount; i++) {
		desc.Range[i].Length = PageBuffers[i].Length;
		desc.Range[i].Offset = PageBuffers[i].Offset;
		desc.Range[i].Pfn = PageBuffers[i].Pfn;
	}

	bufferList[0].Data = &desc;
	bufferList[0].Length = descSize;

	bufferList[1].Data = Buffer;
	bufferList[1].Length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].Length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferInterruptMask(&Channel->Outbound)) {
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
	MULTIPAGE_BUFFER *MultiPageBuffer, void *Buffer, uint32_t BufferLen,
	uint64_t RequestId) 
{
	
	int ret = 0;
	VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;
	uint32_t PfnCount =
		NUM_PAGES_SPANNED(MultiPageBuffer->Offset, MultiPageBuffer->Length);


	if ((PfnCount < 0) || (PfnCount > MAX_MULTIPAGE_BUFFER_COUNT))
		return -EINVAL;

	// Adjust the size down since VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER)
		- ((MAX_MULTIPAGE_BUFFER_COUNT - PfnCount) * sizeof(uint64_t));
	packetLen = descSize + BufferLen;
	packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.Type = VmbusPacketTypeDataUsingGpaDirect;
	desc.Flags = VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.DataOffset8 = descSize >> 3; // in 8-bytes grandularity
	desc.Length8 = (uint16_t) (packetLenAligned >> 3);
	desc.TransactionId = RequestId;
	desc.RangeCount = 1;

	desc.Range.Length = MultiPageBuffer->Length;
	desc.Range.Offset = MultiPageBuffer->Offset;

	memcpy(desc.Range.PfnArray, MultiPageBuffer->PfnArray,
		PfnCount*sizeof(uint64_t));

	bufferList[0].Data = &desc;
	bufferList[0].Length = descSize;

	bufferList[1].Data = Buffer;
	bufferList[1].Length = BufferLen;

	bufferList[2].Data = &alignedData;
	bufferList[2].Length = packetLenAligned - packetLen;

	ret = RingBufferWrite(&Channel->Outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !GetRingBufferInterruptMask(&Channel->Outbound)) {
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

	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;

	*BufferActualLen = 0;
	*RequestId = 0;

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(VMPACKET_DESCRIPTOR));
	if (ret != 0) 
		return 0;


	packetLen = desc.Length8 << 3;
	userLen = packetLen - (desc.DataOffset8 << 3);

	*BufferActualLen = userLen;

	if (userLen > BufferLen)
		return -EINVAL;

	*RequestId = desc.TransactionId;

	// Copy over the packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, userLen,
		(desc.DataOffset8 << 3));
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
	
	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;
	*BufferActualLen = 0;
	*RequestId = 0;

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(VMPACKET_DESCRIPTOR));

	if (ret != 0)
		return 0;

	packetLen = desc.Length8 << 3;
	userLen = packetLen - (desc.DataOffset8 << 3);

	*BufferActualLen = packetLen;

	if (packetLen > BufferLen)
		return -ENOBUFS;


	*RequestId = desc.TransactionId;

	// Copy over the entire packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, packetLen, 0);

	return 0;
}
