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
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/lock.h>
#include <sys/mutex.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include "hv_support.h"
#include "hv_hv.h"
#include "hv_vmbus_var.h"
#include "hv_vmbus_api.h"
#include <dev/hyperv/include/hv_list.h>
#include "hv_ring_buffer.h"
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/include/hv_channel_messages.h>
#include "hv_channel_mgmt.h"
#include "hv_connection.h"
#include "hv_channel.h"
#include "hv_channel_interface.h"
#include "hv_ic.h"
// Fixme:  need this?  Was in hv_vmbus_private.h
#include "hv_vmbus_private.h"

static int
VmbusChannelCreateGpadlHeader(void *Kbuffer, // must be phys and virt contiguous
	uint32_t Size,	 // page-size multiple
	VMBUS_CHANNEL_MSGINFO **msgInfo, uint32_t *MessageCount);

static void
DumpVmbusChannel(VMBUS_CHANNEL *Channel);

static void
VmbusChannelSetEvent(VMBUS_CHANNEL *Channel);

#if 0
void
DumpMonitorPage( HV_MONITOR_PAGE *MonitorPage)
{
	int i=0;
	int j=0;

	DPRINT_DBG(VMBUS, "monitorPage - %p, trigger state - %d", MonitorPage, MonitorPage->TriggerState);

	for (i=0; i<4; i++)
	{
		DPRINT_DBG(VMBUS, "trigger group (%d) - %lx", i, MonitorPage->TriggerGroup[i].as_uint64_t);
	}

	for (i=0; i<4; i++)
	{
		for (j=0; j<32; j++)
		{
			DPRINT_DBG(VMBUS, "latency (%d)(%d) - %lx", i, j, MonitorPage->Latency[i][j]);
		}
	}
	for (i=0; i<4; i++)
	{
		for (j=0; j<32; j++)
		{
			DPRINT_DBG(VMBUS, "param-conn id (%d)(%d) - %d", i, j, MonitorPage->Parameter[i][j].ConnectionId.Asuint32_t);
			DPRINT_DBG(VMBUS, "param-flag (%d)(%d) - %d", i, j, MonitorPage->Parameter[i][j].FlagNumber);

		}
	}
}
#endif

/*++

 Name:
 VmbusChannelSetEvent()

 Description:
 Trigger an event notification on the specified channel.

 --*/
static void
VmbusChannelSetEvent(VMBUS_CHANNEL *Channel) {
	HV_MONITOR_PAGE *monitorPage;

	DPRINT_ENTER(VMBUS);

	if (Channel->OfferMsg.MonitorAllocated) {
		// Each uint32_t represents 32 channels
		BitSet(
			(uint32_t*) gVmbusConnection.SendInterruptPage
				+ (Channel->OfferMsg.ChildRelId >> 5),
			Channel->OfferMsg.ChildRelId & 31);

		monitorPage = (HV_MONITOR_PAGE*) gVmbusConnection.MonitorPages;
		monitorPage++; // Get the child to parent monitor page

		BitSet(
			(uint32_t*) &monitorPage->TriggerGroup[Channel->MonitorGroup].Pending,
			Channel->MonitorBit);
	} else {
		VmbusSetEvent(Channel->OfferMsg.ChildRelId);
	}

	DPRINT_EXIT(VMBUS);
}

#if 0
static void
VmbusChannelClearEvent(
	VMBUS_CHANNEL *Channel
)
{
	HV_MONITOR_PAGE *monitorPage;

	DPRINT_ENTER(VMBUS);

	if (Channel->OfferMsg.MonitorAllocated)
	{
		// Each uint32_t represents 32 channels
		BitClear((uint32_t*)gVmbusConnection.SendInterruptPage + (Channel->OfferMsg.ChildRelId >> 5), Channel->OfferMsg.ChildRelId & 31);

		monitorPage = (HV_MONITOR_PAGE*)gVmbusConnection.MonitorPages;
		monitorPage++;// Get the child to parent monitor page

		BitClear((uint32_t*) &monitorPage->TriggerGroup[Channel->MonitorGroup].Pending, Channel->MonitorBit);
	}

	DPRINT_EXIT(VMBUS);
}

#endif
/*++;

 Name:
 VmbusChannelGetDebugInfo()

 Description:
 Retrieve various channel debug info

 --*/
void
hv_vmbus_channel_get_debug_info(VMBUS_CHANNEL *Channel,
	VMBUS_CHANNEL_DEBUG_INFO *DebugInfo) {

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

/*++;

 Name:
 VmbusChannelOpen()

 Description:
 Open the specified channel.

 --*/
int
hv_vmbus_channel_open(VMBUS_CHANNEL *NewChannel, uint32_t SendRingBufferSize,
	uint32_t RecvRingBufferSize, void *UserData, uint32_t UserDataLen,
	PFN_CHANNEL_CALLBACK pfnOnChannelCallback, void *Context) {

	int ret = 0;
	VMBUS_CHANNEL_OPEN_CHANNEL* openMsg;
	VMBUS_CHANNEL_MSGINFO* openInfo;
	void *in, *out;

	DPRINT_ENTER(VMBUS);

	// Aligned to page size
	ASSERT(!(SendRingBufferSize & (PAGE_SIZE -1)));
	ASSERT(!(RecvRingBufferSize & (PAGE_SIZE -1)));

	NewChannel->OnChannelCallback = pfnOnChannelCallback;
	NewChannel->ChannelCallbackContext = Context;

	// Allocate the ring buffer
	out = hv_page_contigmalloc(
		(SendRingBufferSize + RecvRingBufferSize) >> PAGE_SHIFT);

	in = ((uint8_t *)out + SendRingBufferSize);

	NewChannel->RingBufferPages = out;
	NewChannel->RingBufferPageCount = (SendRingBufferSize
		+ RecvRingBufferSize) >> PAGE_SHIFT;

	RingBufferInit(&NewChannel->Outbound, out, SendRingBufferSize);

	RingBufferInit(&NewChannel->Inbound, in, RecvRingBufferSize);

	// Establish the gpadl for the ring buffer
	DPRINT_DBG(VMBUS, "Establishing ring buffer's gpadl for channel %p...",
		NewChannel);

	NewChannel->RingBufferGpadlHandle = 0;

	ret = hv_vmbus_channel_establish_gpadl(NewChannel,
		NewChannel->Outbound.RingBuffer,
		SendRingBufferSize + RecvRingBufferSize,
		&NewChannel->RingBufferGpadlHandle);

	DPRINT_DBG(
		VMBUS,
		"channel %p <relid %d gpadl 0x%x send ring %p size %d recv ring %p size %d, downstreamoffset %d>",
		NewChannel, NewChannel->OfferMsg.ChildRelId, NewChannel->RingBufferGpadlHandle, NewChannel->Outbound.RingBuffer, NewChannel->Outbound.RingSize, NewChannel->Inbound.RingBuffer, NewChannel->Inbound.RingSize, SendRingBufferSize);

	// Create and init the channel open message 
	openInfo = (VMBUS_CHANNEL_MSGINFO*)malloc(
		   sizeof(VMBUS_CHANNEL_MSGINFO) +
		   sizeof(VMBUS_CHANNEL_OPEN_CHANNEL), M_DEVBUF, M_NOWAIT);

	ASSERT(openInfo != NULL);

	openInfo->WaitEvent = WaitEventCreate();

	openMsg = (VMBUS_CHANNEL_OPEN_CHANNEL*) openInfo->Msg;
	openMsg->Header.MessageType = ChannelMessageOpenChannel;
	openMsg->OpenId = NewChannel->OfferMsg.ChildRelId; // FIXME
	openMsg->ChildRelId = NewChannel->OfferMsg.ChildRelId;
	openMsg->RingBufferGpadlHandle = NewChannel->RingBufferGpadlHandle;
	ASSERT(openMsg->RingBufferGpadlHandle);
	openMsg->DownstreamRingBufferPageOffset = SendRingBufferSize
		>> PAGE_SHIFT;
	openMsg->ServerContextAreaGpadlHandle = 0; // TODO

	ASSERT(UserDataLen <= MAX_USER_DEFINED_BYTES);
	if (UserDataLen) {
		memcpy(openMsg->UserData, UserData, UserDataLen);
	}

	mtx_lock(gVmbusConnection.ChannelMsgLock);
	INSERT_TAIL_LIST(&gVmbusConnection.ChannelMsgList, &openInfo->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	DPRINT_DBG(VMBUS, "Sending channel open msg...");

	ret = VmbusPostMessage(openMsg, sizeof(VMBUS_CHANNEL_OPEN_CHANNEL));
	if (ret != 0) {
		DPRINT_ERR(VMBUS, "unable to open channel - %d", ret);
		goto Cleanup;
	}

	// FIXME: Need to time-out here
	WaitEventWait(openInfo->WaitEvent);

	if (openInfo->Response.OpenResult.Status == 0) {
		DPRINT_DBG(VMBUS, "channel <%p> open success!!", NewChannel);
	} else {
		DPRINT_INFO(VMBUS, "channel <%p> open failed - %d!!",
			NewChannel, openInfo->Response.OpenResult.Status);
	}

Cleanup:
	mtx_lock(gVmbusConnection.ChannelMsgLock);
	REMOVE_ENTRY_LIST(&openInfo->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	WaitEventClose(openInfo->WaitEvent);
	free(openInfo, M_DEVBUF);

	DPRINT_EXIT(VMBUS);

	return 0;
}

/*++;

 Name:
 DumpGpadlBody()

 Description:
 Dump the gpadl body message to the console for debugging purposes.

 --*/
static void
DumpGpadlBody(VMBUS_CHANNEL_GPADL_BODY *Gpadl, uint32_t Len) {
	int i = 0;
	int pfnCount = 0;

	pfnCount = (Len - sizeof(VMBUS_CHANNEL_GPADL_BODY)) / sizeof(uint64_t);
	DPRINT_DBG(VMBUS, "gpadl body - len %ud pfn count %d", Len, pfnCount);

	for (i = 0; i < pfnCount; i++) {
		DPRINT_DBG(VMBUS, "gpadl body  - %d) pfn %lu",
			i, Gpadl->Pfn[i]);
	}
}

/* Fixme:  NetScaler debugging code */
static void
DumpGpadlBody2(VMBUS_CHANNEL_GPADL_BODY *, uint32_t);

static void
DumpGpadlBody2(VMBUS_CHANNEL_GPADL_BODY *Gpadl, uint32_t Len) {
	int i = 0;
	int pfnCount = 0;

	pfnCount = (Len - sizeof(VMBUS_CHANNEL_GPADL_BODY)) / sizeof(uint64_t);
	printf("gpadl body - len %d pfn count %d\n gpadl body -", Len,
		pfnCount);

	for (i = 0; i < pfnCount; i++) {
		printf(" %d) pfn %lu", i, Gpadl->Pfn[i]);
	}
}

/*++;

 Name:
 DumpGpadlHeader()

 Description:
 Dump the gpadl header message to the console for debugging purposes.

 --*/
static void
DumpGpadlHeader(VMBUS_CHANNEL_GPADL_HEADER *Gpadl) {
	int i = 0, j = 0;
	int pageCount = 0;

	DPRINT_DBG(VMBUS,
		"gpadl header - relid %d, range count %d, range buflen %d",
		Gpadl->ChildRelId, Gpadl->RangeCount, Gpadl->RangeBufLen);
	for (i = 0; i < Gpadl->RangeCount; i++) {
		pageCount = Gpadl->Range[i].ByteCount >> PAGE_SHIFT;
		pageCount = (pageCount > 26) ? 26 : pageCount;

		DPRINT_DBG(
			VMBUS,
			"gpadl range %d - len %d offset %d page count %d",
			i, Gpadl->Range[i].ByteCount, Gpadl->Range[i].ByteOffset, pageCount);

		for (j = 0; j < pageCount; j++) {
			DPRINT_DBG(VMBUS, "%d) pfn %lu",
				j, Gpadl->Range[i].PfnArray[j]);
		}
	}
}

/* Fixme:  NetScaler debugging code */
static void
DumpGpadlHeader2(VMBUS_CHANNEL_GPADL_HEADER *Gpadl);

static void
DumpGpadlHeader2(VMBUS_CHANNEL_GPADL_HEADER *Gpadl) {
	int i = 0, j = 0;
	int pageCount = 0;

	printf("gpadl header - relid %d, range count %d, range buflen %d\n",
		Gpadl->ChildRelId, Gpadl->RangeCount, Gpadl->RangeBufLen);
	for (i = 0; i < Gpadl->RangeCount; i++) {
		pageCount = Gpadl->Range[i].ByteCount >> PAGE_SHIFT;
		pageCount = (pageCount > 26) ? 26 : pageCount;

		printf("gpadl range %d - len %d offset %d page count %d\n", i,
			Gpadl->Range[i].ByteCount, Gpadl->Range[i].ByteOffset,
			pageCount);

		for (j = 0; j < pageCount; j++) {
			printf("%d) pfn %lu ", j, Gpadl->Range[i].PfnArray[j]);
		}
	}
}

/*++;

 Name:
 VmbusChannelCreateGpadlHeader()

 Description:
 Creates a gpadl for the specified buffer

 --*/
static int
VmbusChannelCreateGpadlHeader(void *Kbuffer, // from kmalloc()
	uint32_t Size,	// page-size multiple
	VMBUS_CHANNEL_MSGINFO **MsgInfo, uint32_t *MessageCount) {
	int i;
	int pageCount;
	unsigned long long pfn;
	VMBUS_CHANNEL_GPADL_HEADER* gpaHeader;
	VMBUS_CHANNEL_GPADL_BODY* gpadlBody;
	VMBUS_CHANNEL_MSGINFO* msgHeader;
	VMBUS_CHANNEL_MSGINFO* msgBody;
	uint32_t msgSize;

	int pfnSum, pfnCount, pfnLeft, pfnCurr, pfnSize;

	//ASSERT( (kbuffer & (PAGE_SIZE-1)) == 0);
	ASSERT( (Size & (PAGE_SIZE-1)) == 0);

	pageCount = Size >> PAGE_SHIFT;
	pfn = GetPhysicalAddress(Kbuffer) >> PAGE_SHIFT;

	// do we need a gpadl body msg
	pfnSize = MAX_SIZE_CHANNEL_MESSAGE - sizeof(VMBUS_CHANNEL_GPADL_HEADER)
		- sizeof(GPA_RANGE);
	pfnCount = pfnSize / sizeof(uint64_t);

	if (pageCount > pfnCount) // we need a gpadl body
		{
		// fill in the header
		msgSize = sizeof(VMBUS_CHANNEL_MSGINFO)
			+ sizeof(VMBUS_CHANNEL_GPADL_HEADER) + sizeof(GPA_RANGE)
			+ pfnCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		INITIALIZE_LIST_HEAD(&msgHeader->SubMsgList);
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
			ASSERT(msgBody);
			msgBody->MessageSize = msgSize;
			(*MessageCount)++;
			gpadlBody = (VMBUS_CHANNEL_GPADL_BODY*) msgBody->Msg;

			// FIXME: Gpadl is uint32_t and we are using a pointer which could be 64-bit
			//gpadlBody->Gpadl = kbuffer;
			for (i = 0; i < pfnCurr; i++) {
				gpadlBody->Pfn[i] = pfn + pfnSum + i;
			}

			// add to msg header
			INSERT_TAIL_LIST(&msgHeader->SubMsgList, &msgBody->MsgListEntry);
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
hv_vmbus_channel_establish_gpadl(VMBUS_CHANNEL *Channel, void *Kbuffer, // from kmalloc()
	uint32_t Size,	 // page-size multiple
	uint32_t *GpadlHandle) {
	int ret = 0;
	VMBUS_CHANNEL_GPADL_HEADER* gpadlMsg;
	VMBUS_CHANNEL_GPADL_BODY* gpadlBody;
	//VMBUS_CHANNEL_GPADL_CREATED* gpadlCreated;

	VMBUS_CHANNEL_MSGINFO *msgInfo;
	VMBUS_CHANNEL_MSGINFO *subMsgInfo;

	uint32_t msgCount;
	LIST_ENTRY* anchor;
	LIST_ENTRY* curr;
	uint32_t nextGpadlHandle;

	/* Fixme:  NetScaler */
	int retrycnt = 0;

	/* Fixme:  NetScaler:  Used in error message only */
	int mcnt = 0;

	DPRINT_ENTER(VMBUS);

	nextGpadlHandle = gVmbusConnection.NextGpadlHandle;
	InterlockedIncrement((int*) &gVmbusConnection.NextGpadlHandle);

	VmbusChannelCreateGpadlHeader(Kbuffer, Size, &msgInfo, &msgCount);
	ASSERT(msgInfo != NULL);
	ASSERT(msgCount >0);

	msgInfo->WaitEvent = WaitEventCreate();
	gpadlMsg = (VMBUS_CHANNEL_GPADL_HEADER*) msgInfo->Msg;
	gpadlMsg->Header.MessageType = ChannelMessageGpadlHeader;
	gpadlMsg->ChildRelId = Channel->OfferMsg.ChildRelId;
	gpadlMsg->Gpadl = nextGpadlHandle;

	DumpGpadlHeader(gpadlMsg);

	mtx_lock(gVmbusConnection.ChannelMsgLock);
	INSERT_TAIL_LIST(&gVmbusConnection.ChannelMsgList, &msgInfo->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	DPRINT_DBG(VMBUS, "buffer %p, size %d msg cnt %d",
		Kbuffer, Size, msgCount);

	DPRINT_DBG(VMBUS, "Sending GPADL Header - len %d",
		msgInfo->MessageSize - (uint32_t)sizeof(VMBUS_CHANNEL_MSGINFO));

	ret = VmbusPostMessage(gpadlMsg,
		msgInfo->MessageSize - (uint32_t) sizeof(VMBUS_CHANNEL_MSGINFO));
	if (ret != 0) {
		DPRINT_ERR(VMBUS, "Unable to open channel - %d", ret);
		goto Cleanup;
	}

	mcnt = 1;
	if (msgCount > 1) {
		ITERATE_LIST_ENTRIES(anchor, curr, &msgInfo->SubMsgList)
		{
			mcnt++;
			subMsgInfo = (VMBUS_CHANNEL_MSGINFO*) curr;
			gpadlBody = (VMBUS_CHANNEL_GPADL_BODY*) subMsgInfo->Msg;

			gpadlBody->Header.MessageType = ChannelMessageGpadlBody;
			gpadlBody->Gpadl = nextGpadlHandle;

			DPRINT_DBG(
				VMBUS,
				"Sending GPADL Body - len %d",
				subMsgInfo->MessageSize - (uint32_t)sizeof(VMBUS_CHANNEL_MSGINFO));

			DumpGpadlBody(
				gpadlBody,
				subMsgInfo->MessageSize
					- (uint32_t) sizeof(VMBUS_CHANNEL_MSGINFO));
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
					DumpGpadlHeader2(gpadlMsg);
					DumpGpadlBody2(
						gpadlBody,
						subMsgInfo->MessageSize
							- (uint32_t) sizeof(VMBUS_CHANNEL_MSGINFO));
					Sleep(5000);
					retrycnt++;
					goto retry;
				}
			}ASSERT(ret == 0);
		}
	}
	WaitEventWait(msgInfo->WaitEvent);

	// At this point, we received the gpadl created msg
	DPRINT_DBG(
		VMBUS,
		"Received GPADL created (relid %d, status %d handle %x)",
		Channel->OfferMsg.ChildRelId, msgInfo->Response.GpadlCreated.CreationStatus, gpadlMsg->Gpadl);

	*GpadlHandle = gpadlMsg->Gpadl;

Cleanup:

	mtx_lock(gVmbusConnection.ChannelMsgLock);
	REMOVE_ENTRY_LIST(&msgInfo->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	WaitEventClose(msgInfo->WaitEvent);
	free(msgInfo, M_DEVBUF);
	DPRINT_EXIT(VMBUS);

	return ret;
}

/*++;

 Name:
 VmbusChannelTeardownGpadl()

 Description:
 Teardown the specified GPADL handle

 --*/
int
hv_vmbus_channel_teardown_gpdal(VMBUS_CHANNEL *Channel, uint32_t GpadlHandle) {
	int ret = 0;
	VMBUS_CHANNEL_GPADL_TEARDOWN *msg;
	VMBUS_CHANNEL_MSGINFO* info;

	DPRINT_ENTER(VMBUS);

	ASSERT(GpadlHandle != 0);

	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(VMBUS_CHANNEL_GPADL_TEARDOWN),
				M_DEVBUF, M_NOWAIT);

	ASSERT(info != NULL);

	info->WaitEvent = WaitEventCreate();

	msg = (VMBUS_CHANNEL_GPADL_TEARDOWN*) info->Msg;

	msg->Header.MessageType = ChannelMessageGpadlTeardown;
	msg->ChildRelId = Channel->OfferMsg.ChildRelId;
	msg->Gpadl = GpadlHandle;

	mtx_lock(gVmbusConnection.ChannelMsgLock);
	INSERT_TAIL_LIST(&gVmbusConnection.ChannelMsgList, &info->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	ret = VmbusPostMessage(msg, sizeof(VMBUS_CHANNEL_GPADL_TEARDOWN));
	if (ret != 0) {
		// TODO:
	}

	WaitEventWait(info->WaitEvent);

	// Received a torndown response
	mtx_lock(gVmbusConnection.ChannelMsgLock);
	REMOVE_ENTRY_LIST(&info->MsgListEntry);
	mtx_unlock(gVmbusConnection.ChannelMsgLock);

	WaitEventClose(info->WaitEvent);
	free(info, M_DEVBUF);
	DPRINT_EXIT(VMBUS);

	return ret;
}

/*++

 Name:
 VmbusChannelClose()

 Description:
 Close the specified channel

 --*/
void
hv_vmbus_channel_close(VMBUS_CHANNEL *Channel) {
	int ret = 0;
	VMBUS_CHANNEL_CLOSE_CHANNEL* msg;
	VMBUS_CHANNEL_MSGINFO* info;

	DPRINT_ENTER(VMBUS);

	// Stop callback and cancel the timer asap
	Channel->OnChannelCallback = NULL;
	TimerStop(Channel->PollTimer);

	// Send a closing message
	info = (VMBUS_CHANNEL_MSGINFO *)
		malloc(	sizeof(VMBUS_CHANNEL_MSGINFO) +
			sizeof(VMBUS_CHANNEL_CLOSE_CHANNEL),
				M_DEVBUF, M_NOWAIT);

	ASSERT(info != NULL);

	//info->waitEvent = WaitEventCreate();

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

	hv_page_contigfree(Channel->RingBufferPages, Channel->RingBufferPageCount);

	free(info, M_DEVBUF);

	// If we are closing the channel during an error path in opening the channel, don't free the channel
	// since the caller will free the channel
	if (Channel->State == CHANNEL_OPEN_STATE) {
		mtx_lock(gVmbusConnection.ChannelLock);
		REMOVE_ENTRY_LIST(&Channel->ListEntry);
		mtx_unlock(gVmbusConnection.ChannelLock);

		FreeVmbusChannel(Channel);
	}

	DPRINT_EXIT(VMBUS);
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
	uint32_t Flags) {
	
	int ret = 0;
	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen = sizeof(VMPACKET_DESCRIPTOR) + BufferLen;
	uint32_t packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;

	DPRINT_ENTER(VMBUS);DPRINT_DBG(VMBUS, "channel %p buffer %p len %d",
		Channel, Buffer, BufferLen);

	DumpVmbusChannel(Channel);

	ASSERT((packetLenAligned - packetLen) < sizeof(uint64_t));

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

	DPRINT_EXIT(VMBUS);

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
	uint32_t BufferLen, uint64_t RequestId) {
	
	int ret = 0;
	int i = 0;
	VMBUS_CHANNEL_PACKET_PAGE_BUFFER desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;

	DPRINT_ENTER(VMBUS);

	ASSERT(PageCount <= MAX_PAGE_BUFFER_COUNT);

	DumpVmbusChannel(Channel);

	// Adjust the size down since VMBUS_CHANNEL_PACKET_PAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_PAGE_BUFFER)
		- ((MAX_PAGE_BUFFER_COUNT - PageCount) * sizeof(PAGE_BUFFER));
	packetLen = descSize + BufferLen;
	packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));

	ASSERT((packetLenAligned - packetLen) < sizeof(uint64_t));

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

	DPRINT_EXIT(VMBUS);

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
	uint64_t RequestId) {
	
	int ret = 0;
	VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	SG_BUFFER_LIST bufferList[3];
	uint64_t alignedData = 0;
	uint32_t PfnCount =
		NUM_PAGES_SPANNED(MultiPageBuffer->Offset, MultiPageBuffer->Length);

	DPRINT_ENTER(VMBUS);

	DumpVmbusChannel(Channel);

	DPRINT_DBG(VMBUS, "data buffer - offset %u len %u pfn count %u",
		MultiPageBuffer->Offset, MultiPageBuffer->Length, PfnCount);

	ASSERT(PfnCount > 0);
	ASSERT(PfnCount <= MAX_MULTIPAGE_BUFFER_COUNT);

	// Adjust the size down since VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER is the largest size we support
	descSize = sizeof(VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER)
		- ((MAX_MULTIPAGE_BUFFER_COUNT - PfnCount) * sizeof(uint64_t));
	packetLen = descSize + BufferLen;
	packetLenAligned = ALIGN_UP(packetLen, sizeof(uint64_t));

	ASSERT((packetLenAligned - packetLen) < sizeof(uint64_t));

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

	DPRINT_EXIT(VMBUS);

	return ret;
}

/*++

 Name:
 VmbusChannelRecvPacket()

 Description:
 Retrieve the user packet on the specified channel

 --*/
// TODO: Do we ever receive a gpa direct packet other than the ones we send ?
int
hv_vmbus_channel_recv_packet(VMBUS_CHANNEL *Channel, void *Buffer,
	uint32_t BufferLen, uint32_t *BufferActualLen, uint64_t *RequestId) {

	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;

	DPRINT_ENTER(VMBUS);

	*BufferActualLen = 0;
	*RequestId = 0;

	mtx_lock(Channel->InboundLock);

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(VMPACKET_DESCRIPTOR));
	if (ret != 0) {
		mtx_unlock(Channel->InboundLock);
		//DPRINT_DBG(VMBUS, "nothing to read!!");
		DPRINT_EXIT(VMBUS);
		return 0;
	}

	//VmbusChannelClearEvent(Channel);

	packetLen = desc.Length8 << 3;
	userLen = packetLen - (desc.DataOffset8 << 3);
	//ASSERT(userLen > 0);

	DPRINT_DBG(
		VMBUS,
		"packet received on channel %p relid %d <type %d flag %d tid %lx pktlen %d datalen %d> ",
		Channel, Channel->OfferMsg.ChildRelId, desc.Type, desc.Flags, desc.TransactionId, packetLen, userLen);

	*BufferActualLen = userLen;

	if (userLen > BufferLen) {
		mtx_unlock(Channel->InboundLock);

		/* Fixme:  NetScaler:  Commented out */
//		DPRINT_ERR(VMBUS, "buffer too small - got %d needs %d", BufferLen, userLen);
		DPRINT_EXIT(VMBUS);

		return -1;
	}

	*RequestId = desc.TransactionId;

	// Copy over the packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, userLen,
		(desc.DataOffset8 << 3));

	mtx_unlock(Channel->InboundLock);

	DPRINT_EXIT(VMBUS);

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
	uint32_t BufferLen, uint32_t *BufferActualLen, uint64_t *RequestId) {
	
	VMPACKET_DESCRIPTOR desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;

	DPRINT_ENTER(VMBUS);

	*BufferActualLen = 0;
	*RequestId = 0;

	mtx_lock(Channel->InboundLock);

	ret = RingBufferPeek(&Channel->Inbound, &desc,
		sizeof(VMPACKET_DESCRIPTOR));
	if (ret != 0) {
		mtx_unlock(Channel->InboundLock);

		//DPRINT_DBG(VMBUS, "nothing to read!!");
		DPRINT_EXIT(VMBUS);
		return 0;
	}

	//VmbusChannelClearEvent(Channel);

	packetLen = desc.Length8 << 3;
	userLen = packetLen - (desc.DataOffset8 << 3);

	DPRINT_DBG(
		VMBUS,
		"packet received on channel %p relid %d <type %d flag %d tid %lx pktlen %d datalen %d> ",
		Channel, Channel->OfferMsg.ChildRelId, desc.Type, desc.Flags, desc.TransactionId, packetLen, userLen);

	*BufferActualLen = packetLen;

	if (packetLen > BufferLen) {
		mtx_unlock(Channel->InboundLock);

		/* Fixme:  NetScaler:  Commented out */
//		DPRINT_ERR(VMBUS, "buffer too small - needed %d bytes but got space for only %d bytes", packetLen, BufferLen);
		DPRINT_EXIT(VMBUS);
		return -2;
	}

	*RequestId = desc.TransactionId;

	// Copy over the entire packet to the user buffer
	ret = RingBufferRead(&Channel->Inbound, Buffer, packetLen, 0);

	mtx_unlock(Channel->InboundLock);

	DPRINT_EXIT(VMBUS);

	return 0;
}

/*++

 Name:
 VmbusChannelOnChannelEvent()

 Description:
 Channel event callback

 --*/

void
hv_vmbus_channel_on_channel_event(VMBUS_CHANNEL *Channel) {
	DumpVmbusChannel(Channel);
	ASSERT(Channel->OnChannelCallback);
	TimerStop(Channel->PollTimer);
	Channel->OnChannelCallback(Channel->ChannelCallbackContext);
	TimerStart(Channel->PollTimer, 100 /* 100us */);
}

/*++

 Name:
 VmbusChannelOnTimer()

 Description:
 Timer event callback

 --*/
void
hv_vmbus_channel_on_timer(void *Context) {
	VMBUS_CHANNEL *channel = (VMBUS_CHANNEL*) Context;

	/* Fixme:  NetScaler */
	/* If the channel is in poll mode, we don't need timer */
	/* We have to reenable the timer on exit from poll mode */

	if (VmbusGetChannelMode(channel->OfferMsg.ChildRelId))
		return;

	if (channel->OnChannelCallback) {
		channel->OnChannelCallback(channel->ChannelCallbackContext);
		TimerStart(channel->PollTimer, 100 /* 100us */);
	}
}

/*++

 Name:
 DumpVmbusChannel()

 Description:
 Dump vmbus channel info to the console

 --*/
static void
DumpVmbusChannel(VMBUS_CHANNEL *Channel) {
	DPRINT_DBG(VMBUS, "Channel (%d)", Channel->OfferMsg.ChildRelId);
	DumpRingInfo(&Channel->Outbound, "Outbound ");
	DumpRingInfo(&Channel->Inbound, "Inbound ");
}

