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

#include "hyperv.h"
#include "vmbus_priv.h"

static int
VmbusChannelCreateGpadlHeader(void *Kbuffer, // must be phys and virt contiguous
	uint32_t Size,	 // page-size multiple
	hv_vmbus_channel_msg_info **msgInfo, uint32_t *MessageCount);


static void
VmbusChannelSetEvent(hv_vmbus_channel *Channel);

/*++

 Name:
 VmbusChannelSetEvent()

 Description:
 Trigger an event notification on the specified channel.

 --*/
static void
VmbusChannelSetEvent(hv_vmbus_channel *Channel) 
{
	hv_vmbus_monitor_page *monitorPage;


	if (Channel->offer_msg.monitor_allocated) {
		// Each uint32_t represents 32 channels
		synch_set_bit((Channel->offer_msg.child_rel_id & 31),
			((uint32_t *)hv_vmbus_g_connection.send_interrupt_page +
			((Channel->offer_msg.child_rel_id >> 5))));

		monitorPage = (hv_vmbus_monitor_page *) hv_vmbus_g_connection.monitor_pages;
		monitorPage++; // Get the child to parent monitor page

		synch_set_bit(Channel->monitor_bit,
			(uint32_t *)&monitorPage->trigger_group[Channel->monitor_group].pending);
	} else {
		hv_vmbus_set_event(Channel->offer_msg.child_rel_id);
	}

}

/*++;

 Name:
 hv_vmbus_channel_get_debug_info()

 Description:
 Retrieve various channel debug info

 --*/
void
hv_vmbus_channel_get_debug_info(hv_vmbus_channel *Channel,
	hv_vmbus_channel_debug_info *debug_info) 
{

	hv_vmbus_monitor_page *monitorPage;
	uint8_t monitorGroup = (uint8_t) Channel->offer_msg.monitor_id / 32;
	uint8_t monitorOffset = (uint8_t) Channel->offer_msg.monitor_id % 32;
	//uint32_t monitorBit	= 1 << monitorOffset;

	debug_info->rel_id = Channel->offer_msg.child_rel_id;
	debug_info->state = Channel->state;
	memcpy(&debug_info->interface_type,
		&Channel->offer_msg.offer.interface_type, sizeof(hv_guid));
	memcpy(&debug_info->interface_instance,
		&Channel->offer_msg.offer.interface_instance, sizeof(hv_guid));

	monitorPage = (hv_vmbus_monitor_page*) hv_vmbus_g_connection.monitor_pages;

	debug_info->monitor_id = Channel->offer_msg.monitor_id;

	debug_info->server_monitor_pending =
		monitorPage->trigger_group[monitorGroup].pending;
	debug_info->server_monitor_latency =
		monitorPage->latency[monitorGroup][monitorOffset];
	debug_info->server_monitor_connection_id =
		monitorPage->parameter[monitorGroup][monitorOffset].connection_id.u.id;

	monitorPage++;

	debug_info->client_monitor_pending =
		monitorPage->trigger_group[monitorGroup].pending;
	debug_info->client_monitor_latency =
		monitorPage->latency[monitorGroup][monitorOffset];
	debug_info->client_monitor_connection_id =
		monitorPage->parameter[monitorGroup][monitorOffset].connection_id.u.id;

	hv_vmbus_ring_buffer_get_debug_info(&Channel->inbound, &debug_info->inbound);
	hv_vmbus_ring_buffer_get_debug_info(&Channel->outbound, &debug_info->outbound);
}

void
hv_vmbus_get_channel_info(struct hv_device *dev, struct hv_devinfo *p)
{
	hv_vmbus_channel_debug_info di;

	if (dev->channel) {
		hv_vmbus_channel_get_debug_info(dev->channel, &di);

		p->channel_id = di.rel_id;
		p->channel_state = di.state;
		memcpy(&p->channel_type, &di.interface_type, sizeof(hv_guid));
		memcpy(&p->channel_instance, &di.interface_instance,
			sizeof(hv_guid));

		p->monitor_id = di.monitor_id;

		p->server_monitor_pending = di.server_monitor_pending;
		p->server_monitor_latency = di.server_monitor_latency;
		p->server_monitor_connection_id = di.server_monitor_connection_id;

		p->client_monitor_pending = di.client_monitor_pending;
		p->client_monitor_latency = di.client_monitor_latency;
		p->client_monitor_connection_id = di.client_monitor_connection_id;

		p->in_bound.interrupt_mask = di.inbound.current_interrupt_mask;
		p->in_bound.read_index = di.inbound.current_read_index;
		p->in_bound.write_index = di.inbound.current_write_index;
		p->in_bound.bytes_avail_to_read = di.inbound.bytes_avail_to_read;
		p->in_bound.bytes_avail_to_write = di.inbound.bytes_avail_to_write;

		p->out_bound.interrupt_mask = di.outbound.current_interrupt_mask;
		p->out_bound.read_index = di.outbound.current_read_index;
		p->out_bound.write_index = di.outbound.current_write_index;
		p->out_bound.bytes_avail_to_read = di.outbound.bytes_avail_to_read;
		p->out_bound.bytes_avail_to_write = di.outbound.bytes_avail_to_write;
	}
}

/*++;

 Name:
 hv_vmbus_channel_open()

 Description:
 Open the specified channel.

 --*/
int
hv_vmbus_channel_open(hv_vmbus_channel *NewChannel, uint32_t send_ring_buffer_size,
	uint32_t recv_ring_buffer_size, void *user_data, uint32_t user_data_len,
	hv_vmbus_pfn_channel_callback pfn_on_channel_callback, void *Context) 
{

	int ret = 0;
	hv_vmbus_channel_open_channel* openMsg;
	hv_vmbus_channel_msg_info* openInfo;
	void *in, *out;


	NewChannel->on_channel_callback = pfn_on_channel_callback;
	NewChannel->channel_callback_context = Context;

	// Allocate the ring buffer
	out = contigmalloc((send_ring_buffer_size + recv_ring_buffer_size),
			M_DEVBUF, M_ZERO, 0UL, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);
			
	if (!out)
		return -ENOMEM;

	in = ((uint8_t *)out + send_ring_buffer_size);

	NewChannel->ring_buffer_pages = out;
	NewChannel->ring_buffer_page_count = (send_ring_buffer_size
		+ recv_ring_buffer_size) >> PAGE_SHIFT;

	hv_vmbus_ring_buffer_init(&NewChannel->outbound, out, send_ring_buffer_size);

	hv_vmbus_ring_buffer_init(&NewChannel->inbound, in, recv_ring_buffer_size);

	// Establish the gpadl for the ring buffer

	NewChannel->ring_buffer_gpadl_handle = 0;

	ret = hv_vmbus_channel_establish_gpadl(NewChannel,
		NewChannel->outbound.ring_buffer,
		send_ring_buffer_size + recv_ring_buffer_size,
		&NewChannel->ring_buffer_gpadl_handle);


	// Create and init the channel open message 
	openInfo = (hv_vmbus_channel_msg_info*)malloc(
		   sizeof(hv_vmbus_channel_msg_info) +
		   sizeof(hv_vmbus_channel_open_channel), M_DEVBUF, M_NOWAIT);

	if (!openInfo)
		return -ENOMEM;

	sema_init(&openInfo->wait_sema, 0, "Open Info Sema");

	openMsg = (hv_vmbus_channel_open_channel*) openInfo->msg;
	openMsg->header.message_type = HV_CHANNEL_MESSAGE_OPEN_CHANNEL;
	openMsg->open_id = NewChannel->offer_msg.child_rel_id; // FIXME
	openMsg->child_rel_id = NewChannel->offer_msg.child_rel_id;
	openMsg->ring_buffer_gpadl_handle = NewChannel->ring_buffer_gpadl_handle;
	openMsg->downstream_ring_buffer_page_offset = send_ring_buffer_size
		>> PAGE_SHIFT;
	openMsg->server_context_area_gpadl_handle = 0; // TODO

	if (user_data_len) {
		memcpy(openMsg->user_data, user_data, user_data_len);
	}

	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_INSERT_TAIL(&hv_vmbus_g_connection.channel_msg_anchor, openInfo, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);


	ret = hv_vmbus_post_message(openMsg, sizeof(hv_vmbus_channel_open_channel));

	if (ret != 0)
		goto Cleanup;

	ret = sema_timedwait(&openInfo->wait_sema, 500); //KYS 5 seconds 
	
	if (ret)
		goto Cleanup;

	if (openInfo->response.open_result.status == 0) {
		printf("channel <%p> open success!!", NewChannel);
	} else {
		printf("channel <%p> open failed - %d!!",
			NewChannel, openInfo->response.open_result.status);
	}

Cleanup:
	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_REMOVE(&hv_vmbus_g_connection.channel_msg_anchor, openInfo, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);
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
	hv_vmbus_channel_msg_info **MsgInfo, uint32_t *MessageCount) 
{
	int i;
	int pageCount;
	unsigned long long pfn;
	hv_vmbus_channel_gpadl_header* gpaHeader;
	hv_vmbus_channel_gpadl_body* gpadlBody;
	hv_vmbus_channel_msg_info* msgHeader;
	hv_vmbus_channel_msg_info* msgBody;
	uint32_t msgSize;

	int pfnSum, pfnCount, pfnLeft, pfnCurr, pfnSize;


	pageCount = Size >> PAGE_SHIFT;
	pfn = hv_get_phys_addr(Kbuffer) >> PAGE_SHIFT;

	// do we need a gpadl body msg
	pfnSize = HV_MAX_SIZE_CHANNEL_MESSAGE - sizeof(hv_vmbus_channel_gpadl_header)
		- sizeof(hv_gpa_range);
	pfnCount = pfnSize / sizeof(uint64_t);

	if (pageCount > pfnCount) { // we need a gpadl body
		// fill in the header
		msgSize = sizeof(hv_vmbus_channel_msg_info)
			+ sizeof(hv_vmbus_channel_gpadl_header) + sizeof(hv_gpa_range)
			+ pfnCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		TAILQ_INIT(&msgHeader->sub_msg_list_anchor);
		msgHeader->message_size = msgSize;

		gpaHeader = (hv_vmbus_channel_gpadl_header*) msgHeader->msg;
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
		pfnSize = HV_MAX_SIZE_CHANNEL_MESSAGE
			- sizeof(hv_vmbus_channel_gpadl_body);
		pfnCount = pfnSize / sizeof(uint64_t);

		// fill in the body
		while (pfnLeft) {
			if (pfnLeft > pfnCount) {
				pfnCurr = pfnCount;
			} else {
				pfnCurr = pfnLeft;
			}

			msgSize = sizeof(hv_vmbus_channel_msg_info)
				+ sizeof(hv_vmbus_channel_gpadl_body)
				+ pfnCurr * sizeof(uint64_t);
			msgBody = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
			msgBody->message_size = msgSize;
			(*MessageCount)++;
			gpadlBody = (hv_vmbus_channel_gpadl_body*) msgBody->msg;

			// FIXME: Gpadl is uint32_t and we are using a pointer which could be 64-bit
			//gpadlBody->gpadl = kbuffer;
			for (i = 0; i < pfnCurr; i++) {
				gpadlBody->pfn[i] = pfn + pfnSum + i;
			}

			TAILQ_INSERT_TAIL(&msgHeader->sub_msg_list_anchor, msgBody, msg_list_entry);
			pfnSum += pfnCurr;
			pfnLeft -= pfnCurr;
		}
	} else {
		// everything fits in a header
		msgSize = sizeof(hv_vmbus_channel_msg_info)
			+ sizeof(hv_vmbus_channel_gpadl_header) + sizeof(hv_gpa_range)
			+ pageCount * sizeof(uint64_t);
		msgHeader = malloc(msgSize, M_DEVBUF, M_NOWAIT | M_ZERO);
		msgHeader->message_size = msgSize;

		gpaHeader = (hv_vmbus_channel_gpadl_header*) msgHeader->msg;
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
 hv_vmbus_channel_establish_gpadl()

 Description:
 Estabish a GPADL for the specified buffer

 --*/
int
hv_vmbus_channel_establish_gpadl(hv_vmbus_channel *Channel, void *Kbuffer,
	uint32_t Size,	 // page-size multiple
	uint32_t *gpadl_handle) 

{
	int ret = 0;
	hv_vmbus_channel_gpadl_header* gpadlMsg;
	hv_vmbus_channel_gpadl_body* gpadlBody;

	hv_vmbus_channel_msg_info *msgInfo;
	hv_vmbus_channel_msg_info *subMsgInfo;

	uint32_t msgCount;
	struct hv_vmbus_channel_msg_info *curr;
	uint32_t next_gpadl_handle;

	/* Fixme:  NetScaler */
	int retrycnt = 0;

	/* Fixme:  NetScaler:  Used in error message only */
	int mcnt = 0;

	next_gpadl_handle = hv_vmbus_g_connection.next_gpadl_handle;
	atomic_add_int((int*) &hv_vmbus_g_connection.next_gpadl_handle, 1);

	VmbusChannelCreateGpadlHeader(Kbuffer, Size, &msgInfo, &msgCount);

	/*
	 * XXXKYS: Deal with allocation failures in 
	 * VmbusChannelCreateGpadlHeader()
	 */

	sema_init(&msgInfo->wait_sema, 0, "Open Info Sema");
	gpadlMsg = (hv_vmbus_channel_gpadl_header*) msgInfo->msg;
	gpadlMsg->header.message_type = HV_CHANNEL_MESSAGEL_GPADL_HEADER;
	gpadlMsg->child_rel_id = Channel->offer_msg.child_rel_id;
	gpadlMsg->gpadl = next_gpadl_handle;


	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_INSERT_TAIL(&hv_vmbus_g_connection.channel_msg_anchor, msgInfo, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);


	ret = hv_vmbus_post_message(gpadlMsg,
		msgInfo->message_size - (uint32_t) sizeof(hv_vmbus_channel_msg_info));
	if (ret != 0) {
		goto Cleanup;
	}

	mcnt = 1;
	if (msgCount > 1) {
		TAILQ_FOREACH(curr, &msgInfo->sub_msg_list_anchor, msg_list_entry)
		{
			mcnt++;
			subMsgInfo = curr;
			gpadlBody = (hv_vmbus_channel_gpadl_body*) subMsgInfo->msg;

			gpadlBody->header.message_type = HV_CHANNEL_MESSAGE_GPADL_BODY;
			gpadlBody->gpadl = next_gpadl_handle;

			retry: ret =
				hv_vmbus_post_message(
					gpadlBody,
					subMsgInfo->message_size
						- (uint32_t) sizeof(hv_vmbus_channel_msg_info));
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


	*gpadl_handle = gpadlMsg->gpadl;

Cleanup:

	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_REMOVE(&hv_vmbus_g_connection.channel_msg_anchor, msgInfo, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);

	sema_destroy(&msgInfo->wait_sema);
	free(msgInfo, M_DEVBUF);

	return ret;
}

/*++;

 Name:
 hv_vmbus_channel_teardown_gpdal()

 Description:
 Teardown the specified GPADL handle

 --*/
int
hv_vmbus_channel_teardown_gpdal(hv_vmbus_channel *Channel, uint32_t gpadl_handle) 
{
	int ret = 0;
	hv_vmbus_channel_gpadl_teardown *msg;
	hv_vmbus_channel_msg_info* info;


	info = (hv_vmbus_channel_msg_info *)
		malloc(	sizeof(hv_vmbus_channel_msg_info) +
			sizeof(hv_vmbus_channel_gpadl_teardown),
				M_DEVBUF, M_NOWAIT);

	if (!info) {
		ret = -ENOMEM;
		goto cleanup;
	}

	sema_init(&info->wait_sema, 0, "Open Info Sema");

	msg = (hv_vmbus_channel_gpadl_teardown*) info->msg;

	msg->header.message_type = HV_CHANNEL_MESSAGE_GPADL_TEARDOWN;
	msg->child_rel_id = Channel->offer_msg.child_rel_id;
	msg->gpadl = gpadl_handle;

	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_INSERT_TAIL(&hv_vmbus_g_connection.channel_msg_anchor, info, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);

	ret = hv_vmbus_post_message(msg, sizeof(hv_vmbus_channel_gpadl_teardown));
	if (ret != 0) 
		goto cleanup;
	

	ret = sema_timedwait(&info->wait_sema, 500); //KYS 5 seconds

cleanup:

	// Received a torndown response
	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_REMOVE(&hv_vmbus_g_connection.channel_msg_anchor, info, msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	sema_destroy(&info->wait_sema);
	free(info, M_DEVBUF);

	return ret;
}

/*++

 Name:
 hv_vmbus_channel_close()

 Description:
 Close the specified channel

 --*/
void
hv_vmbus_channel_close(hv_vmbus_channel *Channel) 
{
	int ret = 0;
	hv_vmbus_channel_close_channel* msg;
	hv_vmbus_channel_msg_info* info;

	mtx_lock(&Channel->inbound_lock);
	Channel->on_channel_callback = NULL;
	mtx_unlock(&Channel->inbound_lock);

	// Send a closing message
	info = (hv_vmbus_channel_msg_info *)
		malloc(	sizeof(hv_vmbus_channel_msg_info) +
			sizeof(hv_vmbus_channel_close_channel),
				M_DEVBUF, M_NOWAIT);

	KASSERT(info != NULL, ("malloc failed")); //KYS: eliminate this error

	msg = (hv_vmbus_channel_close_channel*) info->msg;
	msg->header.message_type = HV_CHANNEL_MESSAGE_CLOSE_CHANNEL;
	msg->child_rel_id = Channel->offer_msg.child_rel_id;

	ret = hv_vmbus_post_message(msg, sizeof(hv_vmbus_channel_close_channel));
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
	hv_ring_buffer_cleanup(&Channel->outbound);
	hv_ring_buffer_cleanup(&Channel->inbound);

	contigfree(Channel->ring_buffer_pages, Channel->ring_buffer_page_count, M_DEVBUF);

	free(info, M_DEVBUF);

	// If we are closing the channel during an error path in opening the channel, don't free the channel
	// since the caller will free the channel
	if (Channel->state == HV_CHANNEL_OPEN_STATE) {
		mtx_lock_spin(&hv_vmbus_g_connection.channel_lock);
		TAILQ_REMOVE(&hv_vmbus_g_connection.channel_anchor, Channel, list_entry);
		mtx_unlock_spin(&hv_vmbus_g_connection.channel_lock);

		hv_vmbus_free_vmbus_channel(Channel);
	}

}

/*++

 Name:
 hv_vmbus_channel_send_packet()

 Description:
 Send the specified buffer on the given channel

 --*/
int
hv_vmbus_channel_send_packet(hv_vmbus_channel *Channel, void *Buffer,
	uint32_t buffer_len, uint64_t request_id, hv_vmbus_packet_type Type,
	uint32_t Flags) 
{
	
	int ret = 0;
	hv_vm_packet_descriptor desc;
	uint32_t packetLen = sizeof(hv_vm_packet_descriptor) + buffer_len;
	uint32_t packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));
	hv_vmbus_sg_buffer_list bufferList[3];
	uint64_t alignedData = 0;


	// Setup the descriptor
	desc.type = Type;	//HV_VMBUS_PACKET_TYPE_DATA_IN_BAND;
	desc.flags = Flags;	//HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = sizeof(hv_vm_packet_descriptor) >> 3; // in 8-bytes granularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = request_id;

	bufferList[0].data = &desc;
	bufferList[0].length = sizeof(hv_vm_packet_descriptor);

	bufferList[1].data = Buffer;
	bufferList[1].length = buffer_len;

	bufferList[2].data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = hv_ring_buffer_write(&Channel->outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !hv_vmbus_get_ring_buffer_interrupt_mask(&Channel->outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 hv_vmbus_channel_send_packet_pagebuffer()

 Description:
 Send a range of single-page buffer packets using a GPADL Direct packet type.

 --*/
int
hv_vmbus_channel_send_packet_pagebuffer(hv_vmbus_channel *Channel,
	hv_vmbus_page_buffer page_buffers[], uint32_t page_count, void *Buffer,
	uint32_t buffer_len, uint64_t request_id) 
{
	
	int ret = 0;
	int i = 0;
	hv_vmbus_channel_packet_page_buffer desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	hv_vmbus_sg_buffer_list bufferList[3];
	uint64_t alignedData = 0;

        if (page_count > HV_MAX_PAGE_BUFFER_COUNT)
                return -EINVAL;

	// Adjust the size down since hv_vmbus_channel_packet_page_buffer is the largest size we support
	descSize = sizeof(hv_vmbus_channel_packet_page_buffer)
		- ((HV_MAX_PAGE_BUFFER_COUNT - page_count) * sizeof(hv_vmbus_page_buffer));
	packetLen = descSize + buffer_len;
	packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.type = HV_VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT;
	desc.flags = HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = descSize >> 3; // in 8-bytes grandularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = request_id;
	desc.range_count = page_count;

	for (i = 0; i < page_count; i++) {
		desc.range[i].length = page_buffers[i].length;
		desc.range[i].offset = page_buffers[i].offset;
		desc.range[i].pfn = page_buffers[i].pfn;
	}

	bufferList[0].data = &desc;
	bufferList[0].length = descSize;

	bufferList[1].data = Buffer;
	bufferList[1].length = buffer_len;

	bufferList[2].data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = hv_ring_buffer_write(&Channel->outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !hv_vmbus_get_ring_buffer_interrupt_mask(&Channel->outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 hv_vmbus_channel_send_packet_multipagebuffer()

 Description:
 Send a multi-page buffer packet using a GPADL Direct packet type.

 --*/
int
hv_vmbus_channel_send_packet_multipagebuffer(hv_vmbus_channel *Channel,
	hv_vmbus_multipage_buffer *multi_page_buffer, void *Buffer, uint32_t buffer_len,
	uint64_t request_id) 
{
	
	int ret = 0;
	hv_vmbus_channel_packet_multipage_buffer desc;
	uint32_t descSize;
	uint32_t packetLen;
	uint32_t packetLenAligned;
	hv_vmbus_sg_buffer_list bufferList[3];
	uint64_t alignedData = 0;
	uint32_t pfnCount =
		HV_NUM_PAGES_SPANNED(multi_page_buffer->offset, multi_page_buffer->length);


	if ((pfnCount < 0) || (pfnCount > HV_MAX_MULTIPAGE_BUFFER_COUNT))
		return -EINVAL;

	// Adjust the size down since hv_vmbus_channel_packet_multipage_buffer is the largest size we support
	descSize = sizeof(hv_vmbus_channel_packet_multipage_buffer)
		- ((HV_MAX_MULTIPAGE_BUFFER_COUNT - pfnCount) * sizeof(uint64_t));
	packetLen = descSize + buffer_len;
	packetLenAligned = HV_ALIGN_UP(packetLen, sizeof(uint64_t));


	// Setup the descriptor
	desc.type = HV_VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT;
	desc.flags = HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED;
	desc.data_offset8 = descSize >> 3; // in 8-bytes grandularity
	desc.length8 = (uint16_t) (packetLenAligned >> 3);
	desc.transaction_id = request_id;
	desc.range_count = 1;

	desc.range.length = multi_page_buffer->length;
	desc.range.offset = multi_page_buffer->offset;

	memcpy(desc.range.pfn_array, multi_page_buffer->pfn_array,
		pfnCount*sizeof(uint64_t));

	bufferList[0].data = &desc;
	bufferList[0].length = descSize;

	bufferList[1].data = Buffer;
	bufferList[1].length = buffer_len;

	bufferList[2].data = &alignedData;
	bufferList[2].length = packetLenAligned - packetLen;

	ret = hv_ring_buffer_write(&Channel->outbound, bufferList, 3);

	// TODO: We should determine if this is optional
	if (ret == 0 && !hv_vmbus_get_ring_buffer_interrupt_mask(&Channel->outbound)) {
		VmbusChannelSetEvent(Channel);
	}

	return ret;
}

/*++

 Name:
 hv_vmbus_channel_recv_packet()

 Description:
 Retrieve the user packet on the specified channel

 --*/
int
hv_vmbus_channel_recv_packet(hv_vmbus_channel *Channel, void *Buffer,
	uint32_t buffer_len, uint32_t *buffer_actual_len, uint64_t *request_id) 
{

	hv_vm_packet_descriptor desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;

	*buffer_actual_len = 0;
	*request_id = 0;

	ret = hv_ring_buffer_beek(&Channel->inbound, &desc,
		sizeof(hv_vm_packet_descriptor));
	if (ret != 0) 
		return 0;


	packetLen = desc.length8 << 3;
	userLen = packetLen - (desc.data_offset8 << 3);

	*buffer_actual_len = userLen;

	if (userLen > buffer_len)
		return -EINVAL;

	*request_id = desc.transaction_id;

	// Copy over the packet to the user buffer
	ret = hv_ring_buffer_read(&Channel->inbound, Buffer, userLen,
		(desc.data_offset8 << 3));
	return 0;
}

/*++

 Name:
 hv_vmbus_channel_recv_packet_raw()

 Description:
 Retrieve the raw packet on the specified channel

 --*/
int
hv_vmbus_channel_recv_packet_raw(hv_vmbus_channel *Channel, void *Buffer,
	uint32_t buffer_len, uint32_t *buffer_actual_len, uint64_t *request_id) 
{
	
	hv_vm_packet_descriptor desc;
	uint32_t packetLen;
	uint32_t userLen;
	int ret;
	*buffer_actual_len = 0;
	*request_id = 0;

	ret = hv_ring_buffer_beek(&Channel->inbound, &desc,
		sizeof(hv_vm_packet_descriptor));

	if (ret != 0)
		return 0;

	packetLen = desc.length8 << 3;
	userLen = packetLen - (desc.data_offset8 << 3);

	*buffer_actual_len = packetLen;

	if (packetLen > buffer_len)
		return -ENOBUFS;


	*request_id = desc.transaction_id;

	// Copy over the entire packet to the user buffer
	ret = hv_ring_buffer_read(&Channel->inbound, Buffer, packetLen, 0);

	return 0;
}
