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

#include "hyperv.h"
#include "vmbus_priv.h"

//
// Globals
//

hv_vmbus_connection hv_vmbus_g_connection =
	{ .connect_state = HV_DISCONNECTED,
	  .next_gpadl_handle = 0xE1E10, };

/*++

 Name:
 hv_vmbus_connect()

 Description:
 Sends a connect request on the partition service connection

 --*/
int
hv_vmbus_connect(void) {
	int ret = 0;
	hv_vmbus_channel_msg_info *msgInfo = NULL;
	hv_vmbus_channel_initiate_contact *msg;


	// Make sure we are not connecting or connected
	if (hv_vmbus_g_connection.connect_state != HV_DISCONNECTED) {
		return -1;
	}

	// Initialize the vmbus connection
	hv_vmbus_g_connection.connect_state = HV_CONNECTING;
	hv_vmbus_g_connection.work_queue = hv_work_queue_create("vmbusQ");
	sema_init(&hv_vmbus_g_connection.control_sema, 1, "control_sema");

	TAILQ_INIT(&hv_vmbus_g_connection.channel_msg_anchor);
	mtx_init(&hv_vmbus_g_connection.channel_msg_lock, "vmbus channel msg",
		NULL, MTX_SPIN);

	TAILQ_INIT(&hv_vmbus_g_connection.channel_anchor);
	mtx_init(&hv_vmbus_g_connection.channel_lock, "vmbus channel",
		NULL, MTX_SPIN);

	// Set up the vmbus event connection for channel interrupt abstraction
	// stuff
	hv_vmbus_g_connection.interrupt_page = contigmalloc(PAGE_SIZE, M_DEVBUF,
					 M_NOWAIT | M_ZERO, 0UL, BUS_SPACE_MAXADDR,
					 PAGE_SIZE, 0);

	if (hv_vmbus_g_connection.interrupt_page == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	hv_vmbus_g_connection.recv_interrupt_page = hv_vmbus_g_connection.interrupt_page;
	hv_vmbus_g_connection.send_interrupt_page =
		((uint8_t *) hv_vmbus_g_connection.interrupt_page + (PAGE_SIZE >> 1));

	// Set up the monitor notification facility. The 1st page for
	// parent->child and the 2nd page for child->parent
	hv_vmbus_g_connection.monitor_pages = contigmalloc(2*PAGE_SIZE, M_DEVBUF,
					 M_NOWAIT | M_ZERO,
					 0UL, BUS_SPACE_MAXADDR,
					 PAGE_SIZE, 0);

	if (hv_vmbus_g_connection.monitor_pages == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	msgInfo = (hv_vmbus_channel_msg_info*)
			malloc(sizeof(hv_vmbus_channel_msg_info) +
				sizeof(hv_vmbus_channel_initiate_contact),
				M_DEVBUF, M_NOWAIT | M_ZERO);

	if (msgInfo == NULL) {
		ret = -ENOMEM;
		goto Cleanup;
	}

	sema_init(&msgInfo->wait_sema, 0, "Msg Info Sema");
	msg = (hv_vmbus_channel_initiate_contact*) msgInfo->msg;

	msg->header.message_type = HV_CHANNEL_MESSAGE_INITIATED_CONTACT;
	msg->vmbus_version_requested = HV_VMBUS_REVISION_NUMBER;
	msg->interrupt_page = hv_get_phys_addr(hv_vmbus_g_connection.interrupt_page);
	msg->monitor_page_1 = hv_get_phys_addr(hv_vmbus_g_connection.monitor_pages);
	msg->monitor_page_2 =
		hv_get_phys_addr(((uint8_t *) hv_vmbus_g_connection.monitor_pages
					+ PAGE_SIZE));

	// Add to list before we send the request since we may receive the
	// response before returning from this routine
	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_INSERT_TAIL(
		&hv_vmbus_g_connection.channel_msg_anchor,
		msgInfo,
		msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);

	ret = hv_vmbus_post_message(msg, sizeof(hv_vmbus_channel_initiate_contact));
	if (ret != 0) {
		mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
		TAILQ_REMOVE(
			&hv_vmbus_g_connection.channel_msg_anchor,
			msgInfo,
			msg_list_entry);
		mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);
		goto Cleanup;
	}

	// Wait for the connection response
	ret = sema_timedwait(&msgInfo->wait_sema, 500); //KYS 5 seconds

	mtx_lock_spin(&hv_vmbus_g_connection.channel_msg_lock);
	TAILQ_REMOVE(
		&hv_vmbus_g_connection.channel_msg_anchor,
		msgInfo,
		msg_list_entry);
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_msg_lock);

	// Check if successful
	if (msgInfo->response.version_response.version_supported) {
		hv_vmbus_g_connection.connect_state = HV_CONNECTED;
	} else {
		ret = -ECONNREFUSED;
		goto Cleanup;
	}

	sema_destroy(&msgInfo->wait_sema);
	free(msgInfo, M_DEVBUF);

	return 0;

Cleanup:

	hv_vmbus_g_connection.connect_state = HV_DISCONNECTED;

	hv_work_queue_close(hv_vmbus_g_connection.work_queue);
	sema_destroy(&hv_vmbus_g_connection.control_sema);
	mtx_destroy(&hv_vmbus_g_connection.channel_lock);
	mtx_destroy(&hv_vmbus_g_connection.channel_msg_lock);

	if (hv_vmbus_g_connection.interrupt_page) {
		contigfree(hv_vmbus_g_connection.interrupt_page, PAGE_SIZE, M_DEVBUF);
		hv_vmbus_g_connection.interrupt_page = NULL;
	}

	if (hv_vmbus_g_connection.monitor_pages) {
		contigfree(hv_vmbus_g_connection.monitor_pages, 2 * PAGE_SIZE, M_DEVBUF);
		hv_vmbus_g_connection.monitor_pages = NULL;
	}

	if (msgInfo) {
		sema_destroy(&msgInfo->wait_sema);
		free(msgInfo, M_DEVBUF);
	}


	return ret;
}

/*++

 Name:
 hv_vmbus_disconnect()

 Description:
 Sends a disconnect request on the partition service connection

 --*/
int
hv_vmbus_disconnect(void) {
	int ret = 0;
	hv_vmbus_channel_unload *msg;

	msg = malloc(sizeof(hv_vmbus_channel_unload), M_DEVBUF, M_NOWAIT | M_ZERO);

	if (!msg)
		return -ENOMEM;

	msg->message_type = HV_CHANNEL_MESSAGE_UNLOAD;

	ret = hv_vmbus_post_message(msg, sizeof(hv_vmbus_channel_unload));

	KASSERT(ret == 0, ("Message Post Failed\n"));

	contigfree(hv_vmbus_g_connection.interrupt_page, PAGE_SIZE, M_DEVBUF);

	mtx_destroy(&hv_vmbus_g_connection.channel_msg_lock);

	hv_work_queue_close(hv_vmbus_g_connection.work_queue);
	sema_destroy(&hv_vmbus_g_connection.control_sema);

	hv_vmbus_g_connection.connect_state = HV_DISCONNECTED;

	free(msg, M_DEVBUF);

	return ret;
}


/*++

 Name:
 hv_vmbus_get_channel_from_rel_id()

 Description:
 Get the channel object given its child relative id (ie channel id)

 XXX Consider optimization where relids are stored in a fixed size array
 and channels are accessed without the need to take this lock or search the list.
 --*/
hv_vmbus_channel*
hv_vmbus_get_channel_from_rel_id(uint32_t relId) {
	hv_vmbus_channel* channel;
	hv_vmbus_channel* foundChannel = NULL;

	mtx_lock_spin(&hv_vmbus_g_connection.channel_lock);
	TAILQ_FOREACH(channel, &hv_vmbus_g_connection.channel_anchor, list_entry) {

		if (channel->offer_msg.child_rel_id == relId) {
			foundChannel = channel;
			break;
		}
	}
	mtx_unlock_spin(&hv_vmbus_g_connection.channel_lock);

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

	hv_vmbus_channel* channel;

	/*
	 * Find the channel based on this relid and invokes
	 * the channel callback to process the event
	 */

	channel = hv_vmbus_get_channel_from_rel_id(relid);

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

	mtx_lock(&channel->inbound_lock);
	if (channel->on_channel_callback != NULL) {
		channel->on_channel_callback(channel->channel_callback_context);
	}
	mtx_unlock(&channel->inbound_lock);

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
	int maxdword = HV_MAX_NUM_CHANNELS_SUPPORTED >> 5;
	int bit;
	int relid;
	uint32_t* recv_interrupt_page = hv_vmbus_g_connection.recv_interrupt_page;

	// Check events
	if (recv_interrupt_page) {
		for (dword = 0; dword < maxdword; dword++) {
			if (recv_interrupt_page[dword]) {
				for (bit = 0; bit < 32; bit++) {
					if (synch_test_and_clear_bit(bit,
						(uint32_t *)&recv_interrupt_page[dword])) {
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
 hv_vmbus_post_message()

 Description:
 Send a msg on the vmbus's message connection

 --*/
int hv_vmbus_post_message(void *buffer, size_t bufferLen) {
	int ret = 0;
	hv_vmbus_connection_id connId;
	int retries = 0;

	while (retries < 3) {
		connId.as_uint32_t = 0;
		connId.u.id = HV_VMBUS_MESSAGE_CONNECTION_ID;
		ret = hv_vmbus_post_message_via_msg_ipc(connId, 1, buffer, bufferLen);
		if (ret != HV_STATUS_INSUFFICIENT_BUFFERS)
                        return ret;
		retries++;
		DELAY(100); //KYS We should use a blocking wait call.
	}

	return ret;
}

/*++

 Name:
 hv_vmbus_set_event()

 Description:
 Send an event notification to the parent

 --*/
int
hv_vmbus_set_event(uint32_t childRelId) {
	int ret = 0;


	// Each uint32_t represents 32 channels
	synch_set_bit(childRelId & 31,
		(((uint32_t *)hv_vmbus_g_connection.send_interrupt_page + (childRelId >> 5))));
	ret = hv_vmbus_signal_event();

	return ret;
}

