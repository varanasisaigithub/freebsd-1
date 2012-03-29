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
 * Copyright (c) 2010-2012, Citrix, Inc.
 *
 * Ported from lis21 code drop
 *
 * HyperV vmbus network vsc module
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
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/types.h>
#include <machine/bus.h>
#include <machine/atomic.h>

#include "../include/hyperv.h"

#include <dev/hyperv/netvsc/hv_net_vsc.h>
#include <dev/hyperv/netvsc/hv_rndis.h>


/*
 * Forward declarations
 */
static void hv_nv_on_channel_callback(void *context);
static int  hv_nv_init_send_buffer_with_net_vsp(struct hv_device *device);
static int  hv_nv_init_rx_buffer_with_net_vsp(struct hv_device *device);
static int  hv_nv_destroy_send_buffer(netvsc_dev *net_dev);
static int  hv_nv_destroy_rx_buffer(netvsc_dev *net_dev);
static int  hv_nv_connect_to_vsp(struct hv_device *device);
static void hv_nv_on_send_completion(struct hv_device *device,
				     VMPACKET_DESCRIPTOR *pkt);
static void hv_nv_on_receive(struct hv_device *device, VMPACKET_DESCRIPTOR *pkt);
static void hv_nv_send_receive_completion(struct hv_device *device, uint64_t tid);


/*
 *
 */
static inline netvsc_dev *
hv_nv_alloc_net_device(struct hv_device *device)
{
	netvsc_dev *net_dev;
	hn_softc_t *sc = device_get_softc(device->device);

	net_dev = malloc(sizeof(netvsc_dev), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!net_dev) {
		return (NULL);
	}

	net_dev->dev = device;
	net_dev->destroy = false;
	sc->net_dev = net_dev;

	return (net_dev);
}

static inline netvsc_dev *
hv_nv_get_outbound_net_device(struct hv_device *device)
{
	hn_softc_t *sc = device_get_softc(device->device);
	netvsc_dev *net_dev = sc->net_dev;;

	if (net_dev && net_dev->destroy)
		return NULL;

	return net_dev;
}

static inline netvsc_dev *
hv_nv_get_inbound_net_device(struct hv_device *device)
{
	hn_softc_t *sc = device_get_softc(device->device);
	netvsc_dev *net_dev = sc->net_dev;;

	if (!net_dev)
		return net_dev;
	/*
	 * When the device is being destroyed; we only
	 * permit incoming packets if and only if there
	 * are outstanding sends.
	 */
	if (net_dev->destroy &&
		net_dev->num_outstanding_sends == 0)
		return NULL;

	return net_dev;
}

/*
 * Net VSC initialize receive buffer with net VSP
 */
static int 
hv_nv_init_rx_buffer_with_net_vsp(struct hv_device *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev)
		return -ENODEV;

	net_dev->rx_buf = contigmalloc(net_dev->rx_buf_size, M_DEVBUF,
			M_ZERO, 0UL, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);
	if (!net_dev->rx_buf) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = hv_vmbus_channel_establish_gpadl(
		device->channel,
		net_dev->rx_buf, net_dev->rx_buf_size,
		&net_dev->rx_buf_gpadl_handle);

	if (ret != 0)
		goto cleanup;
	
	//sema_wait(&ext->channel_init_sema); KYS CHECK

	/* Notify the NetVsp of the gpadl handle */
	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));

	init_pkt->hdr.msg_type = nvsp_msg_1_type_send_rx_buf;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    net_dev->rx_buf_gpadl_handle;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_RECEIVE_BUFFER_ID;

	/* Send the gpadl notification request */

	ret = hv_vmbus_channel_send_packet(
		device->channel,
		init_pkt, sizeof(nvsp_msg),
		(uint64_t)init_pkt,
		VmbusPacketTypeDataInBand,
		VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0)
		goto cleanup;

	sema_wait(&net_dev->channel_init_sema);

	/* Check the response */
	if (init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.status
						       != nvsp_status_success) {
		ret = -EINVAL;
		goto cleanup;
	}

	net_dev->rx_section_count =
	    init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.num_sections;

	net_dev->rx_sections = malloc(net_dev->rx_section_count *
	    sizeof(nvsp_1_rx_buf_section), M_DEVBUF, M_NOWAIT);
	if (net_dev->rx_sections == NULL) {
		ret = -EINVAL;
		goto cleanup;
	}
	memcpy(net_dev->rx_sections, 
	    init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.sections,
	    net_dev->rx_section_count * sizeof(nvsp_1_rx_buf_section));


	/*
	 * For first release, there should only be 1 section that represents
	 * the entire receive buffer
	 */
	if (net_dev->rx_section_count != 1 ||
		net_dev->rx_sections->offset != 0) {
		ret = -EINVAL;
		goto cleanup;
	}

	goto exit;

cleanup:
	hv_nv_destroy_rx_buffer(net_dev);
	
exit:
	return (ret);
}

/*
 * Net VSC initialize send buffer with net VSP
 */
static int 
hv_nv_init_send_buffer_with_net_vsp(struct hv_device *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev) 
		return -ENODEV;

	net_dev->send_buf  = contigmalloc(net_dev->send_buf_size, M_DEVBUF,
			M_ZERO, 0UL, BUS_SPACE_MAXADDR, PAGE_SIZE, 0);

	if (!net_dev->send_buf){
		ret = -ENOMEM;
		goto cleanup;
	}

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = hv_vmbus_channel_establish_gpadl(
		device->channel,
		net_dev->send_buf, net_dev->send_buf_size,
		&net_dev->send_buf_gpadl_handle);

	if (ret != 0)
		goto cleanup;
	

	/* Notify the NetVsp of the gpadl handle */

	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));

	init_pkt->hdr.msg_type = nvsp_msg_1_type_send_send_buf;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    net_dev->send_buf_gpadl_handle;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_SEND_BUFFER_ID;

	/* Send the gpadl notification request */

	ret = hv_vmbus_channel_send_packet(
		device->channel,
		 init_pkt, sizeof(nvsp_msg), (uint64_t)init_pkt,
		 VmbusPacketTypeDataInBand,
		 VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0)
		goto cleanup;

	sema_wait(&net_dev->channel_init_sema);

	/* Check the response */
	if (init_pkt->msgs.vers_1_msgs.send_send_buf_complete.status
						       != nvsp_status_success) {
		ret = -EINVAL;
		goto cleanup;
	}

	net_dev->send_section_size =
	    init_pkt->msgs.vers_1_msgs.send_send_buf_complete.section_size;

	goto exit;

cleanup:
	hv_nv_destroy_send_buffer(net_dev);
	
exit:
	return (ret);
}

/*
 * Net VSC destroy receive buffer
 */
static int
hv_nv_destroy_rx_buffer(netvsc_dev *net_dev)
{
	nvsp_msg *revoke_pkt;
	int ret = 0;

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (net_dev->rx_section_count) {

		/* Send the revoke receive buffer */
		revoke_pkt = &net_dev->revoke_packet;
		memset(revoke_pkt, 0, sizeof(nvsp_msg));

		revoke_pkt->hdr.msg_type =
		    nvsp_msg_1_type_revoke_rx_buf;
		revoke_pkt->msgs.vers_1_msgs.revoke_rx_buf.id =
		    NETVSC_RECEIVE_BUFFER_ID;

		ret = hv_vmbus_channel_send_packet(
			net_dev->dev->channel,
			revoke_pkt, sizeof(nvsp_msg),
			(uint64_t)revoke_pkt, VmbusPacketTypeDataInBand, 0);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0)
			return ret;
	}
		
	/* Tear down the gpadl on the vsp end */
	if (net_dev->rx_buf_gpadl_handle) {

		ret = hv_vmbus_channel_teardown_gpdal(
			net_dev->dev->channel,
			net_dev->rx_buf_gpadl_handle);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0)
			return ret;
		net_dev->rx_buf_gpadl_handle = 0;
	}

	if (net_dev->rx_buf) {

		/* Free up the receive buffer */
		contigfree(net_dev->rx_buf, net_dev->rx_buf_size, M_DEVBUF);
		net_dev->rx_buf = NULL;
	}

	if (net_dev->rx_sections) {
		free(net_dev->rx_sections, M_DEVBUF);
		net_dev->rx_sections = NULL;
		net_dev->rx_section_count = 0;
	}

	return (ret);
}

/*
 * Net VSC destroy send buffer
 */
static int
hv_nv_destroy_send_buffer(netvsc_dev *net_dev)
{
	nvsp_msg *revoke_pkt;
	int ret = 0;

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (net_dev->send_section_size) {

		/* Send the revoke send buffer */
		revoke_pkt = &net_dev->revoke_packet;
		memset(revoke_pkt, 0, sizeof(nvsp_msg));

		revoke_pkt->hdr.msg_type =
		    nvsp_msg_1_type_revoke_send_buf;
		revoke_pkt->msgs.vers_1_msgs.revoke_send_buf.id =
		    NETVSC_SEND_BUFFER_ID;

		ret = hv_vmbus_channel_send_packet(
			net_dev->dev->channel,
			revoke_pkt, sizeof(nvsp_msg),
			(uint64_t)revoke_pkt, VmbusPacketTypeDataInBand, 0);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0)
			return ret;
	}
		
	/* Tear down the gpadl on the vsp end */
	if (net_dev->send_buf_gpadl_handle) {

		ret = hv_vmbus_channel_teardown_gpdal(
			net_dev->dev->channel,
			net_dev->send_buf_gpadl_handle);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0)
			return ret;
		net_dev->send_buf_gpadl_handle = 0;
	}

	if (net_dev->send_buf) {

		/* Free up the receive buffer */
		contigfree(net_dev->send_buf, net_dev->send_buf_size, M_DEVBUF);
		net_dev->send_buf = NULL;
	}

	return (ret);
}


/*
 * Net VSC connect to VSP
 */
static int
hv_nv_connect_to_vsp(struct hv_device *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;
	uint32_t ndis_version;

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev)
		return -ENODEV;

	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));
	init_pkt->hdr.msg_type = nvsp_msg_type_init;
	/*
	 * XXXKYS: These are ancient versions! Need to update.
	 */
	init_pkt->msgs.init_msgs.init.min_protocol_version =
	NVSP_MIN_PROTOCOL_VERSION;
	init_pkt->msgs.init_msgs.init.max_protocol_version =
	NVSP_MAX_PROTOCOL_VERSION;

	/* Send the init request */
	ret = hv_vmbus_channel_send_packet(
			device->channel,
			init_pkt, sizeof(nvsp_msg),
			(uint64_t)init_pkt, VmbusPacketTypeDataInBand,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0)
		goto cleanup;

	sema_wait(&net_dev->channel_init_sema);

	if (init_pkt->msgs.init_msgs.init_compl.status !=
	  nvsp_status_success) {
		ret = -EINVAL;
		goto cleanup;
	}

	if (init_pkt->msgs.init_msgs.init_compl.negotiated_prot_vers !=
			NVSP_PROTOCOL_VERSION_1) {
		ret = -EPROTO;
		goto cleanup;
	}

	/* Send the ndis version */
	memset(init_pkt, 0, sizeof(nvsp_msg));

	/* Fixme:  Magic number */
	ndis_version = 0x00050000;

	init_pkt->hdr.msg_type = nvsp_msg_1_type_send_ndis_vers;
	init_pkt->msgs.vers_1_msgs.send_ndis_vers.ndis_major_vers =
	    (ndis_version & 0xFFFF0000) >> 16;
	init_pkt->msgs.vers_1_msgs.send_ndis_vers.ndis_minor_vers =
	    ndis_version & 0xFFFF;

	/* Send the init request */

	ret = hv_vmbus_channel_send_packet(
			device->channel,
			init_pkt, sizeof(nvsp_msg),
			(uint64_t)init_pkt, VmbusPacketTypeDataInBand, 0);

	if (ret != 0)
		goto cleanup;
	/*
	 * BUGBUG - We have to wait for the above msg since the netvsp uses
	 * KMCL which acknowledges packet (completion packet) 
	 * since our Vmbus always set the
	 * VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED flag
	 */
	//sema_wait(&NetVscChannel->channel_init_sema);

	/* Post the big receive buffer to NetVSP */
	ret = hv_nv_init_rx_buffer_with_net_vsp(device);
	if (ret == 0)
		ret = hv_nv_init_send_buffer_with_net_vsp(device);

cleanup:
	return (ret);
}

/*
 * Net VSC disconnect from VSP
 */
static void
hv_nv_disconnect_from_vsp(netvsc_dev *net_dev)
{
	hv_nv_destroy_rx_buffer(net_dev);
	hv_nv_destroy_send_buffer(net_dev);
}

/*
 * Net VSC on device add
 * 
 * Callback when the device belonging to this driver is added
 */
netvsc_dev *
hv_nv_on_device_add(struct hv_device *device, void *additional_info)
{
	netvsc_dev *net_dev;
	netvsc_packet *packet;
	netvsc_packet *next_packet;
	int i, ret = 0;

	net_dev = hv_nv_alloc_net_device(device);
	if (!net_dev)
		goto cleanup;

	/* Initialize the NetVSC channel extension */
	net_dev->rx_buf_size = NETVSC_RECEIVE_BUFFER_SIZE;
	mtx_init(&net_dev->rx_pkt_list_lock, "HV-RPL", NULL,
	    MTX_SPIN | MTX_RECURSE);

	net_dev->send_buf_size = NETVSC_SEND_BUFFER_SIZE;

	/* Same effect as STAILQ_HEAD_INITIALIZER() static initializer */
	STAILQ_INIT(&net_dev->myrx_packet_list);

	/* 
	 * malloc a sufficient number of netvsc_packet buffers to hold
	 * a packet list.  Add them to the netvsc device packet queue.
	 */
	for (i=0; i < NETVSC_RECEIVE_PACKETLIST_COUNT; i++) {
		packet = malloc(sizeof(netvsc_packet) +
		    (NETVSC_RECEIVE_SG_COUNT * sizeof(PAGE_BUFFER)),
		    M_DEVBUF, M_NOWAIT | M_ZERO);
		if (!packet)
			break;
		STAILQ_INSERT_TAIL(&net_dev->myrx_packet_list, packet,
		    mylist_entry);
	}
	sema_init(&net_dev->channel_init_sema, 0, "netdev_sema");

	/*
	 * Open the channel
	 */
	ret = hv_vmbus_channel_open(device->channel,
		NETVSC_DEVICE_RING_BUFFER_SIZE,
		NETVSC_DEVICE_RING_BUFFER_SIZE,
		NULL, 0, hv_nv_on_channel_callback, device);

	if (ret != 0)
		goto cleanup;


	/* Connect with the NetVsp */
	ret = hv_nv_connect_to_vsp(device);
	if (ret != 0)
		goto close;

	return (net_dev);

close:
	/* Now, we can close the channel safely */

	hv_vmbus_channel_close(device->channel);

cleanup:
	/*
	 * Free the packet buffers on the netvsc device packet queue.
	 * Release other resources.
	 */
	if (net_dev) {
		sema_destroy(&net_dev->channel_init_sema);

		packet = STAILQ_FIRST(&net_dev->myrx_packet_list);
		while (packet != NULL) {
			next_packet = STAILQ_NEXT(packet, mylist_entry);
			free(packet, M_DEVBUF);
			packet = next_packet;
		}
		/* Reset the list to initial state */
		STAILQ_INIT(&net_dev->myrx_packet_list);

		mtx_destroy(&net_dev->rx_pkt_list_lock);

		free(net_dev, M_DEVBUF);
	}

	return (NULL);
}

/*
 * Net VSC on device remove
 */
int
hv_nv_on_device_remove(struct hv_device *device)
{
	netvsc_packet *net_vsc_pkt;
	netvsc_packet *next_net_vsc_pkt;
	hn_softc_t *sc = device_get_softc(device->device);
	netvsc_dev *net_dev = sc->net_dev;;
	
	/* Stop outbound traffic ie sends and receives completions */
	mtx_lock_spin(&device->channel->InboundLock);
	net_dev->destroy = true;
	mtx_unlock_spin(&device->channel->InboundLock);

	/* Wait for all send completions */
	while (net_dev->num_outstanding_sends)
		DELAY(100);

	hv_nv_disconnect_from_vsp(net_dev);


	/* At this point, no one should be accessing net_dev except in here */

	/* Now, we can close the channel safely */

	hv_vmbus_channel_close(device->channel);

	/* Release all resources */
	net_vsc_pkt = STAILQ_FIRST(&net_dev->myrx_packet_list);
	while (net_vsc_pkt != NULL) {
		next_net_vsc_pkt = STAILQ_NEXT(net_vsc_pkt, mylist_entry);
		free(net_vsc_pkt, M_DEVBUF);
		net_vsc_pkt = next_net_vsc_pkt;
	}
	/* Reset the list to initial state */
	STAILQ_INIT(&net_dev->myrx_packet_list);

	mtx_destroy(&net_dev->rx_pkt_list_lock);

	sema_destroy(&net_dev->channel_init_sema);
	free(net_dev, M_DEVBUF);

	return (0);
}

/*
 * Net VSC on send completion
 */
static void 
hv_nv_on_send_completion(struct hv_device *device, VMPACKET_DESCRIPTOR *pkt)
{
	netvsc_dev *net_dev;
	nvsp_msg *nvsp_msg_pkt;
	netvsc_packet *net_vsc_pkt;

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev)
		return;

	nvsp_msg_pkt =
	    (nvsp_msg *)((unsigned long)pkt + (pkt->DataOffset8 << 3));


	if (nvsp_msg_pkt->hdr.msg_type == nvsp_msg_type_init_complete ||
	    nvsp_msg_pkt->hdr.msg_type ==
	      nvsp_msg_1_type_send_rx_buf_complete ||
	    nvsp_msg_pkt->hdr.msg_type ==
	      nvsp_msg_1_type_send_send_buf_complete) {
		/* Copy the response back */
		memcpy(&net_dev->channel_init_packet,
		    nvsp_msg_pkt, sizeof(nvsp_msg));			
		sema_post(&net_dev->channel_init_sema);
	} else if (nvsp_msg_pkt->hdr.msg_type ==
				    nvsp_msg_1_type_send_rndis_pkt_complete) {
		/* Get the send context */
		net_vsc_pkt =
		    (netvsc_packet *)(unsigned long)pkt->TransactionId;

		/* Notify the layer above us */
		net_vsc_pkt->compl.send.on_send_completion(
		    net_vsc_pkt->compl.send.send_completion_context);

		atomic_subtract_int(&net_dev->num_outstanding_sends, 1);
	}

}

/*
 * Net VSC on send
 */
int
hv_nv_on_send(struct hv_device *device, netvsc_packet *pkt)
{
	netvsc_dev *net_dev;
	nvsp_msg send_msg;
	int ret = 0;

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev)
		return -ENODEV;

	send_msg.hdr.msg_type = nvsp_msg_1_type_send_rndis_pkt;
	if (pkt->is_data_pkt) {
		/* 0 is RMC_DATA */
		send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type = 0;
	} else {
		/* 1 is RMC_CONTROL */
		send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type = 1;
	}

	/* Not using send buffer section */
	send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_idx =
	    0xFFFFFFFF;
	send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_size = 0;

	if (pkt->page_buf_count) {
		ret = hv_vmbus_channel_send_packet_pagebuffer(
			device->channel,
			pkt->page_buffers, pkt->page_buf_count,
			&send_msg, sizeof(nvsp_msg), (uint64_t)pkt);
	} else {
		ret = hv_vmbus_channel_send_packet(
			device->channel,
			&send_msg, sizeof(nvsp_msg), (uint64_t)pkt,
			VmbusPacketTypeDataInBand,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	atomic_add_int(&net_dev->num_outstanding_sends, 1);

	return (ret);
}

/*
 * Net VSC on receive
 *
 * In the FreeBSD Hyper-V virtual world, this function deals exclusively
 * with virtual addresses.
 */
static void 
hv_nv_on_receive(struct hv_device *device, VMPACKET_DESCRIPTOR *pkt)
{
	netvsc_dev *net_dev;
	VMTRANSFER_PAGE_PACKET_HEADER *vm_xfer_page_pkt;
	nvsp_msg *nvsp_msg_pkt;
	netvsc_packet *net_vsc_pkt = NULL;
	unsigned long start;
	xfer_page_packet *xfer_page_pkt = NULL;
	STAILQ_HEAD(PKT_LIST, netvsc_packet_) mylist_head =
	    STAILQ_HEAD_INITIALIZER(mylist_head);
	int count = 0;
	int i = 0;

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev)
		return;

	/*
	 * All inbound packets other than send completion should be
	 * xfer page packet.
	 */
	if (pkt->Type != VmbusPacketTypeDataUsingTransferPages)
		return;

	nvsp_msg_pkt = (nvsp_msg *)((unsigned long)pkt +
	    (pkt->DataOffset8 << 3));

	/* Make sure this is a valid nvsp packet */
	if (nvsp_msg_pkt->hdr.msg_type != nvsp_msg_1_type_send_rndis_pkt) {
		return;
	}
	
	vm_xfer_page_pkt = (VMTRANSFER_PAGE_PACKET_HEADER *)pkt;

	if (vm_xfer_page_pkt->TransferPageSetId != NETVSC_RECEIVE_BUFFER_ID) {
		return;
	}

	STAILQ_INIT(&mylist_head);

	/*
	 * Grab free packets (range count + 1) to represent this xfer page
	 * packet.  +1 to represent the xfer page packet itself.  We grab it
	 * here so that we know exactly how many we can fulfill.
	 */
	mtx_lock(&net_dev->rx_pkt_list_lock);
	while (!STAILQ_EMPTY(&net_dev->myrx_packet_list)) {	
		net_vsc_pkt = STAILQ_FIRST(&net_dev->myrx_packet_list);
		STAILQ_REMOVE_HEAD(&net_dev->myrx_packet_list, mylist_entry);

		STAILQ_INSERT_TAIL(&mylist_head, net_vsc_pkt, mylist_entry);

		if (++count == vm_xfer_page_pkt->RangeCount + 1) {
			break;
		}
	}

	mtx_unlock(&net_dev->rx_pkt_list_lock);

	/*
	 * We need at least 2 netvsc pkts (1 to represent the xfer page
	 * and at least 1 for the range) i.e. we can handle some of the
	 * xfer page packet ranges...
	 */
	if (count < 2) {

		/* Return netvsc packet to the freelist */
		mtx_lock(&net_dev->rx_pkt_list_lock);
		for (i=count; i != 0; i--) {
			net_vsc_pkt = STAILQ_FIRST(&mylist_head);
			STAILQ_REMOVE_HEAD(&mylist_head, mylist_entry);

			STAILQ_INSERT_TAIL(&net_dev->myrx_packet_list,
			    net_vsc_pkt, mylist_entry);
		}
		mtx_unlock(&net_dev->rx_pkt_list_lock);

		hv_nv_send_receive_completion(device,
		    vm_xfer_page_pkt->d.TransactionId);

		return;
	}

	/* Take the first packet in the list */
	xfer_page_pkt = (xfer_page_packet *)STAILQ_FIRST(&mylist_head);
	STAILQ_REMOVE_HEAD(&mylist_head, mylist_entry);

	/* This is how many data packets we can supply */
	xfer_page_pkt->count = count - 1;

	/* Each range represents 1 RNDIS pkt that contains 1 Ethernet frame */
	for (i=0; i < (count - 1); i++) {
		net_vsc_pkt = STAILQ_FIRST(&mylist_head);
		STAILQ_REMOVE_HEAD(&mylist_head, mylist_entry);

		/*
		 * Initialize the netvsc packet
		 */
		net_vsc_pkt->xfer_page_pkt = xfer_page_pkt;
		net_vsc_pkt->compl.rx.rx_completion_context =
		    net_vsc_pkt;
		net_vsc_pkt->device = device;
		/* Save this so that we can send it back */
		net_vsc_pkt->compl.rx.rx_completion_tid =
		    vm_xfer_page_pkt->d.TransactionId;

		net_vsc_pkt->tot_data_buf_len =
		    vm_xfer_page_pkt->Ranges[i].ByteCount;
		net_vsc_pkt->page_buf_count = 1;

		net_vsc_pkt->page_buffers[0].Length =
		    vm_xfer_page_pkt->Ranges[i].ByteCount;

		/* The virtual address of the packet in the receive buffer */
		start = ((unsigned long)net_dev->rx_buf +
		    vm_xfer_page_pkt->Ranges[i].ByteOffset);
		start = ((unsigned long)start) & ~(PAGE_SIZE - 1);

		/* Page number of the virtual page containing packet start */
		net_vsc_pkt->page_buffers[0].Pfn = start >> PAGE_SHIFT;

		/* Calculate the page relative offset */
		net_vsc_pkt->page_buffers[0].Offset =
		    vm_xfer_page_pkt->Ranges[i].ByteOffset & (PAGE_SIZE - 1);

		/*
		 * In this implementation, we are dealing with virtual
		 * addresses exclusively.  Since we aren't using physical
		 * addresses at all, we don't care if a packet crosses a
		 * page boundary.  For this reason, the original code to
		 * check for and handle page crossings has been removed.
		 */

		/*
		 * Pass it to the upper layer.  The receive completion call
		 * has been moved into this function.
		 */
		hv_rf_on_receive(device, net_vsc_pkt);
	}

	
}

/*
 * Net VSC send receive completion
 */
static void
hv_nv_send_receive_completion(struct hv_device *device, uint64_t tid)
{
	nvsp_msg rx_comp_msg;
	int retries = 0;
	int ret = 0;
	
	rx_comp_msg.hdr.msg_type =
	    nvsp_msg_1_type_send_rndis_pkt_complete;

	/* Pass in the status */
	rx_comp_msg.msgs.vers_1_msgs.send_rndis_pkt_complete.status =
	    nvsp_status_success;

retry_send_cmplt:
	/* Send the completion */
	ret = hv_vmbus_channel_send_packet(
		device->channel,
		&rx_comp_msg, sizeof(nvsp_msg), tid,
		VmbusPacketTypeCompletion, 0);

	if (ret == 0) {
		/* success */
		/* no-op */
	} else if (ret == -EAGAIN) {
		/* no more room... wait a bit and attempt to retry 3 times */
		retries++;

		if (retries < 4) {
			DELAY(100);
			goto retry_send_cmplt;
		}
	}
}

/*
 * Net VSC on receive completion
 *
 * Send a receive completion packet to RNDIS device (ie NetVsp)
 */
void
hv_nv_on_receive_completion(void *context)
{
	netvsc_packet *packet = (netvsc_packet *)context;
	struct hv_device *device = (struct hv_device *)packet->device;
	netvsc_dev    *net_dev;
	uint64_t       tid = 0;
	bool send_rx_completion = false;

	/*
	 * Even though it seems logical to do a hv_nv_get_outbound_net_device()
	 * here to send out receive completion, we are using
	 * hv_nv_get_inbound_net_device() since we may have disabled
	 * outbound traffic already.
	 */
	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev)
		return;
	
	/* Overloading use of the lock. */
	mtx_lock(&net_dev->rx_pkt_list_lock);

	packet->xfer_page_pkt->count--;

	/*
	 * Last one in the line that represent 1 xfer page packet.
	 * Return the xfer page packet itself to the free list.
	 */
	if (packet->xfer_page_pkt->count == 0) {
		send_rx_completion = true;
		tid = packet->compl.rx.rx_completion_tid;
		STAILQ_INSERT_TAIL(&net_dev->myrx_packet_list,
		    (netvsc_packet *)(packet->xfer_page_pkt), mylist_entry);
	}

	/* Put the packet back on the free list */
	STAILQ_INSERT_TAIL(&net_dev->myrx_packet_list, packet, mylist_entry);
	mtx_unlock(&net_dev->rx_pkt_list_lock);

	/* Send a receive completion for the xfer page packet */
	if (send_rx_completion) {
		hv_nv_send_receive_completion(device, tid);
	}

}

/*
 * Net VSC on channel callback
 */
static void
hv_nv_on_channel_callback(void *context)
{
	/* Fixme:  Magic number */
	const int net_pkt_size = 2048;
	struct hv_device *device = (struct hv_device *)context;
	netvsc_dev *net_dev;
	uint32_t bytes_rxed;
	uint64_t request_id;
	uint8_t  *packet;
	VMPACKET_DESCRIPTOR *desc;
	uint8_t *buffer;
	int     bufferlen = net_pkt_size;
	int ret = 0;

	packet = malloc(net_pkt_size * sizeof(unsigned char), M_DEVBUF, M_NOWAIT);

	if (!packet)
		return;

	buffer = packet;

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev)
		goto out;

	do {
		ret = hv_vmbus_channel_recv_packet_raw(
			device->channel,
			buffer, bufferlen, &bytes_rxed, &request_id);

		if (ret == 0) {
			if (bytes_rxed > 0) {
				desc = (VMPACKET_DESCRIPTOR *)buffer;
				switch (desc->Type) {
				case VmbusPacketTypeCompletion:
					hv_nv_on_send_completion(device, desc);
					break;

				case VmbusPacketTypeDataUsingTransferPages:
					hv_nv_on_receive(device, desc);
					break;

				default:
					break;
				}

			} else {

				break;
			}
		} else if (ret == -ENOBUFS) {
			/* Handle large packet */
			free(buffer, M_DEVBUF);
			buffer = malloc(bytes_rxed, M_DEVBUF, M_NOWAIT);
			if (buffer == NULL)
				break;
			bufferlen = bytes_rxed;
		}
	} while (1);

out:
	free(buffer, M_DEVBUF);
}

