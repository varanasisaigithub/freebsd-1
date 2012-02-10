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
 */


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <net/if.h>
#include <net/if_arp.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include <dev/hyperv/include/hv_list.h>
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/include/hv_nvsp_protocol.h>
#include <dev/hyperv/vmbus/hv_vmbus_var.h>
#include <dev/hyperv/include/hv_net_vsc_api.h>
#include <dev/hyperv/vmbus/hv_connection.h>
#include <dev/hyperv/include/hv_net_vsc.h>
#include <dev/hyperv/include/hv_rndis_filter.h>
#include <dev/hyperv/include/hv_rndis.h>

/*
 * Globals
 */
static const char* g_net_vsc_driver_name = "netvsc";

/* {F8615163-DF3E-46c5-913F-F2D2F965ED0E} */
static const GUID g_net_vsc_device_type = {
	.Data = {0x63, 0x51, 0x61, 0xF8, 0x3E, 0xDF, 0xc5, 0x46,
		 0x91, 0x3F, 0xF2, 0xD2, 0xF9, 0x65, 0xED, 0x0E}
};


/*
 * Forward declarations
 */
static int  hv_nv_on_device_add(DEVICE_OBJECT *device, void *additional_info);
static int  hv_nv_on_device_remove(DEVICE_OBJECT *device);
static void hv_nv_on_cleanup(DRIVER_OBJECT *driver);
static void hv_nv_on_channel_callback(void *context);
static int  hv_nv_init_send_buffer_with_net_vsp(DEVICE_OBJECT *device);
static int  hv_nv_init_rx_buffer_with_net_vsp(DEVICE_OBJECT *device);
static int  hv_nv_destroy_send_buffer(netvsc_dev *net_dev);
static int  hv_nv_destroy_rx_buffer(netvsc_dev *net_dev);
static int  hv_nv_connect_to_vsp(DEVICE_OBJECT *device);
static void hv_nv_on_send_completion(DEVICE_OBJECT *device,
				     VMPACKET_DESCRIPTOR *pkt);
static int  hv_nv_on_send(DEVICE_OBJECT *device, netvsc_packet *pkt);
// Fixme
extern void hv_nv_on_receive(DEVICE_OBJECT *device, VMPACKET_DESCRIPTOR *pkt);
//static void hv_nv_on_receive(DEVICE_OBJECT *device, VMPACKET_DESCRIPTOR *pkt);
static void hv_nv_send_receive_completion(DEVICE_OBJECT *device, uint64_t tid);


/*
 *
 */
static inline netvsc_dev *
hv_nv_alloc_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = malloc(sizeof(netvsc_dev), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!net_dev) {
		return (NULL);
	}

	/* Set to 2 to allow both inbound and outbound traffic */
	InterlockedCompareExchange(&net_dev->ref_cnt, 2, 0);

	net_dev->dev = device;
	device->Extension = net_dev;

	return (net_dev);
}

/*
 *
 */
static inline void
hv_nv_free_net_device(netvsc_dev *device)
{
	ASSERT(device->ref_cnt == 0);
	device->dev->Extension = NULL;
	free(device, M_DEVBUF);
}


/*
 * Get the net device object iff exists and its refcount > 1
 */
static inline netvsc_dev *
hv_nv_get_outbound_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = (netvsc_dev *)device->Extension;
	if (net_dev && net_dev->ref_cnt > 1) {
		InterlockedIncrement(&net_dev->ref_cnt);
	} else {
		net_dev = NULL;
	}

	return (net_dev);
}

/*
 * Get the net device object iff exists and its refcount > 0
 */
static inline netvsc_dev *
hv_nv_get_inbound_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = (netvsc_dev *)device->Extension;
	if (net_dev && net_dev->ref_cnt) {
		InterlockedIncrement(&net_dev->ref_cnt);
	} else {
		net_dev = NULL;
	}

	return (net_dev);
}

/*
 *
 */
static inline void
hv_nv_put_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = (netvsc_dev *)device->Extension;
	ASSERT(net_dev);

	InterlockedDecrement(&net_dev->ref_cnt);
}

/*
 *
 */
static inline netvsc_dev *
hv_nv_release_outbound_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = (netvsc_dev *)device->Extension;
	if (net_dev == NULL) {
		return (NULL);
	}

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (InterlockedCompareExchange(&net_dev->ref_cnt, 1, 2) != 2) {
		DELAY(100);
	}

	return (net_dev);
}

/*
 *
 */
static inline netvsc_dev *
hv_nv_release_inbound_net_device(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;

	net_dev = (netvsc_dev *)device->Extension;
	if (net_dev == NULL) {
		return (NULL);
	}

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (InterlockedCompareExchange(&net_dev->ref_cnt, 0, 1) != 1) {
		DELAY(100);
	}

	device->Extension = NULL;

	return (net_dev);
}

/*
 * Main entry point
 */
int 
hv_net_vsc_initialize(DRIVER_OBJECT *drv)
{
	netvsc_driver_object *driver = (netvsc_driver_object *)drv;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	DPRINT_DBG(NETVSC, "sizeof(netvsc_packet)=%d, sizeof(nvsp_msg)=%d, "
	    "sizeof(VMTRANSFER_PAGE_PACKET_HEADER)=%d",
	    sizeof(netvsc_packet), sizeof(nvsp_msg),
	    sizeof(VMTRANSFER_PAGE_PACKET_HEADER));

	/* Make sure we are at least 2 pages since 1 page is used for control */
	ASSERT(driver->ring_buf_size >= (PAGE_SIZE << 1));

	drv->name = g_net_vsc_driver_name;
	memcpy(&drv->deviceType, &g_net_vsc_device_type, sizeof(GUID));

	/* Make sure it is set by the caller */
	ASSERT(driver->on_rx_callback);
	ASSERT(driver->on_link_stat_changed);

	/* Setup the dispatch table */
	driver->base.OnDeviceAdd		= hv_nv_on_device_add;
	driver->base.OnDeviceRemove		= hv_nv_on_device_remove;
	driver->base.OnCleanup			= hv_nv_on_cleanup;

	driver->on_send				= hv_nv_on_send;

	hv_rndis_filter_init(driver);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC initialize receive buffer with net VSP
 */
static int 
hv_nv_init_rx_buffer_with_net_vsp(DEVICE_OBJECT *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "Unable to get net device... device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}
	ASSERT(net_dev->rx_buf_size > 0);
	/* page-size granularity */
	ASSERT((net_dev->rx_buf_size & (PAGE_SIZE-1)) == 0);

	net_dev->rx_buf =
	    PageAlloc(net_dev->rx_buf_size >> PAGE_SHIFT);
	if (!net_dev->rx_buf) {
		DPRINT_ERR(NETVSC,
		    "unable to allocate receive buffer of size %d",
		    net_dev->rx_buf_size);
		ret = -1;
		goto cleanup;
	}
	/* page-aligned buffer */
	ASSERT(((unsigned long)net_dev->rx_buf & (PAGE_SIZE-1)) == 0);

	DPRINT_DBG(NETVSC, "Establishing receive buffer's GPADL...");

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = device->Driver->VmbusChannelInterface.EstablishGpadl(device,
	    net_dev->rx_buf, net_dev->rx_buf_size,
	    &net_dev->rx_buf_gpadl_handle);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "cannot establish RX buffer's gpadl");
		goto cleanup;
	}
	
	//WaitEventWait(ext->channel_init_event);

	/* Notify the NetVsp of the gpadl handle */
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_rx_buf...");

	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));

	init_pkt->hdr.msg_type = nvsp_msg_1_type_send_rx_buf;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    net_dev->rx_buf_gpadl_handle;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_RECEIVE_BUFFER_ID;

	/* Send the gpadl notification request */
	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
	    init_pkt, sizeof(nvsp_msg), (unsigned long)init_pkt,
	    VmbusPacketTypeDataInBand,
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "cannot send RX buffer's gpadl to netvsp");
		goto cleanup;
	}

	WaitEventWait(net_dev->channel_init_event);

	/* Check the response */
	if (init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.status
						       != nvsp_status_success) {
		DPRINT_ERR(NETVSC, 
		    "cannot complete RX buffer initialzation with NetVsp - "
		    "status %d", 
		    init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.status);
		ret = -1;
		goto cleanup;
	}

	/* Parse the response */
	ASSERT(net_dev->rx_section_count == 0);
	ASSERT(net_dev->rx_sections == NULL);

	net_dev->rx_section_count =
	    init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.num_sections;

	net_dev->rx_sections = malloc(net_dev->rx_section_count *
	    sizeof(nvsp_1_rx_buf_section), M_DEVBUF, M_NOWAIT);
	if (net_dev->rx_sections == NULL) {
		ret = -1;
		goto cleanup;
	}

	memcpy(net_dev->rx_sections, 
	    init_pkt->msgs.vers_1_msgs.send_rx_buf_complete.sections,
	    net_dev->rx_section_count * sizeof(nvsp_1_rx_buf_section));

	DPRINT_DBG(NETVSC, 
	    "Receive sections info (count %d, offset %d, endoffset %d, "
	    "suballoc size %d, num suballocs %d)",
	    net_dev->rx_section_count,
	    net_dev->rx_sections[0].offset,
	    net_dev->rx_sections[0].end_offset,
	    net_dev->rx_sections[0].sub_allocation_size,
	    net_dev->rx_sections[0].num_sub_allocations);

	/*
	 * For first release, there should only be 1 section that represents
	 * the entire receive buffer
	 */
	if (net_dev->rx_section_count != 1 ||
		net_dev->rx_sections->offset != 0) {
		ret = -1;
		goto cleanup;
	}

	goto exit;

cleanup:
	hv_nv_destroy_rx_buffer(net_dev);
	
exit:
	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC initialize send buffer with net VSP
 */
static int 
hv_nv_init_send_buffer_with_net_vsp(DEVICE_OBJECT *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}
	ASSERT(net_dev->send_buf_size > 0);
	/* page-size granularity */
	ASSERT((net_dev->send_buf_size & (PAGE_SIZE-1)) == 0);

	net_dev->send_buf =
	    PageAlloc(net_dev->send_buf_size >> PAGE_SHIFT);
	if (!net_dev->send_buf) {
		DPRINT_ERR(NETVSC, "unable to allocate send buffer of size %d",
		    net_dev->send_buf_size);
		ret = -1;
		goto cleanup;
	}
	/* page-aligned buffer */
	ASSERT(((unsigned long)net_dev->send_buf & (PAGE_SIZE-1)) == 0);

	DPRINT_DBG(NETVSC, "Establishing send buffer's GPADL...");

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = device->Driver->VmbusChannelInterface.EstablishGpadl(device,
	    net_dev->send_buf, net_dev->send_buf_size,
	    &net_dev->send_buf_gpadl_handle);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to establish send buffer's gpadl");
		goto cleanup;
	}
	
	//WaitEventWait(ext->channel_init_event);

	/* Notify the NetVsp of the gpadl handle */
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_send_buf...");

	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));

	init_pkt->hdr.msg_type = nvsp_msg_1_type_send_send_buf;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    net_dev->send_buf_gpadl_handle;
	init_pkt->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_SEND_BUFFER_ID;

	/* Send the gpadl notification request */
	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
	    init_pkt, sizeof(nvsp_msg), (unsigned long)init_pkt,
	    VmbusPacketTypeDataInBand, 
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "Cannot send RX buffer's gpadl to netvsp");
		goto cleanup;
	}

	WaitEventWait(net_dev->channel_init_event);

	/* Check the response */
	if (init_pkt->msgs.vers_1_msgs.send_send_buf_complete.status
						       != nvsp_status_success) {
		DPRINT_ERR(NETVSC, 
		    "Cannot complete send buffer initialzation with NetVsp - "
		    "status %d", 
		    init_pkt->msgs.vers_1_msgs.send_send_buf_complete.status);
		ret = -1;
		goto cleanup;
	}

	net_dev->send_section_size =
	    init_pkt->msgs.vers_1_msgs.send_send_buf_complete.section_size;

	goto exit;

cleanup:
	hv_nv_destroy_send_buffer(net_dev);
	
exit:
	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);

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

	DPRINT_ENTER(NETVSC);

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (net_dev->rx_section_count) {
		DPRINT_DBG(NETVSC,
		    "Sending nvsp_msg_1_type_revoke_rx_buf...");

		/* Send the revoke receive buffer */
		revoke_pkt = &net_dev->revoke_packet;
		memset(revoke_pkt, 0, sizeof(nvsp_msg));

		revoke_pkt->hdr.msg_type =
		    nvsp_msg_1_type_revoke_rx_buf;
		revoke_pkt->msgs.vers_1_msgs.revoke_rx_buf.id =
		    NETVSC_RECEIVE_BUFFER_ID;

		ret =
		    net_dev->dev->Driver->VmbusChannelInterface.SendPacket(
		    net_dev->dev, revoke_pkt, sizeof(nvsp_msg),
		    (unsigned long)revoke_pkt, VmbusPacketTypeDataInBand, 0);
		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0) {
			DPRINT_ERR(NETVSC, "Cannot send revoke receive buffer "
			    "to netvsp");
			DPRINT_EXIT(NETVSC);
			return (-1);
		}
	}
		
	/* Tear down the gpadl on the vsp end */
	if (net_dev->rx_buf_gpadl_handle) {
		DPRINT_INFO(NETVSC, "Tearing down receive buffer's GPADL...");

		ret = net_dev->dev->Driver->VmbusChannelInterface.TeardownGpadl(
		    net_dev->dev,
		    net_dev->rx_buf_gpadl_handle);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0) {
			DPRINT_ERR(NETVSC,
			    "unable to teardown receive buffer's gpadl");
			DPRINT_EXIT(NETVSC);
			return (-1);
		}
		net_dev->rx_buf_gpadl_handle = 0;
	}

	if (net_dev->rx_buf) {
		DPRINT_INFO(NETVSC, "Freeing up receive buffer...");

		/* Free up the receive buffer */
		PageFree(net_dev->rx_buf,
		    net_dev->rx_buf_size >> PAGE_SHIFT);
		net_dev->rx_buf = NULL;
	}

	if (net_dev->rx_sections) {
		free(net_dev->rx_sections, M_DEVBUF);
		net_dev->rx_sections = NULL;
		net_dev->rx_section_count = 0;
	}

	DPRINT_EXIT(NETVSC);

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

	DPRINT_ENTER(NETVSC);

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (net_dev->send_section_size) {
		DPRINT_DBG(NETVSC,
		    "Sending nvsp_msg_1_type_revoke_send_buf...");

		/* Send the revoke send buffer */
		revoke_pkt = &net_dev->revoke_packet;
		memset(revoke_pkt, 0, sizeof(nvsp_msg));

		revoke_pkt->hdr.msg_type =
		    nvsp_msg_1_type_revoke_send_buf;
		revoke_pkt->msgs.vers_1_msgs.revoke_send_buf.id =
		    NETVSC_SEND_BUFFER_ID;

		ret = net_dev->dev->Driver->VmbusChannelInterface.SendPacket(
		    net_dev->dev, revoke_pkt, sizeof(nvsp_msg), 
		    (unsigned long)revoke_pkt, VmbusPacketTypeDataInBand, 0);
		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0) {
			DPRINT_ERR(NETVSC,
			    "unable to send revoke send buffer to netvsp");
			DPRINT_EXIT(NETVSC);
			return (-1);
		}
	}
		
	/* Tear down the gpadl on the vsp end */
	if (net_dev->send_buf_gpadl_handle) {
		DPRINT_DBG(NETVSC, "Tearing down send buffer's GPADL...");

		ret = net_dev->dev->Driver->VmbusChannelInterface.TeardownGpadl(
		    net_dev->dev, net_dev->send_buf_gpadl_handle);

		/*
		 * If we failed here, we might as well return and have a leak 
		 * rather than continue and a bugchk
		 */
		if (ret != 0) {
			DPRINT_ERR(NETVSC,
			    "unable to teardown send buffer's gpadl");
			DPRINT_EXIT(NETVSC);
			return (-1);
		}
		net_dev->send_buf_gpadl_handle = 0;
	}

	if (net_dev->send_buf) {
		DPRINT_DBG(NETVSC, "Freeing up send buffer...");

		/* Free up the receive buffer */
		PageFree(net_dev->send_buf,
		    net_dev->send_buf_size >> PAGE_SHIFT);
		net_dev->send_buf = NULL;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC connect to VSP
 */
static int
hv_nv_connect_to_vsp(DEVICE_OBJECT *device)
{
	int ret = 0;
	netvsc_dev *net_dev;
	nvsp_msg *init_pkt;
	uint32_t ndis_version;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "Unable to get net device... device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}

	init_pkt = &net_dev->channel_init_packet;

	memset(init_pkt, 0, sizeof(nvsp_msg));
	init_pkt->hdr.msg_type = nvsp_msg_type_init;
	init_pkt->msgs.init_msgs.init.min_protocol_version =
	    NVSP_MIN_PROTOCOL_VERSION;
	init_pkt->msgs.init_msgs.init.max_protocol_version =
	    NVSP_MAX_PROTOCOL_VERSION;

	DPRINT_DBG(NETVSC, "Sending nvsp_msg_type_init...");

	/* Send the init request */
	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
	    init_pkt, sizeof(nvsp_msg), (unsigned long)init_pkt,
	    VmbusPacketTypeDataInBand,
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to send nvsp_msg_type_init");
		goto cleanup;
	}

	WaitEventWait(net_dev->channel_init_event);

	/* Now, check the response */
	//ASSERT(init_pkt->msgs.init_msgs.init_compl.max_mdl_chain_len <=
	//    MAX_MULTIPAGE_BUFFER_COUNT);
	DPRINT_DBG(NETVSC, "nvsp_msg_type_init status(%d) max mdl chain (%d)", 
		init_pkt->msgs.init_msgs.init_compl.status,
		init_pkt->msgs.init_msgs.init_compl.max_mdl_chain_len);

	if (init_pkt->msgs.init_msgs.init_compl.status !=
							  nvsp_status_success) {
		DPRINT_ERR(NETVSC, "Cannot initialize with netvsp "
		    "(status 0x%x)",
		    init_pkt->msgs.init_msgs.init_compl.status);
		ret = -1;
		goto cleanup;
	}

	if (init_pkt->msgs.init_msgs.init_compl.negotiated_prot_vers
						  != NVSP_PROTOCOL_VERSION_1) {
		DPRINT_ERR(NETVSC, "Cannot initialize with netvsp "
		    "(version expected 1 got %d)",
		    init_pkt->msgs.init_msgs.init_compl.negotiated_prot_vers);
		ret = -1;
		goto cleanup;
	}
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_ndis_vers...");

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
	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
	    init_pkt, sizeof(nvsp_msg), (unsigned long)init_pkt,
	    VmbusPacketTypeDataInBand, 0);
	if (ret != 0) {
		DPRINT_ERR(NETVSC,
		    "unable to send nvsp_msg_1_type_send_ndis_vers");
		ret = -1;
		goto cleanup;
	}
	/*
	 * BUGBUG - We have to wait for the above msg since the netvsp uses
	 * KMCL which acknowledges packet (completion packet) 
	 * since our Vmbus always set the
	 * VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED flag
	 */
	//WaitEventWait(NetVscChannel->channel_init_event);

	/* Post the big receive buffer to NetVSP */
	ret = hv_nv_init_rx_buffer_with_net_vsp(device);
	if (ret == 0) {
		ret = hv_nv_init_send_buffer_with_net_vsp(device);
	}

cleanup:
	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC disconnect from VSP
 */
static void
hv_nv_disconnect_from_vsp(netvsc_dev *net_dev)
{
	DPRINT_ENTER(NETVSC);

	hv_nv_destroy_rx_buffer(net_dev);
	hv_nv_destroy_send_buffer(net_dev);

	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on device add
 * 
 * Callback when the device belonging to this driver is added
 */
static int
hv_nv_on_device_add(DEVICE_OBJECT *device, void *additional_info)
{
	netvsc_dev *net_dev;
	netvsc_packet *packet;
	LIST_ENTRY *entry;
	int ret = 0;
	int i;

	netvsc_driver_object *netDriver =
	    (netvsc_driver_object *)device->Driver;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_alloc_net_device(device);
	if (!net_dev) {
		ret = -1;
		goto cleanup;
	}

	DPRINT_DBG(NETVSC, "netvsc channel object allocated - %p", net_dev);

	/* Initialize the NetVSC channel extension */
	net_dev->rx_buf_size = NETVSC_RECEIVE_BUFFER_SIZE;
	net_dev->rx_packet_list_lock = SpinlockCreate();

	net_dev->send_buf_size = NETVSC_SEND_BUFFER_SIZE;

	INITIALIZE_LIST_HEAD(&net_dev->rx_packet_list);

	for (i=0; i < NETVSC_RECEIVE_PACKETLIST_COUNT; i++) {
		packet = malloc(sizeof(netvsc_packet) +
		    (NETVSC_RECEIVE_SG_COUNT * sizeof(PAGE_BUFFER)),
		    M_DEVBUF, M_NOWAIT | M_ZERO);
		if (!packet) {
			DPRINT_DBG(NETVSC, "Cannot allocate netvsc pkts for "
			    "receive pool (wanted %d got %d)",
			    NETVSC_RECEIVE_PACKETLIST_COUNT, i);
			break;
		}

		INSERT_TAIL_LIST(&net_dev->rx_packet_list,
		    &packet->list_entry);
	}
	net_dev->channel_init_event = WaitEventCreate();

	/* Open the channel */
	ret = device->Driver->VmbusChannelInterface.Open(device,
	    netDriver->ring_buf_size, netDriver->ring_buf_size,
	    NULL, 0, hv_nv_on_channel_callback, device);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to open channel: %d", ret);
		ret = -1;
		goto cleanup;
	}

	/* Channel is opened */
	DPRINT_INFO(NETVSC, "*** NetVSC channel opened successfully! ***");

	/* Connect with the NetVsp */
	ret = hv_nv_connect_to_vsp(device);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to connect to NetVSP - %d", ret);
		ret = -1;
		goto close;
	}

	DPRINT_INFO(NETVSC, "*** NetVSC channel handshake result - %d ***",
	    ret);

	DPRINT_EXIT(NETVSC);

	return (ret);

close:
	/* Now, we can close the channel safely */
	device->Driver->VmbusChannelInterface.Close(device);

cleanup:
	
	if (net_dev) {
		WaitEventClose(net_dev->channel_init_event);

		while (!IsListEmpty(&net_dev->rx_packet_list)) {	
			entry = REMOVE_HEAD_LIST(&net_dev->rx_packet_list);
			packet = CONTAINING_RECORD(entry, netvsc_packet,
			    list_entry);
			free(packet, M_DEVBUF);
		}

		SpinlockClose(net_dev->rx_packet_list_lock);

		hv_nv_release_outbound_net_device(device);
		hv_nv_release_inbound_net_device(device);

		hv_nv_free_net_device(net_dev);
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC on device remove
 *
 * Callback when the root bus device is removed
 */
static int
hv_nv_on_device_remove(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev;
	netvsc_packet *net_vsc_pkt;
	LIST_ENTRY *entry;
	int ret = 0;

	DPRINT_ENTER(NETVSC);
	
	DPRINT_INFO(NETVSC, "Disabling outbound traffic on net device (%p)...",
		    device->Extension);
	
	/* Stop outbound traffic ie sends and receives completions */
	net_dev = hv_nv_release_outbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC, "No net device present!!");

		return (-1);
	}

	/* Wait for all send completions */
	while (net_dev->num_outstanding_sends) {
		DPRINT_INFO(NETVSC, "waiting for %d requests to complete...",
		    net_dev->num_outstanding_sends);

		DELAY(100);
	}

	DPRINT_DBG(NETVSC, "Disconnecting from netvsp...");

	hv_nv_disconnect_from_vsp(net_dev);

	DPRINT_INFO(NETVSC, "Disabling inbound traffic on net device (%p)...",
	    device->Extension);

	/* Stop inbound traffic ie receives and sends completions */
	net_dev = hv_nv_release_inbound_net_device(device);

	/* At this point, no one should be accessing net_dev except in here */
	DPRINT_INFO(NETVSC, "net device (%p) safe to remove", net_dev);

	/* Now, we can close the channel safely */
	device->Driver->VmbusChannelInterface.Close(device);

	/* Release all resources */
	while (!IsListEmpty(&net_dev->rx_packet_list)) {	
		entry = REMOVE_HEAD_LIST(&net_dev->rx_packet_list);
		net_vsc_pkt =
		    CONTAINING_RECORD(entry, netvsc_packet, list_entry);

		free(net_vsc_pkt, M_DEVBUF);
	}

	SpinlockClose(net_dev->rx_packet_list_lock);
	WaitEventClose(net_dev->channel_init_event);
	hv_nv_free_net_device(net_dev);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC on cleanup
 *
 * Perform any cleanup when the driver is removed
 */
static void
hv_nv_on_cleanup(DRIVER_OBJECT *driver)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on send completion
 */
static void 
hv_nv_on_send_completion(DEVICE_OBJECT *device, VMPACKET_DESCRIPTOR *pkt)
{
	netvsc_dev *net_dev;
	nvsp_msg *nvsp_msg_pkt;
	netvsc_packet *net_vsc_pkt;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "Unable to get net device... device being destroyed?");
		DPRINT_EXIT(NETVSC);

		return;
	}

	nvsp_msg_pkt =
	    (nvsp_msg *)((unsigned long)pkt + (pkt->DataOffset8 << 3));

	DPRINT_DBG(NETVSC, "send completion packet - type %d",
	    nvsp_msg_pkt->hdr.msg_type);

	if (nvsp_msg_pkt->hdr.msg_type == nvsp_msg_type_init_complete ||
	    nvsp_msg_pkt->hdr.msg_type ==
	      nvsp_msg_1_type_send_rx_buf_complete ||
	    nvsp_msg_pkt->hdr.msg_type ==
	      nvsp_msg_1_type_send_send_buf_complete) {
		/* Copy the response back */
		memcpy(&net_dev->channel_init_packet,
		    nvsp_msg_pkt, sizeof(nvsp_msg));			
		WaitEventSet(net_dev->channel_init_event);
	} else if (nvsp_msg_pkt->hdr.msg_type ==
				    nvsp_msg_1_type_send_rndis_pkt_complete) {
		/* Get the send context */
		net_vsc_pkt =
		    (netvsc_packet *)(unsigned long)pkt->TransactionId;
		ASSERT(net_vsc_pkt);

		/* Notify the layer above us */
		net_vsc_pkt->compl.send.on_send_completion(
		    net_vsc_pkt->compl.send.send_completion_context);

		InterlockedDecrement(&net_dev->num_outstanding_sends);
	} else {
		DPRINT_ERR(NETVSC, "Unknown send completion packet type - %d "
		    "received!!", nvsp_msg_pkt->hdr.msg_type);
	}

	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on send
 */
static int
hv_nv_on_send(DEVICE_OBJECT *device, netvsc_packet *pkt)
{
	netvsc_dev *net_dev;
	nvsp_msg send_msg;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_outbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC, "net device (%p) shutting down... "
		    "ignoring outbound packets", net_dev);
		DPRINT_EXIT(NETVSC);

		return (-2);
	}

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
		ret =
		    device->Driver->VmbusChannelInterface.SendPacketPageBuffer(
		    device, pkt->page_buffers, pkt->page_buf_count,
		    &send_msg, sizeof(nvsp_msg), (unsigned long)pkt);
	} else {
		ret = device->Driver->VmbusChannelInterface.SendPacket(device,
		    &send_msg, sizeof(nvsp_msg), (unsigned long)pkt,
		    VmbusPacketTypeDataInBand,
		    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "Unable to send packet %p ret %d", pkt, ret);
	}

	InterlockedIncrement(&net_dev->num_outstanding_sends);
	hv_nv_put_net_device(device);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC on receive
 *
 * In the FreeBSD Hyper-V virtual world, this function deals exclusively
 * with virtual addresses.
 */
// Fixme:  Done so function name would be visible to debugger
//static void 
void 
hv_nv_on_receive(DEVICE_OBJECT *device, VMPACKET_DESCRIPTOR *pkt)
{
	netvsc_dev *net_dev;
	VMTRANSFER_PAGE_PACKET_HEADER *vm_xfer_page_pkt;
	nvsp_msg *nvsp_msg_pkt;
	netvsc_packet *net_vsc_pkt = NULL;
	LIST_ENTRY *entry;
	unsigned long start;
	XFERPAGE_PACKET *xfer_page_pkt = NULL;
	LIST_ENTRY list_head;
	int count = 0;
	int i = 0;

	DPRINT_ENTER(NETVSC);

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);

		return;
	}

	/*
	 * All inbound packets other than send completion should be
	 * xfer page packet.
	 */
	if (pkt->Type != VmbusPacketTypeDataUsingTransferPages) {
		DPRINT_ERR(NETVSC, "Unknown packet type received - %d",
		    pkt->Type);
		hv_nv_put_net_device(device);

		return;
	}

	nvsp_msg_pkt = (nvsp_msg *)((unsigned long)pkt +
	    (pkt->DataOffset8 << 3));

	/* Make sure this is a valid nvsp packet */
	if (nvsp_msg_pkt->hdr.msg_type != nvsp_msg_1_type_send_rndis_pkt) {
		DPRINT_ERR(NETVSC, "Unknown nvsp packet type received - %d",
		    nvsp_msg_pkt->hdr.msg_type);
		hv_nv_put_net_device(device);

		return;
	}
	
	DPRINT_DBG(NETVSC, "NVSP packet received - type %d",
	    nvsp_msg_pkt->hdr.msg_type);

	vm_xfer_page_pkt = (VMTRANSFER_PAGE_PACKET_HEADER *)pkt;

	if (vm_xfer_page_pkt->TransferPageSetId != NETVSC_RECEIVE_BUFFER_ID) {
		DPRINT_ERR(NETVSC, "Invalid xfer page set id - expecting %x "
		    "got %x", NETVSC_RECEIVE_BUFFER_ID,
		    vm_xfer_page_pkt->TransferPageSetId);
		hv_nv_put_net_device(device);

		return;
	}

	DPRINT_DBG(NETVSC, "xfer page - range count %d",
	    vm_xfer_page_pkt->RangeCount);

	INITIALIZE_LIST_HEAD(&list_head);

	/*
	 * Grab free packets (range count + 1) to represent this xfer page
	 * packet.  +1 to represent the xfer page packet itself.  We grab it
	 * here so that we know exactly how many we can fulfill.
	 */
	SpinlockAcquire(net_dev->rx_packet_list_lock);
	while (!IsListEmpty(&net_dev->rx_packet_list)) {	
		entry = REMOVE_HEAD_LIST(&net_dev->rx_packet_list);
		net_vsc_pkt = CONTAINING_RECORD(entry, netvsc_packet,
		    list_entry);

		INSERT_TAIL_LIST(&list_head, &net_vsc_pkt->list_entry);

		if (++count == vm_xfer_page_pkt->RangeCount + 1) {
			break;
		}
	}
	SpinlockRelease(net_dev->rx_packet_list_lock);

	/*
	 * We need at least 2 netvsc pkts (1 to represent the xfer page
	 * and at least 1 for the range) i.e. we can handled some of the
	 * xfer page packet ranges...
	 */
	if (count < 2) {
		DPRINT_ERR(NETVSC, "Got only %d netvsc pkt...needed %d pkts. "
		    "Dropping this xfer page packet completely!", count,
		    vm_xfer_page_pkt->RangeCount + 1);

		/* Return it to the freelist */
		SpinlockAcquire(net_dev->rx_packet_list_lock);
		for (i=count; i != 0; i--) {
			entry = REMOVE_HEAD_LIST(&list_head);
			net_vsc_pkt = CONTAINING_RECORD(entry, netvsc_packet,
			    list_entry);

			INSERT_TAIL_LIST(&net_dev->rx_packet_list,
			    &net_vsc_pkt->list_entry);
		}
		SpinlockRelease(net_dev->rx_packet_list_lock);

		hv_nv_send_receive_completion(device,
		    vm_xfer_page_pkt->d.TransactionId);

		hv_nv_put_net_device(device);

		return;
	}

	/* Remove the 1st packet to represent the xfer page packet itself */
	entry = REMOVE_HEAD_LIST(&list_head);
	xfer_page_pkt = CONTAINING_RECORD(entry, XFERPAGE_PACKET, ListEntry);
	/* This is how much we can satisfy */
	xfer_page_pkt->Count = count - 1;
	ASSERT(xfer_page_pkt->Count > 0 &&
	    xfer_page_pkt->Count <= vm_xfer_page_pkt->RangeCount);

	if (xfer_page_pkt->Count != vm_xfer_page_pkt->RangeCount) {
		DPRINT_DBG(NETVSC, "Needed %d netvsc pkts to satisy this "
		    "xfer page...got %d", vm_xfer_page_pkt->RangeCount,
		    xfer_page_pkt->Count);
	}

	/* Each range represents 1 RNDIS pkt that contains 1 ethernet frame */
	for (i=0; i < (count - 1); i++) {
		entry = REMOVE_HEAD_LIST(&list_head);
		net_vsc_pkt = CONTAINING_RECORD(entry, netvsc_packet,
		    list_entry);

		/* Initialize the netvsc packet */
		net_vsc_pkt->xfer_page_pkt = xfer_page_pkt;
		net_vsc_pkt->compl.rx.on_rx_completion =
		    hv_nv_on_receive_completion;
		net_vsc_pkt->compl.rx.rx_completion_context =
		    net_vsc_pkt;
		net_vsc_pkt->device = device;
		/* Save this so that we can send it back */
		net_vsc_pkt->compl.rx.rx_completion_tid =
		    vm_xfer_page_pkt->d.TransactionId;

		net_vsc_pkt->tot_data_buf_len =
		    vm_xfer_page_pkt->Ranges[i].ByteCount;
		net_vsc_pkt->page_buf_count = 1;

		ASSERT(vm_xfer_page_pkt->Ranges[i].ByteOffset +
		    vm_xfer_page_pkt->Ranges[i].ByteCount <
		    net_dev->rx_buf_size);

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
		    vm_xfer_page_pkt->Ranges[i].ByteOffset & (PAGE_SIZE -1);

		/*
		 * In this implementation, we are dealing with virtual
		 * addresses exclusively.  Since we aren't using physical
		 * addresses at all, we don't care if a packet crosses a
		 * page boundary.  For this reason, the original code to
		 * check for and handle page crossings has been removed.
		 */

		DPRINT_DBG(NETVSC, "[%d] - (abs offset %u len %u) => "
		    "(pfn %llx, offset %u, len %u)", 
		    i, 
		    vm_xfer_page_pkt->Ranges[i].ByteOffset,
		    vm_xfer_page_pkt->Ranges[i].ByteCount,
		    net_vsc_pkt->page_buffers[0].Pfn, 
		    net_vsc_pkt->page_buffers[0].Offset,
		    net_vsc_pkt->page_buffers[0].Length);

		/* Pass it to the upper layer */
		((netvsc_driver_object *)device->Driver)->on_rx_callback(device,
		    net_vsc_pkt);

		/*
		 * The receive completion call has been moved into the
		 * callback function above.
		 */
		// hv_nv_on_receive_completion(
		//     net_vsc_pkt->compl.Recv.ReceiveCompletionContext);
	}

	ASSERT(IsListEmpty(&list_head));
	
	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC send receive completion
 */
static void
hv_nv_send_receive_completion(DEVICE_OBJECT *device, uint64_t tid)
{
	nvsp_msg rx_comp_msg;
	int retries = 0;
	int ret = 0;

	DPRINT_DBG(NETVSC, "Sending receive completion pkt - %llx", tid);
	
	rx_comp_msg.hdr.msg_type =
	    nvsp_msg_1_type_send_rndis_pkt_complete;

	/* Fixme:  Pass in the status */
	rx_comp_msg.msgs.vers_1_msgs.send_rndis_pkt_complete.status =
	    nvsp_status_success;

retry_send_cmplt:
	/* Send the completion */
	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
	    &rx_comp_msg, sizeof(nvsp_msg), tid,
	    VmbusPacketTypeCompletion, 0);
	if (ret == 0) {
		/* success */
		/* no-op */
	} else if (ret == -1) {
		/* no more room... wait a bit and attempt to retry 3 times */
		retries++;
		DPRINT_ERR(NETVSC, "unable to send receive completion pkt"
		    "(tid %llx)...retrying %d", tid, retries);

		if (retries < 4) {
			DELAY(100);
			goto retry_send_cmplt;
		} else {
			DPRINT_ERR(NETVSC, "unable to send receive completion "
			    "pkt (tid %llx)...give up retrying", tid);
		}
	} else {
		DPRINT_ERR(NETVSC,
		    "unable to send receive completion pkt - %llx",
		    tid);
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
	DEVICE_OBJECT *device = (DEVICE_OBJECT *)packet->device;
	netvsc_dev *net_dev;
	uint64_t       tid = 0;
	BOOL send_rx_completion = FALSE;

	DPRINT_ENTER(NETVSC);

	ASSERT(packet->xfer_page_pkt);

	/*
	 * Even though it seems logical to do a hv_nv_get_outbound_net_device()
	 * here to send out receive completion, we are using
	 * hv_nv_get_inbound_net_device() since we may have disabled
	 * outbound traffic already.
	 */
	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC,
		    "Unable to get net device... device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return;
	}
	
	/* Overloading use of the lock. */
	SpinlockAcquire(net_dev->rx_packet_list_lock);

// 	ASSERT(packet->xfer_page_pkt->Count > 0);
	if (packet->xfer_page_pkt->Count == 0) {
		hv_nv_put_net_device(device);
		DPRINT_EXIT(NETVSC);
	}

	packet->xfer_page_pkt->Count--;

	/* Last one in the line that represent 1 xfer page packet. */
	/* Return the xfer page packet itself to the freelist */
	if (packet->xfer_page_pkt->Count == 0) {
		send_rx_completion = TRUE;
		tid = packet->compl.rx.rx_completion_tid;

		INSERT_TAIL_LIST(&net_dev->rx_packet_list,
		    &packet->xfer_page_pkt->ListEntry);
	}

	/* Put the packet back */
	INSERT_TAIL_LIST(&net_dev->rx_packet_list, &packet->list_entry);
	SpinlockRelease(net_dev->rx_packet_list_lock);

	/* Send a receive completion for the xfer page packet */
	if (send_rx_completion) {
		hv_nv_send_receive_completion(device, tid);
	}

	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on channel callback
 */
static void
hv_nv_on_channel_callback(void *context)
{
	/* Fixme:  Magic number */
	const int net_pkt_size = 2048;
	DEVICE_OBJECT *device = (DEVICE_OBJECT *)context;
	netvsc_dev *net_dev;
	uint32_t bytes_rxed;
	uint64_t request_id;
	uint8_t  packet[net_pkt_size];
	VMPACKET_DESCRIPTOR *desc;
	uint8_t *buffer = packet;
	int	bufferlen = net_pkt_size;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	ASSERT(device);

	net_dev = hv_nv_get_inbound_net_device(device);
	if (!net_dev) {
		DPRINT_ERR(NETVSC, "net device (%p) shutting down...ignoring"
		   " inbound packets", net_dev);
		DPRINT_EXIT(NETVSC);

		return;
	}

	do {
		ret = device->Driver->VmbusChannelInterface.RecvPacketRaw(
		    device, buffer, bufferlen, &bytes_rxed, &request_id);

		if (ret == 0) {
			if (bytes_rxed > 0) {
				DPRINT_DBG(NETVSC, "receive %d bytes, tid %llx",
				    bytes_rxed, request_id);
			 
				desc = (VMPACKET_DESCRIPTOR *)buffer;
				switch (desc->Type) {
				case VmbusPacketTypeCompletion:
//					printf("TxC");
					hv_nv_on_send_completion(device, desc);
					break;

				case VmbusPacketTypeDataUsingTransferPages:
//					printf("R1 ");
					hv_nv_on_receive(device, desc);
					break;

				default:
					DPRINT_ERR(NETVSC, "unhandled packet"
					   " type %d, tid %llx len %d\n",
					   desc->Type, request_id, bytes_rxed);
					break;
				}

				/* Reset */
				if (bufferlen > net_pkt_size) {
					free(buffer, M_DEVBUF);
									
					buffer = packet;
					bufferlen = net_pkt_size;
				}
			} else {
				//DPRINT_DBG(NETVSC, "nothing else to read...");
				
				/* Reset */
				if (bufferlen > net_pkt_size) {
					free(buffer, M_DEVBUF);
									
					buffer = packet;
					bufferlen = net_pkt_size;
				}

				break;
			}
		} else if (ret == -2) {
			/* Handle large packet */
			buffer = malloc(bytes_rxed, M_DEVBUF, M_NOWAIT);
			if (buffer == NULL) {
				/* Try again next time around */
				DPRINT_ERR(NETVSC, "unable to allocate buffer"
				     " of size (%d)!!", bytes_rxed);
				break;
			}

			bufferlen = bytes_rxed;
		} else {
			ASSERT(0);
		}
	} while (1);

	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

