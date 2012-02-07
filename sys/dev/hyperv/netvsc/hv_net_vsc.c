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
static const char* gDriverName = "netvsc";

// {F8615163-DF3E-46c5-913F-F2D2F965ED0E}
static const GUID gNetVscDeviceType = {
	.Data = {0x63, 0x51, 0x61, 0xF8, 0x3E, 0xDF, 0xc5, 0x46,
		 0x91, 0x3F, 0xF2, 0xD2, 0xF9, 0x65, 0xED, 0x0E}
};


/*
 * Forward declarations
 */
static int  hv_nv_on_device_add(DEVICE_OBJECT *Device, void *AdditionalInfo);
static int  hv_nv_on_device_remove(DEVICE_OBJECT *Device);
static void hv_nv_on_cleanup(DRIVER_OBJECT *Driver);
static void hv_nv_on_channel_callback(void *context);
static int  hv_nv_init_send_buffer_with_net_vsp(DEVICE_OBJECT *Device);
static int  hv_nv_init_rx_buffer_with_net_vsp(DEVICE_OBJECT *Device);
static int  hv_nv_destroy_send_buffer(netvsc_dev *NetDevice);
static int  hv_nv_destroy_rx_buffer(netvsc_dev *NetDevice);
static int  hv_nv_connect_to_vsp(DEVICE_OBJECT *Device);
static void hv_nv_on_send_completion(DEVICE_OBJECT *Device,
				     VMPACKET_DESCRIPTOR *Packet);
static int  hv_nv_on_send(DEVICE_OBJECT *Device, netvsc_packet *Packet);
// Fixme
extern void hv_nv_on_receive(DEVICE_OBJECT *Device, VMPACKET_DESCRIPTOR *Packet);
//static void hv_nv_on_receive(DEVICE_OBJECT *Device, VMPACKET_DESCRIPTOR *Packet);
static void hv_nv_send_receive_completion(DEVICE_OBJECT *Device,
					  uint64_t TransactionId);


/*
 *
 */
static inline netvsc_dev *
hv_nv_alloc_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = malloc(sizeof(netvsc_dev), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!netDevice) {
		return (NULL);
	}

	// Set to 2 to allow both inbound and outbound traffic
	InterlockedCompareExchange(&netDevice->ref_cnt, 2, 0);

	netDevice->dev = Device;
	Device->Extension = netDevice;

	return (netDevice);
}

/*
 *
 */
static inline void
hv_nv_free_net_device(netvsc_dev *Device)
{
	ASSERT(Device->ref_cnt == 0);
	Device->dev->Extension = NULL;
	free(Device, M_DEVBUF);
}


/*
 * Get the net device object iff exists and its refcount > 1
 */
static inline netvsc_dev *
hv_nv_get_outbound_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = (netvsc_dev *)Device->Extension;
	if (netDevice && netDevice->ref_cnt > 1) {
		InterlockedIncrement(&netDevice->ref_cnt);
	} else {
		netDevice = NULL;
	}

	return (netDevice);
}

/*
 * Get the net device object iff exists and its refcount > 0
 */
static inline netvsc_dev *
hv_nv_get_inbound_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = (netvsc_dev *)Device->Extension;
	if (netDevice && netDevice->ref_cnt) {
		InterlockedIncrement(&netDevice->ref_cnt);
	} else {
		netDevice = NULL;
	}

	return (netDevice);
}

/*
 *
 */
static inline void
hv_nv_put_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = (netvsc_dev *)Device->Extension;
	ASSERT(netDevice);

	InterlockedDecrement(&netDevice->ref_cnt);
}

/*
 *
 */
static inline netvsc_dev *
hv_nv_release_outbound_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = (netvsc_dev *)Device->Extension;
	if (netDevice == NULL) {
		return (NULL);
	}

	// Busy wait until the ref drop to 2, then set it to 1 
	while (InterlockedCompareExchange(&netDevice->ref_cnt, 1, 2) != 2) {
		Sleep(100);
	}

	return (netDevice);
}

/*
 *
 */
static inline netvsc_dev *
hv_nv_release_inbound_net_device(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;

	netDevice = (netvsc_dev *)Device->Extension;
	if (netDevice == NULL) {
		return (NULL);
	}

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (InterlockedCompareExchange(&netDevice->ref_cnt, 0, 1) != 1) {
		Sleep(100);
	}

	Device->Extension = NULL;

	return (netDevice);
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
	ASSERT(driver->RingBufferSize >= (PAGE_SIZE << 1));

	drv->name = gDriverName;
	memcpy(&drv->deviceType, &gNetVscDeviceType, sizeof(GUID));

	/* Make sure it is set by the caller */
	ASSERT(driver->OnReceiveCallback);
	ASSERT(driver->OnLinkStatusChanged);

	/* Setup the dispatch table */
	driver->Base.OnDeviceAdd		= hv_nv_on_device_add;
	driver->Base.OnDeviceRemove		= hv_nv_on_device_remove;
	driver->Base.OnCleanup			= hv_nv_on_cleanup;

	driver->OnSend				= hv_nv_on_send;

	hv_rndis_filter_init(driver);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC initialize receive buffer with net VSP
 */
static int 
hv_nv_init_rx_buffer_with_net_vsp(DEVICE_OBJECT *Device)
{
	int ret = 0;
	netvsc_dev *netDevice;
	nvsp_msg *initPacket;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_outbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}
	ASSERT(netDevice->rx_buf_size > 0);
	/* page-size granularity */
	ASSERT((netDevice->rx_buf_size & (PAGE_SIZE-1)) == 0);

	netDevice->rx_buf =
	    PageAlloc(netDevice->rx_buf_size >> PAGE_SHIFT);
	if (!netDevice->rx_buf) {
		DPRINT_ERR(NETVSC,
		    "unable to allocate receive buffer of size %d",
		    netDevice->rx_buf_size);
		ret = -1;
		goto Cleanup;
	}
	/* page-aligned buffer */
	ASSERT(((ULONG_PTR)netDevice->rx_buf & (PAGE_SIZE-1)) == 0);

	DPRINT_DBG(NETVSC, "Establishing receive buffer's GPADL...");

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = Device->Driver->VmbusChannelInterface.EstablishGpadl(Device,
	    netDevice->rx_buf, netDevice->rx_buf_size,
	    &netDevice->rx_buf_gpadl_handle);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "cannot establish RX buffer's gpadl");
		goto Cleanup;
	}
	
	//WaitEventWait(ext->channel_init_event);

	/* Notify the NetVsp of the gpadl handle */
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_rx_buf...");

	initPacket = &netDevice->channel_init_packet;

	memset(initPacket, 0, sizeof(nvsp_msg));

	initPacket->hdr.msg_type = nvsp_msg_1_type_send_rx_buf;
	initPacket->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    netDevice->rx_buf_gpadl_handle;
	initPacket->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_RECEIVE_BUFFER_ID;

	/* Send the gpadl notification request */
	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
	    initPacket, sizeof(nvsp_msg), (ULONG_PTR)initPacket,
	    VmbusPacketTypeDataInBand,
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "cannot send RX buffer's gpadl to netvsp");
		goto Cleanup;
	}

	WaitEventWait(netDevice->channel_init_event);

	/* Check the response */
	if (initPacket->msgs.vers_1_msgs.send_rx_buf_complete.status
						       != nvsp_status_success) {
		DPRINT_ERR(NETVSC, 
		    "cannot complete RX buffer initialzation with NetVsp - "
		    "status %d", 
		    initPacket->msgs.vers_1_msgs.send_rx_buf_complete.status);
		ret = -1;
		goto Cleanup;
	}

	/* Parse the response */
	ASSERT(netDevice->rx_section_count == 0);
	ASSERT(netDevice->rx_sections == NULL);

	netDevice->rx_section_count =
	    initPacket->msgs.vers_1_msgs.send_rx_buf_complete.num_sections;

	netDevice->rx_sections = malloc(netDevice->rx_section_count *
	    sizeof(nvsp_1_rx_buf_section), M_DEVBUF, M_NOWAIT);
	if (netDevice->rx_sections == NULL) {
		ret = -1;
		goto Cleanup;
	}

	memcpy(netDevice->rx_sections, 
	    initPacket->msgs.vers_1_msgs.send_rx_buf_complete.sections,
	    netDevice->rx_section_count * sizeof(nvsp_1_rx_buf_section));

	DPRINT_DBG(NETVSC, 
	    "Receive sections info (count %d, offset %d, endoffset %d, "
	    "suballoc size %d, num suballocs %d)",
	    netDevice->rx_section_count,
	    netDevice->rx_sections[0].offset,
	    netDevice->rx_sections[0].end_offset,
	    netDevice->rx_sections[0].sub_allocation_size,
	    netDevice->rx_sections[0].num_sub_allocations);

	/*
	 * For first release, there should only be 1 section that represents
	 * the entire receive buffer
	 */
	if (netDevice->rx_section_count != 1 ||
		netDevice->rx_sections->offset != 0) {
		ret = -1;
		goto Cleanup;
	}

	goto Exit;

Cleanup:
	hv_nv_destroy_rx_buffer(netDevice);
	
Exit:
	hv_nv_put_net_device(Device);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC initialize send buffer with net VSP
 */
static int 
hv_nv_init_send_buffer_with_net_vsp(DEVICE_OBJECT *Device)
{
	int ret = 0;
	netvsc_dev *netDevice;
	nvsp_msg *initPacket;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_outbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}
	ASSERT(netDevice->send_buf_size > 0);
	// page-size granularity
	ASSERT((netDevice->send_buf_size & (PAGE_SIZE-1)) == 0);

	netDevice->send_buf =
	    PageAlloc(netDevice->send_buf_size >> PAGE_SHIFT);
	if (!netDevice->send_buf) {
		DPRINT_ERR(NETVSC, "unable to allocate send buffer of size %d",
		    netDevice->send_buf_size);
		ret = -1;
		goto Cleanup;
	}
	// page-aligned buffer
	ASSERT(((ULONG_PTR)netDevice->send_buf & (PAGE_SIZE-1)) == 0);

	DPRINT_DBG(NETVSC, "Establishing send buffer's GPADL...");

	/*
	 * Establish the gpadl handle for this buffer on this channel.
	 * Note:  This call uses the vmbus connection rather than the
	 * channel to establish the gpadl handle. 
	 */
	ret = Device->Driver->VmbusChannelInterface.EstablishGpadl(Device,
	    netDevice->send_buf, netDevice->send_buf_size,
	    &netDevice->send_buf_gpadl_handle);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to establish send buffer's gpadl");
		goto Cleanup;
	}
	
	//WaitEventWait(ext->channel_init_event);

	// Notify the NetVsp of the gpadl handle
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_send_buf...");

	initPacket = &netDevice->channel_init_packet;

	memset(initPacket, 0, sizeof(nvsp_msg));

	initPacket->hdr.msg_type = nvsp_msg_1_type_send_send_buf;
	initPacket->msgs.vers_1_msgs.send_rx_buf.gpadl_handle =
	    netDevice->send_buf_gpadl_handle;
	initPacket->msgs.vers_1_msgs.send_rx_buf.id =
	    NETVSC_SEND_BUFFER_ID;

	// Send the gpadl notification request
	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
	    initPacket, sizeof(nvsp_msg), (ULONG_PTR)initPacket,
	    VmbusPacketTypeDataInBand, 
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "Cannot send RX buffer's gpadl to netvsp");
		goto Cleanup;
	}

	WaitEventWait(netDevice->channel_init_event);

	/* Check the response */
	if (initPacket->msgs.vers_1_msgs.send_send_buf_complete.status
						       != nvsp_status_success) {
		DPRINT_ERR(NETVSC, 
		    "Cannot complete send buffer initialzation with NetVsp - "
		    "status %d", 
		    initPacket->msgs.vers_1_msgs.send_send_buf_complete.status);
		ret = -1;
		goto Cleanup;
	}

	netDevice->send_section_size =
	    initPacket->msgs.vers_1_msgs.send_send_buf_complete.section_size;

	goto Exit;

Cleanup:
	hv_nv_destroy_send_buffer(netDevice);
	
Exit:
	hv_nv_put_net_device(Device);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC destroy receive buffer
 */
static int
hv_nv_destroy_rx_buffer(netvsc_dev *NetDevice)
{
	nvsp_msg *revokePacket;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (NetDevice->rx_section_count) {
		DPRINT_DBG(NETVSC,
		    "Sending nvsp_msg_1_type_revoke_rx_buf...");

		// Send the revoke receive buffer
		revokePacket = &NetDevice->revoke_packet;
		memset(revokePacket, 0, sizeof(nvsp_msg));

		revokePacket->hdr.msg_type =
		    nvsp_msg_1_type_revoke_rx_buf;
		revokePacket->msgs.vers_1_msgs.revoke_rx_buf.id =
		    NETVSC_RECEIVE_BUFFER_ID;

		ret =
		    NetDevice->dev->Driver->VmbusChannelInterface.SendPacket(
		    NetDevice->dev, revokePacket, sizeof(nvsp_msg),
		    (ULONG_PTR)revokePacket, VmbusPacketTypeDataInBand, 0);
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
		
	// Teardown the gpadl on the vsp end
	if (NetDevice->rx_buf_gpadl_handle) {
		DPRINT_INFO(NETVSC, "Tearing down receive buffer's GPADL...");

		ret = NetDevice->dev->Driver->VmbusChannelInterface.TeardownGpadl(
		    NetDevice->dev,
		    NetDevice->rx_buf_gpadl_handle);

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
		NetDevice->rx_buf_gpadl_handle = 0;
	}

	if (NetDevice->rx_buf) {
		DPRINT_INFO(NETVSC, "Freeing up receive buffer...");

		// Free up the receive buffer
		PageFree(NetDevice->rx_buf,
		    NetDevice->rx_buf_size >> PAGE_SHIFT);
		NetDevice->rx_buf = NULL;
	}

	if (NetDevice->rx_sections) {
		free(NetDevice->rx_sections, M_DEVBUF);
		NetDevice->rx_sections = NULL;
		NetDevice->rx_section_count = 0;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC destroy send buffer
 */
static int
hv_nv_destroy_send_buffer(netvsc_dev *NetDevice)
{
	nvsp_msg *revokePacket;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	/*
	 * If we got a section count, it means we received a
	 * send_rx_buf_complete msg 
	 * (ie sent nvsp_msg_1_type_send_rx_buf msg) therefore,
	 * we need to send a revoke msg here
	 */
	if (NetDevice->send_section_size) {
		DPRINT_DBG(NETVSC,
		    "Sending nvsp_msg_1_type_revoke_send_buf...");

		// Send the revoke send buffer
		revokePacket = &NetDevice->revoke_packet;
		memset(revokePacket, 0, sizeof(nvsp_msg));

		revokePacket->hdr.msg_type =
		    nvsp_msg_1_type_revoke_send_buf;
		revokePacket->msgs.vers_1_msgs.revoke_send_buf.id =
		    NETVSC_SEND_BUFFER_ID;

		ret = NetDevice->dev->Driver->VmbusChannelInterface.SendPacket(
		    NetDevice->dev, revokePacket, sizeof(nvsp_msg), 
		    (ULONG_PTR)revokePacket, VmbusPacketTypeDataInBand, 0);
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
	if (NetDevice->send_buf_gpadl_handle) {
		DPRINT_DBG(NETVSC, "Tearing down send buffer's GPADL...");

		ret = NetDevice->dev->Driver->VmbusChannelInterface.TeardownGpadl(
		    NetDevice->dev, NetDevice->send_buf_gpadl_handle);

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
		NetDevice->send_buf_gpadl_handle = 0;
	}

	if (NetDevice->send_buf) {
		DPRINT_DBG(NETVSC, "Freeing up send buffer...");

		// Free up the receive buffer
		PageFree(NetDevice->send_buf,
		    NetDevice->send_buf_size >> PAGE_SHIFT);
		NetDevice->send_buf = NULL;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC connect to VSP
 */
static int
hv_nv_connect_to_vsp(DEVICE_OBJECT *Device)
{
	int ret = 0;
	netvsc_dev *netDevice;
	nvsp_msg *initPacket;
	int ndisVersion;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_outbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return (-1);
	}

	initPacket = &netDevice->channel_init_packet;

	memset(initPacket, 0, sizeof(nvsp_msg));
	initPacket->hdr.msg_type = nvsp_msg_type_init;
	initPacket->msgs.init_msgs.init.min_protocol_version =
	    NVSP_MIN_PROTOCOL_VERSION;
	initPacket->msgs.init_msgs.init.max_protocol_version =
	    NVSP_MAX_PROTOCOL_VERSION;

	DPRINT_DBG(NETVSC, "Sending nvsp_msg_type_init...");

	/* Send the init request */
	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
	    initPacket, sizeof(nvsp_msg), (ULONG_PTR)initPacket,
	    VmbusPacketTypeDataInBand,
	    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to send nvsp_msg_type_init");
		goto Cleanup;
	}

	WaitEventWait(netDevice->channel_init_event);

	/* Now, check the response */
	//ASSERT(initPacket->msgs.init_msgs.init_compl.max_mdl_chain_len <= MAX_MULTIPAGE_BUFFER_COUNT);
	DPRINT_DBG(NETVSC, "nvsp_msg_type_init status(%d) max mdl chain (%d)", 
		initPacket->msgs.init_msgs.init_compl.status,
		initPacket->msgs.init_msgs.init_compl.max_mdl_chain_len);

	if (initPacket->msgs.init_msgs.init_compl.status !=
							  nvsp_status_success) {
		DPRINT_ERR(NETVSC, "Cannot initialize with netvsp "
		    "(status 0x%x)",
		    initPacket->msgs.init_msgs.init_compl.status);
		ret = -1;
		goto Cleanup;
	}

	if (initPacket->msgs.init_msgs.init_compl.negotiated_prot_vers
						  != NVSP_PROTOCOL_VERSION_1) {
		DPRINT_ERR(NETVSC, "Cannot initialize with netvsp "
		    "(version expected 1 got %d)",
		    initPacket->msgs.init_msgs.init_compl.negotiated_prot_vers);
		ret = -1;
		goto Cleanup;
	}
	DPRINT_DBG(NETVSC, "Sending nvsp_msg_1_type_send_ndis_vers...");

	// Send the ndis version
	memset(initPacket, 0, sizeof(nvsp_msg));

	/* Fixme:  Magic number */
	ndisVersion = 0x00050000;

	initPacket->hdr.msg_type = nvsp_msg_1_type_send_ndis_vers;
	initPacket->msgs.vers_1_msgs.send_ndis_vers.ndis_major_vers =
	    (ndisVersion & 0xFFFF0000) >> 16;
	initPacket->msgs.vers_1_msgs.send_ndis_vers.ndis_minor_vers =
	    ndisVersion & 0xFFFF;

	// Send the init request
	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
	    initPacket, sizeof(nvsp_msg), (ULONG_PTR)initPacket,
	    VmbusPacketTypeDataInBand, 0);
	if (ret != 0) {
		DPRINT_ERR(NETVSC,
		    "unable to send nvsp_msg_1_type_send_ndis_vers");
		ret = -1;
		goto Cleanup;
	}
	/*
	 * BUGBUG - We have to wait for the above msg since the netvsp uses
	 * KMCL which acknowledges packet (completion packet) 
	 * since our Vmbus always set the
	 * VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED flag
	 */
	//WaitEventWait(NetVscChannel->channel_init_event);

	// Post the big receive buffer to NetVSP
	ret = hv_nv_init_rx_buffer_with_net_vsp(Device);
	if (ret == 0) {
		ret = hv_nv_init_send_buffer_with_net_vsp(Device);
	}

Cleanup:
	hv_nv_put_net_device(Device);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC disconnect from VSP
 */
static void
hv_nv_disconnect_from_vsp(netvsc_dev *NetDevice)
{
	DPRINT_ENTER(NETVSC);

	hv_nv_destroy_rx_buffer(NetDevice);
	hv_nv_destroy_send_buffer(NetDevice);

	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on device add
 * 
 * Callback when the device belonging to this driver is added
 */
static int
hv_nv_on_device_add(DEVICE_OBJECT *Device, void *AdditionalInfo)
{
	int ret = 0;
	int i;

	netvsc_dev *netDevice;
	netvsc_packet *packet;
	LIST_ENTRY *entry;

	netvsc_driver_object *netDriver =
	    (netvsc_driver_object *)Device->Driver;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_alloc_net_device(Device);
	if (!netDevice) {
		ret = -1;
		goto Cleanup;
	}

	DPRINT_DBG(NETVSC, "netvsc channel object allocated - %p", netDevice);

	/* Initialize the NetVSC channel extension */
	netDevice->rx_buf_size = NETVSC_RECEIVE_BUFFER_SIZE;
	netDevice->rx_packet_list_lock = SpinlockCreate();

	netDevice->send_buf_size = NETVSC_SEND_BUFFER_SIZE;

	INITIALIZE_LIST_HEAD(&netDevice->rx_packet_list);

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

		INSERT_TAIL_LIST(&netDevice->rx_packet_list,
		    &packet->ListEntry);
	}
	netDevice->channel_init_event = WaitEventCreate();

	/* Open the channel */
	ret = Device->Driver->VmbusChannelInterface.Open(Device,
	    netDriver->RingBufferSize, netDriver->RingBufferSize,
	    NULL, 0, hv_nv_on_channel_callback, Device);

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to open channel: %d", ret);
		ret = -1;
		goto Cleanup;
	}

	/* Channel is opened */
	DPRINT_INFO(NETVSC, "*** NetVSC channel opened successfully! ***");

	/* Connect with the NetVsp */
	ret = hv_nv_connect_to_vsp(Device);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "unable to connect to NetVSP - %d", ret);
		ret = -1;
		goto Close;
	}

	DPRINT_INFO(NETVSC, "*** NetVSC channel handshake result - %d ***",
	    ret);

	DPRINT_EXIT(NETVSC);

	return (ret);

Close:
	// Now, we can close the channel safely
	Device->Driver->VmbusChannelInterface.Close(Device);

Cleanup:
	
	if (netDevice) {
		WaitEventClose(netDevice->channel_init_event);

		while (!IsListEmpty(&netDevice->rx_packet_list)) {	
			entry = REMOVE_HEAD_LIST(&netDevice->rx_packet_list);
			packet = CONTAINING_RECORD(entry, netvsc_packet,
			    ListEntry);
			free(packet, M_DEVBUF);
		}

		SpinlockClose(netDevice->rx_packet_list_lock);

		hv_nv_release_outbound_net_device(Device);
		hv_nv_release_inbound_net_device(Device);

		hv_nv_free_net_device(netDevice);
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
hv_nv_on_device_remove(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice;
	netvsc_packet *netvscPacket;
	int ret = 0;
	LIST_ENTRY *entry;

	DPRINT_ENTER(NETVSC);
	
	DPRINT_INFO(NETVSC, "Disabling outbound traffic on net device (%p)...",
		    Device->Extension);
	
	// Stop outbound traffic ie sends and receives completions
	netDevice = hv_nv_release_outbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC, "No net device present!!");

		return (-1);
	}

	// Wait for all send completions
	while (netDevice->num_outstanding_sends) {
		DPRINT_INFO(NETVSC, "waiting for %d requests to complete...",
		    netDevice->num_outstanding_sends);

		Sleep(100);
	}

	DPRINT_DBG(NETVSC, "Disconnecting from netvsp...");

	hv_nv_disconnect_from_vsp(netDevice);

	DPRINT_INFO(NETVSC, "Disabling inbound traffic on net device (%p)...",
	    Device->Extension);

	// Stop inbound traffic ie receives and sends completions
	netDevice = hv_nv_release_inbound_net_device(Device);

	// At this point, no one should be accessing netDevice except in here
	DPRINT_INFO(NETVSC, "net device (%p) safe to remove", netDevice);

	// Now, we can close the channel safely
	Device->Driver->VmbusChannelInterface.Close(Device);

	// Release all resources
	while (!IsListEmpty(&netDevice->rx_packet_list)) {	
		entry = REMOVE_HEAD_LIST(&netDevice->rx_packet_list);
		netvscPacket =
		    CONTAINING_RECORD(entry, netvsc_packet, ListEntry);

		free(netvscPacket, M_DEVBUF);
	}

	SpinlockClose(netDevice->rx_packet_list_lock);
	WaitEventClose(netDevice->channel_init_event);
	hv_nv_free_net_device(netDevice);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * Net VSC on cleanup
 *
 * Perform any cleanup when the driver is removed
 */
static void
hv_nv_on_cleanup(DRIVER_OBJECT *drv)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on send completion
 */
static void 
hv_nv_on_send_completion(DEVICE_OBJECT *Device, VMPACKET_DESCRIPTOR *Packet)
{
	netvsc_dev *netDevice;
	nvsp_msg *nvspPacket;
	netvsc_packet *nvscPacket;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_inbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);

		return;
	}

	nvspPacket = (nvsp_msg *)((ULONG_PTR)Packet +
	    (Packet->DataOffset8 << 3));

	DPRINT_DBG(NETVSC, "send completion packet - type %d",
	    nvspPacket->hdr.msg_type);

	if (nvspPacket->hdr.msg_type == nvsp_msg_type_init_complete ||
	    nvspPacket->hdr.msg_type ==
	      nvsp_msg_1_type_send_rx_buf_complete ||
	    nvspPacket->hdr.msg_type ==
	      nvsp_msg_1_type_send_send_buf_complete) {
		/* Copy the response back */
		memcpy(&netDevice->channel_init_packet,
		    nvspPacket, sizeof(nvsp_msg));			
		WaitEventSet(netDevice->channel_init_event);
	} else if (nvspPacket->hdr.msg_type ==
				    nvsp_msg_1_type_send_rndis_pkt_complete) {
		/* Get the send context */
		nvscPacket = (netvsc_packet *)(ULONG_PTR)Packet->TransactionId;
		ASSERT(nvscPacket);

		/* Notify the layer above us */
		nvscPacket->Completion.Send.OnSendCompletion(
		    nvscPacket->Completion.Send.SendCompletionContext);

		InterlockedDecrement(&netDevice->num_outstanding_sends);
	} else {
		DPRINT_ERR(NETVSC, "Unknown send completion packet type - %d "
		    "received!!", nvspPacket->hdr.msg_type);
	}

	hv_nv_put_net_device(Device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on send
 */
static int
hv_nv_on_send(DEVICE_OBJECT *Device, netvsc_packet *Packet)
{
	netvsc_dev *netDevice;
	int ret = 0;

	nvsp_msg send_msg;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_outbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC, "net device (%p) shutting down... "
		    "ignoring outbound packets", netDevice);
		DPRINT_EXIT(NETVSC);

		return (-2);
	}

	send_msg.hdr.msg_type = nvsp_msg_1_type_send_rndis_pkt;
	if (Packet->IsDataPacket) {
		/* 0 is RMC_DATA */
		send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type =
		    0;
	} else {
		/* 1 is RMC_CONTROL */
		send_msg.msgs.vers_1_msgs.send_rndis_pkt.chan_type =
		    1;
	}

	/* Not using send buffer section */
	send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_idx
	    = 0xFFFFFFFF;
	send_msg.msgs.vers_1_msgs.send_rndis_pkt.send_buf_section_size
	    = 0;

	if (Packet->PageBufferCount) {
		ret =
		    Device->Driver->VmbusChannelInterface.SendPacketPageBuffer(
		    Device, Packet->PageBuffers, Packet->PageBufferCount,
		    &send_msg, sizeof(nvsp_msg), (ULONG_PTR)Packet);
	} else {
		ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
		    &send_msg, sizeof(nvsp_msg), (ULONG_PTR)Packet,
		    VmbusPacketTypeDataInBand,
		    VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0) {
		DPRINT_ERR(NETVSC, "Unable to send packet %p ret %d",
		    Packet, ret);
	}

	InterlockedIncrement(&netDevice->num_outstanding_sends);
	hv_nv_put_net_device(Device);

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
hv_nv_on_receive(DEVICE_OBJECT *Device, VMPACKET_DESCRIPTOR *Packet)
{
	netvsc_dev *netDevice;
	VMTRANSFER_PAGE_PACKET_HEADER *vmxferpagePacket;
	nvsp_msg *nvspPacket;
	netvsc_packet *netvscPacket=NULL;
	LIST_ENTRY* entry;
	ULONG_PTR start;
	XFERPAGE_PACKET *xferpagePacket=NULL;
	LIST_ENTRY listHead;

	int i = 0;
	int count = 0;

	DPRINT_ENTER(NETVSC);

	netDevice = hv_nv_get_inbound_net_device(Device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);

		return;
	}

	/*
	 * All inbound packets other than send completion should be
	 * xfer page packet.
	 */
	if (Packet->Type != VmbusPacketTypeDataUsingTransferPages) {
		DPRINT_ERR(NETVSC, "Unknown packet type received - %d",
		    Packet->Type);
		hv_nv_put_net_device(Device);

		return;
	}

	nvspPacket = (nvsp_msg *)((ULONG_PTR)Packet +
	    (Packet->DataOffset8 << 3));

	// Make sure this is a valid nvsp packet
	if (nvspPacket->hdr.msg_type != nvsp_msg_1_type_send_rndis_pkt) {
		DPRINT_ERR(NETVSC, "Unknown nvsp packet type received - %d",
		    nvspPacket->hdr.msg_type);
		hv_nv_put_net_device(Device);

		return;
	}
	
	DPRINT_DBG(NETVSC, "NVSP packet received - type %d",
	    nvspPacket->hdr.msg_type);

	vmxferpagePacket = (VMTRANSFER_PAGE_PACKET_HEADER *)Packet;

	if (vmxferpagePacket->TransferPageSetId != NETVSC_RECEIVE_BUFFER_ID) {
		DPRINT_ERR(NETVSC, "Invalid xfer page set id - expecting %x "
		    "got %x", NETVSC_RECEIVE_BUFFER_ID,
		    vmxferpagePacket->TransferPageSetId);
		hv_nv_put_net_device(Device);

		return;
	}

	DPRINT_DBG(NETVSC, "xfer page - range count %d",
	    vmxferpagePacket->RangeCount);

	INITIALIZE_LIST_HEAD(&listHead);

	/*
	 * Grab free packets (range count + 1) to represent this xfer page
	 * packet.  +1 to represent the xfer page packet itself.  We grab it
	 * here so that we know exactly how many we can fulfill.
	 */
	SpinlockAcquire(netDevice->rx_packet_list_lock);
	while (!IsListEmpty(&netDevice->rx_packet_list)) {	
		entry = REMOVE_HEAD_LIST(&netDevice->rx_packet_list);
		netvscPacket = CONTAINING_RECORD(entry, netvsc_packet, ListEntry);

		INSERT_TAIL_LIST(&listHead, &netvscPacket->ListEntry);

		if (++count == vmxferpagePacket->RangeCount + 1)
			break;
	}
	SpinlockRelease(netDevice->rx_packet_list_lock);

	/*
	 * We need at least 2 netvsc pkts (1 to represent the xfer page
	 * and at least 1 for the range) i.e. we can handled some of the
	 * xfer page packet ranges...
	 */
	if (count < 2) {
		DPRINT_ERR(NETVSC, "Got only %d netvsc pkt...needed %d pkts. "
		    "Dropping this xfer page packet completely!", count,
		    vmxferpagePacket->RangeCount + 1);

		// Return it to the freelist
		SpinlockAcquire(netDevice->rx_packet_list_lock);
		for (i=count; i != 0; i--) {
			entry = REMOVE_HEAD_LIST(&listHead);
			netvscPacket = CONTAINING_RECORD(entry, netvsc_packet,
			    ListEntry);

			INSERT_TAIL_LIST(&netDevice->rx_packet_list,
			    &netvscPacket->ListEntry);
		}
		SpinlockRelease(netDevice->rx_packet_list_lock);

		hv_nv_send_receive_completion(Device,
		    vmxferpagePacket->d.TransactionId);

		hv_nv_put_net_device(Device);

		return;
	}

	// Remove the 1st packet to represent the xfer page packet itself
	entry = REMOVE_HEAD_LIST(&listHead);
	xferpagePacket = CONTAINING_RECORD(entry, XFERPAGE_PACKET, ListEntry);
	xferpagePacket->Count = count - 1; // This is how much we can satisfy
	ASSERT(xferpagePacket->Count > 0 &&
	    xferpagePacket->Count <= vmxferpagePacket->RangeCount);

	if (xferpagePacket->Count != vmxferpagePacket->RangeCount) {
		DPRINT_DBG(NETVSC, "Needed %d netvsc pkts to satisy this "
		    "xfer page...got %d", vmxferpagePacket->RangeCount,
		    xferpagePacket->Count);
	}

	/* Each range represents 1 RNDIS pkt that contains 1 ethernet frame */
	for (i=0; i < (count - 1); i++) {
		entry = REMOVE_HEAD_LIST(&listHead);
		netvscPacket = CONTAINING_RECORD(entry, netvsc_packet,
		    ListEntry);

		/* Initialize the netvsc packet */
		netvscPacket->XferPagePacket = xferpagePacket;
		netvscPacket->Completion.Recv.OnReceiveCompletion =
		    hv_nv_on_receive_completion;
		netvscPacket->Completion.Recv.ReceiveCompletionContext =
		    netvscPacket;
		netvscPacket->Device = Device;
		/* Save this so that we can send it back */
		netvscPacket->Completion.Recv.ReceiveCompletionTid =
		    vmxferpagePacket->d.TransactionId;

		netvscPacket->TotalDataBufferLength =
		    vmxferpagePacket->Ranges[i].ByteCount;
		netvscPacket->PageBufferCount = 1;

		ASSERT(vmxferpagePacket->Ranges[i].ByteOffset +
		    vmxferpagePacket->Ranges[i].ByteCount <
		    netDevice->rx_buf_size);

		netvscPacket->PageBuffers[0].Length =
		    vmxferpagePacket->Ranges[i].ByteCount;

		/* The virtual address of the packet in the receive buffer */
		start = ((ULONG_PTR)netDevice->rx_buf +
		    vmxferpagePacket->Ranges[i].ByteOffset);
		start = ((unsigned long)start) & ~(PAGE_SIZE - 1);

		/* Page number of the virtual page containing packet start */
		netvscPacket->PageBuffers[0].Pfn = start >> PAGE_SHIFT;


		/* Calculate the page relative offset */
		netvscPacket->PageBuffers[0].Offset =
		    vmxferpagePacket->Ranges[i].ByteOffset & (PAGE_SIZE -1);

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
		    vmxferpagePacket->Ranges[i].ByteOffset,
		    vmxferpagePacket->Ranges[i].ByteCount,
		    netvscPacket->PageBuffers[0].Pfn, 
		    netvscPacket->PageBuffers[0].Offset,
		    netvscPacket->PageBuffers[0].Length);

		/* Pass it to the upper layer */
		((netvsc_driver_object *)Device->Driver)->OnReceiveCallback(Device,
		    netvscPacket);

		/*
		 * The receive completion call has been moved into the
		 * callback function above.
		 */
		// hv_nv_on_receive_completion(netvscPacket->Completion.Recv.ReceiveCompletionContext);
	}

	ASSERT(IsListEmpty(&listHead));
	
	hv_nv_put_net_device(Device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC send receive completion
 */
static void
hv_nv_send_receive_completion(DEVICE_OBJECT *Device, uint64_t TransactionId)
{
	nvsp_msg rx_comp_msg;
	int retries = 0;
	int ret = 0;

	DPRINT_DBG(NETVSC, "Sending receive completion pkt - %llx",
	    TransactionId);
	
	rx_comp_msg.hdr.msg_type =
	    nvsp_msg_1_type_send_rndis_pkt_complete;

	/* Fixme:  Pass in the status */
	rx_comp_msg.msgs.vers_1_msgs.send_rndis_pkt_complete.status =
	    nvsp_status_success;

retry_send_cmplt:
	/* Send the completion */
	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
	    &rx_comp_msg, sizeof(nvsp_msg), TransactionId,
	    VmbusPacketTypeCompletion, 0);
	if (ret == 0) {
		/* success */
		/* no-op */
	} else if (ret == -1) {
		/* no more room...wait a bit and attempt to retry 3 times */
		retries++;
		DPRINT_ERR(NETVSC, "unable to send receive completion pkt"
		    "(tid %llx)...retrying %d", TransactionId, retries);

		if (retries < 4) {
			Sleep(100);
			goto retry_send_cmplt;
		} else {
			DPRINT_ERR(NETVSC, "unable to send receive completion "
			    "pkt (tid %llx)...give up retrying", TransactionId);
		}
	} else {
		DPRINT_ERR(NETVSC,
		    "unable to send receive completion pkt - %llx",
		    TransactionId);
	}
}

/*
 * Net VSC on receive completion
 *
 * Send a receive completion packet to RNDIS device (ie NetVsp)
 */
void
hv_nv_on_receive_completion(void *Context)
{
	netvsc_packet *packet = (netvsc_packet *)Context;
	DEVICE_OBJECT *device = (DEVICE_OBJECT *)packet->Device;
	netvsc_dev *netDevice;
	uint64_t       transactionId = 0;
	BOOL fSendReceiveComp = FALSE;

	DPRINT_ENTER(NETVSC);

	ASSERT(packet->XferPagePacket);

	/*
	 * Even though it seems logical to do a hv_nv_get_outbound_net_device()
	 * here to send out receive completion, we are using
	 * hv_nv_get_inbound_net_device() since we may have disabled
	 * outbound traffic already.
	 */
	netDevice = hv_nv_get_inbound_net_device(device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC,
		    "unable to get net device...device being destroyed?");
		DPRINT_EXIT(NETVSC);
		return;
	}
	
	/* Overloading use of the lock. */
	SpinlockAcquire(netDevice->rx_packet_list_lock);

// 	ASSERT(packet->XferPagePacket->Count > 0);
	if (packet->XferPagePacket->Count == 0) {
		hv_nv_put_net_device(device);
		DPRINT_EXIT(NETVSC);
	}

	packet->XferPagePacket->Count--;

	/* Last one in the line that represent 1 xfer page packet. */
	/* Return the xfer page packet itself to the freelist */
	if (packet->XferPagePacket->Count == 0) {
		fSendReceiveComp = TRUE;
		transactionId = packet->Completion.Recv.ReceiveCompletionTid;

		INSERT_TAIL_LIST(&netDevice->rx_packet_list,
		    &packet->XferPagePacket->ListEntry);
	}

	/* Put the packet back */
	INSERT_TAIL_LIST(&netDevice->rx_packet_list, &packet->ListEntry);
	SpinlockRelease(netDevice->rx_packet_list_lock);

	/* Send a receive completion for the xfer page packet */
	if (fSendReceiveComp) {
		hv_nv_send_receive_completion(device, transactionId);
	}

	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

/*
 * Net VSC on channel callback
 */
static void
hv_nv_on_channel_callback(void *Context)
{
	const int netPacketSize = 2048;
	int ret = 0;
	DEVICE_OBJECT *device = (DEVICE_OBJECT *)Context;
	netvsc_dev *netDevice;

	uint32_t bytesRecvd;
	uint64_t requestId;
	uint8_t  packet[netPacketSize];
	VMPACKET_DESCRIPTOR *desc;
	uint8_t *buffer = packet;
	int	bufferlen = netPacketSize;

	DPRINT_ENTER(NETVSC);

	ASSERT(device);

	netDevice = hv_nv_get_inbound_net_device(device);
	if (!netDevice) {
		DPRINT_ERR(NETVSC, "net device (%p) shutting down...ignoring"
		   " inbound packets", netDevice);
		DPRINT_EXIT(NETVSC);

		return;
	}

	do {
		ret = device->Driver->VmbusChannelInterface.RecvPacketRaw(
		    device, buffer, bufferlen, &bytesRecvd, &requestId);

		if (ret == 0) {
			if (bytesRecvd > 0) {
				DPRINT_DBG(NETVSC, "receive %d bytes, tid %llx",
				    bytesRecvd, requestId);
			 
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
					   desc->Type, requestId, bytesRecvd);
					break;
				}

				/* reset */
				if (bufferlen > netPacketSize) {
					free(buffer, M_DEVBUF);
									
					buffer = packet;
					bufferlen = netPacketSize;
				}
			} else {
				//DPRINT_DBG(NETVSC, "nothing else to read...");
				
				// reset
				if (bufferlen > netPacketSize) {
					free(buffer, M_DEVBUF);
									
					buffer = packet;
					bufferlen = netPacketSize;
				}

				break;
			}
		} else if (ret == -2) {
			/* Handle large packet */
			buffer = malloc(bytesRecvd, M_DEVBUF, M_NOWAIT);
			if (buffer == NULL) {
				/* Try again next time around */
				DPRINT_ERR(NETVSC, "unable to allocate buffer"
				     " of size (%d)!!", bytesRecvd);
				break;
			}

			bufferlen = bytesRecvd;
		} else {
			ASSERT(0);
		}
	} while (1);

	hv_nv_put_net_device(device);
	DPRINT_EXIT(NETVSC);
}

