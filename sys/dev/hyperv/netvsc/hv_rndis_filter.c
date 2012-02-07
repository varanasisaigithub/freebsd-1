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
 * HyperV RNDIS filter code
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
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <net/if_arp.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include <dev/hyperv/include/hv_list.h>
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/include/hv_nvsp_protocol.h>
#include <dev/hyperv/vmbus/hv_vmbus_var.h>
#include <dev/hyperv/include/hv_net_vsc_api.h>
#include <dev/hyperv/include/hv_net_vsc.h>
#include <dev/hyperv/include/hv_rndis_filter.h>
#include <dev/hyperv/include/hv_rndis.h>


/*
 * Data types
 */

typedef struct rndis_filter_driver_object_ {
	/* The original driver */
	netvsc_driver_object		InnerDriver;
} rndis_filter_driver_object;

typedef enum {
	RNDIS_DEV_UNINITIALIZED = 0,
	RNDIS_DEV_INITIALIZING,
	RNDIS_DEV_INITIALIZED,
	RNDIS_DEV_DATAINITIALIZED,
} rndis_device_state;

typedef struct rndis_device_ {
	netvsc_dev			*NetDevice;

	rndis_device_state		State;
	uint32_t			LinkStatus;
	uint32_t			NewRequestId;

	void				*RequestLock;
	LIST_ENTRY			RequestList;

	uint8_t				HwMacAddr[HW_MACADDR_LEN];
} rndis_device;


typedef struct rndis_request_ {
	LIST_ENTRY			ListEntry;
	void				*WaitEvent;	

	/*
	 * Fixme:  We assumed a fixed size response here.  If we do ever
	 * need to handle a bigger response, we can either define a max
	 * response message or add a response buffer variable above this field
	 */
	rndis_msg			ResponseMessage;

	/* Simplify allocation by having a netvsc packet inline */
	netvsc_packet			Packet;
	PAGE_BUFFER			Buffer;
	/* Fixme:  We assumed a fixed size request here. */
	rndis_msg			RequestMessage;
} rndis_request;


/* Fixme:  not used */
typedef struct rndis_filter_packet_ {
	void				*CompletionContext;
	PFN_ON_SENDRECVCOMPLETION	OnCompletion;

	rndis_msg			Message;
} rndis_filter_packet;

/*
 * Forward declarations
 */
static int  hv_rf_send_request(rndis_device *Device,
				   rndis_request *Request);
static void hv_rf_receive_response(rndis_device *Device,
				       rndis_msg *Response);
static void hv_rf_receive_indicate_status(rndis_device *Device,
					     rndis_msg *Response);
// Fixme
extern void hv_rf_receive_data(rndis_device *Device, rndis_msg *Message,
//static void hv_rf_receive_data(rndis_device *Device, rndis_msg *Message,
				   netvsc_packet *Packet);
static int  hv_rf_on_receive(DEVICE_OBJECT *Device, netvsc_packet *Packet);
static int  hv_rf_query_device(rndis_device *Device, uint32_t Oid,
				   VOID *Result, uint32_t *ResultSize);
static inline int hv_rf_query_device_mac(rndis_device *Device);
static inline int hv_rf_query_device_link_status(rndis_device *Device);
static int  hv_rf_set_packet_filter(rndis_device *Device, uint32_t NewFilter);
static int  hv_rf_init_device(rndis_device *Device);
static int  hv_rf_open_device(rndis_device *Device);
static int  hv_rf_close_device(rndis_device *Device);
static int  hv_rf_on_device_add(DEVICE_OBJECT *Device, void *AdditionalInfo);
static int  hv_rf_on_device_remove(DEVICE_OBJECT *Device);
static void hv_rf_on_cleanup(DRIVER_OBJECT *Driver);
static int  hv_rf_on_open(DEVICE_OBJECT *Device);
static int  hv_rf_on_close(DEVICE_OBJECT *Device);
static int  hv_rf_on_send(DEVICE_OBJECT *Device, netvsc_packet *Packet);
static void hv_rf_on_send_completion(void *Context);
static void hv_rf_on_send_request_completion(void *Context);

/*
 * Global variables
 */

/* The one and only */
rndis_filter_driver_object gRndisFilter;

/*
 * Allow module_param to work and override to switch to promiscuous mode.
 */
static inline rndis_device *
hv_get_rndis_device(void)
{
	rndis_device *device;

	device = malloc(sizeof(rndis_device), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!device) {
		return (NULL);
	}

	device->RequestLock = SpinlockCreate();
	if (!device->RequestLock) {
		free(device, M_DEVBUF);

		return (NULL);
	}

	INITIALIZE_LIST_HEAD(&device->RequestList);

	device->State = RNDIS_DEV_UNINITIALIZED;

	return (device);
}

/*
 *
 */
static inline void
hv_put_rndis_device(rndis_device *Device)
{
	SpinlockClose(Device->RequestLock);
	free(Device, M_DEVBUF);
}

/*
 *
 */
static inline rndis_request *
hv_rndis_request(rndis_device *Device, uint32_t MessageType,
		 uint32_t MessageLength)
{
	rndis_request *request;
	rndis_msg *rndisMessage;
	rndis_set_request *set;

	request = malloc(sizeof(rndis_request), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!request) {
		return (NULL);
	}

	request->WaitEvent = WaitEventCreate();
	if (!request->WaitEvent) {
		free(request, M_DEVBUF);

		return (NULL);
	}
	
	rndisMessage = &request->RequestMessage;
	rndisMessage->ndis_msg_type = MessageType;
	rndisMessage->msg_len = MessageLength;

	/*
	 * Set the request id. This field is always after the rndis header
	 * for request/response packet types so we just use the SetRequest
	 * as a template.
	 */
	set = &rndisMessage->msg.SetRequest;
	set->RequestId = InterlockedIncrement((int *)&Device->NewRequestId);

	/* Add to the request list */
	SpinlockAcquire(Device->RequestLock);
	INSERT_TAIL_LIST(&Device->RequestList, &request->ListEntry);
	SpinlockRelease(Device->RequestLock);

	return (request);
}

/*
 *
 */
static inline void
hv_put_rndis_request(rndis_device *Device, rndis_request *Request)
{
	SpinlockAcquire(Device->RequestLock);
	REMOVE_ENTRY_LIST(&Request->ListEntry);
	SpinlockRelease(Device->RequestLock);

	WaitEventClose(Request->WaitEvent);
	free(Request, M_DEVBUF);
}

/*
 *
 */
static inline void
hv_dump_rndis_message(rndis_msg *rndis_msg)
{
	switch (rndis_msg->ndis_msg_type) {
	case REMOTE_NDIS_PACKET_MSG:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_PACKET_MSG (len %u, data "
		    "offset %u data len %u, # oob %u, oob offset %u, oob "
		    "len %u, pkt offset %u, pkt len %u", 
		    rndis_msg->msg_len,
		    rndis_msg->msg.Packet.DataOffset,
		    rndis_msg->msg.Packet.DataLength,
		    rndis_msg->msg.Packet.NumOOBDataElements,
		    rndis_msg->msg.Packet.OOBDataOffset,
		    rndis_msg->msg.Packet.OOBDataLength,
		    rndis_msg->msg.Packet.PerPacketInfoOffset,
		    rndis_msg->msg.Packet.PerPacketInfoLength);
		break;

	case REMOTE_NDIS_INITIALIZE_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_INITIALIZE_CMPLT (len %u, "
		    "id 0x%x, status 0x%x, major %d, minor %d, device flags "
		    "%d, max xfer size 0x%x, max pkts %u, pkt aligned %u)", 
		    rndis_msg->msg_len,
		    rndis_msg->msg.InitializeComplete.RequestId,
		    rndis_msg->msg.InitializeComplete.Status,
		    rndis_msg->msg.InitializeComplete.MajorVersion,
		    rndis_msg->msg.InitializeComplete.MinorVersion,
		    rndis_msg->msg.InitializeComplete.DeviceFlags,
		    rndis_msg->msg.InitializeComplete.MaxTransferSize,
		    rndis_msg->msg.InitializeComplete.MaxPacketsPerMessage,
		    rndis_msg->msg.InitializeComplete.PacketAlignmentFactor);
		break;

	case REMOTE_NDIS_QUERY_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_QUERY_CMPLT (len %u, id 0x%x, "
		    "status 0x%x, buf len %u, buf offset %u)", 
		    rndis_msg->msg_len,
		    rndis_msg->msg.QueryComplete.RequestId,
		    rndis_msg->msg.QueryComplete.Status,
		    rndis_msg->msg.QueryComplete.InformationBufferLength,
		    rndis_msg->msg.QueryComplete.InformationBufferOffset);
		break;

	case REMOTE_NDIS_SET_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_SET_CMPLT (len %u, id 0x%x, "
		    "status 0x%x)", 
		    rndis_msg->msg_len,
		    rndis_msg->msg.SetComplete.RequestId,
		    rndis_msg->msg.SetComplete.Status);
		break;

	case REMOTE_NDIS_INDICATE_STATUS_MSG:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_INDICATE_STATUS_MSG (len %u, "
		    "status 0x%x, buf len %u, buf offset %u)", 
		    rndis_msg->msg_len,
		    rndis_msg->msg.IndicateStatus.Status,
		    rndis_msg->msg.IndicateStatus.StatusBufferLength,
		    rndis_msg->msg.IndicateStatus.StatusBufferOffset);
		break;

	default:
		DPRINT_DBG(NETVSC, "0x%x (len %u)",
		    rndis_msg->ndis_msg_type,
		    rndis_msg->msg_len);
		break;
	}
}

/*
 *
 */
static int
hv_rf_send_request(rndis_device *Device, rndis_request *Request)
{
	int ret = 0;
	netvsc_packet *packet;
	
	DPRINT_ENTER(NETVSC);

	/* Set up the packet to send it */
	packet = &Request->Packet;
	
	packet->IsDataPacket = FALSE;
	packet->TotalDataBufferLength = Request->RequestMessage.msg_len;
	packet->PageBufferCount = 1;

	packet->PageBuffers[0].Pfn =
	    GetPhysicalAddress(&Request->RequestMessage) >> PAGE_SHIFT;
	packet->PageBuffers[0].Length = Request->RequestMessage.msg_len;
	packet->PageBuffers[0].Offset =
	    (ULONG_PTR)&Request->RequestMessage & (PAGE_SIZE - 1);

	packet->Completion.Send.SendCompletionContext = Request; //packet;
	packet->Completion.Send.OnSendCompletion =
	    hv_rf_on_send_request_completion;
	packet->Completion.Send.SendCompletionTid = (ULONG_PTR)Device;

	ret = gRndisFilter.InnerDriver.OnSend(Device->NetDevice->dev,
	    packet);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter receive response
 */
static void 
hv_rf_receive_response(rndis_device *Device, rndis_msg *Response)
{
	LIST_ENTRY *anchor;
	LIST_ENTRY *curr;
	rndis_request *request = NULL;
	BOOL found = FALSE;

	DPRINT_ENTER(NETVSC);

	SpinlockAcquire(Device->RequestLock);
	ITERATE_LIST_ENTRIES(anchor, curr, &Device->RequestList) {		
		request = CONTAINING_RECORD(curr, rndis_request, ListEntry);

		/*
		 * All request/response message contains RequestId as the
		 * first field
		 */
		if (request->RequestMessage.msg.InitializeRequest.RequestId
			   == Response->msg.InitializeComplete.RequestId) {
			DPRINT_DBG(NETVSC, "found rndis request for this "
			    "response (id 0x%x req type 0x%x res type 0x%x)", 
			    request->RequestMessage.msg.InitializeRequest.RequestId,
			    request->RequestMessage.ndis_msg_type,
			    Response->ndis_msg_type);

			found = TRUE;
			break;
		}
	}
	SpinlockRelease(Device->RequestLock);

	if (found) {
		if (Response->msg_len <= sizeof(rndis_msg)) {
			memcpy(&request->ResponseMessage, Response,
			    Response->msg_len);
		} else {
			DPRINT_ERR(NETVSC, "rndis response buffer overflow "
			    "detected (size %u max %u)",
			    Response->msg_len,
			    sizeof(rndis_filter_packet));

			if (Response->ndis_msg_type == REMOTE_NDIS_RESET_CMPLT) {
				// does not have a request id field
				request->ResponseMessage.msg.ResetComplete.Status =
				    STATUS_BUFFER_OVERFLOW;
			} else {
				request->ResponseMessage.msg.InitializeComplete.Status =
				    STATUS_BUFFER_OVERFLOW;
			}
		}

		WaitEventSet(request->WaitEvent);
	} else {
		DPRINT_ERR(NETVSC, "no rndis request found for this response "
		    "(id 0x%x res type 0x%x)", 
		    Response->msg.InitializeComplete.RequestId,
		    Response->ndis_msg_type);
	}

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter receive indicate status
 */
static void 
hv_rf_receive_indicate_status(rndis_device *Device, rndis_msg *Response)
{
	rndis_indicate_status *indicate = &Response->msg.IndicateStatus;
		
	if (indicate->Status == RNDIS_STATUS_MEDIA_CONNECT) {
		gRndisFilter.InnerDriver.OnLinkStatusChanged(
		    Device->NetDevice->dev, 1);
	}
	else if (indicate->Status == RNDIS_STATUS_MEDIA_DISCONNECT) {
		gRndisFilter.InnerDriver.OnLinkStatusChanged(
		    Device->NetDevice->dev, 0);
	} else {
		// TODO:
	}
}

/*
 * RNDIS filter receive data
 */
// Fixme:  Hacked to make function name visible to debugger
//static void
void
hv_rf_receive_data(rndis_device *Device, rndis_msg *Message,
		       netvsc_packet *Packet)
{
	rndis_packet *rndisPacket;
	uint32_t dataOffset;

	DPRINT_ENTER(NETVSC);

	/* Empty Ethernet frame ?? */
	ASSERT(
	    Packet->PageBuffers[0].Length > RNDIS_MESSAGE_SIZE(rndis_packet));

	rndisPacket = &Message->msg.Packet;

	/*
	 * Fixme:  Handle multiple rndis pkt msgs that may be enclosed in this
	 * netvsc packet (ie TotalDataBufferLength != MessageLength)
	 */

	/* Remove the rndis header and pass it back up the stack */
	dataOffset = RNDIS_HEADER_SIZE + rndisPacket->DataOffset;
		
	Packet->TotalDataBufferLength -= dataOffset;
	Packet->PageBuffers[0].Offset += dataOffset;
	Packet->PageBuffers[0].Length -= dataOffset;

	Packet->IsDataPacket = TRUE;
		
	gRndisFilter.InnerDriver.OnReceiveCallback(Device->NetDevice->dev,
	    Packet);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on receive
 */
static int
hv_rf_on_receive(DEVICE_OBJECT *Device, netvsc_packet *Packet)
{
	netvsc_dev *netDevice = (netvsc_dev *)Device->Extension;
	rndis_device *rndisDevice;
	rndis_msg rndisMessage;
	rndis_msg *rndisHeader;

	DPRINT_ENTER(NETVSC);

	ASSERT(netDevice);

	/* Make sure the rndis device state is initialized */
	if (!netDevice->extension) {
		DPRINT_ERR(NETVSC, "got rndis message but no rndis device... "
		    "dropping this message!");
		DPRINT_EXIT(NETVSC);

		return (-1);
	}

	rndisDevice = (rndis_device *)netDevice->extension;
	if (rndisDevice->State == RNDIS_DEV_UNINITIALIZED) {
		DPRINT_ERR(NETVSC, "got rndis message but rndis device "
		    "uninitialized... dropping this message!");
		DPRINT_EXIT(NETVSC);

		return (-1);
	}

	rndisHeader = (rndis_msg *)PageMapVirtualAddress(
	    Packet->PageBuffers[0].Pfn);

	rndisHeader = (void *)((ULONG_PTR)rndisHeader +
	    Packet->PageBuffers[0].Offset);
	
	/*
	 * Make sure we got a valid rndis message
	 * Fixme:  There seems to be a bug in set completion msg where
	 * its msg_len is 16 bytes but the ByteCount field in the
	 * xfer page range shows 52 bytes
	 */
#if 0
	if (Packet->TotalDataBufferLength != rndisHeader->msg_len) {
		PageUnmapVirtualAddress((void *)(ULONG_PTR)rndisHeader -
		    Packet->PageBuffers[0].Offset);

		DPRINT_ERR(NETVSC, "invalid rndis message? (expected %u "
		    "bytes got %u)... dropping this message!",
		    rndisHeader->msg_len, Packet->TotalDataBufferLength);
		DPRINT_EXIT(NETVSC);

		return (-1);
	}
#endif

	if ((rndisHeader->ndis_msg_type != REMOTE_NDIS_PACKET_MSG) &&
		     (rndisHeader->msg_len > sizeof(rndis_msg))) {
		DPRINT_ERR(NETVSC, "incoming rndis message buffer overflow "
		    "detected (got %u, max %u)...marking it an error!",
		    rndisHeader->msg_len, sizeof(rndis_msg));
	}

	memcpy(&rndisMessage, rndisHeader,
	    (rndisHeader->msg_len > sizeof(rndis_msg)) ?
	    sizeof(rndis_msg) : rndisHeader->msg_len);

	PageUnmapVirtualAddress((void *)((ULONG_PTR)rndisHeader -
	    Packet->PageBuffers[0].Offset));

	hv_dump_rndis_message(&rndisMessage);

	switch (rndisMessage.ndis_msg_type) {

	/* data message */
	case REMOTE_NDIS_PACKET_MSG:
		hv_rf_receive_data(rndisDevice, &rndisMessage, Packet);
		break;

	/* completion messages */
	case REMOTE_NDIS_INITIALIZE_CMPLT:
	case REMOTE_NDIS_QUERY_CMPLT:
	case REMOTE_NDIS_SET_CMPLT:
	//case REMOTE_NDIS_RESET_CMPLT:
	//case REMOTE_NDIS_KEEPALIVE_CMPLT:
		hv_rf_receive_response(rndisDevice, &rndisMessage);
		break;

	/* notification message */
	case REMOTE_NDIS_INDICATE_STATUS_MSG:
		hv_rf_receive_indicate_status(rndisDevice, &rndisMessage);
		break;
	default:
		DPRINT_ERR(NETVSC, "unhandled rndis message (type %u len %u)",
		    rndisMessage.ndis_msg_type, rndisMessage.msg_len);
		break;
	}

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter query device
 */
static int
hv_rf_query_device(rndis_device *Device, uint32_t Oid, VOID *Result,
		       uint32_t *ResultSize)
{
	rndis_request *request;
	uint32_t inresultSize = *ResultSize;
	rndis_query_request *query;
	rndis_query_complete *queryComplete;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	ASSERT(Result);

	*ResultSize = 0;
	request = hv_rndis_request(Device, REMOTE_NDIS_QUERY_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_query_request));
	if (!request) {
		ret = -1;
		goto Cleanup;
	}

	/* Set up the rndis query */
	query = &request->RequestMessage.msg.QueryRequest;
	query->Oid = Oid;
	query->InformationBufferOffset = sizeof(rndis_query_request); 
	query->InformationBufferLength = 0;
	query->DeviceVcHandle = 0;

	ret = hv_rf_send_request(Device, request);
	if (ret != 0) {
		/* Fixme:  printf added */
		printf("RNDISFILTER request failed to Send!\n");
		goto Cleanup;
	}

	WaitEventWait(request->WaitEvent);

	/* Copy the response back */
	queryComplete = &request->ResponseMessage.msg.QueryComplete;
	
	if (queryComplete->InformationBufferLength > inresultSize) {
		ret = -1;
		goto Cleanup;
	}

	memcpy(Result, 
	    (void *)((ULONG_PTR)queryComplete +
	    queryComplete->InformationBufferOffset),
	    queryComplete->InformationBufferLength);

	*ResultSize = queryComplete->InformationBufferLength;

Cleanup:
	if (request) {
		hv_put_rndis_request(Device, request);
	}
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter query device MAC address
 */
static inline int
hv_rf_query_device_mac(rndis_device *Device)
{
	uint32_t size = HW_MACADDR_LEN;

	return (hv_rf_query_device(Device,
	    RNDIS_OID_802_3_PERMANENT_ADDRESS, Device->HwMacAddr, &size));
}

/*
 * RNDIS filter query device link status
 */
static inline int
hv_rf_query_device_link_status(rndis_device *Device)
{
	uint32_t size = sizeof(uint32_t);

	return (hv_rf_query_device(Device,
	    RNDIS_OID_GEN_MEDIA_CONNECT_STATUS, &Device->LinkStatus, &size));
}

/*
 * RNDIS filter set packet filter
 */
static int
hv_rf_set_packet_filter(rndis_device *Device, uint32_t NewFilter)
{
	rndis_request *request;
	rndis_set_request *set;
	rndis_set_complete *setComplete;
	uint32_t status;
	int ret;

	DPRINT_ENTER(NETVSC);

	ASSERT(RNDIS_MESSAGE_SIZE(rndis_set_request) + sizeof(uint32_t) <=
	    sizeof(rndis_msg));

	request = hv_rndis_request(Device, REMOTE_NDIS_SET_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_set_request) + sizeof(uint32_t));
	if (!request) {
		ret = -1;
		goto Cleanup;
	}

	/* Set up the rndis set */
	set = &request->RequestMessage.msg.SetRequest;
	set->Oid = RNDIS_OID_GEN_CURRENT_PACKET_FILTER;
	set->InformationBufferLength = sizeof(uint32_t);
	set->InformationBufferOffset = sizeof(rndis_set_request); 

	memcpy((void *)((ULONG_PTR)set + sizeof(rndis_set_request)),
	    &NewFilter, sizeof(uint32_t));

	ret = hv_rf_send_request(Device, request);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "RNDISFILTER request failed to send!  "
		    "ret %d", ret);
		goto Cleanup;
	}

	/* Fixme:  second parameter is 2000 in the lis21 code drop */
	ret = WaitEventWaitEx(request->WaitEvent, 4000/*2sec*/);
	if (!ret) {
		ret = -1;
		DPRINT_ERR(NETVSC, "timeout before we got a set response... "
		    "cmd %d ", NewFilter);
		/*
		 * We cannot deallocate the request since we may still
		 * receive a send completion for it.
		 */
		goto Exit;
	} else {
		if (ret > 0) {
			ret = 0;
		}
		setComplete = &request->ResponseMessage.msg.SetComplete;
		status = setComplete->Status;
	}

Cleanup:
	if (request) {
		hv_put_rndis_request(Device, request);
	}
Exit:
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter init
 */
int
hv_rndis_filter_init(netvsc_driver_object *Driver)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_DBG(NETVSC, "sizeof(rndis_filter_packet) == %d",
	    sizeof(rndis_filter_packet));

	Driver->RequestExtSize = sizeof(rndis_filter_packet);
	Driver->AdditionalRequestPageBufferCount = 1; // For rndis header

	//Driver->Context = rndisDriver;

	memset(&gRndisFilter, 0, sizeof(rndis_filter_driver_object));

#ifdef REMOVED
	/* Fixme:  Don't know why this code was commented out */
	rndisDriver->Driver = Driver;

	ASSERT(Driver->OnLinkStatusChanged);
	rndisDriver->OnLinkStatusChanged = Driver->OnLinkStatusChanged;
#endif

	/* Save the original dispatch handlers before we override it */
	gRndisFilter.InnerDriver.Base.OnDeviceAdd = Driver->Base.OnDeviceAdd;
	gRndisFilter.InnerDriver.Base.OnDeviceRemove =
	    Driver->Base.OnDeviceRemove;
	gRndisFilter.InnerDriver.Base.OnCleanup = Driver->Base.OnCleanup;

	ASSERT(Driver->OnSend);
	ASSERT(Driver->OnReceiveCallback);
	gRndisFilter.InnerDriver.OnSend = Driver->OnSend;
	gRndisFilter.InnerDriver.OnReceiveCallback = Driver->OnReceiveCallback;
	gRndisFilter.InnerDriver.OnLinkStatusChanged =
	    Driver->OnLinkStatusChanged;

	/* Override */
	Driver->Base.OnDeviceAdd = hv_rf_on_device_add;
	Driver->Base.OnDeviceRemove = hv_rf_on_device_remove;
	Driver->Base.OnCleanup = hv_rf_on_cleanup;

	Driver->OnSend = hv_rf_on_send;
	Driver->OnOpen = hv_rf_on_open;
	Driver->OnClose = hv_rf_on_close;
	//Driver->QueryLinkStatus = hv_rf_query_device_link_status;
	Driver->OnReceiveCallback = hv_rf_on_receive;

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter init device
 */
static int
hv_rf_init_device(rndis_device *Device)
{
	rndis_request *request;
	rndis_initialize_request *init;
	rndis_initialize_complete *initComplete;
	uint32_t status;
	int ret;

	DPRINT_ENTER(NETVSC);

	request = hv_rndis_request(Device, REMOTE_NDIS_INITIALIZE_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_initialize_request));
	if (!request) {
		ret = -1;
		goto Cleanup;
	}

	/* Set up the rndis set */
	init = &request->RequestMessage.msg.InitializeRequest;
	init->MajorVersion = RNDIS_MAJOR_VERSION;
	init->MinorVersion = RNDIS_MINOR_VERSION;
	/* Fixme:  Use 1536 - rounded ethernet frame size */
	init->MaxTransferSize = 2048;
	
	Device->State = RNDIS_DEV_INITIALIZING;

	ret = hv_rf_send_request(Device, request);
	if (ret != 0) {
		Device->State = RNDIS_DEV_UNINITIALIZED;
		goto Cleanup;
	}

	WaitEventWait(request->WaitEvent);

	initComplete = &request->ResponseMessage.msg.InitializeComplete;
	status = initComplete->Status;
	if (status == RNDIS_STATUS_SUCCESS) {
		Device->State = RNDIS_DEV_INITIALIZED;
		ret = 0;
	} else {
		Device->State = RNDIS_DEV_UNINITIALIZED; 
		ret = -1;
	}

Cleanup:
	if (request) {
		hv_put_rndis_request(Device, request);
	}
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter halt device
 */
static void
hv_rf_halt_device(rndis_device *Device)
{
	rndis_request *request;
	rndis_halt_request *halt;

	DPRINT_ENTER(NETVSC);

	/* Attempt to do a rndis device halt */
	request = hv_rndis_request(Device, REMOTE_NDIS_HALT_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_halt_request));
	if (!request) {
		goto Cleanup;
	}

	/* Set up the rndis set */
	halt = &request->RequestMessage.msg.HaltRequest;
	halt->RequestId = InterlockedIncrement((int *)&Device->NewRequestId);
	
	/* Ignore return since this msg is optional. */
	hv_rf_send_request(Device, request);
	
	Device->State = RNDIS_DEV_UNINITIALIZED;

Cleanup:
	if (request) {
		hv_put_rndis_request(Device, request);
	}
	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter open device
 */
static int
hv_rf_open_device(rndis_device *Device)
{
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	if (Device->State != RNDIS_DEV_INITIALIZED) {
		return (0);
	}

	if (promisc_mode != 1) {
		ret = hv_rf_set_packet_filter(Device, 
		    NDIS_PACKET_TYPE_BROADCAST     |
		    NDIS_PACKET_TYPE_ALL_MULTICAST |
		    NDIS_PACKET_TYPE_DIRECTED);
		DPRINT_INFO(NETVSC, "Network set to normal mode");
	} else {
		ret = hv_rf_set_packet_filter(Device, 
		    NDIS_PACKET_TYPE_PROMISCUOUS);
		DPRINT_INFO(NETVSC, "Network set to promiscuous mode");
	}

	if (ret == 0) {
		Device->State = RNDIS_DEV_DATAINITIALIZED;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter close device
 */
static int
hv_rf_close_device(rndis_device *Device)
{
	int ret;

	DPRINT_ENTER(NETVSC);

	if (Device->State != RNDIS_DEV_DATAINITIALIZED) {
		return (0);
	}

	ret = hv_rf_set_packet_filter(Device, 0);
	if (ret == 0) {
		Device->State = RNDIS_DEV_INITIALIZED;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on device add
 */
static int
hv_rf_on_device_add(DEVICE_OBJECT *Device, void *AdditionalInfo)
{
	int ret;
	netvsc_dev *netDevice;
	rndis_device *rndisDevice;
	netvsc_device_info *deviceInfo = (netvsc_device_info *)AdditionalInfo;

	DPRINT_ENTER(NETVSC);

	rndisDevice = hv_get_rndis_device();
	if (!rndisDevice) {
		DPRINT_EXIT(NETVSC);
		return (-1);
	}

	DPRINT_DBG(NETVSC, "rndis device object allocated - %p", rndisDevice);

	/*
	 * Let the inner driver handle this first to create the netvsc channel
	 * NOTE! Once the channel is created, we may get a receive callback 
	 * (hv_rf_on_receive()) before this call is completed
	 */
	ret = gRndisFilter.InnerDriver.Base.OnDeviceAdd(Device, AdditionalInfo);
	if (ret != 0) {
		hv_put_rndis_device(rndisDevice);
		DPRINT_EXIT(NETVSC);
		return (ret);
	}

	/*
	 * Initialize the rndis device
	 */
	netDevice = (netvsc_dev *)Device->Extension;
	ASSERT(netDevice);
	ASSERT(netDevice->dev);

	netDevice->extension = rndisDevice;
	rndisDevice->NetDevice = netDevice;

	/* Send the rndis initialization message */
	ret = hv_rf_init_device(rndisDevice);
	if (ret != 0) {
		/*
		 * TODO: If rndis init failed, we will need to shut down
		 * the channel
		 */
	}

	/* Get the mac address */
	ret = hv_rf_query_device_mac(rndisDevice);
	if (ret != 0) {
		/* TODO: shutdown rndis device and the channel */
	}
	
	DPRINT_INFO(NETVSC, "Device 0x%p mac addr %02x%02x%02x%02x%02x%02x",
	    rndisDevice, rndisDevice->HwMacAddr[0], rndisDevice->HwMacAddr[1],
	    rndisDevice->HwMacAddr[2], rndisDevice->HwMacAddr[3],
	    rndisDevice->HwMacAddr[4], rndisDevice->HwMacAddr[5]);

	memcpy(deviceInfo->MacAddr, rndisDevice->HwMacAddr, HW_MACADDR_LEN);

	hv_rf_query_device_link_status(rndisDevice);
	
	deviceInfo->LinkState = rndisDevice->LinkStatus;
	DPRINT_INFO(NETVSC, "Device 0x%p link state %s", rndisDevice,
	    ((deviceInfo->LinkState) ? ("down") : ("up")));

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on device remove
 */
static int
hv_rf_on_device_remove(DEVICE_OBJECT *Device)
{
	netvsc_dev *netDevice = (netvsc_dev *)Device->Extension;
	rndis_device *rndisDevice = (rndis_device *)netDevice->extension;

	DPRINT_ENTER(NETVSC);

	/* Halt and release the rndis device */
	hv_rf_halt_device(rndisDevice);

	hv_put_rndis_device(rndisDevice);
	netDevice->extension = NULL;

	/* Pass control to inner driver to remove the device */
	gRndisFilter.InnerDriver.Base.OnDeviceRemove(Device);

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter on cleanup
 */
static void
hv_rf_on_cleanup(DRIVER_OBJECT *Driver)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on open
 */
static int
hv_rf_on_open(DEVICE_OBJECT *Device)
{
	int ret;
	netvsc_dev *netDevice = (netvsc_dev *)Device->Extension;
	
	DPRINT_ENTER(NETVSC);
	
	ASSERT(netDevice);
	ret = hv_rf_open_device((rndis_device *)netDevice->extension);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on close
 */
static int 
hv_rf_on_close(DEVICE_OBJECT *Device)
{
	int ret;
	netvsc_dev *netDevice = (netvsc_dev *)Device->Extension;
	
	DPRINT_ENTER(NETVSC);
	
	ASSERT(netDevice);
	ret = hv_rf_close_device((rndis_device *)netDevice->extension);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on send
 */
static int
hv_rf_on_send(DEVICE_OBJECT *Device, netvsc_packet *Packet)
{
	int ret=0;
	rndis_filter_packet *filterPacket;
	rndis_msg *rndisMessage;
	rndis_packet *rndisPacket;
	uint32_t rndisMessageSize;

	DPRINT_ENTER(NETVSC);

	/* Add the rndis header */
	filterPacket = (rndis_filter_packet *)Packet->Extension;
	ASSERT(filterPacket);

	memset(filterPacket, 0, sizeof(rndis_filter_packet));

	rndisMessage = &filterPacket->Message;
	rndisMessageSize = RNDIS_MESSAGE_SIZE(rndis_packet);

	rndisMessage->ndis_msg_type = REMOTE_NDIS_PACKET_MSG;
	rndisMessage->msg_len = Packet->TotalDataBufferLength +
	    rndisMessageSize;
	
	rndisPacket = &rndisMessage->msg.Packet;
	rndisPacket->DataOffset = sizeof(rndis_packet);
	rndisPacket->DataLength = Packet->TotalDataBufferLength;

	Packet->IsDataPacket = TRUE;
	Packet->PageBuffers[0].Pfn =
	    GetPhysicalAddress(rndisMessage) >> PAGE_SHIFT;
	Packet->PageBuffers[0].Offset =
	    (ULONG_PTR)rndisMessage & (PAGE_SIZE-1);
	Packet->PageBuffers[0].Length = rndisMessageSize;

	/* Save the packet send completion and context */
	filterPacket->OnCompletion = Packet->Completion.Send.OnSendCompletion;
	filterPacket->CompletionContext =
	    Packet->Completion.Send.SendCompletionContext;

	/* Use ours */
	Packet->Completion.Send.OnSendCompletion = hv_rf_on_send_completion;
	Packet->Completion.Send.SendCompletionContext = filterPacket;

	ret = gRndisFilter.InnerDriver.OnSend(Device, Packet);
	if (ret != 0) {
		/*
		 * Reset the completion to originals to allow retries from above
		 */
		Packet->Completion.Send.OnSendCompletion =
		    filterPacket->OnCompletion;
		Packet->Completion.Send.SendCompletionContext =
		    filterPacket->CompletionContext;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on send completion
 */
static void 
hv_rf_on_send_completion(void *Context)
{
	rndis_filter_packet *filterPacket = (rndis_filter_packet *)Context;

	DPRINT_ENTER(NETVSC);

	/* Pass it back to the original handler */
	filterPacket->OnCompletion(filterPacket->CompletionContext);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on send request completion
 */
static void 
hv_rf_on_send_request_completion(void *Context)
{
	DPRINT_ENTER(NETVSC);

	/* Noop */
	DPRINT_EXIT(NETVSC);
}

