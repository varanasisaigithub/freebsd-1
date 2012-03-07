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
#include <sys/lock.h>
#include <sys/mutex.h>
#include <net/if_arp.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include <dev/hyperv/include/hv_list.h>
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/netvsc/hv_nvsp_protocol.h>
#include <dev/hyperv/vmbus/hv_vmbus_var.h>
#include <dev/hyperv/netvsc/hv_net_vsc_api.h>
#include <dev/hyperv/netvsc/hv_net_vsc.h>
#include <dev/hyperv/netvsc/hv_rndis_filter.h>
#include <dev/hyperv/netvsc/hv_rndis.h>


/*
 * Data types
 */

typedef struct rndis_filter_driver_object_ {
	/* From the original driver, now called the inner driver */
	netvsc_driver_object		inner_drv;
} rndis_filter_driver_object;

typedef enum {
	RNDIS_DEV_UNINITIALIZED = 0,
	RNDIS_DEV_INITIALIZING,
	RNDIS_DEV_INITIALIZED,
	RNDIS_DEV_DATAINITIALIZED,
} rndis_device_state;

typedef struct rndis_request_ {
	/* Fixme:  list */
	//LIST_ENTRY			list_entry;
	/* Fixme:  list */
	STAILQ_ENTRY(rndis_request_)	mylist_entry;
	void				*wait_event;	

	/*
	 * Fixme:  We assumed a fixed size response here.  If we do ever
	 * need to handle a bigger response, we can either define a max
	 * response message or add a response buffer variable above this field
	 */
	rndis_msg			response_msg;

	/* Simplify allocation by having a netvsc packet inline */
	netvsc_packet			pkt;
	PAGE_BUFFER			buffer;
	/* Fixme:  We assumed a fixed size request here. */
	rndis_msg			request_msg;
} rndis_request;

typedef struct rndis_device_ {
	netvsc_dev			*net_dev;

	rndis_device_state		state;
	uint32_t			link_status;
	uint32_t			new_request_id;

	struct mtx			req_lock;

	/* Fixme:  list */
	//LIST_ENTRY			request_list;
	/* Fixme:  list */
	STAILQ_HEAD(RQ, rndis_request_)	myrequest_list;

	uint8_t				hw_mac_addr[HW_MACADDR_LEN];
} rndis_device;

/* Fixme:  not used */
typedef struct rndis_filter_packet_ {
	void				*completion_context;
	pfn_on_send_rx_completion	on_completion;

	rndis_msg			message;
} rndis_filter_packet;

/*
 * Forward declarations
 */
static int  hv_rf_send_request(rndis_device *device, rndis_request *request);
static void hv_rf_receive_response(rndis_device *device, rndis_msg *response);
static void hv_rf_receive_indicate_status(rndis_device *device,
					  rndis_msg *response);
// Fixme
extern void hv_rf_receive_data(rndis_device *device, rndis_msg *message,
//static void hv_rf_receive_data(rndis_device *device, rndis_msg *message,
				   netvsc_packet *pkt);
/* Fixme  Function pointer removal */
//static int  hv_rf_on_receive(DEVICE_OBJECT *device, netvsc_packet *pkt);
static int  hv_rf_query_device(rndis_device *device, uint32_t oid,
				   void *result, uint32_t *result_size);
static inline int hv_rf_query_device_mac(rndis_device *device);
static inline int hv_rf_query_device_link_status(rndis_device *device);
static int  hv_rf_set_packet_filter(rndis_device *device, uint32_t new_filter);
static int  hv_rf_init_device(rndis_device *device);
static int  hv_rf_open_device(rndis_device *device);
static int  hv_rf_close_device(rndis_device *device);
/* Fixme:  Function pointer removal */
//static int  hv_rf_on_device_add(DEVICE_OBJECT *device, void *additl_info);
//static int  hv_rf_on_device_remove(DEVICE_OBJECT *device);
//static void hv_rf_on_cleanup(DRIVER_OBJECT *driver);
//static int  hv_rf_on_open(DEVICE_OBJECT *device);
//static int  hv_rf_on_close(DEVICE_OBJECT *device);
//static int  hv_rf_on_send(DEVICE_OBJECT *device, netvsc_packet *pkt);
static void hv_rf_on_send_completion(void *context);
static void hv_rf_on_send_request_completion(void *context);

/*
 * Global variables
 */

/* The one and only */
rndis_filter_driver_object g_rndis_filter;

#ifdef REMOVED

	/* Fixme:  list */
	STAILQ_ENTRY(rndis_device_)	myrequest_list;
	STAILQ_HEAD(FOO, rndis_device_)	myhead;

/*
 * Singly-linked Tail queue declarations.
 */
#define STAILQ_HEAD(name, type)                                         \
struct name {                                                           \
        struct type *stqh_first;/* first element */                     \
        struct type **stqh_last;/* addr of last next element */         \
}

#define STAILQ_HEAD_INITIALIZER(head)                                   \
        { NULL, &(head).stqh_first }

// Fixme
//	STAILQ_ENTRY(rndis_device_)	myrequest_list;
//	STAILQ_HEAD(FOO, rndis_device_)	myhead;


#define STAILQ_ENTRY(type)                                              \
struct {                                                                \
        struct type *stqe_next; /* next element */                      \
}

#define STAILQ_FIRST(head)      ((head)->stqh_first)

#define STAILQ_INIT(head) do {                                          \
        STAILQ_FIRST((head)) = NULL;                                    \
        (head)->stqh_last = &STAILQ_FIRST((head));                      \
} while (0)

#endif


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

	mtx_init(&device->req_lock, "HV-FRL", NULL, MTX_SPIN | MTX_RECURSE);

	/* Fixme:  list */
	//INITIALIZE_LIST_HEAD(&device->request_list);
	/* Fixme:  list */
	/* Same effect as STAILQ_HEAD_INITIALIZER() static initializer */
	STAILQ_INIT(&device->myrequest_list);

	device->state = RNDIS_DEV_UNINITIALIZED;

	return (device);
}

/*
 *
 */
static inline void
hv_put_rndis_device(rndis_device *device)
{
	mtx_destroy(&device->req_lock);
	free(device, M_DEVBUF);
}

/*
 *
 */
static inline rndis_request *
hv_rndis_request(rndis_device *device, uint32_t message_type,
		 uint32_t message_length)
{
	rndis_request *request;
	rndis_msg *rndis_mesg;
	rndis_set_request *set;

	request = malloc(sizeof(rndis_request), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (!request) {
		return (NULL);
	}

	request->wait_event = WaitEventCreate();
	if (!request->wait_event) {
		free(request, M_DEVBUF);

		return (NULL);
	}
	
	rndis_mesg = &request->request_msg;
	rndis_mesg->ndis_msg_type = message_type;
	rndis_mesg->msg_len = message_length;

	/*
	 * Set the request id. This field is always after the rndis header
	 * for request/response packet types so we just use the set_request
	 * as a template.
	 */
	set = &rndis_mesg->msg.set_request;
	set->request_id = InterlockedIncrement((int *)&device->new_request_id);

	/* Add to the request list */
	mtx_lock(&device->req_lock);
	/* Fixme:  list */
	//INSERT_TAIL_LIST(&device->request_list, &request->list_entry);
	/* Fixme:  list */
	STAILQ_INSERT_TAIL(&device->myrequest_list, request, mylist_entry);
	mtx_unlock(&device->req_lock);

	return (request);
}

/*
 *
 */
static inline void
hv_put_rndis_request(rndis_device *device, rndis_request *request)
{
	mtx_lock(&device->req_lock);
	/* Fixme:  list */
	//REMOVE_ENTRY_LIST(&request->list_entry);
	/* Fixme:  list */
	/* Fixme:  Has O(n) performance */
	STAILQ_REMOVE(&device->myrequest_list, request, rndis_request_,
	    mylist_entry);
	mtx_unlock(&device->req_lock);

	WaitEventClose(request->wait_event);
	free(request, M_DEVBUF);
}

/*
 *
 */
static inline void
hv_dump_rndis_message(rndis_msg *rndis_mesg)
{
	switch (rndis_mesg->ndis_msg_type) {

	case REMOTE_NDIS_PACKET_MSG:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_PACKET_MSG (len %u, data "
		    "offset %u data len %u, # oob %u, oob offset %u, oob "
		    "len %u, pkt offset %u, pkt len %u", 
		    rndis_mesg->msg_len,
		    rndis_mesg->msg.packet.data_offset,
		    rndis_mesg->msg.packet.data_length,
		    rndis_mesg->msg.packet.num_oob_data_elements,
		    rndis_mesg->msg.packet.oob_data_offset,
		    rndis_mesg->msg.packet.oob_data_length,
		    rndis_mesg->msg.packet.per_pkt_info_offset,
		    rndis_mesg->msg.packet.per_pkt_info_length);
		break;
	case REMOTE_NDIS_INITIALIZE_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_INITIALIZE_CMPLT (len %u, "
		    "id 0x%x, status 0x%x, major %d, minor %d, device flags "
		    "%d, max xfer size 0x%x, max pkts %u, pkt aligned %u)", 
		    rndis_mesg->msg_len,
		    rndis_mesg->msg.init_complete.request_id,
		    rndis_mesg->msg.init_complete.status,
		    rndis_mesg->msg.init_complete.major_version,
		    rndis_mesg->msg.init_complete.minor_version,
		    rndis_mesg->msg.init_complete.device_flags,
		    rndis_mesg->msg.init_complete.max_xfer_size,
		    rndis_mesg->msg.init_complete.max_pkts_per_msg,
		    rndis_mesg->msg.init_complete.pkt_align_factor);
		break;
	case REMOTE_NDIS_QUERY_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_QUERY_CMPLT (len %u, id 0x%x, "
		    "status 0x%x, buf len %u, buf offset %u)", 
		    rndis_mesg->msg_len,
		    rndis_mesg->msg.query_complete.request_id,
		    rndis_mesg->msg.query_complete.status,
		    rndis_mesg->msg.query_complete.info_buffer_length,
		    rndis_mesg->msg.query_complete.info_buffer_offset);
		break;
	case REMOTE_NDIS_SET_CMPLT:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_SET_CMPLT (len %u, id 0x%x, "
		    "status 0x%x)", 
		    rndis_mesg->msg_len,
		    rndis_mesg->msg.set_complete.request_id,
		    rndis_mesg->msg.set_complete.status);
		break;
	case REMOTE_NDIS_INDICATE_STATUS_MSG:
		DPRINT_DBG(NETVSC, "REMOTE_NDIS_INDICATE_STATUS_MSG (len %u, "
		    "status 0x%x, buf len %u, buf offset %u)", 
		    rndis_mesg->msg_len,
		    rndis_mesg->msg.indicate_status.status,
		    rndis_mesg->msg.indicate_status.status_buf_length,
		    rndis_mesg->msg.indicate_status.status_buf_offset);
		break;
	default:
		DPRINT_DBG(NETVSC, "0x%x (len %u)",
		    rndis_mesg->ndis_msg_type,
		    rndis_mesg->msg_len);
		break;
	}
}

/*
 *
 */
static int
hv_rf_send_request(rndis_device *device, rndis_request *request)
{
	int ret = 0;
	netvsc_packet *packet;
	
	DPRINT_ENTER(NETVSC);

	/* Set up the packet to send it */
	packet = &request->pkt;
	
	packet->is_data_pkt = FALSE;
	packet->tot_data_buf_len = request->request_msg.msg_len;
	packet->page_buf_count = 1;

	packet->page_buffers[0].Pfn =
	    GetPhysicalAddress(&request->request_msg) >> PAGE_SHIFT;
	packet->page_buffers[0].Length = request->request_msg.msg_len;
	packet->page_buffers[0].Offset =
	    (unsigned long)&request->request_msg & (PAGE_SIZE - 1);

	packet->compl.send.send_completion_context = request; /* packet; */
	packet->compl.send.on_send_completion =
	    hv_rf_on_send_request_completion;
	packet->compl.send.send_completion_tid = (unsigned long)device;

	/* Fixme:  Function pointer removal */
	//ret = g_rndis_filter.inner_drv.on_send(device->net_dev->dev,
	//    packet);
	ret = hv_nv_on_send(device->net_dev->dev, packet);
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter receive response
 */
static void 
hv_rf_receive_response(rndis_device *device, rndis_msg *response)
{
	/* Fixme:  list */
	//LIST_ENTRY *anchor;
	//LIST_ENTRY *curr;
	rndis_request *request = NULL;
	rndis_request *next_request;
	BOOL found = FALSE;

	DPRINT_ENTER(NETVSC);

	mtx_lock(&device->req_lock);
	/* Fixme:  list */
	//ITERATE_LIST_ENTRIES(anchor, curr, &device->request_list) {		
	/* Fixme:  list */
	request = STAILQ_FIRST(&device->myrequest_list);
	while (request != NULL) {

		//request = CONTAINING_RECORD(curr, rndis_request, list_entry);

		/*
		 * All request/response message contains RequestId as the
		 * first field
		 */
		if (request->request_msg.msg.init_request.request_id ==
				      response->msg.init_complete.request_id) {
			DPRINT_DBG(NETVSC, "found rndis request for this "
			    "response (id 0x%x req type 0x%x res type 0x%x)", 
			    request->request_msg.msg.init_request.request_id,
			    request->request_msg.ndis_msg_type,
			    response->ndis_msg_type);

			found = TRUE;
			break;
		}
		next_request = STAILQ_NEXT(request, mylist_entry);
		request = next_request;
	}
	//}
	mtx_unlock(&device->req_lock);

	if (found) {
		if (response->msg_len <= sizeof(rndis_msg)) {
			memcpy(&request->response_msg, response,
			    response->msg_len);
		} else {
			DPRINT_ERR(NETVSC, "rndis response buffer overflow "
			    "detected (size %u max %lu)",
			    response->msg_len,
			    sizeof(rndis_filter_packet));

			if (response->ndis_msg_type == REMOTE_NDIS_RESET_CMPLT) {
				/* Does not have a request id field */
				request->response_msg.msg.reset_complete.status =
				    STATUS_BUFFER_OVERFLOW;
			} else {
				request->response_msg.msg.init_complete.status =
				    STATUS_BUFFER_OVERFLOW;
			}
		}

		WaitEventSet(request->wait_event);
	} else {
		DPRINT_ERR(NETVSC, "no rndis request found for this response "
		    "(id 0x%x res type 0x%x)", 
		    response->msg.init_complete.request_id,
		    response->ndis_msg_type);
	}

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter receive indicate status
 */
static void 
hv_rf_receive_indicate_status(rndis_device *device, rndis_msg *response)
{
	rndis_indicate_status *indicate = &response->msg.indicate_status;
		
	if (indicate->status == RNDIS_STATUS_MEDIA_CONNECT) {
		/* Fixme:  Function pointer removal */
		//g_rndis_filter.inner_drv.on_link_stat_changed(
		//    device->net_dev->dev, 1);
		netvsc_linkstatus_callback(device->net_dev->dev, 1);
	} else if (indicate->status == RNDIS_STATUS_MEDIA_DISCONNECT) {
		/* Fixme:  Function pointer removal */
		//g_rndis_filter.inner_drv.on_link_stat_changed(
		//    device->net_dev->dev, 0);
		netvsc_linkstatus_callback(device->net_dev->dev, 0);
	} else {
		/* TODO: */
	}
}

/*
 * RNDIS filter receive data
 */
// Fixme:  Hacked to make function name visible to debugger
//static void
void
hv_rf_receive_data(rndis_device *device, rndis_msg *message, netvsc_packet *pkt)
{
	rndis_packet *rndis_pkt;
	uint32_t data_offset;

	DPRINT_ENTER(NETVSC);

	/* Empty Ethernet frame??? */
	ASSERT(pkt->page_buffers[0].Length > RNDIS_MESSAGE_SIZE(rndis_packet));

	rndis_pkt = &message->msg.packet;

	/*
	 * Fixme:  Handle multiple rndis pkt msgs that may be enclosed in this
	 * netvsc packet (ie tot_data_buf_len != message_length)
	 */

	/* Remove the rndis header and pass it back up the stack */
	data_offset = RNDIS_HEADER_SIZE + rndis_pkt->data_offset;
		
	pkt->tot_data_buf_len       -= data_offset;
	pkt->page_buffers[0].Offset += data_offset;
	pkt->page_buffers[0].Length -= data_offset;

	pkt->is_data_pkt = TRUE;
		
	/* Fixme:  Function pointer removal */
	//g_rndis_filter.inner_drv.on_rx_callback(device->net_dev->dev, pkt);
	netvsc_recv_callback(device->net_dev->dev, pkt);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on receive
 */
int
hv_rf_on_receive(DEVICE_OBJECT *device, netvsc_packet *pkt)
{
	netvsc_dev *net_dev = (netvsc_dev *)device->Extension;
	rndis_device *rndis_dev;
	rndis_msg rndis_mesg;
	rndis_msg *rndis_hdr;

	DPRINT_ENTER(NETVSC);

	ASSERT(net_dev);

	/* Make sure the rndis device state is initialized */
	if (!net_dev->extension) {
		DPRINT_ERR(NETVSC, "got rndis message but no rndis device... "
		    "dropping this message!");
		DPRINT_EXIT(NETVSC);

		return (-1);
	}

	rndis_dev = (rndis_device *)net_dev->extension;
	if (rndis_dev->state == RNDIS_DEV_UNINITIALIZED) {
		DPRINT_ERR(NETVSC, "got rndis message but rndis device "
		    "uninitialized... dropping this message!");
		DPRINT_EXIT(NETVSC);

		return (-1);
	}

	/* Shift virtual page number to form virtual page address */
	rndis_hdr = (rndis_msg *)(pkt->page_buffers[0].Pfn << PAGE_SHIFT);

	rndis_hdr = (void *)((unsigned long)rndis_hdr +
	    pkt->page_buffers[0].Offset);
	
	/*
	 * Make sure we got a valid rndis message
	 * Fixme:  There seems to be a bug in set completion msg where
	 * its msg_len is 16 bytes but the ByteCount field in the
	 * xfer page range shows 52 bytes
	 */
#if 0
	if (pkt->tot_data_buf_len != rndis_hdr->msg_len) {
		DPRINT_ERR(NETVSC, "invalid rndis message? (expected %u "
		    "bytes got %u)... dropping this message!",
		    rndis_hdr->msg_len, pkt->tot_data_buf_len);
		DPRINT_EXIT(NETVSC);

		return (-1);
	}
#endif

	if ((rndis_hdr->ndis_msg_type != REMOTE_NDIS_PACKET_MSG) &&
		     (rndis_hdr->msg_len > sizeof(rndis_msg))) {
		DPRINT_ERR(NETVSC, "incoming rndis message buffer overflow "
		    "detected (got %u, max %lu)...marking it an error!",
		    rndis_hdr->msg_len, sizeof(rndis_msg));
	}

	memcpy(&rndis_mesg, rndis_hdr,
	    (rndis_hdr->msg_len > sizeof(rndis_msg)) ?
	    sizeof(rndis_msg) : rndis_hdr->msg_len);

	hv_dump_rndis_message(&rndis_mesg);

	switch (rndis_mesg.ndis_msg_type) {

	/* data message */
	case REMOTE_NDIS_PACKET_MSG:
		hv_rf_receive_data(rndis_dev, &rndis_mesg, pkt);
		break;

	/* completion messages */
	case REMOTE_NDIS_INITIALIZE_CMPLT:
	case REMOTE_NDIS_QUERY_CMPLT:
	case REMOTE_NDIS_SET_CMPLT:
	//case REMOTE_NDIS_RESET_CMPLT:
	//case REMOTE_NDIS_KEEPALIVE_CMPLT:
		hv_rf_receive_response(rndis_dev, &rndis_mesg);
		break;

	/* notification message */
	case REMOTE_NDIS_INDICATE_STATUS_MSG:
		hv_rf_receive_indicate_status(rndis_dev, &rndis_mesg);
		break;
	default:
		DPRINT_ERR(NETVSC, "unhandled rndis message (type %u len %u)",
		    rndis_mesg.ndis_msg_type, rndis_mesg.msg_len);
		break;
	}

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter query device
 */
static int
hv_rf_query_device(rndis_device *device, uint32_t oid, void *result,
		       uint32_t *result_size)
{
	rndis_request *request;
	uint32_t inresultSize = *result_size;
	rndis_query_request *query;
	rndis_query_complete *query_complete;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	ASSERT(result);

	*result_size = 0;
	request = hv_rndis_request(device, REMOTE_NDIS_QUERY_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_query_request));
	if (!request) {
		ret = -1;
		goto cleanup;
	}

	/* Set up the rndis query */
	query = &request->request_msg.msg.query_request;
	query->oid = oid;
	query->info_buffer_offset = sizeof(rndis_query_request); 
	query->info_buffer_length = 0;
	query->device_vc_handle = 0;

	ret = hv_rf_send_request(device, request);
	if (ret != 0) {
		/* Fixme:  printf added */
		printf("RNDISFILTER request failed to Send!\n");
		goto cleanup;
	}

	WaitEventWait(request->wait_event);

	/* Copy the response back */
	query_complete = &request->response_msg.msg.query_complete;
	
	if (query_complete->info_buffer_length > inresultSize) {
		ret = -1;
		goto cleanup;
	}

	memcpy(result, 
	    (void *)((unsigned long)query_complete +
	    query_complete->info_buffer_offset),
	    query_complete->info_buffer_length);

	*result_size = query_complete->info_buffer_length;

cleanup:
	if (request) {
		hv_put_rndis_request(device, request);
	}
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter query device MAC address
 */
static inline int
hv_rf_query_device_mac(rndis_device *device)
{
	uint32_t size = HW_MACADDR_LEN;

	return (hv_rf_query_device(device,
	    RNDIS_OID_802_3_PERMANENT_ADDRESS, device->hw_mac_addr, &size));
}

/*
 * RNDIS filter query device link status
 */
static inline int
hv_rf_query_device_link_status(rndis_device *device)
{
	uint32_t size = sizeof(uint32_t);

	return (hv_rf_query_device(device,
	    RNDIS_OID_GEN_MEDIA_CONNECT_STATUS, &device->link_status, &size));
}

/*
 * RNDIS filter set packet filter
 */
static int
hv_rf_set_packet_filter(rndis_device *device, uint32_t new_filter)
{
	rndis_request *request;
	rndis_set_request *set;
	rndis_set_complete *set_complete;
	uint32_t status;
	int ret;

	DPRINT_ENTER(NETVSC);

	ASSERT(RNDIS_MESSAGE_SIZE(rndis_set_request) + sizeof(uint32_t) <=
	    sizeof(rndis_msg));

	request = hv_rndis_request(device, REMOTE_NDIS_SET_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_set_request) + sizeof(uint32_t));
	if (!request) {
		ret = -1;
		goto cleanup;
	}

	/* Set up the rndis set */
	set = &request->request_msg.msg.set_request;
	set->oid = RNDIS_OID_GEN_CURRENT_PACKET_FILTER;
	set->info_buffer_length = sizeof(uint32_t);
	set->info_buffer_offset = sizeof(rndis_set_request); 

	memcpy((void *)((unsigned long)set + sizeof(rndis_set_request)),
	    &new_filter, sizeof(uint32_t));

	ret = hv_rf_send_request(device, request);
	if (ret != 0) {
		DPRINT_ERR(NETVSC, "RNDISFILTER request failed to send!  "
		    "ret %d", ret);
		goto cleanup;
	}

	/* Fixme:  second parameter is 2000 in the lis21 code drop */
	ret = WaitEventWaitEx(request->wait_event, 4000/*2sec*/);
	if (!ret) {
		ret = -1;
		DPRINT_ERR(NETVSC, "timeout before we got a set response... "
		    "cmd %d ", new_filter);
		/*
		 * We cannot deallocate the request since we may still
		 * receive a send completion for it.
		 */
		goto exit;
	} else {
		if (ret > 0) {
			ret = 0;
		}
		set_complete = &request->response_msg.msg.set_complete;
		status = set_complete->status;
	}

cleanup:
	if (request) {
		hv_put_rndis_request(device, request);
	}
exit:
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter init
 */
int
hv_rndis_filter_init(netvsc_driver_object *driver)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_DBG(NETVSC, "sizeof(rndis_filter_packet) == %lu",
	    sizeof(rndis_filter_packet));

	driver->request_ext_size = sizeof(rndis_filter_packet);
	driver->additional_request_page_buf_cnt = 1; /* For rndis header */

	//driver->Context = rndis_driver;

	memset(&g_rndis_filter, 0, sizeof(rndis_filter_driver_object));

#ifdef REMOVED
	/* Fixme:  Don't know why this code was commented out */
	rndis_driver->Driver = driver;

	ASSERT(driver->on_link_stat_changed);
	rndis_driver->on_link_stat_changed = driver->on_link_stat_changed;
#endif

	/* Save the original dispatch handlers before we override it */
	g_rndis_filter.inner_drv.base.OnDeviceAdd = driver->base.OnDeviceAdd;
	g_rndis_filter.inner_drv.base.OnDeviceRemove =
	    driver->base.OnDeviceRemove;
	g_rndis_filter.inner_drv.base.OnCleanup = driver->base.OnCleanup;

	ASSERT(driver->on_send);
	ASSERT(driver->on_rx_callback);
	g_rndis_filter.inner_drv.on_send = driver->on_send;
	g_rndis_filter.inner_drv.on_rx_callback = driver->on_rx_callback;
	g_rndis_filter.inner_drv.on_link_stat_changed =
	    driver->on_link_stat_changed;

	/* Override */
	driver->base.OnDeviceAdd = hv_rf_on_device_add;
	driver->base.OnDeviceRemove = hv_rf_on_device_remove;
	driver->base.OnCleanup = hv_rf_on_cleanup;

	driver->on_send = hv_rf_on_send;
	driver->on_open = hv_rf_on_open;
	driver->on_close = hv_rf_on_close;
	//driver->Querylink_status = hv_rf_query_device_link_status;
	driver->on_rx_callback = hv_rf_on_receive;

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter init device
 */
static int
hv_rf_init_device(rndis_device *device)
{
	rndis_request *request;
	rndis_initialize_request *init;
	rndis_initialize_complete *init_complete;
	uint32_t status;
	int ret;

	DPRINT_ENTER(NETVSC);

	request = hv_rndis_request(device, REMOTE_NDIS_INITIALIZE_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_initialize_request));
	if (!request) {
		ret = -1;
		goto cleanup;
	}

	/* Set up the rndis set */
	init = &request->request_msg.msg.init_request;
	init->major_version = RNDIS_MAJOR_VERSION;
	init->minor_version = RNDIS_MINOR_VERSION;
	/* Fixme:  Use 1536 - rounded ethernet frame size */
	/* Fixme:  Magic number */
	init->max_xfer_size = 2048;
	
	device->state = RNDIS_DEV_INITIALIZING;

	ret = hv_rf_send_request(device, request);
	if (ret != 0) {
		device->state = RNDIS_DEV_UNINITIALIZED;
		goto cleanup;
	}

	WaitEventWait(request->wait_event);

	init_complete = &request->response_msg.msg.init_complete;
	status = init_complete->status;
	if (status == RNDIS_STATUS_SUCCESS) {
		device->state = RNDIS_DEV_INITIALIZED;
		ret = 0;
	} else {
		device->state = RNDIS_DEV_UNINITIALIZED; 
		ret = -1;
	}

cleanup:
	if (request) {
		hv_put_rndis_request(device, request);
	}
	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter halt device
 */
static void
hv_rf_halt_device(rndis_device *device)
{
	rndis_request *request;
	rndis_halt_request *halt;

	DPRINT_ENTER(NETVSC);

	/* Attempt to do a rndis device halt */
	request = hv_rndis_request(device, REMOTE_NDIS_HALT_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_halt_request));
	if (!request) {
		goto cleanup;
	}

	/* Set up the rndis set */
	halt = &request->request_msg.msg.halt_request;
	halt->request_id = InterlockedIncrement((int *)&device->new_request_id);
	
	/* Ignore return since this msg is optional. */
	hv_rf_send_request(device, request);
	
	device->state = RNDIS_DEV_UNINITIALIZED;

cleanup:
	if (request) {
		hv_put_rndis_request(device, request);
	}
	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter open device
 */
static int
hv_rf_open_device(rndis_device *device)
{
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	if (device->state != RNDIS_DEV_INITIALIZED) {
		return (0);
	}

	if (promisc_mode != 1) {
		ret = hv_rf_set_packet_filter(device, 
		    NDIS_PACKET_TYPE_BROADCAST     |
		    NDIS_PACKET_TYPE_ALL_MULTICAST |
		    NDIS_PACKET_TYPE_DIRECTED);
		DPRINT_INFO(NETVSC, "Network set to normal mode");
	} else {
		ret = hv_rf_set_packet_filter(device, 
		    NDIS_PACKET_TYPE_PROMISCUOUS);
		DPRINT_INFO(NETVSC, "Network set to promiscuous mode");
	}

	if (ret == 0) {
		device->state = RNDIS_DEV_DATAINITIALIZED;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter close device
 */
static int
hv_rf_close_device(rndis_device *device)
{
	int ret;

	DPRINT_ENTER(NETVSC);

	if (device->state != RNDIS_DEV_DATAINITIALIZED) {
		return (0);
	}

	ret = hv_rf_set_packet_filter(device, 0);
	if (ret == 0) {
		device->state = RNDIS_DEV_INITIALIZED;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on device add
 */
int
hv_rf_on_device_add(DEVICE_OBJECT *device, void *additl_info)
{
	int ret;
	netvsc_dev *net_dev;
	rndis_device *rndis_dev;
	netvsc_device_info *dev_info = (netvsc_device_info *)additl_info;

	DPRINT_ENTER(NETVSC);

	rndis_dev = hv_get_rndis_device();
	if (!rndis_dev) {
		DPRINT_EXIT(NETVSC);
		return (-1);
	}

	DPRINT_DBG(NETVSC, "rndis device object allocated - %p", rndis_dev);

	/*
	 * Let the inner driver handle this first to create the netvsc channel
	 * NOTE! Once the channel is created, we may get a receive callback 
	 * (hv_rf_on_receive()) before this call is completed
	 */
	/* Fixme:  Function pointer removal */
	//ret = g_rndis_filter.inner_drv.base.OnDeviceAdd(device, additl_info);
	ret = hv_nv_on_device_add(device, additl_info);
	if (ret != 0) {
		hv_put_rndis_device(rndis_dev);
		DPRINT_EXIT(NETVSC);
		return (ret);
	}

	/*
	 * Initialize the rndis device
	 */
	net_dev = (netvsc_dev *)device->Extension;
	ASSERT(net_dev);
	ASSERT(net_dev->dev);

	net_dev->extension = rndis_dev;
	rndis_dev->net_dev = net_dev;

	/* Send the rndis initialization message */
	ret = hv_rf_init_device(rndis_dev);
	if (ret != 0) {
		/*
		 * TODO: If rndis init failed, we will need to shut down
		 * the channel
		 */
	}

	/* Get the mac address */
	ret = hv_rf_query_device_mac(rndis_dev);
	if (ret != 0) {
		/* TODO: shutdown rndis device and the channel */
	}
	
	DPRINT_INFO(NETVSC, "Device 0x%p mac addr %02x%02x%02x%02x%02x%02x",
	    rndis_dev,
	    rndis_dev->hw_mac_addr[0], rndis_dev->hw_mac_addr[1],
	    rndis_dev->hw_mac_addr[2], rndis_dev->hw_mac_addr[3],
	    rndis_dev->hw_mac_addr[4], rndis_dev->hw_mac_addr[5]);

	memcpy(dev_info->mac_addr, rndis_dev->hw_mac_addr, HW_MACADDR_LEN);

	hv_rf_query_device_link_status(rndis_dev);
	
	dev_info->link_state = rndis_dev->link_status;
	DPRINT_INFO(NETVSC, "Device 0x%p link state %s", rndis_dev,
	    ((dev_info->link_state) ? ("down") : ("up")));

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on device remove
 */
int
hv_rf_on_device_remove(DEVICE_OBJECT *device)
{
	netvsc_dev *net_dev = (netvsc_dev *)device->Extension;
	rndis_device *rndis_dev = (rndis_device *)net_dev->extension;

	DPRINT_ENTER(NETVSC);

	/* Halt and release the rndis device */
	hv_rf_halt_device(rndis_dev);

	hv_put_rndis_device(rndis_dev);
	net_dev->extension = NULL;

	/* Pass control to inner driver to remove the device */
	/* Fixme:  Function pointer removal */
	//g_rndis_filter.inner_drv.base.OnDeviceRemove(device);
	hv_nv_on_device_remove(device);

	DPRINT_EXIT(NETVSC);

	return (0);
}

/*
 * RNDIS filter on cleanup
 */
void
hv_rf_on_cleanup(DRIVER_OBJECT *driver)
{
	DPRINT_ENTER(NETVSC);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on open
 */
int
hv_rf_on_open(DEVICE_OBJECT *device)
{
	int ret;
	netvsc_dev *net_dev = (netvsc_dev *)device->Extension;
	
	DPRINT_ENTER(NETVSC);
	
	ASSERT(net_dev);
	ret = hv_rf_open_device((rndis_device *)net_dev->extension);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on close
 */
int 
hv_rf_on_close(DEVICE_OBJECT *device)
{
	int ret;
	netvsc_dev *net_dev = (netvsc_dev *)device->Extension;
	
	DPRINT_ENTER(NETVSC);
	
	ASSERT(net_dev);
	ret = hv_rf_close_device((rndis_device *)net_dev->extension);

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on send
 */
int
hv_rf_on_send(DEVICE_OBJECT *device, netvsc_packet *pkt)
{
	rndis_filter_packet *filter_pkt;
	rndis_msg *rndis_mesg;
	rndis_packet *rndis_pkt;
	uint32_t rndis_msg_size;
	int ret = 0;

	DPRINT_ENTER(NETVSC);

	/* Add the rndis header */
	filter_pkt = (rndis_filter_packet *)pkt->extension;
	ASSERT(filter_pkt);

	memset(filter_pkt, 0, sizeof(rndis_filter_packet));

	rndis_mesg = &filter_pkt->message;
	rndis_msg_size = RNDIS_MESSAGE_SIZE(rndis_packet);

	rndis_mesg->ndis_msg_type = REMOTE_NDIS_PACKET_MSG;
	rndis_mesg->msg_len = pkt->tot_data_buf_len + rndis_msg_size;
	
	rndis_pkt = &rndis_mesg->msg.packet;
	rndis_pkt->data_offset = sizeof(rndis_packet);
	rndis_pkt->data_length = pkt->tot_data_buf_len;

	pkt->is_data_pkt = TRUE;
	pkt->page_buffers[0].Pfn =
	    GetPhysicalAddress(rndis_mesg) >> PAGE_SHIFT;
	pkt->page_buffers[0].Offset =
	    (unsigned long)rndis_mesg & (PAGE_SIZE - 1);
	pkt->page_buffers[0].Length = rndis_msg_size;

	/* Save the packet send completion and context */
	filter_pkt->on_completion = pkt->compl.send.on_send_completion;
	filter_pkt->completion_context =
	    pkt->compl.send.send_completion_context;

	/* Use ours */
	pkt->compl.send.on_send_completion = hv_rf_on_send_completion;
	pkt->compl.send.send_completion_context = filter_pkt;

	/* Fixme:  Function pointer removal */
	//ret = g_rndis_filter.inner_drv.on_send(device, pkt);
	ret = hv_nv_on_send(device, pkt);
	if (ret != 0) {
		/*
		 * Reset the completion to originals to allow retries from above
		 * Fixme:  Research how to eliminate this function pointer.
		 */
		pkt->compl.send.on_send_completion =
		    filter_pkt->on_completion;
		pkt->compl.send.send_completion_context =
		    filter_pkt->completion_context;
	}

	DPRINT_EXIT(NETVSC);

	return (ret);
}

/*
 * RNDIS filter on send completion
 */
static void 
hv_rf_on_send_completion(void *context)
{
	rndis_filter_packet *filter_pkt = (rndis_filter_packet *)context;

	DPRINT_ENTER(NETVSC);

	/* Pass it back to the original handler */
	filter_pkt->on_completion(filter_pkt->completion_context);

	DPRINT_EXIT(NETVSC);
}

/*
 * RNDIS filter on send request completion
 */
static void 
hv_rf_on_send_request_completion(void *context)
{
	DPRINT_ENTER(NETVSC);

	/* Noop */
	DPRINT_EXIT(NETVSC);
}

