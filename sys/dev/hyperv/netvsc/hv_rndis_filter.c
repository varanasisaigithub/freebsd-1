/*-
 * Copyright (c) 2012 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 *   K. Y. Srinivasan <kys@microsoft.com>
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <machine/atomic.h>
#include <sys/sema.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <dev/hyperv/include/hyperv.h>
#include "hv_net_vsc.h"
#include "hv_rndis.h"

/*
 * Data types
 */

typedef enum {
	RNDIS_DEV_UNINITIALIZED = 0,
	RNDIS_DEV_INITIALIZING,
	RNDIS_DEV_INITIALIZED,
	RNDIS_DEV_DATAINITIALIZED,
} rndis_device_state;

typedef struct rndis_request_ {
	STAILQ_ENTRY(rndis_request_)	mylist_entry;
	struct sema			wait_sema;	

	/*
	 * Fixme:  We assumed a fixed size response here.  If we do ever
	 * need to handle a bigger response, we can either define a max
	 * response message or add a response buffer variable above this field
	 */
	rndis_msg			response_msg;

	/* Simplify allocation by having a netvsc packet inline */
	netvsc_packet			pkt;
	hv_vmbus_page_buffer			buffer;
	/* Fixme:  We assumed a fixed size request here. */
	rndis_msg			request_msg;
} rndis_request;

typedef struct rndis_device_ {
	netvsc_dev			*net_dev;

	rndis_device_state		state;
	uint32_t			link_status;
	uint32_t			new_request_id;

	struct mtx			req_lock;

	STAILQ_HEAD(RQ, rndis_request_)	myrequest_list;

	uint8_t				hw_mac_addr[HW_MACADDR_LEN];
} rndis_device;

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
static void hv_rf_receive_data(rndis_device *device, rndis_msg *message,
			       netvsc_packet *pkt);
static int  hv_rf_query_device(rndis_device *device, uint32_t oid,
			       void *result, uint32_t *result_size);
static inline int hv_rf_query_device_mac(rndis_device *device);
static inline int hv_rf_query_device_link_status(rndis_device *device);
static int  hv_rf_set_packet_filter(rndis_device *device, uint32_t new_filter);
static int  hv_rf_init_device(rndis_device *device);
static int  hv_rf_open_device(rndis_device *device);
static int  hv_rf_close_device(rndis_device *device);
static void hv_rf_on_send_completion(void *context);
static void hv_rf_on_send_request_completion(void *context);


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

	sema_init(&request->wait_sema, 0, "rndis sema");
	
	rndis_mesg = &request->request_msg;
	rndis_mesg->ndis_msg_type = message_type;
	rndis_mesg->msg_len = message_length;

	/*
	 * Set the request id. This field is always after the rndis header
	 * for request/response packet types so we just use the set_request
	 * as a template.
	 */
	set = &rndis_mesg->msg.set_request;
	set->request_id = atomic_fetchadd_int(&device->new_request_id, 1);
	/* Increment to get the new value (call above returns old value) */
	set->request_id += 1; /* KYS need to add 1! */

	/* Add to the request list */
	mtx_lock_spin(&device->req_lock);
	STAILQ_INSERT_TAIL(&device->myrequest_list, request, mylist_entry);
	mtx_unlock_spin(&device->req_lock);

	return (request);
}

/*
 *
 */
static inline void
hv_put_rndis_request(rndis_device *device, rndis_request *request)
{
	mtx_lock_spin(&device->req_lock);
	/* Fixme:  Has O(n) performance */
	/*
	 * XXXKYS: Use Doubly linked lists.
	 */
	STAILQ_REMOVE(&device->myrequest_list, request, rndis_request_,
	    mylist_entry);
	mtx_unlock_spin(&device->req_lock);

	sema_destroy(&request->wait_sema);
	free(request, M_DEVBUF);
}

/*
 *
 */
static int
hv_rf_send_request(rndis_device *device, rndis_request *request)
{
	int ret = 0;
	netvsc_packet *packet;

	/* Set up the packet to send it */
	packet = &request->pkt;
	
	packet->is_data_pkt = FALSE;
	packet->tot_data_buf_len = request->request_msg.msg_len;
	packet->page_buf_count = 1;

	packet->page_buffers[0].pfn =
		hv_get_phys_addr(&request->request_msg) >> PAGE_SHIFT;
	packet->page_buffers[0].length = request->request_msg.msg_len;
	packet->page_buffers[0].offset =
	    (unsigned long)&request->request_msg & (PAGE_SIZE - 1);

	packet->compl.send.send_completion_context = request; /* packet; */
	packet->compl.send.on_send_completion =
	    hv_rf_on_send_request_completion;
	packet->compl.send.send_completion_tid = (unsigned long)device;

	ret = hv_nv_on_send(device->net_dev->dev, packet);

	return (ret);
}

/*
 * RNDIS filter receive response
 */
static void 
hv_rf_receive_response(rndis_device *device, rndis_msg *response)
{
	rndis_request *request = NULL;
	rndis_request *next_request;
	bool found = FALSE;

	mtx_lock_spin(&device->req_lock);
	request = STAILQ_FIRST(&device->myrequest_list);
	while (request != NULL) {
		/*
		 * All request/response message contains request_id as the
		 * first field
		 */
		if (request->request_msg.msg.init_request.request_id ==
				      response->msg.init_complete.request_id) {
			found = TRUE;
			break;
		}
		next_request = STAILQ_NEXT(request, mylist_entry);
		request = next_request;
	}
	mtx_unlock_spin(&device->req_lock);

	if (found) {
		if (response->msg_len <= sizeof(rndis_msg)) {
			memcpy(&request->response_msg, response,
			    response->msg_len);
		} else {
			if (response->ndis_msg_type == REMOTE_NDIS_RESET_CMPLT) {
				/* Does not have a request id field */
				request->response_msg.msg.reset_complete.status =
				    STATUS_BUFFER_OVERFLOW;
			} else {
				request->response_msg.msg.init_complete.status =
				    STATUS_BUFFER_OVERFLOW;
			}
		}

		sema_post(&request->wait_sema);
	}
}

/*
 * RNDIS filter receive indicate status
 */
static void 
hv_rf_receive_indicate_status(rndis_device *device, rndis_msg *response)
{
	rndis_indicate_status *indicate = &response->msg.indicate_status;
		
	if (indicate->status == RNDIS_STATUS_MEDIA_CONNECT) {
		netvsc_linkstatus_callback(device->net_dev->dev, 1);
	} else if (indicate->status == RNDIS_STATUS_MEDIA_DISCONNECT) {
		netvsc_linkstatus_callback(device->net_dev->dev, 0);
	} else {
		/* TODO: */
	}
}

/*
 * RNDIS filter receive data
 */
static void
hv_rf_receive_data(rndis_device *device, rndis_msg *message, netvsc_packet *pkt)
{
	rndis_packet *rndis_pkt;
	uint32_t data_offset;

	rndis_pkt = &message->msg.packet;

	/*
	 * Fixme:  Handle multiple rndis pkt msgs that may be enclosed in this
	 * netvsc packet (ie tot_data_buf_len != message_length)
	 */

	/* Remove the rndis header and pass it back up the stack */
	data_offset = RNDIS_HEADER_SIZE + rndis_pkt->data_offset;

	/* The L2 frame length, including CRC, which must be added. */
	pkt->tot_data_buf_len        = rndis_pkt->data_length + ETHER_CRC_LEN;
	pkt->page_buffers[0].offset += data_offset;
	pkt->page_buffers[0].length -= data_offset;

	pkt->is_data_pkt = TRUE;
		
	netvsc_recv_callback(device->net_dev->dev, pkt);
}

/*
 * RNDIS filter on receive
 */
int
hv_rf_on_receive(struct hv_device *device, netvsc_packet *pkt)
{
	hn_softc_t *sc = device_get_softc(device->device);
	netvsc_dev *net_dev = sc->net_dev;
	rndis_device *rndis_dev;
	rndis_msg rndis_mesg;
	rndis_msg *rndis_hdr;

	/* Make sure the rndis device state is initialized */
	if (!net_dev->extension) {
		return (ENODEV);
	}

	rndis_dev = (rndis_device *)net_dev->extension;
	if (rndis_dev->state == RNDIS_DEV_UNINITIALIZED) {
		return (EINVAL);
	}

	/* Shift virtual page number to form virtual page address */
	rndis_hdr = (rndis_msg *)(pkt->page_buffers[0].pfn << PAGE_SHIFT);

	rndis_hdr = (void *)((unsigned long)rndis_hdr +
	    pkt->page_buffers[0].offset);
	
	/*
	 * Make sure we got a valid rndis message
	 * Fixme:  There seems to be a bug in set completion msg where
	 * its msg_len is 16 bytes but the byte_count field in the
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

	memcpy(&rndis_mesg, rndis_hdr,
	    (rndis_hdr->msg_len > sizeof(rndis_msg)) ?
	    sizeof(rndis_msg) : rndis_hdr->msg_len);

	switch (rndis_mesg.ndis_msg_type) {

	/* data message */
	case REMOTE_NDIS_PACKET_MSG:
		hv_rf_receive_data(rndis_dev, &rndis_mesg, pkt);
		break;
	/* completion messages */
	case REMOTE_NDIS_INITIALIZE_CMPLT:
	case REMOTE_NDIS_QUERY_CMPLT:
	case REMOTE_NDIS_SET_CMPLT:
	/* Fixme:  Restored this case */
	case REMOTE_NDIS_RESET_CMPLT:
	/* Fixme:  Restored this case */
	case REMOTE_NDIS_KEEPALIVE_CMPLT:
		hv_rf_receive_response(rndis_dev, &rndis_mesg);
		break;
	/* notification message */
	case REMOTE_NDIS_INDICATE_STATUS_MSG:
		hv_rf_receive_indicate_status(rndis_dev, &rndis_mesg);
		break;
	default:
		printf("hv_rf_on_receive():  Unknown msg_type 0x%x\n",
		    rndis_mesg.ndis_msg_type);
		break;
	}

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

	sema_wait(&request->wait_sema);

	/* Copy the response back */
	query_complete = &request->response_msg.msg.query_complete;
	
	if (query_complete->info_buffer_length > inresultSize) {
		ret = EINVAL;
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
		goto cleanup;
	}

	/*
	 * XXXKYS: For some reason timed waits don't appear to work;
	 * need to check this.
	 *
	 * Fixme:  Replaced with correct sema_wait() call
	 * Address filter hang fixed elsewhere
	 * Fixme:  Remove the unnecessary return checking code
	 */
	/*ret = sema_timedwait(&request->wait_sema, 500); */ /* Fixme: KYS 5 seconds */

	sema_wait(&request->wait_sema);
	/* Fixme:  Kludge */
	ret = 1;

	if (!ret) {
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
	return (ret);
}

/*
 * RNDIS filter init
 */
int
hv_rndis_filter_init(netvsc_driver_object *driver)
{
	driver->request_ext_size = sizeof(rndis_filter_packet);
	driver->additional_request_page_buf_cnt = 1; /* For rndis header */

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

	sema_wait(&request->wait_sema);

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

	/* Attempt to do a rndis device halt */
	request = hv_rndis_request(device, REMOTE_NDIS_HALT_MSG,
	    RNDIS_MESSAGE_SIZE(rndis_halt_request));
	if (!request) {
		goto cleanup;
	}

	/* Set up the rndis set */
	halt = &request->request_msg.msg.halt_request;
	halt->request_id = atomic_fetchadd_int(&device->new_request_id, 1);
	halt->request_id += 1; /* KYS need to add 1! */
	
	/* Ignore return since this msg is optional. */
	hv_rf_send_request(device, request);
	
	device->state = RNDIS_DEV_UNINITIALIZED;

cleanup:
	if (request) {
		hv_put_rndis_request(device, request);
	}
}

/*
 * RNDIS filter open device
 */
static int
hv_rf_open_device(rndis_device *device)
{
	int ret = 0;

	if (device->state != RNDIS_DEV_INITIALIZED) {
		return (0);
	}

	if (hv_promisc_mode != 1) {
		ret = hv_rf_set_packet_filter(device, 
		    NDIS_PACKET_TYPE_BROADCAST     |
		    NDIS_PACKET_TYPE_ALL_MULTICAST |
		    NDIS_PACKET_TYPE_DIRECTED);
	} else {
		ret = hv_rf_set_packet_filter(device, 
		    NDIS_PACKET_TYPE_PROMISCUOUS);
	}

	if (ret == 0) {
		device->state = RNDIS_DEV_DATAINITIALIZED;
	}

	return (ret);
}

/*
 * RNDIS filter close device
 */
static int
hv_rf_close_device(rndis_device *device)
{
	int ret;

	if (device->state != RNDIS_DEV_DATAINITIALIZED) {
		return (0);
	}

	ret = hv_rf_set_packet_filter(device, 0);
	if (ret == 0) {
		device->state = RNDIS_DEV_INITIALIZED;
	}

	return (ret);
}

/*
 * RNDIS filter on device add
 */
int
hv_rf_on_device_add(struct hv_device *device, void *additl_info)
{
	int ret;
	netvsc_dev *net_dev;
	rndis_device *rndis_dev;
	netvsc_device_info *dev_info = (netvsc_device_info *)additl_info;

	rndis_dev = hv_get_rndis_device();
	if (!rndis_dev) {
		return (ENOMEM);
	}

	/*
	 * Let the inner driver handle this first to create the netvsc channel
	 * NOTE! Once the channel is created, we may get a receive callback 
	 * (hv_rf_on_receive()) before this call is completed.
	 * Earlier code used a function pointer here.
	 */
	net_dev = hv_nv_on_device_add(device, additl_info);
	if (!net_dev) {
		hv_put_rndis_device(rndis_dev);

		return (ENOMEM);
	}

	/*
	 * Initialize the rndis device
	 */

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
	
	memcpy(dev_info->mac_addr, rndis_dev->hw_mac_addr, HW_MACADDR_LEN);

	hv_rf_query_device_link_status(rndis_dev);
	
	dev_info->link_state = rndis_dev->link_status;

	return (ret);
}

/*
 * RNDIS filter on device remove
 */
int
hv_rf_on_device_remove(struct hv_device *device)
{
	hn_softc_t *sc = device_get_softc(device->device);	
	netvsc_dev *net_dev = sc->net_dev;
	rndis_device *rndis_dev = (rndis_device *)net_dev->extension;

	/* Halt and release the rndis device */
	hv_rf_halt_device(rndis_dev);

	hv_put_rndis_device(rndis_dev);
	net_dev->extension = NULL;

	/* Pass control to inner driver to remove the device */
	hv_nv_on_device_remove(device);

	return (0);
}

/*
 * RNDIS filter on open
 */
int
hv_rf_on_open(struct hv_device *device)
{
	hn_softc_t *sc = device_get_softc(device->device);	
	netvsc_dev *net_dev = sc->net_dev;

	return (hv_rf_open_device((rndis_device *)net_dev->extension));
}

/*
 * RNDIS filter on close
 */
int 
hv_rf_on_close(struct hv_device *device)
{
	hn_softc_t *sc = device_get_softc(device->device);	
	netvsc_dev *net_dev = sc->net_dev;

	return (hv_rf_close_device((rndis_device *)net_dev->extension));
}

/*
 * RNDIS filter on send
 */
int
hv_rf_on_send(struct hv_device *device, netvsc_packet *pkt)
{
	rndis_filter_packet *filter_pkt;
	rndis_msg *rndis_mesg;
	rndis_packet *rndis_pkt;
	uint32_t rndis_msg_size;
	int ret = 0;

	/* Add the rndis header */
	filter_pkt = (rndis_filter_packet *)pkt->extension;

	memset(filter_pkt, 0, sizeof(rndis_filter_packet));

	rndis_mesg = &filter_pkt->message;
	rndis_msg_size = RNDIS_MESSAGE_SIZE(rndis_packet);

	rndis_mesg->ndis_msg_type = REMOTE_NDIS_PACKET_MSG;
	rndis_mesg->msg_len = pkt->tot_data_buf_len + rndis_msg_size;
	
	rndis_pkt = &rndis_mesg->msg.packet;
	rndis_pkt->data_offset = sizeof(rndis_packet);
	rndis_pkt->data_length = pkt->tot_data_buf_len;

	pkt->is_data_pkt = TRUE;
	pkt->page_buffers[0].pfn =
		hv_get_phys_addr(rndis_mesg) >> PAGE_SHIFT;
	pkt->page_buffers[0].offset =
	    (unsigned long)rndis_mesg & (PAGE_SIZE - 1);
	pkt->page_buffers[0].length = rndis_msg_size;

	/* Save the packet send completion and context */
	filter_pkt->on_completion = pkt->compl.send.on_send_completion;
	filter_pkt->completion_context =
	    pkt->compl.send.send_completion_context;

	/* Use ours */
	pkt->compl.send.on_send_completion = hv_rf_on_send_completion;
	pkt->compl.send.send_completion_context = filter_pkt;

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

	return (ret);
}

/*
 * RNDIS filter on send completion
 */
static void 
hv_rf_on_send_completion(void *context)
{
	rndis_filter_packet *filter_pkt = (rndis_filter_packet *)context;

	/* Pass it back to the original handler */
	filter_pkt->on_completion(filter_pkt->completion_context);
}

/*
 * RNDIS filter on send request completion
 */
static void 
hv_rf_on_send_request_completion(void *context)
{
}

