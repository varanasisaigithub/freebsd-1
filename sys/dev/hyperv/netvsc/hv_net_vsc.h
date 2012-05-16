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

/*
 * Authors:
 *   Haiyang Zhang <haiyangz@microsoft.com>
 *   Hank Janssen  <hjanssen@microsoft.com>
 */

#ifndef __HV_NET_VSC_H__
#define __HV_NET_VSC_H__

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sema.h>

#include "../include/hyperv.h"


#define NVSP_INVALID_PROTOCOL_VERSION           (0xFFFFFFFF)

#define NVSP_PROTOCOL_VERSION_1                 2
#define NVSP_PROTOCOL_VERSION_2                 0x30002
#define NVSP_MIN_PROTOCOL_VERSION               (NVSP_PROTOCOL_VERSION_1)
#define NVSP_MAX_PROTOCOL_VERSION               (NVSP_PROTOCOL_VERSION_2)

typedef enum nvsp_msg_type_ {
	nvsp_msg_type_none                      = 0,

	/*
	 * Init Messages
	 */
	nvsp_msg_type_init                      = 1,
	nvsp_msg_type_init_complete             = 2,

	nvsp_version_msg_start                  = 100,

	/*
	 * Version 1 Messages
	 */
	nvsp_msg_1_type_send_ndis_vers          = nvsp_version_msg_start,

	nvsp_msg_1_type_send_rx_buf,
	nvsp_msg_1_type_send_rx_buf_complete,
	nvsp_msg_1_type_revoke_rx_buf,

	nvsp_msg_1_type_send_send_buf,
	nvsp_msg_1_type_send_send_buf_complete,
	nvsp_msg_1_type_revoke_send_buf,

	nvsp_msg_1_type_send_rndis_pkt,
	nvsp_msg_1_type_send_rndis_pkt_complete,
    
	/*
	 * Version 2 Messages
	 */
	nvsp_msg_2_type_send_chimney_delegated_buf,
	nvsp_msg_2_type_send_chimney_delegated_buf_complete,
	nvsp_msg_2_type_revoke_chimney_delegated_buf,

	nvsp_msg_2_type_resume_chimney_rx_indication,

	nvsp_msg_2_type_terminate_chimney,
	nvsp_msg_2_type_terminate_chimney_complete,

	nvsp_msg_2_type_indicate_chimney_event,

	nvsp_msg_2_type_send_chimney_packet,
	nvsp_msg_2_type_send_chimney_packet_complete,

	nvsp_msg_2_type_post_chimney_rx_request,
	nvsp_msg_2_type_post_chimney_rx_request_complete,

	nvsp_msg_2_type_alloc_rx_buf,
	nvsp_msg_2_type_alloc_rx_buf_complete,

	nvsp_msg_2_type_free_rx_buf,

	nvsp_msg_2_send_vmq_rndis_pkt,
	nvsp_msg_2_send_vmq_rndis_pkt_complete,

	nvsp_msg_2_type_send_ndis_config,

	nvsp_msg_2_type_alloc_chimney_handle,
	nvsp_msg_2_type_alloc_chimney_handle_complete,
} nvsp_msg_type;

typedef enum nvsp_status_ {
	nvsp_status_none = 0,
	nvsp_status_success,
	nvsp_status_failure,
	/* Deprecated */
	nvsp_status_prot_vers_range_too_new,
	/* Deprecated */
	nvsp_status_prot_vers_range_too_old,
	nvsp_status_invalid_rndis_pkt,
	nvsp_status_busy,
	nvsp_status_max,
} nvsp_status;

typedef struct nvsp_msg_hdr_ {
	uint32_t                                msg_type;
} __attribute__((packed)) nvsp_msg_hdr;

/*
 * Init Messages
 */

/*
 * This message is used by the VSC to initialize the channel
 * after the channels has been opened. This message should 
 * never include anything other then versioning (i.e. this
 * message will be the same for ever).
 */
typedef struct nvsp_msg_init_ {
	uint32_t                                min_protocol_version;
	uint32_t                                max_protocol_version;
} __attribute__((packed)) nvsp_msg_init;

/*
 * This message is used by the VSP to complete the initialization
 * of the channel. This message should never include anything other 
 * then versioning (i.e. this message will be the same for ever).
 */
typedef struct nvsp_msg_init_complete_ {
	uint32_t                                negotiated_prot_vers;
	uint32_t                                max_mdl_chain_len;
	uint32_t                                status;
} __attribute__((packed)) nvsp_msg_init_complete;

typedef union nvsp_msg_init_uber_ {
	nvsp_msg_init                           init;
	nvsp_msg_init_complete                  init_compl;
} __attribute__((packed)) nvsp_msg_init_uber;

/*
 * Version 1 Messages
 */

/*
 * This message is used by the VSC to send the NDIS version
 * to the VSP. The VSP can use this information when handling
 * OIDs sent by the VSC.
 */
typedef struct nvsp_1_msg_send_ndis_version_ {
	uint32_t                                ndis_major_vers;
	uint32_t                                ndis_minor_vers;
} __attribute__((packed)) nvsp_1_msg_send_ndis_version;

/*
 * This message is used by the VSC to send a receive buffer
 * to the VSP. The VSP can then use the receive buffer to
 * send data to the VSC.
 */
typedef struct nvsp_1_msg_send_rx_buf_ {
	uint32_t                                gpadl_handle;
	uint16_t                                id;
} __attribute__((packed)) nvsp_1_msg_send_rx_buf;

typedef struct nvsp_1_rx_buf_section_ {
	uint32_t                                offset;
	uint32_t                                sub_allocation_size;
	uint32_t                                num_sub_allocations;
	uint32_t                                end_offset;
} __attribute__((packed)) nvsp_1_rx_buf_section;

/*
 * This message is used by the VSP to acknowledge a receive 
 * buffer send by the VSC. This message must be sent by the 
 * VSP before the VSP uses the receive buffer.
 */
typedef struct nvsp_1_msg_send_rx_buf_complete_ {
	uint32_t                                status;
	uint32_t                                num_sections;

	/*
	 * The receive buffer is split into two parts, a large
	 * suballocation section and a small suballocation
	 * section. These sections are then suballocated by a 
	 * certain size.
	 *
	 * For example, the following break up of the receive
	 * buffer has 6 large suballocations and 10 small
	 * suballocations.
	 *
	 * |            Large Section          |  |   Small Section   |
	 * ------------------------------------------------------------
	 * |     |     |     |     |     |     |  | | | | | | | | | | |
	 * |                                      |  
	 * LargeOffset                            SmallOffset
	 */
	nvsp_1_rx_buf_section                   sections[1];

} __attribute__((packed)) nvsp_1_msg_send_rx_buf_complete;

/*
 * This message is sent by the VSC to revoke the receive buffer.
 * After the VSP completes this transaction, the vsp should never
 * use the receive buffer again.
 */
typedef struct nvsp_1_msg_revoke_rx_buf_ {
	uint16_t                                id;
} __attribute__((packed)) nvsp_1_msg_revoke_rx_buf;

/*
 * This message is used by the VSC to send a send buffer
 * to the VSP. The VSC can then use the send buffer to
 * send data to the VSP.
 */
typedef struct nvsp_1_msg_send_send_buf_ {
	uint32_t                                gpadl_handle;
	uint16_t                                id;
} __attribute__((packed)) nvsp_1_msg_send_send_buf;

/*
 * This message is used by the VSP to acknowledge a send 
 * buffer sent by the VSC. This message must be sent by the 
 * VSP before the VSP uses the sent buffer.
 */
typedef struct nvsp_1_msg_send_send_buf_complete_ {
	uint32_t                                status;

	/*
	 * The VSC gets to choose the size of the send buffer and
	 * the VSP gets to choose the sections size of the buffer.
	 * This was done to enable dynamic reconfigurations when
	 * the cost of GPA-direct buffers decreases.
	 */
	uint32_t                                section_size;
} __attribute__((packed)) nvsp_1_msg_send_send_buf_complete;

/*
 * This message is sent by the VSC to revoke the send buffer.
 * After the VSP completes this transaction, the vsp should never
 * use the send buffer again.
 */
typedef struct nvsp_1_msg_revoke_send_buf_ {
	uint16_t                                id;
} __attribute__((packed)) nvsp_1_msg_revoke_send_buf;

/*
 * This message is used by both the VSP and the VSC to send
 * an RNDIS message to the opposite channel endpoint.
 */
typedef struct nvsp_1_msg_send_rndis_pkt_ {
	/*
	 * This field is specified by RNIDS.  They assume there's
	 * two different channels of communication. However, 
	 * the Network VSP only has one.  Therefore, the channel
	 * travels with the RNDIS packet.
	 */
	uint32_t                                chan_type;

	/*
	 * This field is used to send part or all of the data
	 * through a send buffer. This values specifies an 
	 * index into the send buffer.  If the index is 
	 * 0xFFFFFFFF, then the send buffer is not being used
	 * and all of the data was sent through other VMBus
	 * mechanisms.
	 */
	uint32_t                                send_buf_section_idx;
	uint32_t                                send_buf_section_size;
} __attribute__((packed)) nvsp_1_msg_send_rndis_pkt;

/*
 * This message is used by both the VSP and the VSC to complete
 * a RNDIS message to the opposite channel endpoint.  At this
 * point, the initiator of this message cannot use any resources
 * associated with the original RNDIS packet.
 */
typedef struct nvsp_1_msg_send_rndis_pkt_complete_ {
	uint32_t                                status;
} __attribute__((packed)) nvsp_1_msg_send_rndis_pkt_complete;

typedef union nvsp_1_msg_uber_ {
	nvsp_1_msg_send_ndis_version            send_ndis_vers;

	nvsp_1_msg_send_rx_buf                  send_rx_buf;
	nvsp_1_msg_send_rx_buf_complete         send_rx_buf_complete;
	nvsp_1_msg_revoke_rx_buf                revoke_rx_buf;

	nvsp_1_msg_send_send_buf                send_send_buf;
	nvsp_1_msg_send_send_buf_complete       send_send_buf_complete;
	nvsp_1_msg_revoke_send_buf              revoke_send_buf;

	nvsp_1_msg_send_rndis_pkt               send_rndis_pkt;
	nvsp_1_msg_send_rndis_pkt_complete      send_rndis_pkt_complete;
} __attribute__((packed)) nvsp_1_msg_uber;

typedef union nvsp_all_msgs_ {
	nvsp_msg_init_uber                      init_msgs;
	nvsp_1_msg_uber                         vers_1_msgs;
} __attribute__((packed)) nvsp_all_msgs;

/*
 * ALL Messages
 */
typedef struct nvsp_msg_ {
	nvsp_msg_hdr                            hdr; 
	nvsp_all_msgs                           msgs;
} __attribute__((packed)) nvsp_msg;


/*
 * Defines
 */

/*#define NVSC_MIN_PROTOCOL_VERSION		1 */
/*#define NVSC_MAX_PROTOCOL_VERSION		1 */

#define NETVSC_SEND_BUFFER_SIZE			(64*1024)   /* 64K */
#define NETVSC_SEND_BUFFER_ID			0xface


#define NETVSC_RECEIVE_BUFFER_SIZE		(1024*1024) /* 1MB */

#define NETVSC_RECEIVE_BUFFER_ID		0xcafe

#define NETVSC_RECEIVE_SG_COUNT			1

/* Preallocated receive packets */
#define NETVSC_RECEIVE_PACKETLIST_COUNT		256

/*
 * Data types
 */

/*
 * Per netvsc channel-specific
 */
typedef struct netvsc_dev_ {
	struct hv_device			*dev;
	int					num_outstanding_sends;

	/* List of free preallocated NETVSC_PACKET to represent RX packet */
	STAILQ_HEAD(PQ, netvsc_packet_)		myrx_packet_list;
	struct mtx				rx_pkt_list_lock;

	/* Send buffer allocated by us but manages by NetVSP */
	void					*send_buf;
	uint32_t				send_buf_size;
	uint32_t				send_buf_gpadl_handle;
	uint32_t				send_section_size;

	/* Receive buffer allocated by us but managed by NetVSP */
	void					*rx_buf;
	uint32_t				rx_buf_size;
	uint32_t				rx_buf_gpadl_handle;
	uint32_t				rx_section_count;
	nvsp_1_rx_buf_section			*rx_sections;

	/* Used for NetVSP initialization protocol */
	struct sema				channel_init_sema;
	nvsp_msg				channel_init_packet;

	nvsp_msg				revoke_packet;
	/*uint8_t				hw_mac_addr[HW_MACADDR_LEN];*/

	/* Holds rndis device info */
	void					*extension;

	hv_small_bool				destroy;
	/* Negotiated NVSP version */
	uint32_t				nvsp_version;
} netvsc_dev;


typedef void (*pfn_on_send_rx_completion)(void *);

#define NETVSC_DEVICE_RING_BUFFER_SIZE   (64 * PAGE_SIZE)
#define NETVSC_PACKET_MAXPAGE            4


typedef struct xfer_page_packet_ {
	/*
	 * This needs to be here because the network RX code casts
	 * an instantiation of this structure to a netvsc_packet.
	 */
	STAILQ_ENTRY(netvsc_packet_) mylist_entry;

	uint32_t count;
} xfer_page_packet;

typedef struct netvsc_packet_ {
	/*
	 * List used when enqueued on &net_dev->rx_packet_list,
	 * and when enqueued within the netvsc code
	 */
	STAILQ_ENTRY(netvsc_packet_)	mylist_entry;
	struct hv_device		*device;
	hv_small_bool			is_data_pkt;      /* One byte */
	xfer_page_packet		*xfer_page_pkt;

	/* Completion */
	union {
		struct {
			uint64_t   rx_completion_tid;
			void	   *rx_completion_context;
			/* This is no longer used */
			pfn_on_send_rx_completion   on_rx_completion;
		} rx;
		struct {
			uint64_t    send_completion_tid;
			void	    *send_completion_context;
			/* Still used in netvsc and filter code */
			pfn_on_send_rx_completion   on_send_completion;
		} send;
	} compl;

	void		*extension;
	uint32_t	tot_data_buf_len;
	uint32_t	page_buf_count;
	hv_vmbus_page_buffer	page_buffers[NETVSC_PACKET_MAXPAGE];
} netvsc_packet;


typedef struct netvsc_driver_object_ {
	uint32_t	ring_buf_size;
	uint32_t	request_ext_size;
	uint32_t	additional_request_page_buf_cnt;
	void		*context;
} netvsc_driver_object;

typedef struct {
	uint8_t		mac_addr[6];  /* Assumption unsigned long */
	hv_small_bool	link_state;
} netvsc_device_info;

/*
 * Device-specific softc structure
 */
typedef struct hn_softc {
	struct ifnet	*hn_ifp;
	struct arpcom   arpcom;
	device_t        hn_dev;
	uint8_t         hn_unit;
	int             hn_carrier;
	int             hn_if_flags;
	struct mtx      hn_lock;
/*	vm_offset_t     hn_vaddr;		*/
	int             hn_initdone;
/*	int             hn_xc;			*/
	struct hv_device   *hn_dev_obj;
	netvsc_dev  	*net_dev;
/*	int             hn_cb_status;		*/
/*	uint64_t        hn_sts_err_tx_nobufs;	*/
/*	uint64_t        hn_sts_err_tx_enxio; 	*/ /* device not ready to xmit */
/*	uint64_t        hn_sts_err_tx_eio;	*/ /* device not ready to xmit */
} hn_softc_t;


/*
 * Externs
 */
extern int hv_promisc_mode;

void hv_nv_on_receive_completion(void *context);
void netvsc_linkstatus_callback(struct hv_device *device_obj,
				       uint32_t status);
int  netvsc_recv_callback(struct hv_device *device_obj,
				 netvsc_packet *packet);
netvsc_dev *hv_nv_on_device_add(struct hv_device *device, void *additional_info);
int  hv_nv_on_device_remove(struct hv_device *device);
int  hv_nv_on_send(struct hv_device *device, netvsc_packet *pkt);

#endif  /* __HV_NET_VSC_H__ */

