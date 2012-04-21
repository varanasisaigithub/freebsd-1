
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
 * Copyright (c) 2010-2012, Citrix, Inc.
 *
 * Ported from lis21 code drop
 *
 * HyperV definitions for messages that are sent between instances of the
 * Channel Management Library in separate partitions, or in some cases,
 * back to itself.
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

#ifndef __HYPERV_H__
#define __HYPERV_H__

#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/kthread.h>
#include <sys/taskqueue.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/sema.h>
#include <sys/mutex.h>
#include <sys/bus.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <amd64/include/xen/synch_bitops.h>
#include <amd64/include/atomic.h>


typedef unsigned char bool;

#ifndef false
#define false  0
#endif

#ifndef true
#define true  1
#endif

#define HV_S_OK			0x00000000
#define HV_E_FAIL		0x80004005
#define HV_ERROR_NOT_SUPPORTED	0x80070032
#define HV_ERROR_MACHINE_LOCKED	0x800704F7

/*
 * A revision number of vmbus that is used for ensuring both ends on a
 * partition are using compatible versions.
 */
#define HV_VMBUS_REVISION_NUMBER	13

/*
 * Make maximum size of pipe payload of 16K
 */
#define HV_MAX_PIPE_DATA_PAYLOAD	(sizeof(BYTE) * 16384)

/*
 * Define pipe_mode values
 */
#define HV_VMBUS_PIPE_TYPE_BYTE		0x00000000
#define HV_VMBUS_PIPE_TYPE_MESSAGE	0x00000004

/*
 * The size of the user defined data buffer for non-pipe offers
 */
#define HV_MAX_USER_DEFINED_BYTES	120

/*
 *  The size of the user defined data buffer for pipe offers
 */
#define HV_MAX_PIPE_USER_DEFINED_BYTES	116

#pragma pack(push,1)

typedef struct hv_guid {
	 unsigned char data[16];
} hv_guid;

typedef struct hv_guid hv_guid;

typedef struct hv_bound {
	int interrupt_mask;
	int read_index;
	int write_index;
	int bytes_avail_to_read;
	int bytes_avail_to_write;
} hv_bound;

typedef struct hv_devinfo {
	int channel_id;
	int channel_state;
	int channel_type;
	int channel_instance;
	int monitor_id;
	int server_monitor_pending;
	int server_monitor_latency;
	int server_monitor_connection_id;
	int client_monitor_pending;
	int client_monitor_latency;
	int client_monitor_connection_id;
	hv_bound in_bound, out_bound;
} hv_devinfo;

/*
 * At the center of the Channel Management library is
 * the Channel Offer. This struct contains the
 * fundamental information about an offer.
 */

typedef struct hv_vmbus_channel_offer {
	hv_guid		interface_type;
	hv_guid		interface_instance;
	uint64_t	interrupt_latency_in_100ns_units;
	uint32_t	interface_revision;
	uint32_t	server_context_area_size; /* in bytes */
	uint16_t	channel_flags;
	uint16_t	mmio_megabytes;		  /* in bytes * 1024 * 1024 */
	union
	{
        /*
         * Non-pipes: The user has HV_MAX_USER_DEFINED_BYTES bytes.
         */
		struct {
			uint8_t	user_defined[HV_MAX_USER_DEFINED_BYTES];
		} standard;

        /*
         * Pipes: The following structure is an integrated pipe protocol, which
         *        is implemented on top of standard user-defined data. pipe clients
         *        have HV_MAX_PIPE_USER_DEFINED_BYTES left for their own use.
         */
		struct {
			uint32_t	pipe_mode;
			uint8_t	user_defined[HV_MAX_PIPE_USER_DEFINED_BYTES];
		} pipe;
	} u;

	uint32_t	padding;

} hv_vmbus_channel_offer;

typedef uint32_t hv_gpadl_handle;

typedef struct {
	union {
		struct {
			volatile uint32_t  in;  /* offset in bytes from the ring base */
			volatile uint32_t  out; /* offset in bytes from the ring base */
		} io;
		volatile int64_t	in_out;
	} rio;

	/*
	 * If the receiving endpoint sets this to some non-zero
	 * value, the sending endpoint should not send any interrupts.
	 */
	volatile uint32_t interrupt_mask;
} hv_vm_rcb;

typedef struct {
	union {
		struct {
			hv_vm_rcb control;
		} ctl;
		uint8_t reserved[PAGE_SIZE];
	} rctl;

	/*
	 * Beginning of the ring data.  Note: It must be guaranteed that
	 * this data does not share a page with the control structure.
	 */
	uint8_t data[1];
} hv_vm_ring;

typedef struct {
	uint16_t type;
	uint16_t data_offset8;
	uint16_t length8;
	uint16_t flags;
	uint64_t transaction_id;
} hv_vm_packet_descriptor;

typedef uint32_t hv_previous_packet_offset;

typedef struct {
	hv_previous_packet_offset	previous_packet_start_offset;
	hv_vm_packet_descriptor		descriptor;
} hv_vm_packet_header;

typedef struct {
	uint32_t byte_count;
	uint32_t byte_offset;
} hv_vm_transfer_page;

typedef struct {
	hv_vm_packet_descriptor	d;
	uint16_t		transfer_page_set_id;
	bool			sender_owns_set;
	uint8_t			reserved;
	uint32_t		range_count;
	hv_vm_transfer_page	ranges[1];
} hv_vm_transfer_page_packet_header;

typedef struct {
	hv_vm_packet_descriptor	d;
	uint32_t		gpadl;
	uint32_t		reserved;
} hv_vm_gpadl_packet_header;

typedef struct {
	hv_vm_packet_descriptor	d;
	uint32_t		gpadl;
	uint16_t		transfer_page_set_id;
	uint16_t		reserved;
} hv_vm_add_remove_transfer_page_set;

/*
 * This structure defines a range in guest
 * physical space that can be made
 * to look virtually contiguous.
 */

typedef struct {
	uint32_t  byte_count;
	uint32_t  byte_offset;
	uint64_t  pfn_array[0];
} hv_gpa_range;

/*
 * This is the format for an Establish Gpadl packet, which contains a handle
 * by which this GPADL will be known and a set of GPA ranges associated with
 * it.  This can be converted to a MDL by the guest OS.  If there are multiple
 * GPA ranges, then the resulting MDL will be "chained," representing multiple
 * VA ranges.
 */

typedef struct {
	hv_vm_packet_descriptor	d;
	uint32_t		gpadl;
	uint32_t		range_count;
	hv_gpa_range		range[1];
} hv_vm_establish_gpadl;

/*
 * This is the format for a Teardown Gpadl packet, which indicates that the
 * GPADL handle in the Establish Gpadl packet will never be referenced again.
 */

typedef struct {
	hv_vm_packet_descriptor	d;
	uint32_t		gpadl;
	uint32_t		reserved; // for alignment to a 8-byte boundary
} hv_vm_teardown_gpadl;

/*
 * This is the format for a GPA-Direct packet, which contains a set of GPA
 * ranges, in addition to commands and/or data.
 */

typedef struct {
	hv_vm_packet_descriptor	d;
	uint32_t		reserved;
	uint32_t		range_count;
	hv_gpa_range		range[1];
} hv_vm_data_gpa_direct;

/*
 * This is the format for a Additional data Packet.
 */

typedef struct {
	hv_vm_packet_descriptor	d;
	uint64_t		total_bytes;
	uint32_t		byte_offset;
	uint32_t		byte_count;
	uint8_t			data[1];
} hv_vm_additional_data;

typedef union {
	hv_vm_packet_descriptor             simple_header;
	hv_vm_transfer_page_packet_header   transfer_page_header;
	hv_vm_gpadl_packet_header           gpadl_header;
	hv_vm_add_remove_transfer_page_set  add_remove_transfer_page_header;
	hv_vm_establish_gpadl               establish_gpadl_header;
	hv_vm_teardown_gpadl                teardown_gpadl_header;
	hv_vm_data_gpa_direct               data_gpa_direct_header;
} hv_vm_packet_largest_possible_header;

#define HV_VMPACKET_DATA_START_ADDRESS(__packet)                           \
    (void *)(((PUCHAR)__packet) + ((hv_vm_packet_descriptor *)__packet)->data_offset8 * 8)

#define HV_VMPACKET_DATA_LENGTH(__packet)                                  \
    ((((hv_vm_packet_descriptor *)__packet)->length8 - ((hv_vm_packet_descriptor *)__packet)->data_offset8) * 8)

#define HV_VMPACKET_TRANSFER_MODE(__packet) ((hv_vm_packet_descriptor *)__packet)->type

typedef enum {
	HV_VMBUS_SERVER_ENDPOINT = 0,
	HV_VMBUS_CLIENT_ENDPOINT,
	HV_VMBUS_ENDPOINT_MAXIMUM
} hv_endpoint_type;

typedef enum {
	HV_VMBUS_PACKET_TYPE_INVALID				= 0x0,
	HV_VMBUS_PACKET_TYPES_SYNCH				= 0x1,
	HV_VMBUS_PACKET_TYPE_ADD_TRANSFER_PAGE_SET		= 0x2,
	HV_VMBUS_PACKET_TYPE_REMOVE_TRANSFER_PAGE_SET		= 0x3,
	HV_VMBUS_PACKET_TYPE_ESTABLISH_GPADL			= 0x4,
	HV_VMBUS_PACKET_TYPE_TEAR_DOWN_GPADL			= 0x5,
	HV_VMBUS_PACKET_TYPE_DATA_IN_BAND			= 0x6,
	HV_VMBUS_PACKET_TYPE_DATA_USING_TRANSFER_PAGES		= 0x7,
	HV_VMBUS_PACKET_TYPE_DATA_USING_GPADL			= 0x8,
	HV_VMBUS_PACKET_TYPE_DATA_USING_GPA_DIRECT		= 0x9,
	HV_VMBUS_PACKET_TYPE_CANCEL_REQUEST			= 0xa,
	HV_VMBUS_PACKET_TYPE_COMPLETION				= 0xb,
	HV_VMBUS_PACKET_TYPE_DATA_USING_ADDITIONAL_PACKETS	= 0xc,
	HV_VMBUS_PACKET_TYPE_ADDITIONAL_DATA = 0xd
} hv_vmbus_packet_type;

#define HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED    1

/*
 * Version 1 messages
 */
typedef enum {
	HV_CHANNEL_MESSAGE_INVALID			= 0,
	HV_CHANNEL_MESSAGE_OFFER_CHANNEL		= 1,
	HV_CHANNEL_MESSAGE_RESCIND_CHANNEL_OFFER	= 2,
	HV_CHANNEL_MESSAGE_REQUEST_OFFERS		= 3,
	HV_CHANNEL_MESSAGE_ALL_OFFERS_DELIVERED		= 4,
	HV_CHANNEL_MESSAGE_OPEN_CHANNEL			= 5,
	HV_CHANNEL_MESSAGE_OPEN_CHANNEL_RESULT		= 6,
	HV_CHANNEL_MESSAGE_CLOSE_CHANNEL		= 7,
	HV_CHANNEL_MESSAGEL_GPADL_HEADER		= 8,
	HV_CHANNEL_MESSAGE_GPADL_BODY			= 9,
	HV_CHANNEL_MESSAGE_GPADL_CREATED		= 10,
	HV_CHANNEL_MESSAGE_GPADL_TEARDOWN		= 11,
	HV_CHANNEL_MESSAGE_GPADL_TORNDOWN		= 12,
	HV_CHANNEL_MESSAGE_REL_ID_RELEASED		= 13,
	HV_CHANNEL_MESSAGE_INITIATED_CONTACT		= 14,
	HV_CHANNEL_MESSAGE_VERSION_RESPONSE		= 15,
	HV_CHANNEL_MESSAGE_UNLOAD			= 16,

#ifdef	HV_VMBUS_FEATURE_PARENT_OR_PEER_MEMORY_MAPPED_INTO_A_CHILD
	HV_CHANNEL_MESSAGE_VIEW_RANGE_ADD		= 17,
	HV_CHANNEL_MESSAGE_VIEW_RANGE_REMOVE		= 18,
#endif
	HV_CHANNEL_MESSAGE_COUNT
} hv_vmbus_channel_message_type;

typedef struct {
	hv_vmbus_channel_message_type	message_type;
	uint32_t			padding;
} hv_vmbus_channel_message_header;

/*
 * Query VMBus Version parameters
 */
typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t			version;
} hv_vmbus_channel_query_vmbus_version;

/*
 * VMBus Version Supported parameters
 */
typedef struct {
	hv_vmbus_channel_message_header	header;
	bool				version_supported;
} hv_vmbus_channel_version_supported;

/*
 * Channel Offer parameters
 */
typedef struct {
	hv_vmbus_channel_message_header	header;
	hv_vmbus_channel_offer		offer;
	uint32_t			child_rel_id;
	uint8_t				monitor_id;
	bool				monitor_allocated;
} hv_vmbus_channel_offer_channel;

/*
 * Rescind Offer parameters
 */
typedef struct
{
    hv_vmbus_channel_message_header	header;
    uint32_t				child_rel_id;
} hv_vmbus_channel_rescind_offer;


/*
 * Request Offer -- no parameters, SynIC message contains the partition ID
 *
 * Set Snoop -- no parameters, SynIC message contains the partition ID
 *
 * Clear Snoop -- no parameters, SynIC message contains the partition ID
 *
 * All Offers Delivered -- no parameters, SynIC message contains the partition ID
 *
 * Flush Client -- no parameters, SynIC message contains the partition ID
 */


/*
 * Open Channel parameters
 */
typedef struct
{
    hv_vmbus_channel_message_header header;

    /*
     * Identifies the specific VMBus channel that is being opened.
     */
    uint32_t		child_rel_id;

    /*
     * ID making a particular open request at a channel offer unique.
     */
    uint32_t		open_id;

    /*
     * GPADL for the channel's ring buffer.
     */
    hv_gpadl_handle	ring_buffer_gpadl_handle;

    /*
     * GPADL for the channel's server context save area.
     */
    hv_gpadl_handle	server_context_area_gpadl_handle;

    /*
     * The upstream ring buffer begins at offset zero in the memory described
     * by ring_buffer_gpadl_handle. The downstream ring buffer follows it at this
     * offset (in pages).
     */
    uint32_t		downstream_ring_buffer_page_offset;

    /*
     * User-specific data to be passed along to the server endpoint.
     */
    uint8_t		user_data[HV_MAX_USER_DEFINED_BYTES];

} hv_vmbus_channel_open_channel;

typedef uint32_t hv_nt_status;

/*
 * Open Channel Result parameters
 */
typedef struct
{
	hv_vmbus_channel_message_header	header;
	uint32_t			child_rel_id;
	uint32_t			open_id;
	hv_nt_status			status;
} hv_vmbus_channel_open_result;

/*
 * Close channel parameters
 */
typedef struct
{
	hv_vmbus_channel_message_header	header;
	uint32_t			child_rel_id;
} hv_vmbus_channel_close_channel;

/*
 * Channel Message GPADL
 */
#define HV_GPADL_TYPE_RING_BUFFER	1
#define HV_GPADL_TYPE_SERVER_SAVE_AREA	2
#define HV_GPADL_TYPE_TRANSACTION	8

/*
 * The number of PFNs in a GPADL message is defined by the number of pages
 * that would be spanned by byte_count and byte_offset.  If the implied number
 * of PFNs won't fit in this packet, there will be a follow-up packet that
 * contains more
 */

typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	child_rel_id;
	uint32_t	gpadl;
	uint16_t	range_buf_len;
	uint16_t	range_count;
	hv_gpa_range	range[0];
} hv_vmbus_channel_gpadl_header;

/*
 * This is the follow-up packet that contains more PFNs
 */
typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	message_number;
	uint32_t 	gpadl;
	uint64_t 	pfn[0];
} hv_vmbus_channel_gpadl_body;

typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	child_rel_id;
	uint32_t	gpadl;
	uint32_t	creation_status;
} hv_vmbus_channel_gpadl_created;

typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	child_rel_id;
	uint32_t	gpadl;
} hv_vmbus_channel_gpadl_teardown;

typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	gpadl;
} hv_vmbus_channel_gpadl_torndown;

typedef struct {
	hv_vmbus_channel_message_header	header;
	uint32_t	child_rel_id;
} hv_vmbus_channel_relid_released;

typedef struct {
	hv_vmbus_channel_message_header header;
	uint32_t	vmbus_version_requested;
	uint32_t	padding2;
	uint64_t	interrupt_page;
	uint64_t	monitor_page_1;
	uint64_t	monitor_page_2;
} hv_vmbus_channel_initiate_contact;

typedef struct {
	hv_vmbus_channel_message_header header;
	bool		version_supported;
} hv_vmbus_channel_version_response;

typedef hv_vmbus_channel_message_header hv_vmbus_channel_unload;

/*
 * Kind of a table to use the preprocessor to get us the right type for a
 * specified message ID. Used with ChAllocateSendMessage()
 *
 * NOTE: These are reserved for future use
 */
/*
#define HV_CHANNEL_MESSAGE_QUERY_VMBUS_VERSION_TYPE	hv_vmbus_channel_message_header
#define HV_CHANNEL_MESSAGE_VERSION_SUPPORTED_TYPE	hv_vmbus_channel_version_supported
#define HV_CHANNEL_MESSAGE_OFFER_CHANNEL_TYPE		hv_vmbus_channel_offer_channel
#define HV_CHANNEL_MESSAGE_RESCIND_CHANNEL_OFFER_TYPE	hv_vmbus_channel_rescind_offer
#define HV_CHANNEL_MESSAGE_REQUEST_OFFERS_TYPE		hv_vmbus_channel_message_header
#define HV_CHANNEL_MESSAGE_ALL_OFFERS_DELIVERED_TYPE	hv_vmbus_channel_message_header
#define HV_CHANNEL_MESSAGE_OPEN_CHANNEL_TYPE		hv_vmbus_channel_open_channel
#define HV_CHANNEL_MESSAGE_OPEN_CHANNEL_RESULT_TYPE	hv_vmbus_channel_open_result
#define HV_CHANNEL_MESSAGE_CLOSE_CHANNEL_TYPE		hv_vmbus_channel_close_channel
#define HV_CHANNEL_MESSAGE_ALL_GPDALS_UNMAPPED_TYPE	hv_vmbus_channel_close_channel
#define HV_CHANNEL_MESSAGEL_GPADL_HEADER_TYPE		hv_vmbus_channel_gpadl_header
#define HV_CHANNEL_MESSAGE_GPADL_BODY_TYPE		hv_vmbus_channel_gpadl_body
#define HV_CHANNEL_MESSAGE_GPADL_CREATED_TYPE		hv_vmbus_channel_gpadl_created
#define HV_CHANNEL_MESSAGE_GPADL_TEARDOWN_TYPE		hv_vmbus_channel_gpadl_teardown
#define HV_CHANNEL_MESSAGE_GPADL_TORNDOWN_TYPE		hv_vmbus_channel_gpadl_torndown
#define HV_CHANNEL_MESSAGE_VIEW_RANGE_ADD_TYPE		VMBUS_CHANNEL_VIEW_RANGE_ADD
#define HV_CHANNEL_MESSAGE_VIEW_RANGE_REMOVE_TYPE	VMBUS_CHANNEL_VIEW_RANGE_REMOVE
#define HV_CHANNEL_MESSAGE_REL_ID_RELEASED_TYPE		hv_vmbus_channel_relid_released
#define HV_CHANNEL_MESSAGE_INITIATED_CONTACT_TYPE	hv_vmbus_channel_initiate_contact
#define HV_CHANNEL_MESSAGE_VERSION_RESPONSE_TYPE	hv_vmbus_channel_version_response
#define HV_CHANNEL_MESSAGE_UNLOAD_TYPE			hv_vmbus_channel_unload
*/

#define HW_MACADDR_LEN	6

#define HV_LOWORD(dw)	((unsigned short) (dw))
#define HV_HIWORD(dw)	((unsigned short) (((unsigned int) (dw) >> 16) & 0xFFFF))

/*
 * Fixme:  Added to quiet "typeof" errors involving hv_vmbus.h when
 * the including C file was compiled with "-std=c99".
 */
#ifndef typeof
#define typeof __typeof
#endif

#ifndef NULL
#define NULL  (void *)0
#endif


typedef void *hv_vmbus_handle;

#ifndef HV_CONTAINING_RECORD
#define HV_CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (uint8_t *)(address) - \
                                                  (uint8_t *)(&((type *)0)->field)))
#endif /* HV_CONTAINING_RECORD */


#define HV_VMPACKET_DATA_START_ADDRESS(__packet)	\
    (void *)(((PUCHAR)__packet) + ((hv_vm_packet_descriptor *)__packet)->data_offset8 * 8)

#define HV_VMPACKET_DATA_LENGTH(__packet)		\
    ((((hv_vm_packet_descriptor *)__packet)->length8 - ((hv_vm_packet_descriptor *)__packet)->data_offset8) * 8)

#define HV_VMPACKET_TRANSFER_MODE(__packet) ((hv_vm_packet_descriptor *)__packet)->type

#define HV_VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED    1


#define HV_CONTAINER_OF(ptr, type, member)	({		\
        __typeof__( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

enum {
	HV_VMBUS_IVAR_TYPE,
	HV_VMBUS_IVAR_INSTANCE,
	HV_VMBUS_IVAR_NODE,
	HV_VMBUS_IVAR_DEVCTX
};


#define HV_VMBUS_ACCESSOR(var, ivar, type) \
		__BUS_ACCESSOR(vmbus, var, VMBUS, ivar, type)

HV_VMBUS_ACCESSOR(type, TYPE,  const char *)
HV_VMBUS_ACCESSOR(devctx, DEVCTX,  struct hv_device *)

/*
 * Common header for Hyper-V ICs
 */
#define HV_ICMSGTYPE_NEGOTIATE		0
#define HV_ICMSGTYPE_HEARTBEAT		1
#define HV_ICMSGTYPE_KVPEXCHANGE	2
#define HV_ICMSGTYPE_SHUTDOWN		3
#define HV_ICMSGTYPE_TIMESYNC		4
#define HV_ICMSGTYPE_VSS		5

#define HV_ICMSGHDRFLAG_TRANSACTION	1
#define HV_ICMSGHDRFLAG_REQUEST		2
#define HV_ICMSGHDRFLAG_RESPONSE	4

typedef struct hv_vmbus_pipe_hdr {
	uint32_t flags;
	uint32_t msgsize;
} hv_vmbus_pipe_hdr;

struct hv_vmbus_ic_version {
	uint16_t major;
	uint16_t minor;
}__attribute__((packed));

struct icmsg_hdr {
	struct ic_version icverframe;
	uint16_t icmsgtype;
	struct ic_version icvermsg;
	uint16_t icmsgsize;
	uint32_t status;
	uint8_t ictransaction_id;
	uint8_t icflags;
	uint8_t reserved[2];
}__attribute__((packed));

struct icmsg_negotiate {
	uint16_t icframe_vercnt;
	uint16_t icmsg_vercnt;
	uint32_t reserved;
	struct ic_version icversion_data[1]; /* any size array */
}__attribute__((packed));

struct shutdown_msg_data {
	uint32_t reason_code;
	uint32_t timeout_seconds;
	uint32_t flags;
	uint8_t display_message[2048];
}__attribute__((packed));

struct heartbeat_msg_data {
	uint64_t seq_num;
	uint32_t reserved[8];
}__attribute__((packed));

#pragma pack(pop)

typedef struct _RING_BUFFER {
	volatile uint32_t       WriteIndex;     // Offset in bytes from the start of ring data below
	volatile uint32_t       ReadIndex;      // Offset in bytes from the start of ring data below
	volatile uint32_t       InterruptMask;
	uint8_t                 Reserved[4084]; // Pad it to PAGE_SIZE so that data starts on a page 

	// NOTE: The InterruptMask field is used only for channels but since our vmbus connection
	// also uses this data structure and its data starts here, we commented out this field.
	// __volatile__ uint32_t InterruptMask;
	// Ring data starts here + RingDataStartOffset !!! DO NOT place any fields below this !!!
	uint8_t Buffer[0];
} __attribute__((__packed__)) RING_BUFFER;

typedef struct _RING_BUFFER_INFO {
	RING_BUFFER* RingBuffer;
	uint32_t RingSize;      // Include the shared header
	struct mtx RingLock;
	uint32_t RingDataSize;  // < ringSize
	uint32_t RingDataStartOffset;
} RING_BUFFER_INFO;


typedef void (*PFN_CHANNEL_CALLBACK)(void *context);

typedef enum {
	HV_CHANNEL_OFFER_STATE,
	HV_CHANNEL_OPENING_STATE,
	HV_CHANNEL_OPEN_STATE,
} hv_vmbus_channel_state;

typedef struct _VMBUS_CHANNEL {
	TAILQ_ENTRY(_VMBUS_CHANNEL) ListEntry;
	struct hv_device *device;
	hv_vmbus_channel_state State;
	hv_vmbus_channel_offer_channel OfferMsg;
	/*
	 * These are based on the OfferMsg.monitor_id.
	 * Save it here for easy access.
	 */
	uint8_t MonitorGroup;
	uint8_t MonitorBit;

	uint32_t ring_buffer_gpadl_handle;

	// Allocated memory for ring buffer
	void *RingBufferPages;
	uint32_t RingBufferPageCount;
	hv_vmbus_ring_buffer_info Outbound;      // send to parent
	hv_vmbus_ring_buffer_info Inbound;       // receive from parent
	struct mtx InboundLock;
	hv_vmbus_handle ControlWQ;

	hv_vmbus_pfn_channel_callback OnChannelCallback;
	void *ChannelCallbackContext;

} VMBUS_CHANNEL;

#pragma pack(push,1)

struct hv_device {
	hv_guid			class_id;
	hv_guid			device_id;
	device_t		device;
	VMBUS_CHANNEL		*channel;
};

typedef struct {
	int		length;
	int		offset;
	uint64_t	pfn;
} PAGE_BUFFER;

#define HV_MAX_PAGE_BUFFER_COUNT	16
#define HV_MAX_MULTIPAGE_BUFFER_COUNT	32

#define HV_ALIGN_UP(value, align)		\
		(((value) & (align-1)) ? (((value) + (align-1)) & ~(align-1) ) : (value))

#define HV_ALIGN_DOWN(value, align) ( (value) & ~(align-1) )

#define HV_NUM_PAGES_SPANNED(addr, len)	\
		((HV_ALIGN_UP(addr+len, PAGE_SIZE) - HV_ALIGN_DOWN(addr, PAGE_SIZE)) >> PAGE_SHIFT )

typedef struct {
	int		length;
	int		offset;
	uint64_t	pfn_array[HV_MAX_MULTIPAGE_BUFFER_COUNT];
} hv_vmbus_multipage_buffer;


#pragma pack(pop)

struct hv_util_service {
	uint8_t		*recv_buffer;
	char		*serv_name;
	struct hv_work_queue *workq;
	void (*util_cb)(void *);
	int  (*util_init)(struct hv_util_service *);
	void (*util_deinit)(void);
};

void
vmbus_prep_negotiate_resp(struct hv_vmbus_icmsg_hdr *icmsghdrp,
                               struct hv_vmbus_icmsg_negotiate *negop, uint8_t *buf);

int
hv_vmbus_channel_recv_packet(VMBUS_CHANNEL *Channel, void *Buffer,
		uint32_t BufferLen, uint32_t* BufferActualLen,
		uint64_t* RequestId);

int
hv_vmbus_channel_recv_packet_raw(VMBUS_CHANNEL *Channel, void *Buffer,
        uint32_t BufferLen, uint32_t* BufferActualLen, uint64_t* RequestId);

int
hv_vmbus_channel_open(VMBUS_CHANNEL *Channel, uint32_t SendRingBufferSize,
        uint32_t RecvRingBufferSize, void *user_data, uint32_t UserDataLen,
        hv_vmbus_pfn_channel_callback pfnOnChannelCallback, void *Context);

void
hv_vmbus_channel_close(VMBUS_CHANNEL *Channel);


int
hv_vmbus_channel_send_packet(VMBUS_CHANNEL *Channel, void *Buffer,
        uint32_t BufferLen, uint64_t RequestId, hv_vmbus_packet_type Type,
        uint32_t Flags);


int
hv_vmbus_channel_send_packet_pagebuffer(VMBUS_CHANNEL *Channel,
        PAGE_BUFFER PageBuffers[], uint32_t PageCount, void *Buffer,
        uint32_t BufferLen, uint64_t RequestId);

int
hv_vmbus_channel_send_packet_multipagebuffer(VMBUS_CHANNEL *Channel,
        hv_vmbus_multipage_buffer *MultiPageBuffer, void *Buffer, uint32_t BufferLen,
        uint64_t RequestId);

int
hv_vmbus_channel_establish_gpadl(VMBUS_CHANNEL *Channel, void *Kbuffer,// from kmalloc()
	uint32_t Size,          // page-size multiple
	uint32_t *GpadlHandle);

int
hv_vmbus_channel_teardown_gpdal(VMBUS_CHANNEL *Channel, uint32_t GpadlHandle);

/*
 * Work abstraction.
 */
typedef struct hv_work_queue {
	struct taskqueue	*queue;
	struct proc		*proc;
	struct sema		*work_sema;
} hv_work_queue;

typedef struct hv_work_item {
	struct task		work;
	void			(*callback)(void *);
	void			*context;
	hv_work_queue		*wq;
} hv_work_item;

struct hv_work_queue *
hv_work_queue_create(char* name);

void
hv_work_queue_close(struct hv_work_queue *wq);

int
hv_queue_work_item(struct hv_work_queue *wq, void (*callback)(void *), void *context);

static inline unsigned long
hv_get_phys_addr(void *virt)
{
	unsigned long ret;
	ret = (vtophys(virt) | ((vm_offset_t) virt & PAGE_MASK));
	return ret;
}

#endif  /* __HYPERV_H__ */

