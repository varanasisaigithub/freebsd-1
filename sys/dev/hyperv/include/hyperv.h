
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


typedef unsigned char		bool;

#ifndef false
#define false  0
#endif

#ifndef true
#define true  1
#endif


#define HV_S_OK		0x00000000
#define HV_E_FAIL	0x80004005
#define HV_ERROR_NOT_SUPPORTED    0x80070032
#define HV_ERROR_MACHINE_LOCKED   0x800704F7


// A revision number of vmbus that is used for ensuring both ends on a
// partition are using compatible versions.
//
#define VMBUS_REVISION_NUMBER       13

//
// Make maximum size of pipe payload of 16K
//
#define MAX_PIPE_DATA_PAYLOAD 		(sizeof(BYTE) * 16384)

//
// Define PipeMode values.
//
#define VMBUS_PIPE_TYPE_BYTE                    0x00000000
#define VMBUS_PIPE_TYPE_MESSAGE                 0x00000004

//
// The size of the user defined data buffer for non-pipe offers.
//
#define MAX_USER_DEFINED_BYTES                  120

//
// The size of the user defined data buffer for pipe offers.
//
#define MAX_PIPE_USER_DEFINED_BYTES             116

#pragma pack(push,1)

typedef struct {
	unsigned char		Data[16];
} GUID;

typedef struct {
	int InterruptMask;
	int ReadIndex;
	int WriteIndex;
	int BytesAvailToRead;
	int BytesAvailToWrite;
} BOUND;

struct hv_devinfo {
	int ChannelId;
	int ChannelState;
	int ChannelType;
	int ChannelInstance;
	int MonitorId;
	int ServerMonitorPending;
	int ServerMonitorLatency;
	int ServerMonitorConnectionId;
	int ClientMonitorPending;
	int ClientMonitorLatency;
	int ClientMonitorConnectionId;
	BOUND Inbound, Outbound;
};

//
// At the center of the Channel Management library is
// the Channel Offer. This struct contains the
// fundamental information about an offer.
//

typedef struct
{
    GUID	InterfaceType;
    GUID	InterfaceInstance;
    uint64_t	InterruptLatencyIn100nsUnits;
    uint32_t	InterfaceRevision;
    uint32_t	ServerContextAreaSize;  /* in bytes */
    uint16_t	ChannelFlags;
    uint16_t	MmioMegabytes;          /* in bytes * 1024 * 1024 */

    union
    {
        /*
         * Non-pipes: The user has MAX_USER_DEFINED_BYTES bytes.
         */
        struct
        {
            uint8_t	UserDefined[MAX_USER_DEFINED_BYTES];
        } Standard;

        /*
         * Pipes: The following structure is an integrated pipe protocol, which
         *        is implemented on top of standard user-defined data. Pipe clients
         *        have MAX_PIPE_USER_DEFINED_BYTES left for their own use.
         */
        struct
        {
            uint32_t	PipeMode;
            uint8_t	UserDefined[MAX_PIPE_USER_DEFINED_BYTES];
        } Pipe;
    } u;

    uint32_t	Padding;

} VMBUS_CHANNEL_OFFER, *PVMBUS_CHANNEL_OFFER;

typedef uint32_t GPADL_HANDLE;


typedef struct {
    union {
        struct {
            volatile uint32_t  In;        // Offset in bytes from the ring base
            volatile uint32_t  Out;       // Offset in bytes from the ring base
        } io;
        volatile int64_t    InOut;
    } rio;

    //
    // If the receiving endpoint sets this to some non-zero value, the sending 
    // endpoint should not send any interrupts.
    //

    volatile uint32_t InterruptMask;
} VMRCB, *PVMRCB;

typedef struct {
    union {
        struct {
            VMRCB Control;
        } ctl;
        uint8_t Reserved[PAGE_SIZE];
    } rctl;
    
    //
    // Beginning of the ring data.  Note: It must be guaranteed that
    // this data does not share a page with the control structure.
    //
    uint8_t Data[1];
} VMRING, *PVMRING;


typedef struct {
	uint16_t Type;
	uint16_t DataOffset8;
	uint16_t Length8;
	uint16_t Flags;
	uint64_t TransactionId;
} VMPACKET_DESCRIPTOR, *PVMPACKET_DESCRIPTOR;

typedef uint32_t PREVIOUS_PACKET_OFFSET, *PPREVIOUS_PACKET_OFFSET;

typedef struct {
	PREVIOUS_PACKET_OFFSET  PreviousPacketStartOffset;
	VMPACKET_DESCRIPTOR     Descriptor;
} VMPACKET_HEADER, *PVMPACKET_HEADER;

typedef struct {
	uint32_t ByteCount;
	uint32_t ByteOffset;
} VMTRANSFER_PAGE_RANGE, *PVMTRANSFER_PAGE_RANGE;

typedef struct VMTRANSFER_PAGE_PACKET_HEADER {
	VMPACKET_DESCRIPTOR d;
	uint16_t	TransferPageSetId;
	bool	SenderOwnsSet;
	uint8_t	Reserved;
	uint32_t	RangeCount;
	VMTRANSFER_PAGE_RANGE   Ranges[1];
} VMTRANSFER_PAGE_PACKET_HEADER, *PVMTRANSFER_PAGE_PACKET_HEADER;

typedef struct _VMGPADL_PACKET_HEADER {
	VMPACKET_DESCRIPTOR d;
	uint32_t  Gpadl;
	uint32_t  Reserved;
} VMGPADL_PACKET_HEADER, *PVMGPADL_PACKET_HEADER;

typedef struct _VMADD_REMOVE_TRANSFER_PAGE_SET {
	VMPACKET_DESCRIPTOR d;
	uint32_t  Gpadl;
	uint16_t  TransferPageSetId;
	uint16_t  Reserved;
} VMADD_REMOVE_TRANSFER_PAGE_SET, *PVMADD_REMOVE_TRANSFER_PAGE_SET;


//
// This structure defines a range in guest physical space that can be made
// to look virtually contiguous.
// 

typedef struct _GPA_RANGE {
	uint32_t  ByteCount;
	uint32_t  ByteOffset;
	uint64_t  PfnArray[0];
} GPA_RANGE, *PGPA_RANGE;



//
// This is the format for an Establish Gpadl packet, which contains a handle
// by which this GPADL will be known and a set of GPA ranges associated with
// it.  This can be converted to a MDL by the guest OS.  If there are multiple
// GPA ranges, then the resulting MDL will be "chained," representing multiple
// VA ranges.
// 

typedef struct _VMESTABLISH_GPADL {
	VMPACKET_DESCRIPTOR d;
	uint32_t  Gpadl;
	uint32_t  RangeCount;
	GPA_RANGE Range[1];
} VMESTABLISH_GPADL, *PVMESTABLISH_GPADL;


//
// This is the format for a Teardown Gpadl packet, which indicates that the
// GPADL handle in the Establish Gpadl packet will never be referenced again.
//

typedef struct _VMTEARDOWN_GPADL {
	VMPACKET_DESCRIPTOR d;
	uint32_t  Gpadl;
	uint32_t  Reserved; // for alignment to a 8-byte boundary
} VMTEARDOWN_GPADL, *PVMTEARDOWN_GPADL;


//
// This is the format for a GPA-Direct packet, which contains a set of GPA
// ranges, in addition to commands and/or data.
// 

typedef struct _VMDATA_GPA_DIRECT {
	VMPACKET_DESCRIPTOR d;
	uint32_t      Reserved;
	uint32_t      RangeCount;
	GPA_RANGE   Range[1];
} VMDATA_GPA_DIRECT, *PVMDATA_GPA_DIRECT;


//
// This is the format for a Additional Data Packet.
// 

typedef struct _VMADDITIONAL_DATA {
	VMPACKET_DESCRIPTOR d;
	uint64_t  TotalBytes;
	uint32_t  ByteOffset;
	uint32_t  ByteCount;
	uint8_t   Data[1];
} VMADDITIONAL_DATA, *PVMADDITIONAL_DATA;



typedef union {
	VMPACKET_DESCRIPTOR             SimpleHeader;
	VMTRANSFER_PAGE_PACKET_HEADER   TransferPageHeader;
	VMGPADL_PACKET_HEADER           GpadlHeader;
	VMADD_REMOVE_TRANSFER_PAGE_SET  AddRemoveTransferPageHeader;
	VMESTABLISH_GPADL               EstablishGpadlHeader;
	VMTEARDOWN_GPADL                TeardownGpadlHeader;
	VMDATA_GPA_DIRECT               DataGpaDirectHeader;
} VMPACKET_LARGEST_POSSIBLE_HEADER, *PVMPACKET_LARGEST_POSSIBLE_HEADER;

#define VMPACKET_DATA_START_ADDRESS(__packet)                           \
    (void *)(((PUCHAR)__packet) + ((PVMPACKET_DESCRIPTOR)__packet)->DataOffset8 * 8)

#define VMPACKET_DATA_LENGTH(__packet)                                  \
    ((((PVMPACKET_DESCRIPTOR)__packet)->Length8 - ((PVMPACKET_DESCRIPTOR)__packet)->DataOffset8) * 8)

#define VMPACKET_TRANSFER_MODE(__packet) ((PVMPACKET_DESCRIPTOR)__packet)->Type

typedef enum {
    VmbusServerEndpoint = 0,
    VmbusClientEndpoint,
    VmbusEndpointMaximum
} ENDPOINT_TYPE, *PENDPOINT_TYPE;

typedef enum {
    VmbusPacketTypeInvalid                      = 0x0,
    VmbusPacketTypeSynch                        = 0x1,
    VmbusPacketTypeAddTransferPageSet           = 0x2,
    VmbusPacketTypeRemoveTransferPageSet        = 0x3,
    VmbusPacketTypeEstablishGpadl               = 0x4,
    VmbusPacketTypeTearDownGpadl                = 0x5,
    VmbusPacketTypeDataInBand                   = 0x6,
    VmbusPacketTypeDataUsingTransferPages       = 0x7,
    VmbusPacketTypeDataUsingGpadl               = 0x8,
    VmbusPacketTypeDataUsingGpaDirect           = 0x9,
    VmbusPacketTypeCancelRequest                = 0xa,
    VmbusPacketTypeCompletion                   = 0xb,
    VmbusPacketTypeDataUsingAdditionalPackets   = 0xc,
    VmbusPacketTypeAdditionalData               = 0xd
} VMBUS_PACKET_TYPE, *PVMBUS_PACKET_TYPE;

#define VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED    1



typedef uint32_t NTSTATUS; //KYS clean this


//
// Version 1 messages
//

typedef enum _VMBUS_CHANNEL_MESSAGE_TYPE
{
    ChannelMessageInvalid                   =  0,
    ChannelMessageOfferChannel              =  1,
    ChannelMessageRescindChannelOffer       =  2,
    ChannelMessageRequestOffers             =  3,
    ChannelMessageAllOffersDelivered        =  4,
    ChannelMessageOpenChannel               =  5,
    ChannelMessageOpenChannelResult         =  6,
    ChannelMessageCloseChannel              =  7,
    ChannelMessageGpadlHeader               =  8,
    ChannelMessageGpadlBody                 =  9,
    ChannelMessageGpadlCreated              = 10,
    ChannelMessageGpadlTeardown             = 11,
    ChannelMessageGpadlTorndown             = 12,
    ChannelMessageRelIdReleased             = 13,
    ChannelMessageInitiateContact           = 14,
    ChannelMessageVersionResponse           = 15,
    ChannelMessageUnload                    = 16,
#ifdef VMBUS_FEATURE_PARENT_OR_PEER_MEMORY_MAPPED_INTO_A_CHILD
    ChannelMessageViewRangeAdd              = 17,
    ChannelMessageViewRangeRemove           = 18,
#endif
    ChannelMessageCount
} VMBUS_CHANNEL_MESSAGE_TYPE, *PVMBUS_CHANNEL_MESSAGE_TYPE;


typedef struct _VMBUS_CHANNEL_MESSAGE_HEADER
{
    VMBUS_CHANNEL_MESSAGE_TYPE  MessageType;
    uint32_t                      Padding;
} VMBUS_CHANNEL_MESSAGE_HEADER, *PVMBUS_CHANNEL_MESSAGE_HEADER;

// Query VMBus Version parameters
typedef struct _VMBUS_CHANNEL_QUERY_VMBUS_VERSION
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t Version;
} VMBUS_CHANNEL_QUERY_VMBUS_VERSION, *PVMBUS_CHANNEL_QUERY_VMBUS_VERSION;

// VMBus Version Supported parameters
typedef struct _VMBUS_CHANNEL_VERSION_SUPPORTED
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    bool VersionSupported;
} VMBUS_CHANNEL_VERSION_SUPPORTED, *PVMBUS_CHANNEL_VERSION_SUPPORTED;

// Offer Channel parameters
typedef struct _VMBUS_CHANNEL_OFFER_CHANNEL
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    VMBUS_CHANNEL_OFFER Offer;
    uint32_t  ChildRelId;
    uint8_t   MonitorId;
    bool	 MonitorAllocated;
} VMBUS_CHANNEL_OFFER_CHANNEL, *PVMBUS_CHANNEL_OFFER_CHANNEL;


// Rescind Offer parameters
typedef struct _VMBUS_CHANNEL_RESCIND_OFFER
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t          ChildRelId;
} VMBUS_CHANNEL_RESCIND_OFFER, *PVMBUS_CHANNEL_RESCIND_OFFER;

// Request Offer -- no parameters, SynIC message contains the partition ID
// Set Snoop -- no parameters, SynIC message contains the partition ID
// Clear Snoop -- no parameters, SynIC message contains the partition ID
// All Offers Delivered -- no parameters, SynIC message contains the partition ID
// Flush Client -- no parameters, SynIC message contains the partition ID

// Open Channel parameters
typedef struct _VMBUS_CHANNEL_OPEN_CHANNEL
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;

    //
    // Identifies the specific VMBus channel that is being opened.
    //
    uint32_t          ChildRelId;

    //
    // ID making a particular open request at a channel offer unique.
    //
    uint32_t          OpenId;

    //
    // GPADL for the channel's ring buffer.
    //
    GPADL_HANDLE    RingBufferGpadlHandle;

    //
    // GPADL for the channel's server context save area.
    //
    GPADL_HANDLE    ServerContextAreaGpadlHandle;

    //
    // The upstream ring buffer begins at offset zero in the memory described
    // by RingBufferGpadlHandle. The downstream ring buffer follows it at this
    // offset (in pages).
    //
    uint32_t          DownstreamRingBufferPageOffset;

    //
    // User-specific data to be passed along to the server endpoint.
    //
    uint8_t           UserData[MAX_USER_DEFINED_BYTES];

} VMBUS_CHANNEL_OPEN_CHANNEL, *PVMBUS_CHANNEL_OPEN_CHANNEL;

// Reopen Channel parameters;
typedef VMBUS_CHANNEL_OPEN_CHANNEL VMBUS_CHANNEL_REOPEN_CHANNEL, *PVMBUS_CHANNEL_REOPEN_CHANNEL;

// Open Channel Result parameters
typedef struct _VMBUS_CHANNEL_OPEN_RESULT
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t      ChildRelId;
    uint32_t      OpenId;
    NTSTATUS    Status;
} VMBUS_CHANNEL_OPEN_RESULT, *PVMBUS_CHANNEL_OPEN_RESULT;

// Close channel parameters;
typedef struct _VMBUS_CHANNEL_CLOSE_CHANNEL
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t      ChildRelId;
} VMBUS_CHANNEL_CLOSE_CHANNEL, *PVMBUS_CHANNEL_CLOSE_CHANNEL;

// Channel Message GPADL
#define GPADL_TYPE_RING_BUFFER          1
#define GPADL_TYPE_SERVER_SAVE_AREA     2
#define GPADL_TYPE_TRANSACTION          8

//
// The number of PFNs in a GPADL message is defined by the number of pages
// that would be spanned by ByteCount and ByteOffset.  If the implied number
// of PFNs won't fit in this packet, there will be a follow-up packet that
// contains more.
//

typedef struct _VMBUS_CHANNEL_GPADL_HEADER
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t      ChildRelId;
    uint32_t      Gpadl;
    uint16_t      RangeBufLen;
    uint16_t      RangeCount;
    GPA_RANGE   Range[0];
} VMBUS_CHANNEL_GPADL_HEADER, *PVMBUS_CHANNEL_GPADL_HEADER;


//
// This is the followup packet that contains more PFNs.
//

typedef struct _VMBUS_CHANNEL_GPADL_BODY
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              MessageNumber;
    uint32_t              Gpadl;
    uint64_t              Pfn[0];
} VMBUS_CHANNEL_GPADL_BODY, *PVMBUS_CHANNEL_GPADL_BODY;


typedef struct _VMBUS_CHANNEL_GPADL_CREATED
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              ChildRelId;
    uint32_t              Gpadl;
    uint32_t              CreationStatus;
} VMBUS_CHANNEL_GPADL_CREATED, *PVMBUS_CHANNEL_GPADL_CREATED;

typedef struct _VMBUS_CHANNEL_GPADL_TEARDOWN
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              ChildRelId;
    uint32_t              Gpadl;
} VMBUS_CHANNEL_GPADL_TEARDOWN, *PVMBUS_CHANNEL_GPADL_TEARDOWN;

typedef struct _VMBUS_CHANNEL_GPADL_TORNDOWN
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              Gpadl;
} VMBUS_CHANNEL_GPADL_TORNDOWN, *PVMBUS_CHANNEL_GPADL_TORNDOWN;

typedef struct _VMBUS_CHANNEL_RELID_RELEASED
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              ChildRelId;
} VMBUS_CHANNEL_RELID_RELEASED, *PVMBUS_CHANNEL_RELID_RELEASED;

typedef struct _VMBUS_CHANNEL_INITIATE_CONTACT
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    uint32_t              VMBusVersionRequested;
    uint32_t              Padding2;
    uint64_t              InterruptPage;
    uint64_t              MonitorPage1;
    uint64_t              MonitorPage2;
} VMBUS_CHANNEL_INITIATE_CONTACT, *PVMBUS_CHANNEL_INITIATE_CONTACT;

typedef struct _VMBUS_CHANNEL_VERSION_RESPONSE
{
    VMBUS_CHANNEL_MESSAGE_HEADER Header;
    bool     VersionSupported;
} VMBUS_CHANNEL_VERSION_RESPONSE, *PVMBUS_CHANNEL_VERSION_RESPONSE;

typedef VMBUS_CHANNEL_MESSAGE_HEADER VMBUS_CHANNEL_UNLOAD, *PVMBUS_CHANNEL_UNLOAD;

//
// Kind of a table to use the preprocessor to get us the right type for a
// specified message ID. Used with ChAllocateSendMessage()
//
#define ChannelMessageQueryVmbusVersion_TYPE    VMBUS_CHANNEL_MESSAGE_HEADER
#define ChannelMessageVmbusVersionSupported_TYPE VMBUS_CHANNEL_VERSION_SUPPORTED
#define ChannelMessageOfferChannel_TYPE         VMBUS_CHANNEL_OFFER_CHANNEL
#define ChannelMessageRescindChannelOffer_TYPE  VMBUS_CHANNEL_RESCIND_OFFER
#define ChannelMessageRequestOffers_TYPE        VMBUS_CHANNEL_MESSAGE_HEADER
#define ChannelMessageAllOffersDelivered_TYPE   VMBUS_CHANNEL_MESSAGE_HEADER
#define ChannelMessageOpenChannel_TYPE          VMBUS_CHANNEL_OPEN_CHANNEL
#define ChannelMessageOpenChannelResult_TYPE    VMBUS_CHANNEL_OPEN_RESULT
#define ChannelMessageCloseChannel_TYPE         VMBUS_CHANNEL_CLOSE_CHANNEL
#define ChannelMessageAllGpadlsUnmapped_TYPE    VMBUS_CHANNEL_CLOSE_CHANNEL
#define ChannelMessageGpadlHeader_TYPE          VMBUS_CHANNEL_GPADL_HEADER
#define ChannelMessageGpadlBody_TYPE            VMBUS_CHANNEL_GPADL_BODY
#define ChannelMessageGpadlCreated_TYPE         VMBUS_CHANNEL_GPADL_CREATED
#define ChannelMessageGpadlTeardown_TYPE        VMBUS_CHANNEL_GPADL_TEARDOWN
#define ChannelMessageGpadlTorndown_TYPE        VMBUS_CHANNEL_GPADL_TORNDOWN
#define ChannelMessageViewRangeAdd_TYPE         VMBUS_CHANNEL_VIEW_RANGE_ADD
#define ChannelMessageViewRangeRemove_TYPE      VMBUS_CHANNEL_VIEW_RANGE_REMOVE
#define ChannelMessageRelIdReleased_TYPE        VMBUS_CHANNEL_RELID_RELEASED
#define ChannelMessageInitiateContact_TYPE      VMBUS_CHANNEL_INITIATE_CONTACT
#define ChannelMessageVersionResponse_TYPE      VMBUS_CHANNEL_VERSION_RESPONSE
#define ChannelMessageUnload_TYPE               VMBUS_CHANNEL_UNLOAD



#define HW_MACADDR_LEN		6

#define LOWORD(dw)	((unsigned short) (dw))
#define HIWORD(dw)	((unsigned short) (((unsigned int) (dw) >> 16) & 0xFFFF))


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



typedef void*			HANDLE;


#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) ((type *)( \
                                                  (uint8_t *)(address) - \
                                                  (uint8_t *)(&((type *)0)->field)))
#endif /* CONTAINING_RECORD */

// 
// A revision number of vmbus that is used for ensuring both ends on a
// partition are using compatible versions.
//
#define VMBUS_REVISION_NUMBER       13

//
// Make maximum size of pipe payload of 16K
//
#define MAX_PIPE_DATA_PAYLOAD 		(sizeof(BYTE) * 16384)

//
// Define PipeMode values.
//
#define VMBUS_PIPE_TYPE_BYTE                    0x00000000
#define VMBUS_PIPE_TYPE_MESSAGE                 0x00000004

//
// The size of the user defined data buffer for non-pipe offers.
//
#define MAX_USER_DEFINED_BYTES                  120

//
// The size of the user defined data buffer for pipe offers.
//
#define MAX_PIPE_USER_DEFINED_BYTES             116


#define VMPACKET_DATA_START_ADDRESS(__packet)                           \
    (void *)(((PUCHAR)__packet) + ((PVMPACKET_DESCRIPTOR)__packet)->DataOffset8 * 8)

#define VMPACKET_DATA_LENGTH(__packet)                                  \
    ((((PVMPACKET_DESCRIPTOR)__packet)->Length8 - ((PVMPACKET_DESCRIPTOR)__packet)->DataOffset8) * 8)

#define VMPACKET_TRANSFER_MODE(__packet) ((PVMPACKET_DESCRIPTOR)__packet)->Type



#define VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED    1



#define container_of(ptr, type, member) ({		\
        __typeof__( ((type *)0)->member ) *__mptr = (ptr);  \
        (type *)( (char *)__mptr - offsetof(type,member) );})



enum {
	VMBUS_IVAR_TYPE,
	VMBUS_IVAR_INSTANCE,
	VMBUS_IVAR_NODE,
	VMBUS_IVAR_DEVCTX
};


#define VMBUS_ACCESSOR(var, ivar, type) \
		__BUS_ACCESSOR(vmbus, var, VMBUS, ivar, type)

VMBUS_ACCESSOR(type, TYPE,  const char *)
VMBUS_ACCESSOR(devctx, DEVCTX,  struct hv_device *)



/**
 * Common header for Hyper-V ICs
 */

#define ICMSGTYPE_NEGOTIATE 0
#define ICMSGTYPE_HEARTBEAT 1
#define ICMSGTYPE_KVPEXCHANGE 2
#define ICMSGTYPE_SHUTDOWN 3
#define ICMSGTYPE_TIMESYNC 4
#define ICMSGTYPE_VSS 5

#define ICMSGHDRFLAG_TRANSACTION 1
#define ICMSGHDRFLAG_REQUEST 2
#define ICMSGHDRFLAG_RESPONSE 4

struct vmbuspipe_hdr {
	uint32_t flags;
	uint32_t msgsize;
}__attribute__((packed));

struct ic_version {
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
	CHANNEL_OFFER_STATE,
	CHANNEL_OPENING_STATE,
	CHANNEL_OPEN_STATE,
} VMBUS_CHANNEL_STATE;

typedef struct _VMBUS_CHANNEL {
	TAILQ_ENTRY(_VMBUS_CHANNEL) ListEntry;
	struct hv_device *device;
	VMBUS_CHANNEL_STATE State;
	VMBUS_CHANNEL_OFFER_CHANNEL OfferMsg;
	// These are based on the OfferMsg.MonitorId. Save it here for easy access.
	uint8_t MonitorGroup;
	uint8_t MonitorBit;

	uint32_t RingBufferGpadlHandle;

	// Allocated memory for ring buffer
	void *RingBufferPages;
	uint32_t RingBufferPageCount;
	RING_BUFFER_INFO Outbound;      // send to parent
	RING_BUFFER_INFO Inbound;       // receive from parent
	struct mtx InboundLock;
	HANDLE ControlWQ;

	PFN_CHANNEL_CALLBACK OnChannelCallback;
	void *ChannelCallbackContext;

} VMBUS_CHANNEL;

#pragma pack(push,1)

struct hv_device {
	GUID			class_id;
	GUID			device_id;
	device_t		device;
	VMBUS_CHANNEL		*channel;
};

typedef struct {
	int Length;
	int Offset;
	uint64_t Pfn;
} PAGE_BUFFER;

#define MAX_PAGE_BUFFER_COUNT   16
#define MAX_MULTIPAGE_BUFFER_COUNT 32

#define ALIGN_UP(value, align)  \
(((value) & (align-1)) ? (((value) + (align-1)) & ~(align-1) ) : (value))

#define ALIGN_DOWN(value, align) ( (value) & ~(align-1) )

#define NUM_PAGES_SPANNED(addr, len) \
((ALIGN_UP(addr+len, PAGE_SIZE) - ALIGN_DOWN(addr, PAGE_SIZE)) >> PAGE_SHIFT )

typedef struct {
	int Length;
	int Offset;
	uint64_t PfnArray[MAX_MULTIPAGE_BUFFER_COUNT];
} MULTIPAGE_BUFFER;


#pragma pack(pop)

struct hv_util_service {
	uint8_t *recv_buffer;
	char *serv_name;
	struct work_queue *workq;
	void (*util_cb)(void *);
	int  (*util_init)(struct hv_util_service *);
	void (*util_deinit)(void);
};

void vmbus_prep_negotiate_resp(struct icmsg_hdr *icmsghdrp,
                               struct icmsg_negotiate *negop, uint8_t *buf);

int hv_vmbus_channel_recv_packet(VMBUS_CHANNEL *Channel, void *Buffer,
		uint32_t BufferLen, uint32_t* BufferActualLen,
		uint64_t* RequestId);

int hv_vmbus_channel_recv_packet_raw(VMBUS_CHANNEL *Channel, void *Buffer,
        uint32_t BufferLen, uint32_t* BufferActualLen, uint64_t* RequestId);

int hv_vmbus_channel_open(VMBUS_CHANNEL *Channel, uint32_t SendRingBufferSize,
        uint32_t RecvRingBufferSize, void *UserData, uint32_t UserDataLen,
        PFN_CHANNEL_CALLBACK pfnOnChannelCallback, void *Context);

void hv_vmbus_channel_close(VMBUS_CHANNEL *Channel);


int hv_vmbus_channel_send_packet(VMBUS_CHANNEL *Channel, void *Buffer,
        uint32_t BufferLen, uint64_t RequestId, VMBUS_PACKET_TYPE Type,
        uint32_t Flags);


int hv_vmbus_channel_send_packet_pagebuffer(VMBUS_CHANNEL *Channel,
        PAGE_BUFFER PageBuffers[], uint32_t PageCount, void *Buffer,
        uint32_t BufferLen, uint64_t RequestId);

int hv_vmbus_channel_send_packet_multipagebuffer(VMBUS_CHANNEL *Channel,
        MULTIPAGE_BUFFER *MultiPageBuffer, void *Buffer, uint32_t BufferLen,
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
struct work_queue {
	struct taskqueue *queue;
	struct proc *proc;
	struct sema *work_sema;
};

struct work_item{
	struct task work;
	void (*callback)(void *);
	void *context;
	struct work_queue *wq;
};

struct work_queue *work_queue_create(char* name);
void work_queue_close(struct work_queue *wq);
int queue_work_item(struct work_queue *wq, void (*callback)(void *), void *context);

static inline unsigned long get_phys_addr(void *virt)
{
	unsigned long ret;

	ret = (vtophys(virt) | ((vm_offset_t) virt & PAGE_MASK));

	return ret;
}

#endif  /* __HYPERV_H__ */
