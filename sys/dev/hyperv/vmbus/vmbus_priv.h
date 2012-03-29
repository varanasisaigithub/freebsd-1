
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
 * Channel definition file
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

#ifndef __HYPERV_PRIV_H__
#define __HYPERV_PRIV_H__

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sema.h>

#include "../include/hyperv.h"

//
// Status codes for hypervisor operations.
//
typedef uint16_t HV_STATUS, *PHV_STATUS;

#define HV_MESSAGE_SIZE                 (256)
#define HV_MESSAGE_PAYLOAD_BYTE_COUNT   (240)
#define HV_MESSAGE_PAYLOAD_QWORD_COUNT  (30)
#define HV_ANY_VP                       (0xFFFFFFFF)

//
// Define synthetic interrupt controller flag constants.
//
#define HV_EVENT_FLAGS_COUNT        (256 * 8)
#define HV_EVENT_FLAGS_BYTE_COUNT   (256)
#define HV_EVENT_FLAGS_DWORD_COUNT  (256 / sizeof(uint32_t))


//
// MessageId: HV_STATUS_INSUFFICIENT_BUFFERS
//
// MessageText:
//
// You did not supply enough message buffers to send a message.
//

#define HV_STATUS_INSUFFICIENT_BUFFERS   ((uint16_t)0x0013)

typedef void (*VMBUS_CHANNEL_CALLBACK)(void *context);

typedef struct _SG_BUFFER_LIST {
	void		*Data;
	uint32_t	Length;
} SG_BUFFER_LIST;

typedef struct _RING_BUFFER_DEBUG_INFO {
	uint32_t CurrentInterruptMask;
	uint32_t CurrentReadIndex;
	uint32_t CurrentWriteIndex;
	uint32_t BytesAvailToRead;
	uint32_t BytesAvailToWrite;
} RING_BUFFER_DEBUG_INFO;

//
// Interface
//

extern int
RingBufferInit(RING_BUFFER_INFO *RingInfo, void *Buffer, uint32_t BufferLen);

extern void
RingBufferCleanup(RING_BUFFER_INFO *RingInfo);

extern int
RingBufferWrite(RING_BUFFER_INFO *RingInfo, SG_BUFFER_LIST SgBuffers[],
	uint32_t SgBufferCount);

extern int
RingBufferPeek(RING_BUFFER_INFO *RingInfo, void *Buffer, uint32_t BufferLen);

extern int
RingBufferRead(RING_BUFFER_INFO *RingInfo, void *Buffer, uint32_t BufferLen,
	uint32_t Offset);

extern uint32_t
GetRingBufferInterruptMask(RING_BUFFER_INFO *RingInfo);

extern void
DumpRingInfo(RING_BUFFER_INFO* RingInfo, char *Prefix);

extern void
RingBufferGetDebugInfo(RING_BUFFER_INFO *RingInfo,
	RING_BUFFER_DEBUG_INFO *DebugInfo);

/*
 * Externs
 */
extern void SetRingBufferInterruptMask(RING_BUFFER_INFO *rbi);
extern void ClearRingBufferInterruptMask(RING_BUFFER_INFO *rbi);
extern int RingBufferCheck(RING_BUFFER_INFO *rbi);



typedef struct _VMBUS_CHANNEL_DEBUG_INFO {
	uint32_t RelId;
	VMBUS_CHANNEL_STATE State;
	GUID InterfaceType;
	GUID InterfaceInstance;
	uint32_t MonitorId;
	uint32_t ServerMonitorPending;
	uint32_t ServerMonitorLatency;
	uint32_t ServerMonitorConnectionId;
	uint32_t ClientMonitorPending;
	uint32_t ClientMonitorLatency;
	uint32_t ClientMonitorConnectionId;

	RING_BUFFER_DEBUG_INFO Inbound;
	RING_BUFFER_DEBUG_INFO Outbound;
} VMBUS_CHANNEL_DEBUG_INFO;

typedef union {
	VMBUS_CHANNEL_VERSION_SUPPORTED VersionSupported;
	VMBUS_CHANNEL_OPEN_RESULT OpenResult;
	VMBUS_CHANNEL_GPADL_TORNDOWN GpadlTorndown;
	VMBUS_CHANNEL_GPADL_CREATED GpadlCreated;
	VMBUS_CHANNEL_VERSION_RESPONSE VersionResponse;
} VMBUS_CHANNEL_MESSAGE_RESPONSE;

// Represents each channel msg on the vmbus connection
// This is a variable-size data structure depending on
// the msg type itself
typedef struct _VMBUS_CHANNEL_MSGINFO {
	// Bookkeeping stuff
	LIST_ENTRY(_VMBUS_CHANNEL_MSGINFO)  MsgListEntry;

	// So far, this is only used to handle gpadl body message
	LIST_HEAD(, _VMBUS_CHANNEL_MSGINFO) sub_msg_list_anchor; 

	// Synchronize the request/response if needed
	// KYS: Use a semaphore for now. Not perf critical.
	struct sema wait_sema;

	VMBUS_CHANNEL_MESSAGE_RESPONSE Response;

	uint32_t MessageSize;
	// The channel message that goes out on the "wire".
	// It will contain at minimum the VMBUS_CHANNEL_MESSAGE_HEADER header
	unsigned char Msg[0];
} VMBUS_CHANNEL_MSGINFO;

extern VMBUS_CHANNEL*
AllocVmbusChannel(void);

extern void
FreeVmbusChannel(VMBUS_CHANNEL *Channel);

extern void
VmbusOnChannelMessage(void *Context);

extern int
VmbusChannelRequestOffers(void);

extern void
VmbusChannelReleaseUnattachedChannels(void);


#pragma pack(push,1)

// The format must be the same as VMDATA_GPA_DIRECT
typedef struct _VMBUS_CHANNEL_PACKET_PAGE_BUFFER {
	uint16_t Type;
	uint16_t DataOffset8;
	uint16_t Length8;
	uint16_t Flags;
	uint64_t TransactionId;
	uint32_t Reserved;
	uint32_t RangeCount;
	PAGE_BUFFER Range[MAX_PAGE_BUFFER_COUNT];
} VMBUS_CHANNEL_PACKET_PAGE_BUFFER;

// The format must be the same as VMDATA_GPA_DIRECT
typedef struct _VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER {
	uint16_t Type;
	uint16_t DataOffset8;
	uint16_t Length8;
	uint16_t Flags;
	uint64_t TransactionId;
	uint32_t Reserved;
	uint32_t RangeCount;		// Always 1 in this case
	MULTIPAGE_BUFFER Range;
} VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER;

#pragma pack(pop)

void
hv_vmbus_channel_get_debug_info(VMBUS_CHANNEL *Channel,
	VMBUS_CHANNEL_DEBUG_INFO *DebugInfo);

void
GetChannelInfo(struct hv_device *dev, struct hv_devinfo *info);


enum {
	VMBUS_MESSAGE_CONNECTION_ID = 1,
	VMBUS_MESSAGE_PORT_ID = 1,
	VMBUS_EVENT_CONNECTION_ID = 2,
	VMBUS_EVENT_PORT_ID = 2,
	VMBUS_MONITOR_CONNECTION_ID = 3,
	VMBUS_MONITOR_PORT_ID = 3,
	VMBUS_MESSAGE_SINT = 2
};

/* 
 * #defines
 */
#define HV_PRESENT_BIT		0x80000000


#define HV_LINUX_GUEST_ID_LO	0x00000000
#define HV_LINUX_GUEST_ID_HI	0xB16B00B5
#define HV_LINUX_GUEST_ID	(((uint64_t)HV_LINUX_GUEST_ID_HI << 32) | HV_LINUX_GUEST_ID_LO)


#define HV_HYPERCALL_PARAM_ALIGN sizeof(uint64_t)

//
// Define connection identifier type.
//

typedef union _HV_CONNECTION_ID {
	uint32_t Asuint32_t;

	struct {
		uint32_t Id:24;
		uint32_t Reserved:8;
	} u;

} HV_CONNECTION_ID, *PHV_CONNECTION_ID;

//
// Definition of the HvSignalEvent hypercall input structure.
//
typedef struct _HV_INPUT_SIGNAL_EVENT {
	HV_CONNECTION_ID ConnectionId;
	uint16_t           FlagNumber;
	uint16_t           RsvdZ;
} HV_INPUT_SIGNAL_EVENT, *PHV_INPUT_SIGNAL_EVENT;

typedef struct {
	uint64_t Align8;
	HV_INPUT_SIGNAL_EVENT Event;
} HV_INPUT_SIGNAL_EVENT_BUFFER;

typedef struct {
	uint64_t GuestId;
	void* HypercallPage;

	bool SynICInitialized;
	// This is used as an input param to HvCallSignalEvent hypercall. The input param is immutable 
	// in our usage and must be dynamic mem (vs stack or global). 
	HV_INPUT_SIGNAL_EVENT_BUFFER *SignalEventBuffer;
	HV_INPUT_SIGNAL_EVENT *SignalEventParam; // 8-bytes aligned of the buffer above

	HANDLE synICMessagePage[MAXCPU];
	HANDLE synICEventPage[MAXCPU];
} HV_CONTEXT;

//
// Define hypervisor message types.
//
typedef enum _HV_MESSAGE_TYPE {
	HvMessageTypeNone = 0x00000000,

	//
	// Memory access messages.
	//
	HvMessageTypeUnmappedGpa = 0x80000000,
	HvMessageTypeGpaIntercept = 0x80000001,

	//
	// Timer notification messages.
	//
	HvMessageTimerExpired = 0x80000010,

	//
	// Error messages.
	//
	HvMessageTypeInvalidVpRegisterValue = 0x80000020,
	HvMessageTypeUnrecoverableException = 0x80000021,
	HvMessageTypeUnsupportedFeature = 0x80000022,

	//
	// Trace buffer complete messages.
	//
	HvMessageTypeEventLogBufferComplete = 0x80000040,

	//
	// Platform-specific processor intercept messages.
	//
	HvMessageTypeX64IoPortIntercept = 0x80010000,
	HvMessageTypeX64MsrIntercept = 0x80010001,
	HvMessageTypeX64CpuidIntercept = 0x80010002,
	HvMessageTypeX64ExceptionIntercept = 0x80010003,
	HvMessageTypeX64ApicEoi = 0x80010004,
	HvMessageTypeX64LegacyFpError = 0x80010005
} HV_MESSAGE_TYPE, *PHV_MESSAGE_TYPE;

//
// Define port identifier type.
//
typedef union _HV_PORT_ID {
	uint32_t Asuint32_t;

	struct {
		uint32_t Id:24;
		uint32_t Reserved:8;
	} u ;

} HV_PORT_ID, *PHV_PORT_ID;

//
// Define synthetic interrupt controller message flags.
//
typedef union _HV_MESSAGE_FLAGS {
	uint8_t Asuint8_t;
	struct {
		uint8_t MessagePending:1;
		uint8_t Reserved:7;
	};
} HV_MESSAGE_FLAGS, *PHV_MESSAGE_FLAGS;

typedef uint64_t HV_PARTITION_ID, *PHV_PARTITION_ID;

//
// Define synthetic interrupt controller message header.
//
typedef struct _HV_MESSAGE_HEADER {
	HV_MESSAGE_TYPE MessageType;
	uint8_t PayloadSize;
	HV_MESSAGE_FLAGS MessageFlags;
	uint8_t Reserved[2];
	union {
		HV_PARTITION_ID Sender;
		HV_PORT_ID      Port;
	};
} HV_MESSAGE_HEADER, *PHV_MESSAGE_HEADER;

//
// Define synthetic interrupt controller message format.
//

typedef struct _HV_MESSAGE {
	HV_MESSAGE_HEADER Header;
	union {
		uint64_t Payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
	} u ;
} HV_MESSAGE, *PHV_MESSAGE;

#ifdef __x86_64__

#define RDMSR(reg, v) {			\
	uint32_t h, l;			\
	__asm__ __volatile__("rdmsr"	\
	: "=a" (l), "=d" (h)		\
	: "c" (reg));			\
	v = (((uint64_t)h) << 32) | l;	\
}

#define WRMSR(reg, v) {						\
	uint32_t h, l;						\
	l = (uint32_t)(((uint64_t)(v)) & 0xFFFFFFFF);		\
	h = (uint32_t)((((uint64_t)(v)) >> 32) & 0xFFFFFFFF);	\
	__asm__ __volatile__("wrmsr"				\
	: /* no outputs */					\
	: "c" (reg), "a" (l), "d" (h));				\
}

#else

#define RDMSR(reg, v)			\
     __asm__ __volatile__("rdmsr"	\
    : "=A" (v)				\
    : "c" (reg))

#define WRMSR(reg, v)			\
     __asm__ __volatile__("wrmsr"	\
    : /* no outputs */			\
    : "c" (reg), "A" ((uint64_t)v))

#endif



/*
 * Inline functions
 */

static inline unsigned long long ReadMsr(int msr) {
	unsigned long long val;
	RDMSR(msr, val);
	return val;
}

static inline void WriteMsr(int msr, uint64_t val) {
	WRMSR(msr, val);
	return;
}

extern int
HvInit(void);

extern void
HvCleanup( void);

extern uint16_t 
HvPostMessage(HV_CONNECTION_ID connectionId, HV_MESSAGE_TYPE messageType,
	      void *payload, size_t payloadSize);

extern uint16_t 
HvSignalEvent( void);

extern void
HvSynicInit(void *irqArg);

extern void
HvSynicCleanup(void *arg);

extern HV_CONTEXT gHvContext;
extern int HvQueryHypervisorPresence(void);




//
// Defines
//

// Maximum channels is determined by the size of the interrupt page which is PAGE_SIZE. 1/2 of PAGE_SIZE is for
// send endpoint interrupt and the other is receive endpoint interrupt
#define MAX_NUM_CHANNELS				(PAGE_SIZE >> 1) << 3  // 16348 channels
// The value here must be in multiple of 32
// TODO: Need to make this configurable
#define MAX_NUM_CHANNELS_SUPPORTED		256

//
// Data types
//

typedef enum {
	Disconnected,
	Connecting,
	Connected,
	Disconnecting
} VMBUS_CONNECT_STATE;

#define MAX_SIZE_CHANNEL_MESSAGE			HV_MESSAGE_PAYLOAD_BYTE_COUNT

typedef struct _VMBUS_CONNECTION {

	VMBUS_CONNECT_STATE ConnectState;

	uint32_t NextGpadlHandle;

	// Represents channel interrupts. Each bit position
	// represents a channel.
	// When a channel sends an interrupt via VMBUS, it 
	// finds its bit in the sendInterruptPage, set it and 
	// calls Hv to generate a port event. The other end
	// receives the port event and parse the recvInterruptPage
	// to see which bit is set
	void* InterruptPage;
	void* SendInterruptPage;
	void* RecvInterruptPage;

	// 2 pages - 1st page for parent->child notification and 2nd is child->parent notification
	void* MonitorPages;
	LIST_HEAD(, _VMBUS_CHANNEL_MSGINFO)  channel_msg_anchor;
	struct mtx ChannelMsgLock;

	// List of channels
	LIST_HEAD(, _VMBUS_CHANNEL)  channel_anchor;
	struct mtx ChannelLock;

	HANDLE WorkQueue;
} VMBUS_CONNECTION;


//
// Externs
//
extern VMBUS_CONNECTION gVmbusConnection;
//
// General vmbus interface
//

struct hv_device *
vmbus_child_device_create(GUID deviceType, GUID deviceInstance,
			 VMBUS_CHANNEL *channel);


int vmbus_child_device_register(struct hv_device *child_dev);

int vmbus_child_device_unregister(struct hv_device *child_dev);


VMBUS_CHANNEL*
GetChannelFromRelId(uint32_t relId);

//
// Connection interface
//
extern int
VmbusConnect(void);

extern int
VmbusDisconnect(void);

extern int
VmbusPostMessage(void * buffer, size_t bufSize);

extern int
VmbusSetEvent(uint32_t childRelId);

extern void
vmbus_on_events(void *);

//
// Declare the MSR used to identify the guest OS.
//
#define HV_X64_MSR_GUEST_OS_ID 0x40000000

typedef union _HV_X64_MSR_GUEST_OS_ID_CONTENTS {
    uint64_t Asuint64_t;
    struct {
        uint64_t BuildNumber    : 16;
        uint64_t ServiceVersion : 8; // Service Pack, etc.
        uint64_t MinorVersion   : 8;
        uint64_t MajorVersion   : 8;
        uint64_t OsId           : 8; // HV_GUEST_OS_MICROSOFT_IDS (If Vendor=MS)
        uint64_t VendorId       : 16; // HV_GUEST_OS_VENDOR
    };
} HV_X64_MSR_GUEST_OS_ID_CONTENTS, *PHV_X64_MSR_GUEST_OS_ID_CONTENTS;

//
// Declare the MSR used to setup pages used to communicate with the hypervisor.
//
#define HV_X64_MSR_HYPERCALL 0x40000001

typedef union _HV_X64_MSR_HYPERCALL_CONTENTS {
    uint64_t Asuint64_t;
    struct {
        uint64_t Enable               : 1;
        uint64_t Reserved             : 11;
        uint64_t GuestPhysicalAddress : 52;
    };
} HV_X64_MSR_HYPERCALL_CONTENTS, *PHV_X64_MSR_HYPERCALL_CONTENTS;

typedef union _HV_MONITOR_TRIGGER_STATE {
	uint32_t Asuint32_t;

	struct {
		uint32_t GroupEnable : 4;
		uint32_t RsvdZ       : 28;
	};
} HV_MONITOR_TRIGGER_STATE, *PHV_MONITOR_TRIGGER_STATE;

typedef union _HV_MONITOR_TRIGGER_GROUP {
	uint64_t Asuint64_t;

	struct {
		uint32_t Pending;
		uint32_t Armed;
	};
} HV_MONITOR_TRIGGER_GROUP, *PHV_MONITOR_TRIGGER_GROUP;

typedef struct _HV_MONITOR_PARAMETER {
	HV_CONNECTION_ID    ConnectionId;
	uint16_t              FlagNumber;
	uint16_t              RsvdZ;
} HV_MONITOR_PARAMETER, *PHV_MONITOR_PARAMETER;


//
// HV_MONITOR_PAGE Layout
// ------------------------------------------------------
// | 0   | TriggerState (4 bytes) | Rsvd1 (4 bytes)     |
// | 8   | TriggerGroup[0]                              |
// | 10  | TriggerGroup[1]                              |
// | 18  | TriggerGroup[2]                              |
// | 20  | TriggerGroup[3]                              |
// | 28  | Rsvd2[0]                                     |
// | 30  | Rsvd2[1]                                     |
// | 38  | Rsvd2[2]                                     |
// | 40  | NextCheckTime[0][0]    | NextCheckTime[0][1] |
// | ...                                                |
// | 240 | Latency[0][0..3]                             |
// | 340 | Rsvz3[0]                                     |
// | 440 | Parameter[0][0]                              |
// | 448 | Parameter[0][1]                              |
// | ...                                                |
// | 840 | Rsvd4[0]                                     |
// ------------------------------------------------------

typedef struct _HV_MONITOR_PAGE {
	HV_MONITOR_TRIGGER_STATE TriggerState;
	uint32_t                   RsvdZ1;

	HV_MONITOR_TRIGGER_GROUP TriggerGroup[4];
	uint64_t                   RsvdZ2[3];

	int32_t                    NextCheckTime[4][32];

	uint16_t                   Latency[4][32];
	uint64_t                   RsvdZ3[32];

	HV_MONITOR_PARAMETER     Parameter[4][32];

	uint8_t                    RsvdZ4[1984];
} HV_MONITOR_PAGE, *PHV_MONITOR_PAGE;

//
// The below CPUID leaves are present if VersionAndFeatures.HypervisorPresent
// is set by CPUID(HvCpuIdFunctionVersionAndFeatures).
// ==========================================================================
//
typedef enum _HV_CPUID_FUNCTION {
	HvCpuIdFunctionVersionAndFeatures           = 0x00000001,
	HvCpuIdFunctionHvVendorAndMaxFunction       = 0x40000000,
	HvCpuIdFunctionHvInterface                  = 0x40000001,

	//
	// The remaining functions depend on the value of HvCpuIdFunctionInterface
	//
	HvCpuIdFunctionMsHvVersion                  = 0x40000002,
	HvCpuIdFunctionMsHvFeatures                 = 0x40000003,
	HvCpuIdFunctionMsHvEnlightenmentInformation = 0x40000004,
	HvCpuIdFunctionMsHvImplementationLimits     = 0x40000005

} HV_CPUID_FUNCTION, *PHV_CPUID_FUNCTION;

//
// Define the format of the SIMP register
//
typedef union _HV_SYNIC_SIMP {
	uint64_t Asuint64_t;
	struct {
		uint64_t SimpEnabled : 1;
		uint64_t Preserved   : 11;
		uint64_t BaseSimpGpa : 52;
	};
} HV_SYNIC_SIMP, *PHV_SYNIC_SIMP;

//
// Define the format of the SIEFP register
//
typedef union _HV_SYNIC_SIEFP {
	uint64_t Asuint64_t;
	struct {
		uint64_t SiefpEnabled : 1;
		uint64_t Preserved   : 11;
		uint64_t BaseSiefpGpa : 52;
	};
} HV_SYNIC_SIEFP, *PHV_SYNIC_SIEFP;

//
// Define synthetic interrupt source.
//
typedef union _HV_SYNIC_SINT {
	uint64_t Asuint64_t;
	struct {
		uint64_t Vector    :8;
		uint64_t Reserved1 :8;
		uint64_t Masked    :1;
		uint64_t AutoEoi   :1;
		uint64_t Reserved2 :46;
	};
} HV_SYNIC_SINT, *PHV_SYNIC_SINT;

//
// Define SynIC control register.
//
typedef union _HV_SYNIC_SCONTROL {
    uint64_t Asuint64_t;
    struct {
        uint64_t Enable:1;
        uint64_t Reserved:63;
    };
} HV_SYNIC_SCONTROL, *PHV_SYNIC_SCONTROL;

//
// Definition of the HvPostMessage hypercall input structure.
//
typedef struct _HV_INPUT_POST_MESSAGE {
    HV_CONNECTION_ID    ConnectionId;
    uint32_t              Reserved;
    HV_MESSAGE_TYPE     MessageType;
    uint32_t              PayloadSize;
    uint64_t              Payload[HV_MESSAGE_PAYLOAD_QWORD_COUNT];
} HV_INPUT_POST_MESSAGE, *PHV_INPUT_POST_MESSAGE;

//
// Define the synthetic interrupt controller event flags format.
//
typedef union _HV_SYNIC_EVENT_FLAGS {
	uint8_t Flags8[HV_EVENT_FLAGS_BYTE_COUNT];
	uint32_t Flags32[HV_EVENT_FLAGS_DWORD_COUNT];
} HV_SYNIC_EVENT_FLAGS, *PHV_SYNIC_EVENT_FLAGS;


//
// Define synthetic interrupt controller model specific registers.
//
#define HV_X64_MSR_SCONTROL   (0x40000080)
#define HV_X64_MSR_SVERSION   (0x40000081)
#define HV_X64_MSR_SIEFP      (0x40000082)
#define HV_X64_MSR_SIMP       (0x40000083)
#define HV_X64_MSR_EOM        (0x40000084)

#define HV_X64_MSR_SINT0      (0x40000090)
#define HV_X64_MSR_SINT1      (0x40000091)
#define HV_X64_MSR_SINT2      (0x40000092)
#define HV_X64_MSR_SINT3      (0x40000093)
#define HV_X64_MSR_SINT4      (0x40000094)
#define HV_X64_MSR_SINT5      (0x40000095)
#define HV_X64_MSR_SINT6      (0x40000096)
#define HV_X64_MSR_SINT7      (0x40000097)
#define HV_X64_MSR_SINT8      (0x40000098)
#define HV_X64_MSR_SINT9      (0x40000099)
#define HV_X64_MSR_SINT10     (0x4000009A)
#define HV_X64_MSR_SINT11     (0x4000009B)
#define HV_X64_MSR_SINT12     (0x4000009C)
#define HV_X64_MSR_SINT13     (0x4000009D)
#define HV_X64_MSR_SINT14     (0x4000009E)
#define HV_X64_MSR_SINT15     (0x4000009F)

//
// Declare the various hypercall operations.
//
typedef enum _HV_CALL_CODE {
	HvCallPostMessage                   = 0x005c,
	HvCallSignalEvent                   = 0x005d,
} HV_CALL_CODE, *PHV_CALL_CODE;

#endif  /* __HYPERV_PRIV_H__ */
