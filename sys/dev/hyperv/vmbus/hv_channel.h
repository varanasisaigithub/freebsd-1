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
 */

#ifndef __HV_CHANNEL_H__
#define __HV_CHANNEL_H__

#include "hv_vmbus_var.h"
#include "hv_channel_mgmt.h"
#include <dev/hyperv/include/hv_channel_messages.h>

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

int
hv_vmbus_channel_open(VMBUS_CHANNEL *Channel, uint32_t SendRingBufferSize,
	uint32_t RecvRingBufferSize, PVOID UserData, uint32_t UserDataLen,
	PFN_CHANNEL_CALLBACK pfnOnChannelCallback, PVOID Context);

void
hv_vmbus_channel_close(VMBUS_CHANNEL *Channel);

int
hv_vmbus_channel_send_packet(VMBUS_CHANNEL *Channel, const PVOID Buffer,
	uint32_t BufferLen, uint64_t RequestId, VMBUS_PACKET_TYPE Type,
	uint32_t Flags);

int
hv_vmbus_channel_send_packet_pagebuffer(VMBUS_CHANNEL *Channel,
	PAGE_BUFFER PageBuffers[], uint32_t PageCount, PVOID Buffer,
	uint32_t BufferLen, uint64_t RequestId);

int
hv_vmbus_channel_send_packet_multipagebuffer(VMBUS_CHANNEL *Channel,
	MULTIPAGE_BUFFER *MultiPageBuffer, PVOID Buffer, uint32_t BufferLen,
	uint64_t RequestId);

int
hv_vmbus_channel_establish_gpadl(VMBUS_CHANNEL *Channel, PVOID Kbuffer,// from kmalloc()
	uint32_t Size,		// page-size multiple
	uint32_t *GpadlHandle);

int
hv_vmbus_channel_teardown_gpdal(VMBUS_CHANNEL *Channel, uint32_t GpadlHandle);

int
hv_vmbus_channel_recv_packet(VMBUS_CHANNEL *Channel, PVOID Buffer, uint32_t BufferLen,
	uint32_t* BufferActualLen, uint64_t* RequestId);

int
hv_vmbus_channel_recv_packet_raw(VMBUS_CHANNEL *Channel, PVOID Buffer,
	uint32_t BufferLen, uint32_t* BufferActualLen, uint64_t* RequestId);

void
hv_vmbus_channel_on_channel_event(VMBUS_CHANNEL *Channel);

void
hv_vmbus_channel_get_debug_info(VMBUS_CHANNEL *Channel,
	VMBUS_CHANNEL_DEBUG_INFO *DebugInfo);

void
hv_vmbus_channel_on_timer(void *Context);

#endif  /* __HV_CHANNEL_H__ */
