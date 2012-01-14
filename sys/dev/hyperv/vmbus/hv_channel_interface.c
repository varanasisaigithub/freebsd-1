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
 * Public wrapper around the static channel APIs
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

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
/* Fixme -- contains globals, cannot be included more than once */
//#include "hv_version_info.h"
#include "hv_hv.h"
#include "hv_vmbus_var.h"
#include "hv_vmbus_api.h"
#include <dev/hyperv/include/hv_list.h>
#include "hv_ring_buffer.h"
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/include/hv_channel_messages.h>

#include "hv_channel_mgmt.h"
#include "hv_channel.h"
#include "hv_channel_interface.h"
#include "hv_vmbus_private.h"

static int
IVmbusChannelOpen(PDEVICE_OBJECT Device, UINT32 SendBufferSize,
	UINT32 RecvRingBufferSize, PVOID UserData, UINT32 UserDataLen,
	VMBUS_CHANNEL_CALLBACK ChannelCallback, PVOID Context) {
	return VmbusChannelOpen((VMBUS_CHANNEL*) Device->context,
		SendBufferSize, RecvRingBufferSize, UserData, UserDataLen,
		ChannelCallback, Context);
}

static void
IVmbusChannelClose(PDEVICE_OBJECT Device) {
	VmbusChannelClose((VMBUS_CHANNEL*) Device->context);
}

static int
IVmbusChannelSendPacket(PDEVICE_OBJECT Device, const PVOID Buffer,
	UINT32 BufferLen, UINT64 RequestId, UINT32 Type, UINT32 Flags) {
	return VmbusChannelSendPacket((VMBUS_CHANNEL*) Device->context, Buffer,
		BufferLen, RequestId, Type, Flags);
}

static int
IVmbusChannelSendPacketPageBuffer(PDEVICE_OBJECT Device,
	PAGE_BUFFER PageBuffers[], UINT32 PageCount, PVOID Buffer,
	UINT32 BufferLen, UINT64 RequestId) {
	return VmbusChannelSendPacketPageBuffer(
		(VMBUS_CHANNEL*) Device->context, PageBuffers, PageCount,
		Buffer, BufferLen, RequestId);
}

static int
IVmbusChannelSendPacketMultiPageBuffer(PDEVICE_OBJECT Device,
	MULTIPAGE_BUFFER *MultiPageBuffer, PVOID Buffer, UINT32 BufferLen,
	UINT64 RequestId) {
	return VmbusChannelSendPacketMultiPageBuffer(
		(VMBUS_CHANNEL*) Device->context, MultiPageBuffer, Buffer,
		BufferLen, RequestId);
}

static int
IVmbusChannelRecvPacket(PDEVICE_OBJECT Device, PVOID Buffer,
	UINT32 BufferLen, UINT32* BufferActualLen, UINT64* RequestId) {
	return VmbusChannelRecvPacket((VMBUS_CHANNEL*) Device->context, Buffer,
		BufferLen, BufferActualLen, RequestId);
}

static int
IVmbusChannelRecvPacketRaw(PDEVICE_OBJECT Device, PVOID Buffer,
	UINT32 BufferLen, UINT32* BufferActualLen, UINT64* RequestId) {
	return VmbusChannelRecvPacketRaw((VMBUS_CHANNEL*) Device->context,
		Buffer, BufferLen, BufferActualLen, RequestId);
}

static int
IVmbusChannelEstablishGpadl(PDEVICE_OBJECT Device, PVOID Buffer,
	UINT32 BufferLen, UINT32* GpadlHandle) {
	return VmbusChannelEstablishGpadl((VMBUS_CHANNEL*) Device->context,
		Buffer, BufferLen, GpadlHandle);
}

static int
IVmbusChannelTeardownGpadl(PDEVICE_OBJECT Device, UINT32 GpadlHandle) {
	return VmbusChannelTeardownGpadl((VMBUS_CHANNEL*) Device->context,
		GpadlHandle);
}

extern void
GetChannelInfo(PDEVICE_OBJECT q, DEVICE_INFO *p) {
	VMBUS_CHANNEL_DEBUG_INFO di;

	if (q->context) {
		VmbusChannelGetDebugInfo((VMBUS_CHANNEL*) q->context, &di);

		p->ChannelId = di.RelId;
		p->ChannelState = di.State;
		memcpy(&p->ChannelType, &di.InterfaceType, sizeof(GUID));
		memcpy(&p->ChannelInstance, &di.InterfaceInstance,
			sizeof(GUID));

		p->MonitorId = di.MonitorId;

		p->ServerMonitorPending = di.ServerMonitorPending;
		p->ServerMonitorLatency = di.ServerMonitorLatency;
		p->ServerMonitorConnectionId = di.ServerMonitorConnectionId;

		p->ClientMonitorPending = di.ClientMonitorPending;
		p->ClientMonitorLatency = di.ClientMonitorLatency;
		p->ClientMonitorConnectionId = di.ClientMonitorConnectionId;

		p->Inbound.InterruptMask = di.Inbound.CurrentInterruptMask;
		p->Inbound.ReadIndex = di.Inbound.CurrentReadIndex;
		p->Inbound.WriteIndex = di.Inbound.CurrentWriteIndex;
		p->Inbound.BytesAvailToRead = di.Inbound.BytesAvailToRead;
		p->Inbound.BytesAvailToWrite = di.Inbound.BytesAvailToWrite;

		p->Outbound.InterruptMask = di.Outbound.CurrentInterruptMask;
		p->Outbound.ReadIndex = di.Outbound.CurrentReadIndex;
		p->Outbound.WriteIndex = di.Outbound.CurrentWriteIndex;
		p->Outbound.BytesAvailToRead = di.Outbound.BytesAvailToRead;
		p->Outbound.BytesAvailToWrite = di.Outbound.BytesAvailToWrite;
	}
}

extern void
GetChannelInterface(VMBUS_CHANNEL_INTERFACE *p) {
	p->Open = IVmbusChannelOpen;
	p->Close = IVmbusChannelClose;
	p->SendPacket = IVmbusChannelSendPacket;
	p->SendPacketPageBuffer = IVmbusChannelSendPacketPageBuffer;
	p->SendPacketMultiPageBuffer = IVmbusChannelSendPacketMultiPageBuffer;
	p->RecvPacket = IVmbusChannelRecvPacket;
	p->RecvPacketRaw = IVmbusChannelRecvPacketRaw;
	p->EstablishGpadl = IVmbusChannelEstablishGpadl;
	p->TeardownGpadl = IVmbusChannelTeardownGpadl;
	p->GetInfo = GetChannelInfo;
}
