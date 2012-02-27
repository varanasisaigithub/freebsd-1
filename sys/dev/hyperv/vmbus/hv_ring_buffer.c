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
 * HyperV vmbus ring buffer code
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


#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

/* Fixme:  Not all these are likely needed */
#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
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
#include "hv_ic.h"
#include "hv_vmbus_private.h"
#include "hv_support.h"

//
// #defines
//

// Amount of space to write to
#define BYTES_AVAIL_TO_WRITE(r, w, z) ((w) >= (r))?((z) - ((w) - (r))):((r) - (w)) 

/*++

 Name:
 GetRingBufferAvailBytes()

 Description:
 Get number of bytes available to read and to write to
 for the specified ring buffer

 --*/
static inline void
GetRingBufferAvailBytes(RING_BUFFER_INFO *rbi, uint32_t *read,
			uint32_t *write) {
	uint32_t read_loc, write_loc;

	// Capture the read/write indices before they changed
	read_loc = rbi->RingBuffer->ReadIndex;
	write_loc = rbi->RingBuffer->WriteIndex;

	*write = BYTES_AVAIL_TO_WRITE(read_loc, write_loc, rbi->RingDataSize);
	*read = rbi->RingDataSize - *write;
}

/*++

 Name:
 GetNextWriteLocation()

 Description:
 Get the next write location for the specified ring buffer

 --*/
static inline uint32_t
GetNextWriteLocation(RING_BUFFER_INFO* RingInfo) {
	uint32_t next = RingInfo->RingBuffer->WriteIndex;

	ASSERT(next < RingInfo->RingDataSize);

	return next;
}

/*++

 Name:
 SetNextWriteLocation()

 Description:
 Set the next write location for the specified ring buffer

 --*/
static inline void
SetNextWriteLocation(RING_BUFFER_INFO* RingInfo,
	uint32_t NextWriteLocation) {
	RingInfo->RingBuffer->WriteIndex = NextWriteLocation;
}

/*++

 Name:
 GetNextReadLocation()

 Description:
 Get the next read location for the specified ring buffer

 --*/
static inline uint32_t
GetNextReadLocation(RING_BUFFER_INFO* RingInfo) {
	uint32_t next = RingInfo->RingBuffer->ReadIndex;

	ASSERT(next < RingInfo->RingDataSize);

	return next;
}

/*++

 Name:
 GetNextReadLocationWithOffset()

 Description:
 Get the next read location + offset for the specified ring buffer.
 This allows the caller to skip

 --*/
static inline uint32_t
GetNextReadLocationWithOffset(RING_BUFFER_INFO* RingInfo,
	uint32_t Offset) {
	uint32_t next = RingInfo->RingBuffer->ReadIndex;

	ASSERT(next < RingInfo->RingDataSize);
	next += Offset;
	next %= RingInfo->RingDataSize;

	return next;
}

/*++

 Name:
 SetNextReadLocation()

 Description:
 Set the next read location for the specified ring buffer

 --*/
static inline void
SetNextReadLocation(RING_BUFFER_INFO* RingInfo,
	uint32_t NextReadLocation) {
	RingInfo->RingBuffer->ReadIndex = NextReadLocation;
}

/*++

 Name:
 GetRingBuffer()

 Description:
 Get the start of the ring buffer

 --*/
static inline void *
GetRingBuffer(RING_BUFFER_INFO* RingInfo) {
	return (void *) RingInfo->RingBuffer->Buffer;
}

/*++

 Name:
 GetRingBufferSize()

 Description:
 Get the size of the ring buffer

 --*/
static inline uint32_t
GetRingBufferSize(RING_BUFFER_INFO* RingInfo) {
	return RingInfo->RingDataSize;
}

/*++

 Name:
 GetRingBufferIndices()

 Description:
 Get the read and write indices as uint64_t of the specified ring buffer

 --*/
static inline uint64_t
GetRingBufferIndices(RING_BUFFER_INFO* RingInfo) {
	return (uint64_t) RingInfo->RingBuffer->WriteIndex << 32;
}

/*++

 Name:
 DumpRingInfo()

 Description:
 Dump out to console the ring buffer info

 --*/
void
DumpRingInfo(RING_BUFFER_INFO* RingInfo, char *Prefix) {
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;

	GetRingBufferAvailBytes(RingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	DPRINT(
		VMBUS,
		DEBUG_RING_LVL,
		"%s <<ringinfo %p buffer %p avail write %u avail read %u read idx %u write idx %u>>",
		Prefix, RingInfo, RingInfo->RingBuffer->Buffer, bytesAvailToWrite, bytesAvailToRead,
		RingInfo->RingBuffer->ReadIndex, RingInfo->RingBuffer->WriteIndex);
}

//
// Internal routines
//
static uint32_t
CopyToRingBuffer(RING_BUFFER_INFO *RingInfo, uint32_t StartWriteOffset, void *Src,
	uint32_t SrcLen);

static uint32_t
CopyFromRingBuffer(RING_BUFFER_INFO *RingInfo, void *Dest, uint32_t DestLen,
	uint32_t StartReadOffset);

/*++

 Name:
 RingBufferGetDebugInfo()

 Description:
 Get various debug metrics for the specified ring buffer

 --*/
void
RingBufferGetDebugInfo(RING_BUFFER_INFO *RingInfo,
	RING_BUFFER_DEBUG_INFO *DebugInfo) {
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;

	if (RingInfo->RingBuffer) {
		GetRingBufferAvailBytes(RingInfo, &bytesAvailToRead,
			&bytesAvailToWrite);

		DebugInfo->BytesAvailToRead = bytesAvailToRead;
		DebugInfo->BytesAvailToWrite = bytesAvailToWrite;
		DebugInfo->CurrentReadIndex = RingInfo->RingBuffer->ReadIndex;
		DebugInfo->CurrentWriteIndex = RingInfo->RingBuffer->WriteIndex;

		DebugInfo->CurrentInterruptMask =
			RingInfo->RingBuffer->InterruptMask;
	}
}

/*++

 Name:
 GetRingBufferInterruptMask()

 Description:
 Get the interrupt mask for the specified ring buffer

 --*/
uint32_t
GetRingBufferInterruptMask(RING_BUFFER_INFO *rbi) {
	return rbi->RingBuffer->InterruptMask;
}

/*++

 Name:
 RingBufferInit()

 Description:
 Initialize the ring buffer

 --*/
int
RingBufferInit(RING_BUFFER_INFO *RingInfo, void *Buffer, uint32_t BufferLen) {
	ASSERT(sizeof(RING_BUFFER) == PAGE_SIZE);

	memset(RingInfo, 0, sizeof(RING_BUFFER_INFO));

	RingInfo->RingBuffer = (RING_BUFFER*) Buffer;
	RingInfo->RingBuffer->ReadIndex = RingInfo->RingBuffer->WriteIndex = 0;

	RingInfo->RingSize = BufferLen;
	RingInfo->RingDataSize = BufferLen - sizeof(RING_BUFFER);

	RingInfo->RingLock = hv_mtx_create("vmbus ring buffer");

	return 0;
}

/*++

 Name:
 RingBufferCleanup()

 Description:
 Cleanup the ring buffer

 --*/
void RingBufferCleanup(RING_BUFFER_INFO* RingInfo) {
	hv_mtx_destroy(RingInfo->RingLock);
}

/*++

 Name:
 RingBufferWrite()

 Description:
 Write to the ring buffer

 --*/
int
RingBufferWrite(RING_BUFFER_INFO* OutRingInfo, SG_BUFFER_LIST SgBuffers[],
	uint32_t SgBufferCount) {
	int i = 0;
	uint32_t byteAvailToWrite;
	uint32_t byteAvailToRead;
	uint32_t totalBytesToWrite = 0;

	volatile uint32_t nextWriteLocation;
	uint64_t prevIndices=0;

	DPRINT_ENTER(VMBUS);

	for (i = 0; i < SgBufferCount; i++) {
		totalBytesToWrite += SgBuffers[i].Length;
	}

	totalBytesToWrite += sizeof(uint64_t);

	mtx_lock(OutRingInfo->RingLock);

	GetRingBufferAvailBytes(OutRingInfo, &byteAvailToRead,
		&byteAvailToWrite);

	DPRINT_DBG(VMBUS, "Writing %u bytes...", totalBytesToWrite);

	//DumpRingInfo(OutRingInfo, "BEFORE ");

	// If there is only room for the packet, assume it is full. Otherwise, the next time around, we think the ring buffer
	// is empty since the read index == write index
	if (byteAvailToWrite <= totalBytesToWrite) {
		DPRINT_DBG(
			VMBUS,
			"No more space left on outbound ring buffer (needed %u, avail %u)",
			totalBytesToWrite, byteAvailToWrite);

		mtx_unlock(OutRingInfo->RingLock);

		DPRINT_EXIT(VMBUS);

		return -1;
	}

	// Write to the ring buffer
	nextWriteLocation = GetNextWriteLocation(OutRingInfo);

	for (i = 0; i < SgBufferCount; i++) {
		nextWriteLocation = CopyToRingBuffer(OutRingInfo,
			nextWriteLocation, SgBuffers[i].Data,
			SgBuffers[i].Length);
	}

	// Set previous packet start
	prevIndices = GetRingBufferIndices(OutRingInfo);

	nextWriteLocation = CopyToRingBuffer(OutRingInfo, nextWriteLocation,
		&prevIndices, sizeof(uint64_t));

	// Make sure we flush all writes before updating the writeIndex
	MemoryFence();

	// Now, update the write location
	SetNextWriteLocation(OutRingInfo, nextWriteLocation);

	//DumpRingInfo(OutRingInfo, "AFTER ");

	mtx_unlock(OutRingInfo->RingLock);

	DPRINT_EXIT(VMBUS);

	return 0;
}

/*++

 Name:
 RingBufferPeek()

 Description:
 Read without advancing the read index

 --*/
int
RingBufferPeek(RING_BUFFER_INFO* InRingInfo, void* Buffer, uint32_t BufferLen) {
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;

	mtx_lock(InRingInfo->RingLock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		//DPRINT_DBG(VMBUS, "got callback but not enough to read <avail to read %d read size %d>!!", bytesAvailToRead, BufferLen);
		mtx_unlock(InRingInfo->RingLock);
		return -1;
	}

	// Convert to byte offset
	nextReadLocation = GetNextReadLocation(InRingInfo);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, Buffer, BufferLen,
		nextReadLocation);

	mtx_unlock(InRingInfo->RingLock);

	return 0;
}

/*++

 Name:
 RingBufferRead()

 Description:
 Read and advance the read index

 --*/
int
RingBufferRead(RING_BUFFER_INFO* InRingInfo, void *Buffer, uint32_t BufferLen,
	uint32_t Offset) {
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;
	uint64_t prevIndices = 0;

	ASSERT(BufferLen > 0);

	mtx_lock(InRingInfo->RingLock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	DPRINT_DBG(VMBUS, "Reading %u bytes...", BufferLen);

	//DumpRingInfo(InRingInfo, "BEFORE ");

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		DPRINT_DBG(
			VMBUS,
			"got callback but not enough to read <avail to read %d read size %d>!!",
			bytesAvailToRead, BufferLen);

		mtx_unlock(InRingInfo->RingLock);

		return -1;
	}

	nextReadLocation = GetNextReadLocationWithOffset(InRingInfo, Offset);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, Buffer, BufferLen,
		nextReadLocation);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, &prevIndices,
		sizeof(uint64_t), nextReadLocation);

	// Make sure all reads are done before we update the read index since 
	// the writer may start writing to the read area once the read index is updated
	MemoryFence();

	// Update the read index
	SetNextReadLocation(InRingInfo, nextReadLocation);

	//DumpRingInfo(InRingInfo, "AFTER ");

	mtx_unlock(InRingInfo->RingLock);

	return 0;
}

/*++

 Name:
 CopyToRingBuffer()

 Description:
 Helper routine to copy from source to ring buffer.
 Assume there is enough room. Handles wrap-around in dest case only!!

 --*/
uint32_t
CopyToRingBuffer(RING_BUFFER_INFO *RingInfo, uint32_t StartWriteOffset,
	void *Src, uint32_t SrcLen) {
	/* Fixme:  This should not be a void pointer! */
	void *ringBuffer = GetRingBuffer(RingInfo);
	uint32_t ringBufferSize = GetRingBufferSize(RingInfo);
	uint32_t fragLen;

	if (SrcLen > ringBufferSize - StartWriteOffset) // wrap-around detected!
		{
		DPRINT_DBG(VMBUS, "wrap-around detected!");

		fragLen = ringBufferSize - StartWriteOffset;
		/* Fixme:  Cast needed due to void pointer */
		memcpy((uint8_t *)ringBuffer + StartWriteOffset, Src, fragLen);
		/* Fixme:  Cast needed due to void pointer */
		memcpy(ringBuffer, (uint8_t *)Src + fragLen, SrcLen - fragLen);
	} else {
		/* Fixme:  Cast needed due to void pointer */
		memcpy((uint8_t *)ringBuffer + StartWriteOffset, Src,
			SrcLen);
	}

	StartWriteOffset += SrcLen;
	StartWriteOffset %= ringBufferSize;

	return StartWriteOffset;
}

/*++

 Name:
 CopyFromRingBuffer()

 Description:
 Helper routine to copy to source from ring buffer.
 Assume there is enough room. Handles wrap-around in src case only!!

 --*/
uint32_t
CopyFromRingBuffer(RING_BUFFER_INFO *RingInfo, void *Dest,
	uint32_t DestLen, uint32_t StartReadOffset) {
	/* Fixme:  This should not be a void pointer! */
	void *ringBuffer = GetRingBuffer(RingInfo);
	uint32_t ringBufferSize = GetRingBufferSize(RingInfo);

	uint32_t fragLen;

	if (DestLen > ringBufferSize - StartReadOffset) // wrap-around detected at the src
		{
		DPRINT_DBG(VMBUS, "src wrap-around detected!");

		fragLen = ringBufferSize - StartReadOffset;

		/* Fixme:  Cast needed due to void pointer */
		memcpy(Dest, (uint8_t *)ringBuffer + StartReadOffset, fragLen);
		/* Fixme:  Cast needed due to void pointer */
		memcpy((uint8_t *)Dest + fragLen, ringBuffer, DestLen - fragLen);
	} else {
		/* Fixme:  Cast needed due to void pointer */
		memcpy(Dest, (uint8_t *)ringBuffer + StartReadOffset, DestLen);
	}

	StartReadOffset += DestLen;
	StartReadOffset %= ringBufferSize;

	return StartReadOffset;
}

/*
 * Fixme:  originally for NetScaler.  Do we need these functions now?
 *
 * All functions below added for HyperV porting effort.
 */

void
SetRingBufferInterruptMask(RING_BUFFER_INFO *rbi) {
	rbi->RingBuffer->InterruptMask = 1;
}

void
ClearRingBufferInterruptMask(RING_BUFFER_INFO *rbi) {
	rbi->RingBuffer->InterruptMask = 0;
}

#define _PREFETCHT0(addr) \
	__extension__ ({ \
		__asm__ __volatile__ ("prefetcht0 (%0)\n" \
		: : "g" ((void *)(addr)) ); \
	})

int
RingBufferCheck(RING_BUFFER_INFO *rbi) {
#if 1
	uint32_t ri, wi, len;

	// Capture the read/write indices before they changed
	ri = rbi->RingBuffer->ReadIndex;
	wi = rbi->RingBuffer->WriteIndex;

	len = (ri <= wi) ? (wi - ri) : (rbi->RingDataSize - (ri - wi));

	if (len < sizeof(VMPACKET_DESCRIPTOR))
		return 0;

	_PREFETCHT0(rbi->RingBuffer->Buffer + ri);
#if 0
	if (ri <= wi) {
		/* no wrap */
		while (len > 0) {
			_PREFETCHT0(rbi->RingBuffer->Buffer + ri);
			len -= 128;
			ri += 128;
		}
	} else {
		/* wrap */
		while (ri < rbi->RingDataSize) {
			_PREFETCHT0(rbi->RingBuffer->Buffer + ri);
			len -= 128;
			ri += 128;
		}
		ri = 0;
		while (len > 0) {
			_PREFETCHT0(rbi->RingBuffer->Buffer + ri);
			len -= 128;
			ri += 128;
		}
	}
#endif

	return 1;

#else
	uint32_t toRead = 0;
	uint32_t toWrite;
	uint32_t addr;
	int i;

	GetRingBufferAvailBytes(rbi, &toRead, &toWrite);

	if (toRead < sizeof(VMPACKET_DESCRIPTOR))
	return 0;
	else {
		r = rbi->Ringbuffer;
		rdindx = r->ReadIndex;

		addr = r->Buffer + rdindx;
		toRead += (addr & 0x~07f);
		addr &= ~0x7f;

		if (toRead > r->size - rdindx) {
			end = buf + size;
			for(;addr < end; ) {
				_PREFETCHT0(addr & ~0x7f);
				addr += 128;

			}
		} else {
			_PREFETCH0(addr & ~0x7f);
		}
		return 1;
	}
#endif

}

