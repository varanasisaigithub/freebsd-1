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
 *   K. Y. Srinivasan <kys@microsoft.com>
 */


#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>


#include "../include/hyperv.h"
#include "vmbus_priv.h"

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
GetRingBufferAvailBytes(hv_vmbus_ring_buffer_info *rbi, uint32_t *read,
			uint32_t *write) 
{
	uint32_t read_loc, write_loc;

	// Capture the read/write indices before they changed
	read_loc = rbi->ring_buffer->read_index;
	write_loc = rbi->ring_buffer->write_index;

	*write = BYTES_AVAIL_TO_WRITE(read_loc, write_loc, rbi->ring_data_size);
	*read = rbi->ring_data_size - *write;
}

/*++

 Name:
 GetNextWriteLocation()

 Description:
 Get the next write location for the specified ring buffer

 --*/
static inline uint32_t
GetNextWriteLocation(hv_vmbus_ring_buffer_info* RingInfo) 
{
	uint32_t next = RingInfo->ring_buffer->write_index;

	return next;
}

/*++

 Name:
 SetNextWriteLocation()

 Description:
 Set the next write location for the specified ring buffer

 --*/
static inline void
SetNextWriteLocation(hv_vmbus_ring_buffer_info* RingInfo,
	uint32_t NextWriteLocation) 
{
	RingInfo->ring_buffer->write_index = NextWriteLocation;
}

/*++

 Name:
 GetNextReadLocation()

 Description:
 Get the next read location for the specified ring buffer

 --*/
static inline uint32_t
GetNextReadLocation(hv_vmbus_ring_buffer_info* RingInfo) 
{
	uint32_t next = RingInfo->ring_buffer->read_index;

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
GetNextReadLocationWithOffset(hv_vmbus_ring_buffer_info* RingInfo,
	uint32_t Offset) 
{
	uint32_t next = RingInfo->ring_buffer->read_index;

	next += Offset;
	next %= RingInfo->ring_data_size;

	return next;
}

/*++

 Name:
 SetNextReadLocation()

 Description:
 Set the next read location for the specified ring buffer

 --*/
static inline void
SetNextReadLocation(hv_vmbus_ring_buffer_info* RingInfo,
	uint32_t NextReadLocation) 
{
	RingInfo->ring_buffer->read_index = NextReadLocation;
}

/*++

 Name:
 GetRingBuffer()

 Description:
 Get the start of the ring buffer

 --*/
static inline void *
GetRingBuffer(hv_vmbus_ring_buffer_info* RingInfo) 
{
	return (void *) RingInfo->ring_buffer->Buffer;
}

/*++

 Name:
 GetRingBufferSize()

 Description:
 Get the size of the ring buffer

 --*/
static inline uint32_t
GetRingBufferSize(hv_vmbus_ring_buffer_info* RingInfo) 
{
	return RingInfo->ring_data_size;
}

/*++

 Name:
 GetRingBufferIndices()

 Description:
 Get the read and write indices as uint64_t of the specified ring buffer

 --*/
static inline uint64_t
GetRingBufferIndices(hv_vmbus_ring_buffer_info* RingInfo) 
{
	return (uint64_t) RingInfo->ring_buffer->write_index << 32;
}


//
// Internal routines
//
static uint32_t
CopyToRingBuffer(hv_vmbus_ring_buffer_info *RingInfo, uint32_t StartWriteOffset, char *Src,
	uint32_t SrcLen);

static uint32_t
CopyFromRingBuffer(hv_vmbus_ring_buffer_info *RingInfo, char *Dest, uint32_t DestLen,
	uint32_t StartReadOffset);

/*++

 Name:
 RingBufferGetDebugInfo()

 Description:
 Get various debug metrics for the specified ring buffer

 --*/
void
RingBufferGetDebugInfo(hv_vmbus_ring_buffer_info *RingInfo,
	RING_BUFFER_DEBUG_INFO *DebugInfo) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;

	if (RingInfo->ring_buffer) {
		GetRingBufferAvailBytes(RingInfo, &bytesAvailToRead,
			&bytesAvailToWrite);

		DebugInfo->BytesAvailToRead = bytesAvailToRead;
		DebugInfo->BytesAvailToWrite = bytesAvailToWrite;
		DebugInfo->CurrentReadIndex = RingInfo->ring_buffer->read_index;
		DebugInfo->CurrentWriteIndex = RingInfo->ring_buffer->write_index;

		DebugInfo->Currentinterrupt_mask =
			RingInfo->ring_buffer->interrupt_mask;
	}
}

/*++

 Name:
 GetRingBufferinterrupt_mask()

 Description:
 Get the interrupt mask for the specified ring buffer

 --*/
uint32_t
GetRingBufferinterrupt_mask(hv_vmbus_ring_buffer_info *rbi) 
{
	return rbi->ring_buffer->interrupt_mask;
}

/*++

 Name:
 RingBufferInit()

 Description:
 Initialize the ring buffer

 --*/
int
RingBufferInit(hv_vmbus_ring_buffer_info *RingInfo, void *Buffer, uint32_t BufferLen) 
{

	memset(RingInfo, 0, sizeof(hv_vmbus_ring_buffer_info));

	RingInfo->ring_buffer = (hv_vmbus_ring_buffer*) Buffer;
	RingInfo->ring_buffer->read_index = RingInfo->ring_buffer->write_index = 0;

	RingInfo->ring_size = BufferLen;
	RingInfo->ring_data_size = BufferLen - sizeof(hv_vmbus_ring_buffer);

	mtx_init(&RingInfo->ring_lock, "vmbus ring buffer", NULL, MTX_SPIN);

	return 0;
}

/*++

 Name:
 RingBufferCleanup()

 Description:
 Cleanup the ring buffer

 --*/
void RingBufferCleanup(hv_vmbus_ring_buffer_info* RingInfo) 
{
	mtx_destroy(&RingInfo->ring_lock);
}

/*++

 Name:
 RingBufferWrite()

 Description:
 Write to the ring buffer

 --*/
int
RingBufferWrite(hv_vmbus_ring_buffer_info* OutRingInfo, SG_BUFFER_LIST SgBuffers[],
	uint32_t SgBufferCount) 
{
	int i = 0;
	uint32_t byteAvailToWrite;
	uint32_t byteAvailToRead;
	uint32_t totalBytesToWrite = 0;

	volatile uint32_t nextWriteLocation;
	uint64_t prevIndices=0;

	for (i = 0; i < SgBufferCount; i++) {
		totalBytesToWrite += SgBuffers[i].length;
	}

	totalBytesToWrite += sizeof(uint64_t);

	mtx_lock_spin(&OutRingInfo->ring_lock);

	GetRingBufferAvailBytes(OutRingInfo, &byteAvailToRead,
		&byteAvailToWrite);


	// If there is only room for the packet, assume it is full.
	// Otherwise, the next time around, we think the ring buffer
	// is empty since the read index == write index

	if (byteAvailToWrite <= totalBytesToWrite) {

		mtx_unlock_spin(&OutRingInfo->ring_lock);
		return -EAGAIN;
	}

	// Write to the ring buffer
	nextWriteLocation = GetNextWriteLocation(OutRingInfo);

	for (i = 0; i < SgBufferCount; i++) {
		nextWriteLocation = CopyToRingBuffer(OutRingInfo,
			nextWriteLocation, (char *)SgBuffers[i].Data,
			SgBuffers[i].length);
	}

	// Set previous packet start
	prevIndices = GetRingBufferIndices(OutRingInfo);

	nextWriteLocation = CopyToRingBuffer(OutRingInfo, nextWriteLocation,
		(char *)&prevIndices, sizeof(uint64_t));

	// Make sure we flush all writes before updating the writeIndex
	wmb();

	// Now, update the write location
	SetNextWriteLocation(OutRingInfo, nextWriteLocation);


	mtx_unlock_spin(&OutRingInfo->ring_lock);

	return 0;
}

/*++

 Name:
 RingBufferPeek()

 Description:
 Read without advancing the read index

 --*/
int
RingBufferPeek(hv_vmbus_ring_buffer_info* InRingInfo, void* Buffer, uint32_t BufferLen) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;

	mtx_lock_spin(&InRingInfo->ring_lock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		mtx_unlock_spin(&InRingInfo->ring_lock);
		return -EAGAIN;
	}

	// Convert to byte offset
	nextReadLocation = GetNextReadLocation(InRingInfo);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, (char *)Buffer, BufferLen,
		nextReadLocation);

	mtx_unlock_spin(&InRingInfo->ring_lock);

	return 0;
}

/*++

 Name:
 RingBufferRead()

 Description:
 Read and advance the read index

 --*/
int
RingBufferRead(hv_vmbus_ring_buffer_info* InRingInfo, void *Buffer, uint32_t BufferLen,
	uint32_t Offset) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;
	uint64_t prevIndices = 0;

        if (BufferLen <= 0)
                return -EINVAL;

	mtx_lock_spin(&InRingInfo->ring_lock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		mtx_unlock_spin(&InRingInfo->ring_lock);
		return -EAGAIN;
	}

	nextReadLocation = GetNextReadLocationWithOffset(InRingInfo, Offset);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, (char *)Buffer, BufferLen,
		nextReadLocation);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, (char *)&prevIndices,
		sizeof(uint64_t), nextReadLocation);

	// Make sure all reads are done before we update the read index since 
	// the writer may start writing to the read area once the read index is updated
	wmb();

	// Update the read index
	SetNextReadLocation(InRingInfo, nextReadLocation);

	//DumpRingInfo(InRingInfo, "AFTER ");

	mtx_unlock_spin(&InRingInfo->ring_lock);

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
CopyToRingBuffer(hv_vmbus_ring_buffer_info *RingInfo, uint32_t StartWriteOffset,
	char *Src, uint32_t SrcLen) 
{
	/* Fixme:  This should not be a void pointer! */
	char *ringBuffer = GetRingBuffer(RingInfo);
	uint32_t ringBufferSize = GetRingBufferSize(RingInfo);
	uint32_t fragLen;

	if (SrcLen > ringBufferSize - StartWriteOffset) // wrap-around detected!
		{

		fragLen = ringBufferSize - StartWriteOffset;
		memcpy(ringBuffer + StartWriteOffset, Src, fragLen);
		memcpy(ringBuffer, Src + fragLen, SrcLen - fragLen);
	} else {
		/* Fixme:  Cast needed due to void pointer */
		memcpy(ringBuffer + StartWriteOffset, Src, SrcLen);
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
CopyFromRingBuffer(hv_vmbus_ring_buffer_info *RingInfo, char *Dest,
	uint32_t DestLen, uint32_t StartReadOffset) 
{
	char *ringBuffer = GetRingBuffer(RingInfo);
	uint32_t ringBufferSize = GetRingBufferSize(RingInfo);

	uint32_t fragLen;

	if (DestLen > ringBufferSize - StartReadOffset) // wrap-around detected at the src
		{

		fragLen = ringBufferSize - StartReadOffset;

		memcpy(Dest, ringBuffer + StartReadOffset, fragLen);
		memcpy(Dest + fragLen, ringBuffer, DestLen - fragLen);
	} else {
		memcpy(Dest, ringBuffer + StartReadOffset, DestLen);
	}

	StartReadOffset += DestLen;
	StartReadOffset %= ringBufferSize;

	return StartReadOffset;
}

