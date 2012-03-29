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
GetRingBufferAvailBytes(RING_BUFFER_INFO *rbi, uint32_t *read,
			uint32_t *write) 
{
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
GetNextWriteLocation(RING_BUFFER_INFO* RingInfo) 
{
	uint32_t next = RingInfo->RingBuffer->WriteIndex;

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
	uint32_t NextWriteLocation) 
{
	RingInfo->RingBuffer->WriteIndex = NextWriteLocation;
}

/*++

 Name:
 GetNextReadLocation()

 Description:
 Get the next read location for the specified ring buffer

 --*/
static inline uint32_t
GetNextReadLocation(RING_BUFFER_INFO* RingInfo) 
{
	uint32_t next = RingInfo->RingBuffer->ReadIndex;

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
	uint32_t Offset) 
{
	uint32_t next = RingInfo->RingBuffer->ReadIndex;

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
	uint32_t NextReadLocation) 
{
	RingInfo->RingBuffer->ReadIndex = NextReadLocation;
}

/*++

 Name:
 GetRingBuffer()

 Description:
 Get the start of the ring buffer

 --*/
static inline void *
GetRingBuffer(RING_BUFFER_INFO* RingInfo) 
{
	return (void *) RingInfo->RingBuffer->Buffer;
}

/*++

 Name:
 GetRingBufferSize()

 Description:
 Get the size of the ring buffer

 --*/
static inline uint32_t
GetRingBufferSize(RING_BUFFER_INFO* RingInfo) 
{
	return RingInfo->RingDataSize;
}

/*++

 Name:
 GetRingBufferIndices()

 Description:
 Get the read and write indices as uint64_t of the specified ring buffer

 --*/
static inline uint64_t
GetRingBufferIndices(RING_BUFFER_INFO* RingInfo) 
{
	return (uint64_t) RingInfo->RingBuffer->WriteIndex << 32;
}


//
// Internal routines
//
static uint32_t
CopyToRingBuffer(RING_BUFFER_INFO *RingInfo, uint32_t StartWriteOffset, char *Src,
	uint32_t SrcLen);

static uint32_t
CopyFromRingBuffer(RING_BUFFER_INFO *RingInfo, char *Dest, uint32_t DestLen,
	uint32_t StartReadOffset);

/*++

 Name:
 RingBufferGetDebugInfo()

 Description:
 Get various debug metrics for the specified ring buffer

 --*/
void
RingBufferGetDebugInfo(RING_BUFFER_INFO *RingInfo,
	RING_BUFFER_DEBUG_INFO *DebugInfo) 
{
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
GetRingBufferInterruptMask(RING_BUFFER_INFO *rbi) 
{
	return rbi->RingBuffer->InterruptMask;
}

/*++

 Name:
 RingBufferInit()

 Description:
 Initialize the ring buffer

 --*/
int
RingBufferInit(RING_BUFFER_INFO *RingInfo, void *Buffer, uint32_t BufferLen) 
{

	memset(RingInfo, 0, sizeof(RING_BUFFER_INFO));

	RingInfo->RingBuffer = (RING_BUFFER*) Buffer;
	RingInfo->RingBuffer->ReadIndex = RingInfo->RingBuffer->WriteIndex = 0;

	RingInfo->RingSize = BufferLen;
	RingInfo->RingDataSize = BufferLen - sizeof(RING_BUFFER);

	mtx_init(&RingInfo->RingLock, "vmbus ring buffer", NULL, MTX_SPIN);

	return 0;
}

/*++

 Name:
 RingBufferCleanup()

 Description:
 Cleanup the ring buffer

 --*/
void RingBufferCleanup(RING_BUFFER_INFO* RingInfo) 
{
	mtx_destroy(&RingInfo->RingLock);
}

/*++

 Name:
 RingBufferWrite()

 Description:
 Write to the ring buffer

 --*/
int
RingBufferWrite(RING_BUFFER_INFO* OutRingInfo, SG_BUFFER_LIST SgBuffers[],
	uint32_t SgBufferCount) 
{
	int i = 0;
	uint32_t byteAvailToWrite;
	uint32_t byteAvailToRead;
	uint32_t totalBytesToWrite = 0;

	volatile uint32_t nextWriteLocation;
	uint64_t prevIndices=0;

	for (i = 0; i < SgBufferCount; i++) {
		totalBytesToWrite += SgBuffers[i].Length;
	}

	totalBytesToWrite += sizeof(uint64_t);

	mtx_lock_spin(&OutRingInfo->RingLock);

	GetRingBufferAvailBytes(OutRingInfo, &byteAvailToRead,
		&byteAvailToWrite);


	// If there is only room for the packet, assume it is full.
	// Otherwise, the next time around, we think the ring buffer
	// is empty since the read index == write index

	if (byteAvailToWrite <= totalBytesToWrite) {

		mtx_unlock_spin(&OutRingInfo->RingLock);
		return -EAGAIN;
	}

	// Write to the ring buffer
	nextWriteLocation = GetNextWriteLocation(OutRingInfo);

	for (i = 0; i < SgBufferCount; i++) {
		nextWriteLocation = CopyToRingBuffer(OutRingInfo,
			nextWriteLocation, (char *)SgBuffers[i].Data,
			SgBuffers[i].Length);
	}

	// Set previous packet start
	prevIndices = GetRingBufferIndices(OutRingInfo);

	nextWriteLocation = CopyToRingBuffer(OutRingInfo, nextWriteLocation,
		(char *)&prevIndices, sizeof(uint64_t));

	// Make sure we flush all writes before updating the writeIndex
	wmb();

	// Now, update the write location
	SetNextWriteLocation(OutRingInfo, nextWriteLocation);


	mtx_unlock_spin(&OutRingInfo->RingLock);

	return 0;
}

/*++

 Name:
 RingBufferPeek()

 Description:
 Read without advancing the read index

 --*/
int
RingBufferPeek(RING_BUFFER_INFO* InRingInfo, void* Buffer, uint32_t BufferLen) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;

	mtx_lock_spin(&InRingInfo->RingLock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		mtx_unlock_spin(&InRingInfo->RingLock);
		return -EAGAIN;
	}

	// Convert to byte offset
	nextReadLocation = GetNextReadLocation(InRingInfo);

	nextReadLocation = CopyFromRingBuffer(InRingInfo, (char *)Buffer, BufferLen,
		nextReadLocation);

	mtx_unlock_spin(&InRingInfo->RingLock);

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
	uint32_t Offset) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;
	uint64_t prevIndices = 0;

        if (BufferLen <= 0)
                return -EINVAL;

	mtx_lock_spin(&InRingInfo->RingLock);

	GetRingBufferAvailBytes(InRingInfo, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < BufferLen) {
		mtx_unlock_spin(&InRingInfo->RingLock);
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

	mtx_unlock_spin(&InRingInfo->RingLock);

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
CopyFromRingBuffer(RING_BUFFER_INFO *RingInfo, char *Dest,
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

