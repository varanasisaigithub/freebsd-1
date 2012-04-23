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

#include "hyperv.h"
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
GetNextWriteLocation(hv_vmbus_ring_buffer_info* ring_info) 
{
	uint32_t next = ring_info->ring_buffer->write_index;

	return next;
}

/*++

 Name:
 SetNextWriteLocation()

 Description:
 Set the next write location for the specified ring buffer

 --*/
static inline void
SetNextWriteLocation(hv_vmbus_ring_buffer_info* ring_info,
	uint32_t NextWriteLocation) 
{
	ring_info->ring_buffer->write_index = NextWriteLocation;
}

/*++

 Name:
 GetNextReadLocation()

 Description:
 Get the next read location for the specified ring buffer

 --*/
static inline uint32_t
GetNextReadLocation(hv_vmbus_ring_buffer_info* ring_info) 
{
	uint32_t next = ring_info->ring_buffer->read_index;

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
GetNextReadLocationWithOffset(hv_vmbus_ring_buffer_info* ring_info,
	uint32_t Offset) 
{
	uint32_t next = ring_info->ring_buffer->read_index;

	next += Offset;
	next %= ring_info->ring_data_size;

	return next;
}

/*++

 Name:
 SetNextReadLocation()

 Description:
 Set the next read location for the specified ring buffer

 --*/
static inline void
SetNextReadLocation(hv_vmbus_ring_buffer_info* ring_info,
	uint32_t NextReadLocation) 
{
	ring_info->ring_buffer->read_index = NextReadLocation;
}

/*++

 Name:
 GetRingBuffer()

 Description:
 Get the start of the ring buffer

 --*/
static inline void *
GetRingBuffer(hv_vmbus_ring_buffer_info* ring_info) 
{
	return (void *) ring_info->ring_buffer->buffer;
}

/*++

 Name:
 GetRingBufferSize()

 Description:
 Get the size of the ring buffer

 --*/
static inline uint32_t
GetRingBufferSize(hv_vmbus_ring_buffer_info* ring_info) 
{
	return ring_info->ring_data_size;
}

/*++

 Name:
 GetRingBufferIndices()

 Description:
 Get the read and write indices as uint64_t of the specified ring buffer

 --*/
static inline uint64_t
GetRingBufferIndices(hv_vmbus_ring_buffer_info* ring_info) 
{
	return (uint64_t) ring_info->ring_buffer->write_index << 32;
}


//
// Internal routines
//
static uint32_t
CopyToRingBuffer(hv_vmbus_ring_buffer_info *ring_info, uint32_t StartWriteOffset, char *Src,
	uint32_t SrcLen);

static uint32_t
CopyFromRingBuffer(hv_vmbus_ring_buffer_info *ring_info, char *Dest, uint32_t DestLen,
	uint32_t StartReadOffset);

/*++

 Name:
 hv_vmbus_ring_buffer_get_debug_info()

 Description:
 Get various debug metrics for the specified ring buffer

 --*/
void
hv_vmbus_ring_buffer_get_debug_info(hv_vmbus_ring_buffer_info *ring_info,
	hv_vmbus_ring_buffer_debug_info *debug_info)
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;

	if (ring_info->ring_buffer) {
		GetRingBufferAvailBytes(ring_info, &bytesAvailToRead,
			&bytesAvailToWrite);

		debug_info->bytes_avail_to_read = bytesAvailToRead;
		debug_info->bytes_avail_to_write = bytesAvailToWrite;
		debug_info->current_read_index = ring_info->ring_buffer->read_index;
		debug_info->current_write_index = ring_info->ring_buffer->write_index;

		debug_info->current_interrupt_mask =
			ring_info->ring_buffer->interrupt_mask;
	}
}

/*++

 Name:
 hv_vmbus_get_ring_buffer_interrupt_mask()

 Description:
 Get the interrupt mask for the specified ring buffer

 --*/
uint32_t
hv_vmbus_get_ring_buffer_interrupt_mask(hv_vmbus_ring_buffer_info *rbi) 
{
	return rbi->ring_buffer->interrupt_mask;
}

/*++

 Name:
 hv_vmbus_ring_buffer_init()

 Description:
 Initialize the ring buffer

 --*/
int
hv_vmbus_ring_buffer_init(hv_vmbus_ring_buffer_info *ring_info, void *Buffer, uint32_t buffer_len) 
{

	memset(ring_info, 0, sizeof(hv_vmbus_ring_buffer_info));

	ring_info->ring_buffer = (hv_vmbus_ring_buffer*) Buffer;
	ring_info->ring_buffer->read_index = ring_info->ring_buffer->write_index = 0;

	ring_info->ring_size = buffer_len;
	ring_info->ring_data_size = buffer_len - sizeof(hv_vmbus_ring_buffer);

	mtx_init(&ring_info->ring_lock, "vmbus ring buffer", NULL, MTX_SPIN);

	return 0;
}

/*++

 Name:
 hv_ring_buffer_cleanup()

 Description:
 Cleanup the ring buffer

 --*/
void hv_ring_buffer_cleanup(hv_vmbus_ring_buffer_info* ring_info) 
{
	mtx_destroy(&ring_info->ring_lock);
}

/*++

 Name:
 hv_ring_buffer_write()

 Description:
 Write to the ring buffer

 --*/
int
hv_ring_buffer_write(hv_vmbus_ring_buffer_info* Outring_info, hv_vmbus_sg_buffer_list sg_buffers[],
	uint32_t sg_buffer_count) 
{
	int i = 0;
	uint32_t byteAvailToWrite;
	uint32_t byteAvailToRead;
	uint32_t totalBytesToWrite = 0;

	volatile uint32_t nextWriteLocation;
	uint64_t prevIndices=0;

	for (i = 0; i < sg_buffer_count; i++) {
		totalBytesToWrite += sg_buffers[i].length;
	}

	totalBytesToWrite += sizeof(uint64_t);

	mtx_lock_spin(&Outring_info->ring_lock);

	GetRingBufferAvailBytes(Outring_info, &byteAvailToRead,
		&byteAvailToWrite);


	// If there is only room for the packet, assume it is full.
	// Otherwise, the next time around, we think the ring buffer
	// is empty since the read index == write index

	if (byteAvailToWrite <= totalBytesToWrite) {

		mtx_unlock_spin(&Outring_info->ring_lock);
		return -EAGAIN;
	}

	// Write to the ring buffer
	nextWriteLocation = GetNextWriteLocation(Outring_info);

	for (i = 0; i < sg_buffer_count; i++) {
		nextWriteLocation = CopyToRingBuffer(Outring_info,
			nextWriteLocation, (char *)sg_buffers[i].data,
			sg_buffers[i].length);
	}

	// Set previous packet start
	prevIndices = GetRingBufferIndices(Outring_info);

	nextWriteLocation = CopyToRingBuffer(Outring_info, nextWriteLocation,
		(char *)&prevIndices, sizeof(uint64_t));

	// Make sure we flush all writes before updating the writeIndex
	wmb();

	// Now, update the write location
	SetNextWriteLocation(Outring_info, nextWriteLocation);


	mtx_unlock_spin(&Outring_info->ring_lock);

	return 0;
}

/*++

 Name:
 hv_ring_buffer_beek()

 Description:
 Read without advancing the read index

 --*/
int
hv_ring_buffer_beek(hv_vmbus_ring_buffer_info* Inring_info, void* Buffer, uint32_t buffer_len) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;

	mtx_lock_spin(&Inring_info->ring_lock);

	GetRingBufferAvailBytes(Inring_info, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < buffer_len) {
		mtx_unlock_spin(&Inring_info->ring_lock);
		return -EAGAIN;
	}

	// Convert to byte offset
	nextReadLocation = GetNextReadLocation(Inring_info);

	nextReadLocation = CopyFromRingBuffer(Inring_info, (char *)Buffer, buffer_len,
		nextReadLocation);

	mtx_unlock_spin(&Inring_info->ring_lock);

	return 0;
}

/*++

 Name:
 hv_ring_buffer_read()

 Description:
 Read and advance the read index

 --*/
int
hv_ring_buffer_read(hv_vmbus_ring_buffer_info* Inring_info, void *Buffer, uint32_t buffer_len,
	uint32_t Offset) 
{
	uint32_t bytesAvailToWrite;
	uint32_t bytesAvailToRead;
	uint32_t nextReadLocation = 0;
	uint64_t prevIndices = 0;

        if (buffer_len <= 0)
                return -EINVAL;

	mtx_lock_spin(&Inring_info->ring_lock);

	GetRingBufferAvailBytes(Inring_info, &bytesAvailToRead,
		&bytesAvailToWrite);

	// Make sure there is something to read
	if (bytesAvailToRead < buffer_len) {
		mtx_unlock_spin(&Inring_info->ring_lock);
		return -EAGAIN;
	}

	nextReadLocation = GetNextReadLocationWithOffset(Inring_info, Offset);

	nextReadLocation = CopyFromRingBuffer(Inring_info, (char *)Buffer, buffer_len,
		nextReadLocation);

	nextReadLocation = CopyFromRingBuffer(Inring_info, (char *)&prevIndices,
		sizeof(uint64_t), nextReadLocation);

	// Make sure all reads are done before we update the read index since 
	// the writer may start writing to the read area once the read index is updated
	wmb();

	// Update the read index
	SetNextReadLocation(Inring_info, nextReadLocation);

	//Dumpring_info(Inring_info, "AFTER ");

	mtx_unlock_spin(&Inring_info->ring_lock);

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
CopyToRingBuffer(hv_vmbus_ring_buffer_info *ring_info, uint32_t StartWriteOffset,
	char *Src, uint32_t SrcLen) 
{
	/* Fixme:  This should not be a void pointer! */
	char *ringBuffer = GetRingBuffer(ring_info);
	uint32_t ringBufferSize = GetRingBufferSize(ring_info);
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
CopyFromRingBuffer(hv_vmbus_ring_buffer_info *ring_info, char *Dest,
	uint32_t DestLen, uint32_t StartReadOffset) 
{
	char *ringBuffer = GetRingBuffer(ring_info);
	uint32_t ringBufferSize = GetRingBufferSize(ring_info);

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

