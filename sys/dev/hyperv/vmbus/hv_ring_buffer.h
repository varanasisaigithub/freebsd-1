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
 * HyperV ring buffer definition file
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

#ifndef __HV_RING_BUFFER_H__
#define __HV_RING_BUFFER_H__

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

typedef struct _SG_BUFFER_LIST {
	void		*Data;
	uint32_t	Length;
} SG_BUFFER_LIST;

typedef struct _RING_BUFFER {
	volatile uint32_t	WriteIndex;     // Offset in bytes from the start of ring data below
	volatile uint32_t	ReadIndex;      // Offset in bytes from the start of ring data below
	volatile uint32_t	InterruptMask;
	uint8_t			Reserved[4084];	// Pad it to PAGE_SIZE so that data starts on page boundary
	// NOTE: The InterruptMask field is used only for channels but since our vmbus connection
	// also uses this data structure and its data starts here, we commented out this field.
	// __volatile__ uint32_t InterruptMask;
	// Ring data starts here + RingDataStartOffset !!! DO NOT place any fields below this !!!
	uint8_t Buffer[0];
} STRUCT_PACKED RING_BUFFER;

typedef struct _RING_BUFFER_INFO {
	RING_BUFFER* RingBuffer;
	uint32_t RingSize;	// Include the shared header
	struct mtx *RingLock;
	uint32_t RingDataSize;	// < ringSize
	uint32_t RingDataStartOffset;
} RING_BUFFER_INFO;

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

#endif  /* __HV_RING_BUFFER_H__ */

