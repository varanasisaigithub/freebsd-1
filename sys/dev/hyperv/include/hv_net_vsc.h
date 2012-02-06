/*-
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
 * HyperV vmbus network vsc header file
 *
 */

/*-
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

#ifndef __HV_NET_VSC_H__
#define __HV_NET_VSC_H__


/*
 * Defines
 */

//#define NVSC_MIN_PROTOCOL_VERSION		1
//#define NVSC_MAX_PROTOCOL_VERSION		1

#define NETVSC_SEND_BUFFER_SIZE			(64*1024)   /* 64K */
#define NETVSC_SEND_BUFFER_ID			0xface


#define NETVSC_RECEIVE_BUFFER_SIZE		(1024*1024) /* 1MB */

#define NETVSC_RECEIVE_BUFFER_ID		0xcafe

#define NETVSC_RECEIVE_SG_COUNT			1

/* Preallocated receive packets */
#define NETVSC_RECEIVE_PACKETLIST_COUNT		256

/*
 * Data types
 */

/*
 * Per netvsc channel-specific
 */
typedef struct netvsc_dev_ {
	DEVICE_OBJECT				*Device;

	int					RefCount;

	int					NumOutstandingSends;
	/* List of free preallocated NETVSC_PACKET to represent RX packet */
	LIST_ENTRY				ReceivePacketList;
	void					*ReceivePacketListLock;

	/* Send buffer allocated by us but manages by NetVSP */
	void					*SendBuffer;
	uint32_t				SendBufferSize;
	uint32_t				SendBufferGpadlHandle;
	uint32_t				SendSectionSize;

	/* Receive buffer allocated by us but managed by NetVSP */
	void					*ReceiveBuffer;
	uint32_t				ReceiveBufferSize;
	uint32_t				ReceiveBufferGpadlHandle;
	uint32_t				ReceiveSectionCount;
	nvsp_1_rx_buf_section			*ReceiveSections;

	/* Used for NetVSP initialization protocol */
	void					*ChannelInitEvent;
	nvsp_msg				ChannelInitPacket;

	nvsp_msg				RevokePacket;
	//uint8_t				HwMacAddr[HW_MACADDR_LEN];

	/* Holds rndis device info */
	void					*Extension;
} netvsc_dev;

#endif  /* __HV_NET_VSC_H__ */

