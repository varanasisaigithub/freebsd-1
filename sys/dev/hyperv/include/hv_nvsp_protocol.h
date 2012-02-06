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
 * HyperV protocol used by the network VSP/VSC.  This protocol defines the
 * messages that are sent through the VMBus ring buffer established
 * during the channel offer from the VSP to the VSC.  The small size of this
 * protocol is possible because most of the work for facilitating a network
 * connection is handled by the RNDIS protocol.
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

#ifndef __HV_NVSP_PROTOCOL_H__
#define __HV_NVSP_PROTOCOL_H__


#define NVSP_INVALID_PROTOCOL_VERSION           ((uint32_t)0xFFFFFFFF)

#define NVSP_PROTOCOL_VERSION_1                 2
#define NVSP_MIN_PROTOCOL_VERSION               (NVSP_PROTOCOL_VERSION_1)
#define NVSP_MAX_PROTOCOL_VERSION               (NVSP_PROTOCOL_VERSION_1)

typedef enum nvsp_msg_type_ {
	nvsp_msg_type_none                      = 0,

	/*
	 * Init Messages
	 */
	nvsp_msg_type_init                      = 1,
	nvsp_msg_type_init_complete             = 2,

	nvsp_version_msg_start                  = 100,

	/*
	 * Version 1 Messages
	 */
	nvsp_msg_1_type_send_ndis_vers          = nvsp_version_msg_start,

	nvsp_msg_1_type_send_rx_buf,
	nvsp_msg_1_type_send_rx_buf_complete,
	nvsp_msg_1_type_revoke_rx_buf,

	nvsp_msg_1_type_send_send_buf,
	nvsp_msg_1_type_send_send_buf_complete,
	nvsp_msg_1_type_revoke_send_buf,

	nvsp_msg_1_type_send_rndis_pkt,
	nvsp_msg_1_type_send_rndis_pkt_complete,
    
	/*
	 * This should be set to the number of messages for the version
	 * with the maximum number of messages.
	 */
	nvsp_num_msg_per_version                = 9,
} nvsp_msg_type;

typedef enum nvsp_status_ {
	nvsp_status_none = 0,
	nvsp_status_success,
	nvsp_status_failure,
	nvsp_status_prot_vers_range_too_new,
	nvsp_status_prot_vers_range_too_old,
	nvsp_status_invalid_rndis_pkt,
	nvsp_status_busy,
	nvsp_status_max,
} nvsp_status;

#pragma pack(push, 1)

typedef struct nvsp_msg_hdr_ {
	uint32_t                                MessageType;
} nvsp_msg_hdr;

/*
 * Init Messages
 */

/*
 * This message is used by the VSC to initialize the channel
 * after the channels has been opened. This message should 
 * never include anything other then versioning (i.e. this
 * message will be the same for ever).
 */
typedef struct nvsp_msg_init_ {
	uint32_t                                MinProtocolVersion;
	uint32_t                                MaxProtocolVersion;
} nvsp_msg_init;

/*
 * This message is used by the VSP to complete the initialization
 * of the channel. This message should never include anything other 
 * then versioning (i.e. this message will be the same for ever).
 */
typedef struct nvsp_msg_init_complete_ {
	uint32_t                                NegotiatedProtocolVersion;
	uint32_t                                MaximumMdlChainLength;
	uint32_t                                Status;
} nvsp_msg_init_complete;

typedef union nvsp_msg_init_uber_ {
	nvsp_msg_init                           Init;
	nvsp_msg_init_complete                  InitComplete;
} nvsp_msg_init_uber;

/*
 * Version 1 Messages
 */

/*
 * This message is used by the VSC to send the NDIS version
 * to the VSP. The VSP can use this information when handling
 * OIDs sent by the VSC.
 */
typedef struct nvsp_1_msg_send_ndis_version_ {
	uint32_t                                NdisMajorVersion;
	uint32_t                                NdisMinorVersion;
} nvsp_1_msg_send_ndis_version;

/*
 * This message is used by the VSC to send a receive buffer
 * to the VSP. The VSP can then use the receive buffer to
 * send data to the VSC.
 */
typedef struct nvsp_1_msg_send_rx_buf_ {
	uint32_t                                GpadlHandle;
	uint16_t                                Id;
} nvsp_1_msg_send_rx_buf, *pnvsp_1_msg_send_rx_buf;

typedef struct nvsp_1_rx_buf_section_ {
	uint32_t                                Offset;
	uint32_t                                SubAllocationSize;
	uint32_t                                NumSubAllocations;
	uint32_t                                EndOffset;
} nvsp_1_rx_buf_section, *pnvsp_1_rx_buf_section;

/*
 * This message is used by the VSP to acknowledge a receive 
 * buffer send by the VSC. This message must be sent by the 
 * VSP before the VSP uses the receive buffer.
 */
typedef struct nvsp_1_msg_send_rx_buf_complete_ {
	uint32_t                                Status;
	uint32_t                                NumSections;

	/*
	 * The receive buffer is split into two parts, a large
	 * suballocation section and a small suballocation
	 * section. These sections are then suballocated by a 
	 * certain size.
	 *
	 * For example, the following break up of the receive
	 * buffer has 6 large suballocations and 10 small
	 * suballocations.
	 *
	 * |            Large Section          |  |   Small Section   |
	 * ------------------------------------------------------------
	 * |     |     |     |     |     |     |  | | | | | | | | | | |
	 * |                                      |  
	 * LargeOffset                            SmallOffset
	 */
	nvsp_1_rx_buf_section                   Sections[1];

} nvsp_1_msg_send_rx_buf_complete;

/*
 * This message is sent by the VSC to revoke the receive buffer.
 * After the VSP completes this transaction, the vsp should never
 * use the receive buffer again.
 */
typedef struct nvsp_1_msg_revoke_rx_buf_ {
	uint16_t                                Id;
} nvsp_1_msg_revoke_rx_buf;

/*
 * This message is used by the VSC to send a send buffer
 * to the VSP. The VSC can then use the send buffer to
 * send data to the VSP.
 */
typedef struct nvsp_1_msg_send_send_buf_ {
	uint32_t                                GpadlHandle;
	uint16_t                                Id;
} nvsp_1_msg_send_send_buf;

/*
 * This message is used by the VSP to acknowledge a send 
 * buffer sent by the VSC. This message must be sent by the 
 * VSP before the VSP uses the sent buffer.
 */
typedef struct nvsp_1_msg_send_send_buf_complete_ {
	uint32_t                                Status;

	/*
	 * The VSC gets to choose the size of the send buffer and
	 * the VSP gets to choose the sections size of the buffer.
	 * This was done to enable dynamic reconfigurations when
	 * the cost of GPA-direct buffers decreases.
	 */
	uint32_t                                SectionSize;
} nvsp_1_msg_send_send_buf_complete;

/*
 * This message is sent by the VSC to revoke the send buffer.
 * After the VSP completes this transaction, the vsp should never
 * use the send buffer again.
 */
typedef struct nvsp_1_msg_revoke_send_buf_ {
	uint16_t                                Id;
} nvsp_1_msg_revoke_send_buf;

/*
 * This message is used by both the VSP and the VSC to send
 * a RNDIS message to the opposite channel endpoint.
 */
typedef struct nvsp_1_msg_send_rndis_pkt_ {
	/*
	 * This field is specified by RNIDS.  They assume there's
	 * two different channels of communication. However, 
	 * the Network VSP only has one.  Therefore, the channel
	 * travels with the RNDIS packet.
	 */
	uint32_t                                ChannelType;

	/*
	 * This field is used to send part or all of the data
	 * through a send buffer. This values specifies an 
	 * index into the send buffer.  If the index is 
	 * 0xFFFFFFFF, then the send buffer is not being used
	 * and all of the data was sent through other VMBus
	 * mechanisms.
	 */
	uint32_t                                SendBufferSectionIndex;
	uint32_t                                SendBufferSectionSize;
} nvsp_1_msg_send_rndis_pkt;

/*
 * This message is used by both the VSP and the VSC to complete
 * a RNDIS message to the opposite channel endpoint.  At this
 * point, the initiator of this message cannot use any resources
 * associated with the original RNDIS packet.
 */
typedef struct nvsp_1_msg_send_rndis_pkt_complete_ {
	uint32_t                                Status;
} nvsp_1_msg_send_rndis_pkt_complete;

typedef union nvsp_1_msg_uber_ {
	nvsp_1_msg_send_ndis_version            SendNdisVersion;

	nvsp_1_msg_send_rx_buf                  SendReceiveBuffer;
	nvsp_1_msg_send_rx_buf_complete         SendReceiveBufferComplete;
	nvsp_1_msg_revoke_rx_buf                RevokeReceiveBuffer;

	nvsp_1_msg_send_send_buf                SendSendBuffer;
	nvsp_1_msg_send_send_buf_complete       SendSendBufferComplete;
	nvsp_1_msg_revoke_send_buf              RevokeSendBuffer;

	nvsp_1_msg_send_rndis_pkt               SendRNDISPacket;
	nvsp_1_msg_send_rndis_pkt_complete      SendRNDISPacketComplete;
} nvsp_1_msg_uber;

typedef union nvsp_all_msgs_ {
	nvsp_msg_init_uber                      InitMessages;
	nvsp_1_msg_uber                         Version1Messages;
} nvsp_all_msgs;

/*
 * ALL Messages
 */
typedef struct nvsp_msg_ {
	nvsp_msg_hdr                            Header; 
	nvsp_all_msgs                           Messages;
} nvsp_msg;

#pragma pack(pop)

#endif  /* __HV_NVSP_PROTOCOL_H__ */

