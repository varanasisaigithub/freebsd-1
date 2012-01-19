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
 * HyperV remote NDIS message structures
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

#ifndef __HV_RNDIS_H__
#define __HV_RNDIS_H__


/*
 *  Basic types
 */
typedef uint32_t                                RNDIS_REQUEST_ID;
typedef uint32_t                                RNDIS_HANDLE;
typedef uint32_t                                RNDIS_STATUS;
typedef uint32_t                                RNDIS_REQUEST_TYPE;
typedef uint32_t                                RNDIS_OID;
typedef uint32_t                                RNDIS_CLASS_ID;
typedef uint32_t                                RNDIS_MEDIUM;
typedef uint32_t                                *PRNDIS_REQUEST_ID;
typedef uint32_t                                *PRNDIS_HANDLE;
typedef uint32_t                                *PRNDIS_STATUS;
typedef uint32_t                                *PRNDIS_REQUEST_TYPE;
typedef uint32_t                                *PRNDIS_OID;
typedef uint32_t                                *PRNDIS_CLASS_ID;
typedef uint32_t                                *PRNDIS_MEDIUM;
typedef uint32_t                                RNDIS_AF;

/*
 *  Status codes
 */

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                          (0x00000000L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL                     (0xC0000001L)
#endif

#ifndef STATUS_PENDING
#define STATUS_PENDING                          (0x00000103L)
#endif

#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES           (0xC000009AL)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW                  (0x80000005L)
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED                    (0xC00000BBL)
#endif

#define RNDIS_STATUS_SUCCESS                    ((RNDIS_STATUS)STATUS_SUCCESS)
#define RNDIS_STATUS_PENDING                    ((RNDIS_STATUS)STATUS_PENDING)
#define RNDIS_STATUS_NOT_RECOGNIZED             ((RNDIS_STATUS)0x00010001L)
#define RNDIS_STATUS_NOT_COPIED                 ((RNDIS_STATUS)0x00010002L)
#define RNDIS_STATUS_NOT_ACCEPTED               ((RNDIS_STATUS)0x00010003L)
#define RNDIS_STATUS_CALL_ACTIVE                ((RNDIS_STATUS)0x00010007L)

#define RNDIS_STATUS_ONLINE                     ((RNDIS_STATUS)0x40010003L)
#define RNDIS_STATUS_RESET_START                ((RNDIS_STATUS)0x40010004L)
#define RNDIS_STATUS_RESET_END                  ((RNDIS_STATUS)0x40010005L)
#define RNDIS_STATUS_RING_STATUS                ((RNDIS_STATUS)0x40010006L)
#define RNDIS_STATUS_CLOSED                     ((RNDIS_STATUS)0x40010007L)
#define RNDIS_STATUS_WAN_LINE_UP                ((RNDIS_STATUS)0x40010008L)
#define RNDIS_STATUS_WAN_LINE_DOWN              ((RNDIS_STATUS)0x40010009L)
#define RNDIS_STATUS_WAN_FRAGMENT               ((RNDIS_STATUS)0x4001000AL)
#define RNDIS_STATUS_MEDIA_CONNECT              ((RNDIS_STATUS)0x4001000BL)
#define RNDIS_STATUS_MEDIA_DISCONNECT           ((RNDIS_STATUS)0x4001000CL)
#define RNDIS_STATUS_HARDWARE_LINE_UP           ((RNDIS_STATUS)0x4001000DL)
#define RNDIS_STATUS_HARDWARE_LINE_DOWN         ((RNDIS_STATUS)0x4001000EL)
#define RNDIS_STATUS_INTERFACE_UP               ((RNDIS_STATUS)0x4001000FL)
#define RNDIS_STATUS_INTERFACE_DOWN             ((RNDIS_STATUS)0x40010010L)
#define RNDIS_STATUS_MEDIA_BUSY                 ((RNDIS_STATUS)0x40010011L)
#define RNDIS_STATUS_MEDIA_SPECIFIC_INDICATION  ((RNDIS_STATUS)0x40010012L)
#define RNDIS_STATUS_WW_INDICATION              RNDIS_STATUS_MEDIA_SPECIFIC_INDICATION
#define RNDIS_STATUS_LINK_SPEED_CHANGE          ((RNDIS_STATUS)0x40010013L)

#define RNDIS_STATUS_NOT_RESETTABLE             ((RNDIS_STATUS)0x80010001L)
#define RNDIS_STATUS_SOFT_ERRORS                ((RNDIS_STATUS)0x80010003L)
#define RNDIS_STATUS_HARD_ERRORS                ((RNDIS_STATUS)0x80010004L)
#define RNDIS_STATUS_BUFFER_OVERFLOW            ((RNDIS_STATUS)STATUS_BUFFER_OVERFLOW)

#define RNDIS_STATUS_FAILURE                    ((RNDIS_STATUS)STATUS_UNSUCCESSFUL)
#define RNDIS_STATUS_RESOURCES                  ((RNDIS_STATUS)STATUS_INSUFFICIENT_RESOURCES)
#define RNDIS_STATUS_CLOSING                    ((RNDIS_STATUS)0xC0010002L)
#define RNDIS_STATUS_BAD_VERSION                ((RNDIS_STATUS)0xC0010004L)
#define RNDIS_STATUS_BAD_CHARACTERISTICS        ((RNDIS_STATUS)0xC0010005L)
#define RNDIS_STATUS_ADAPTER_NOT_FOUND          ((RNDIS_STATUS)0xC0010006L)
#define RNDIS_STATUS_OPEN_FAILED                ((RNDIS_STATUS)0xC0010007L)
#define RNDIS_STATUS_DEVICE_FAILED              ((RNDIS_STATUS)0xC0010008L)
#define RNDIS_STATUS_MULTICAST_FULL             ((RNDIS_STATUS)0xC0010009L)
#define RNDIS_STATUS_MULTICAST_EXISTS           ((RNDIS_STATUS)0xC001000AL)
#define RNDIS_STATUS_MULTICAST_NOT_FOUND        ((RNDIS_STATUS)0xC001000BL)
#define RNDIS_STATUS_REQUEST_ABORTED            ((RNDIS_STATUS)0xC001000CL)
#define RNDIS_STATUS_RESET_IN_PROGRESS          ((RNDIS_STATUS)0xC001000DL)
#define RNDIS_STATUS_CLOSING_INDICATING         ((RNDIS_STATUS)0xC001000EL)
#define RNDIS_STATUS_NOT_SUPPORTED              ((RNDIS_STATUS)STATUS_NOT_SUPPORTED)
#define RNDIS_STATUS_INVALID_PACKET             ((RNDIS_STATUS)0xC001000FL)
#define RNDIS_STATUS_OPEN_LIST_FULL             ((RNDIS_STATUS)0xC0010010L)
#define RNDIS_STATUS_ADAPTER_NOT_READY          ((RNDIS_STATUS)0xC0010011L)
#define RNDIS_STATUS_ADAPTER_NOT_OPEN           ((RNDIS_STATUS)0xC0010012L)
#define RNDIS_STATUS_NOT_INDICATING             ((RNDIS_STATUS)0xC0010013L)
#define RNDIS_STATUS_INVALID_LENGTH             ((RNDIS_STATUS)0xC0010014L)
#define RNDIS_STATUS_INVALID_DATA               ((RNDIS_STATUS)0xC0010015L)
#define RNDIS_STATUS_BUFFER_TOO_SHORT           ((RNDIS_STATUS)0xC0010016L)
#define RNDIS_STATUS_INVALID_OID                ((RNDIS_STATUS)0xC0010017L)
#define RNDIS_STATUS_ADAPTER_REMOVED            ((RNDIS_STATUS)0xC0010018L)
#define RNDIS_STATUS_UNSUPPORTED_MEDIA          ((RNDIS_STATUS)0xC0010019L)
#define RNDIS_STATUS_GROUP_ADDRESS_IN_USE       ((RNDIS_STATUS)0xC001001AL)
#define RNDIS_STATUS_FILE_NOT_FOUND             ((RNDIS_STATUS)0xC001001BL)
#define RNDIS_STATUS_ERROR_READING_FILE         ((RNDIS_STATUS)0xC001001CL)
#define RNDIS_STATUS_ALREADY_MAPPED             ((RNDIS_STATUS)0xC001001DL)
#define RNDIS_STATUS_RESOURCE_CONFLICT          ((RNDIS_STATUS)0xC001001EL)
#define RNDIS_STATUS_NO_CABLE                   ((RNDIS_STATUS)0xC001001FL)

#define RNDIS_STATUS_INVALID_SAP                ((RNDIS_STATUS)0xC0010020L)
#define RNDIS_STATUS_SAP_IN_USE                 ((RNDIS_STATUS)0xC0010021L)
#define RNDIS_STATUS_INVALID_ADDRESS            ((RNDIS_STATUS)0xC0010022L)
#define RNDIS_STATUS_VC_NOT_ACTIVATED           ((RNDIS_STATUS)0xC0010023L)
#define RNDIS_STATUS_DEST_OUT_OF_ORDER          ((RNDIS_STATUS)0xC0010024L)
#define RNDIS_STATUS_VC_NOT_AVAILABLE           ((RNDIS_STATUS)0xC0010025L)
#define RNDIS_STATUS_CELLRATE_NOT_AVAILABLE     ((RNDIS_STATUS)0xC0010026L)
#define RNDIS_STATUS_INCOMPATABLE_QOS           ((RNDIS_STATUS)0xC0010027L)
#define RNDIS_STATUS_AAL_PARAMS_UNSUPPORTED     ((RNDIS_STATUS)0xC0010028L)
#define RNDIS_STATUS_NO_ROUTE_TO_DESTINATION    ((RNDIS_STATUS)0xC0010029L)

#define RNDIS_STATUS_TOKEN_RING_OPEN_ERROR      ((RNDIS_STATUS)0xC0011000L)


/*
 * Object Identifiers used by NdisRequest Query/Set Information
 */

/*
 * General Objects
 */

#define RNDIS_OID_GEN_SUPPORTED_LIST                    0x00010101
#define RNDIS_OID_GEN_HARDWARE_STATUS                   0x00010102
#define RNDIS_OID_GEN_MEDIA_SUPPORTED                   0x00010103
#define RNDIS_OID_GEN_MEDIA_IN_USE                      0x00010104
#define RNDIS_OID_GEN_MAXIMUM_LOOKAHEAD                 0x00010105
#define RNDIS_OID_GEN_MAXIMUM_FRAME_SIZE                0x00010106
#define RNDIS_OID_GEN_LINK_SPEED                        0x00010107
#define RNDIS_OID_GEN_TRANSMIT_BUFFER_SPACE             0x00010108
#define RNDIS_OID_GEN_RECEIVE_BUFFER_SPACE              0x00010109
#define RNDIS_OID_GEN_TRANSMIT_BLOCK_SIZE               0x0001010A
#define RNDIS_OID_GEN_RECEIVE_BLOCK_SIZE                0x0001010B
#define RNDIS_OID_GEN_VENDOR_ID                         0x0001010C
#define RNDIS_OID_GEN_VENDOR_DESCRIPTION                0x0001010D
#define RNDIS_OID_GEN_CURRENT_PACKET_FILTER             0x0001010E
#define RNDIS_OID_GEN_CURRENT_LOOKAHEAD                 0x0001010F
#define RNDIS_OID_GEN_DRIVER_VERSION                    0x00010110
#define RNDIS_OID_GEN_MAXIMUM_TOTAL_SIZE                0x00010111
#define RNDIS_OID_GEN_PROTOCOL_OPTIONS                  0x00010112
#define RNDIS_OID_GEN_MAC_OPTIONS                       0x00010113
#define RNDIS_OID_GEN_MEDIA_CONNECT_STATUS              0x00010114
#define RNDIS_OID_GEN_MAXIMUM_SEND_PACKETS              0x00010115
#define RNDIS_OID_GEN_VENDOR_DRIVER_VERSION             0x00010116
#define RNDIS_OID_GEN_NETWORK_LAYER_ADDRESSES           0x00010118
#define RNDIS_OID_GEN_TRANSPORT_HEADER_OFFSET           0x00010119
#define RNDIS_OID_GEN_MACHINE_NAME                      0x0001021A
#define RNDIS_OID_GEN_RNDIS_CONFIG_PARAMETER            0x0001021B

#define RNDIS_OID_GEN_XMIT_OK                           0x00020101
#define RNDIS_OID_GEN_RCV_OK                            0x00020102
#define RNDIS_OID_GEN_XMIT_ERROR                        0x00020103
#define RNDIS_OID_GEN_RCV_ERROR                         0x00020104
#define RNDIS_OID_GEN_RCV_NO_BUFFER                     0x00020105

#define RNDIS_OID_GEN_DIRECTED_BYTES_XMIT               0x00020201
#define RNDIS_OID_GEN_DIRECTED_FRAMES_XMIT              0x00020202
#define RNDIS_OID_GEN_MULTICAST_BYTES_XMIT              0x00020203
#define RNDIS_OID_GEN_MULTICAST_FRAMES_XMIT             0x00020204
#define RNDIS_OID_GEN_BROADCAST_BYTES_XMIT              0x00020205
#define RNDIS_OID_GEN_BROADCAST_FRAMES_XMIT             0x00020206
#define RNDIS_OID_GEN_DIRECTED_BYTES_RCV                0x00020207
#define RNDIS_OID_GEN_DIRECTED_FRAMES_RCV               0x00020208
#define RNDIS_OID_GEN_MULTICAST_BYTES_RCV               0x00020209
#define RNDIS_OID_GEN_MULTICAST_FRAMES_RCV              0x0002020A
#define RNDIS_OID_GEN_BROADCAST_BYTES_RCV               0x0002020B
#define RNDIS_OID_GEN_BROADCAST_FRAMES_RCV              0x0002020C

#define RNDIS_OID_GEN_RCV_CRC_ERROR                     0x0002020D
#define RNDIS_OID_GEN_TRANSMIT_QUEUE_LENGTH             0x0002020E

#define RNDIS_OID_GEN_GET_TIME_CAPS                     0x0002020F
#define RNDIS_OID_GEN_GET_NETCARD_TIME                  0x00020210

/*
 * These are connection-oriented general OIDs.
 * These replace the above OIDs for connection-oriented media.
 */
#define RNDIS_OID_GEN_CO_SUPPORTED_LIST                 0x00010101
#define RNDIS_OID_GEN_CO_HARDWARE_STATUS                0x00010102
#define RNDIS_OID_GEN_CO_MEDIA_SUPPORTED                0x00010103
#define RNDIS_OID_GEN_CO_MEDIA_IN_USE                   0x00010104
#define RNDIS_OID_GEN_CO_LINK_SPEED                     0x00010105
#define RNDIS_OID_GEN_CO_VENDOR_ID                      0x00010106
#define RNDIS_OID_GEN_CO_VENDOR_DESCRIPTION             0x00010107
#define RNDIS_OID_GEN_CO_DRIVER_VERSION                 0x00010108
#define RNDIS_OID_GEN_CO_PROTOCOL_OPTIONS               0x00010109
#define RNDIS_OID_GEN_CO_MAC_OPTIONS                    0x0001010A
#define RNDIS_OID_GEN_CO_MEDIA_CONNECT_STATUS           0x0001010B
#define RNDIS_OID_GEN_CO_VENDOR_DRIVER_VERSION          0x0001010C
#define RNDIS_OID_GEN_CO_MINIMUM_LINK_SPEED             0x0001010D

#define RNDIS_OID_GEN_CO_GET_TIME_CAPS                  0x00010201
#define RNDIS_OID_GEN_CO_GET_NETCARD_TIME               0x00010202

/*
 * These are connection-oriented statistics OIDs.
 */
#define RNDIS_OID_GEN_CO_XMIT_PDUS_OK                   0x00020101
#define RNDIS_OID_GEN_CO_RCV_PDUS_OK                    0x00020102
#define RNDIS_OID_GEN_CO_XMIT_PDUS_ERROR                0x00020103
#define RNDIS_OID_GEN_CO_RCV_PDUS_ERROR                 0x00020104
#define RNDIS_OID_GEN_CO_RCV_PDUS_NO_BUFFER             0x00020105


#define RNDIS_OID_GEN_CO_RCV_CRC_ERROR                  0x00020201
#define RNDIS_OID_GEN_CO_TRANSMIT_QUEUE_LENGTH          0x00020202
#define RNDIS_OID_GEN_CO_BYTES_XMIT                     0x00020203
#define RNDIS_OID_GEN_CO_BYTES_RCV                      0x00020204
#define RNDIS_OID_GEN_CO_BYTES_XMIT_OUTSTANDING         0x00020205
#define RNDIS_OID_GEN_CO_NETCARD_LOAD                   0x00020206

/*
 * These are objects for Connection-oriented media call-managers.
 */
#define RNDIS_OID_CO_ADD_PVC                            0xFF000001
#define RNDIS_OID_CO_DELETE_PVC                         0xFF000002
#define RNDIS_OID_CO_GET_CALL_INFORMATION               0xFF000003
#define RNDIS_OID_CO_ADD_ADDRESS                        0xFF000004
#define RNDIS_OID_CO_DELETE_ADDRESS                     0xFF000005
#define RNDIS_OID_CO_GET_ADDRESSES                      0xFF000006
#define RNDIS_OID_CO_ADDRESS_CHANGE                     0xFF000007
#define RNDIS_OID_CO_SIGNALING_ENABLED                  0xFF000008
#define RNDIS_OID_CO_SIGNALING_DISABLED                 0xFF000009


/*
 * 802.3 Objects (Ethernet)
 */

#define RNDIS_OID_802_3_PERMANENT_ADDRESS               0x01010101
#define RNDIS_OID_802_3_CURRENT_ADDRESS                 0x01010102
#define RNDIS_OID_802_3_MULTICAST_LIST                  0x01010103
#define RNDIS_OID_802_3_MAXIMUM_LIST_SIZE               0x01010104
#define RNDIS_OID_802_3_MAC_OPTIONS                     0x01010105

/*
 *
 */
#define NDIS_802_3_MAC_OPTION_PRIORITY                  0x00000001

#define RNDIS_OID_802_3_RCV_ERROR_ALIGNMENT             0x01020101
#define RNDIS_OID_802_3_XMIT_ONE_COLLISION              0x01020102
#define RNDIS_OID_802_3_XMIT_MORE_COLLISIONS            0x01020103

#define RNDIS_OID_802_3_XMIT_DEFERRED                   0x01020201
#define RNDIS_OID_802_3_XMIT_MAX_COLLISIONS             0x01020202
#define RNDIS_OID_802_3_RCV_OVERRUN                     0x01020203
#define RNDIS_OID_802_3_XMIT_UNDERRUN                   0x01020204
#define RNDIS_OID_802_3_XMIT_HEARTBEAT_FAILURE          0x01020205
#define RNDIS_OID_802_3_XMIT_TIMES_CRS_LOST             0x01020206
#define RNDIS_OID_802_3_XMIT_LATE_COLLISIONS            0x01020207


/*
 * Remote NDIS message types
 */
#define REMOTE_NDIS_PACKET_MSG                  0x00000001
#define REMOTE_NDIS_INITIALIZE_MSG              0x00000002
#define REMOTE_NDIS_HALT_MSG                    0x00000003
#define REMOTE_NDIS_QUERY_MSG                   0x00000004
#define REMOTE_NDIS_SET_MSG                     0x00000005
#define REMOTE_NDIS_RESET_MSG                   0x00000006
#define REMOTE_NDIS_INDICATE_STATUS_MSG         0x00000007
#define REMOTE_NDIS_KEEPALIVE_MSG               0x00000008

#define REMOTE_CONDIS_MP_CREATE_VC_MSG          0x00008001
#define REMOTE_CONDIS_MP_DELETE_VC_MSG          0x00008002
#define REMOTE_CONDIS_MP_ACTIVATE_VC_MSG        0x00008005
#define REMOTE_CONDIS_MP_DEACTIVATE_VC_MSG      0x00008006
#define REMOTE_CONDIS_INDICATE_STATUS_MSG       0x00008007

/*
 * Remote NDIS message completion types
 */
#define REMOTE_NDIS_INITIALIZE_CMPLT            0x80000002
#define REMOTE_NDIS_QUERY_CMPLT                 0x80000004
#define REMOTE_NDIS_SET_CMPLT                   0x80000005
#define REMOTE_NDIS_RESET_CMPLT                 0x80000006
#define REMOTE_NDIS_KEEPALIVE_CMPLT             0x80000008

#define REMOTE_CONDIS_MP_CREATE_VC_CMPLT        0x80008001
#define REMOTE_CONDIS_MP_DELETE_VC_CMPLT        0x80008002
#define REMOTE_CONDIS_MP_ACTIVATE_VC_CMPLT      0x80008005
#define REMOTE_CONDIS_MP_DEACTIVATE_VC_CMPLT    0x80008006

/*
 * Reserved message type for private communication between lower-layer
 * host driver and remote device, if necessary.
 */
#define REMOTE_NDIS_BUS_MSG                     0xff000001

/*
 * Defines for DeviceFlags in rndis_initialize_complete
 */
#define RNDIS_DF_CONNECTIONLESS             0x00000001
#define RNDIS_DF_CONNECTION_ORIENTED        0x00000002
#define RNDIS_DF_RAW_DATA                   0x00000004

/*
 * Remote NDIS medium types.
 */
#define RNdisMedium802_3                    0x00000000
#define RNdisMedium802_5                    0x00000001
#define RNdisMediumFddi                     0x00000002
#define RNdisMediumWan                      0x00000003
#define RNdisMediumLocalTalk                0x00000004
#define RNdisMediumArcnetRaw                0x00000006
#define RNdisMediumArcnet878_2              0x00000007
#define RNdisMediumAtm                      0x00000008
#define RNdisMediumWirelessWan              0x00000009
#define RNdisMediumIrda                     0x0000000a
#define RNdisMediumCoWan                    0x0000000b
#define RNdisMediumMax                      0x0000000d     // Not a real medium, defined as an upper-bound

/*
 * Remote NDIS medium connection states.
 */
#define RNdisMediaStateConnected            0x00000000
#define RNdisMediaStateDisconnected         0x00000001

/*
 * Remote NDIS version numbers
 */
#define RNDIS_MAJOR_VERSION                 0x00000001
#define RNDIS_MINOR_VERSION                 0x00000000

/*
 * NdisInitialize message
 */
typedef struct rndis_initialize_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    uint32_t                                MajorVersion;
    uint32_t                                MinorVersion;
    uint32_t                                MaxTransferSize;
} rndis_initialize_request, *prndis_initialize_request;


/*
 *  Response to NdisInitialize
 */
typedef struct rndis_initialize_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
    uint32_t                                MajorVersion;
    uint32_t                                MinorVersion;
    uint32_t                                DeviceFlags;
    RNDIS_MEDIUM                            Medium;
    uint32_t                                MaxPacketsPerMessage;
    uint32_t                                MaxTransferSize;
    uint32_t                                PacketAlignmentFactor;
    uint32_t                                AFListOffset;
    uint32_t                                AFListSize;
} rndis_initialize_complete, *prndis_initialize_complete;


/*
 *  Call manager devices only: Information about an address family
 *  supported by the device is appended to the response to NdisInitialize.
 */
typedef struct rndis_co_address_family_ {
    RNDIS_AF                                AddressFamily;
    uint32_t                                MajorVersion;
    uint32_t                                MinorVersion;
} rndis_co_address_family, *prndis_co_address_family;


/*
 *  NdisHalt message
 */
typedef struct rndis_halt_request_ {
    RNDIS_REQUEST_ID                        RequestId;
} rndis_halt_request, *prndis_halt_request;


/*
 * NdisQueryRequest message
 */
typedef struct rndis_query_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_OID                               Oid;
    uint32_t                                InformationBufferLength;
    uint32_t                                InformationBufferOffset;
    RNDIS_HANDLE                            DeviceVcHandle;
} rndis_query_request, *prndis_query_request;


/*
 * Response to NdisQueryRequest
 */
typedef struct rndis_query_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
    uint32_t                                InformationBufferLength;
    uint32_t                                InformationBufferOffset;
} rndis_query_complete, *prndis_query_complete;


/*
 * NdisSetRequest message
 */
typedef struct rndis_set_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_OID                               Oid;
    uint32_t                                InformationBufferLength;
    uint32_t                                InformationBufferOffset;
    RNDIS_HANDLE                            DeviceVcHandle;
} rndis_set_request, *prndis_set_request;


/*
 * Response to NdisSetRequest
 */
typedef struct rndis_set_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
} rndis_set_complete, *prndis_set_complete;


/*
 * NdisReset message
 */
typedef struct rndis_reset_request_ {
    uint32_t                                Reserved;
} rndis_reset_request, *prndis_reset_request;

/*
 * Response to NdisReset
 */
typedef struct rndis_reset_complete_ {
    RNDIS_STATUS                            Status;
    uint32_t                                AddressingReset;
} rndis_reset_complete, *prndis_reset_complete;


/*
 * NdisMIndicateStatus message
 */
typedef struct rndis_indicate_status_ {
    RNDIS_STATUS                            Status;
    uint32_t                                StatusBufferLength;
    uint32_t                                StatusBufferOffset;
} rndis_indicate_status, *prndis_indicate_status;


/*
 * Diagnostic information passed as the status buffer in
 * rndis_indicate_status messages signifying error conditions.
 */
typedef struct rndis_diagnostic_info_ {
    RNDIS_STATUS                            DiagStatus;
    uint32_t                                ErrorOffset;
} rndis_diagnostic_info, *prndis_diagnostic_info;



/*
 * NdisKeepAlive message
 */
typedef struct rndis_keepalive_request_ {
    RNDIS_REQUEST_ID                        RequestId;
} rndis_keepalive_request, *prndis_keepalive_request;


/*
 * Response to NdisKeepAlive
 */  
typedef struct rndis_keepalive_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
} rndis_keepalive_complete, *prndis_keepalive_complete;


/*
 *  Data message. All Offset fields contain byte offsets from the beginning
 *  of the rndis_packet structure. All Length fields are in bytes.
 *  VcHandle is set to 0 for connectionless data, otherwise it
 *  contains the VC handle.
 */
typedef struct rndis_packet_ {
    uint32_t                                DataOffset;
    uint32_t                                DataLength;
    uint32_t                                OOBDataOffset;
    uint32_t                                OOBDataLength;
    uint32_t                                NumOOBDataElements;
    uint32_t                                PerPacketInfoOffset;
    uint32_t                                PerPacketInfoLength;
    RNDIS_HANDLE                            VcHandle;
    uint32_t                                Reserved;
} rndis_packet, *prndis_packet;

/*
 *  Optional Out of Band data associated with a Data message.
 */
typedef struct rndis_oobd_ {
    uint32_t                                Size;
    RNDIS_CLASS_ID                          Type;
    uint32_t                                ClassInformationOffset;
} rndis_oobd, *prndis_oobd;

/*
 * Packet extension field contents associated with a Data message.
 */
typedef struct rndis_per_packet_info_ {
    uint32_t                                Size;
    uint32_t                                Type;
    uint32_t                                PerPacketInformationOffset;
} rndis_per_packet_info, *prndis_per_packet_info;

/*
 * Format of Information buffer passed in a SetRequest for the OID
 * OID_GEN_RNDIS_CONFIG_PARAMETER.
 */
typedef struct rndis_config_parameter_info_ {
    uint32_t                                ParameterNameOffset;
    uint32_t                                ParameterNameLength;
    uint32_t                                ParameterType;
    uint32_t                                ParameterValueOffset;
    uint32_t                                ParameterValueLength;
} rndis_config_parameter_info, *prndis_config_parameter_info;

/*
 * Values for ParameterType in rndis_config_parameter_info
 */
#define RNDIS_CONFIG_PARAM_TYPE_INTEGER     0
#define RNDIS_CONFIG_PARAM_TYPE_STRING      2


/*
 * CONDIS Miniport messages for connection oriented devices
 * that do not implement a call manager.
 */

/*
 * CoNdisMiniportCreateVc message
 */
typedef struct rcondis_mp_create_vc_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_HANDLE                            NdisVcHandle;
} rcondis_mp_create_vc, *prcondis_mp_create_vc;

/*
 * Response to CoNdisMiniportCreateVc
 */
typedef struct rcondis_mp_create_vc_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_HANDLE                            DeviceVcHandle;
    RNDIS_STATUS                            Status;
} rcondis_mp_create_vc_complete, *prcondis_mp_create_vc_complete;

/*
 * CoNdisMiniportDeleteVc message
 */
typedef struct rcondis_mp_delete_vc_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_HANDLE                            DeviceVcHandle;
} rcondis_mp_delete_vc, *prcondis_mp_delete_vc;

/*
 * Response to CoNdisMiniportDeleteVc
 */
typedef struct rcondis_mp_delete_vc_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
} rcondis_mp_delete_vc_complete, *prcondis_mp_delete_vc_complete;

/*
 * CoNdisMiniportQueryRequest message
 */
typedef struct rcondis_mp_query_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_REQUEST_TYPE                      RequestType;
    RNDIS_OID                               Oid;
    RNDIS_HANDLE                            DeviceVcHandle;
    uint32_t                                InformationBufferLength;
    uint32_t                                InformationBufferOffset;
} rcondis_mp_query_request, *prcondis_mp_query_request;

/*
 * CoNdisMiniportSetRequest message
 */
typedef struct rcondis_mp_set_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_REQUEST_TYPE                      RequestType;
    RNDIS_OID                               Oid;
    RNDIS_HANDLE                            DeviceVcHandle;
    uint32_t                                InformationBufferLength;
    uint32_t                                InformationBufferOffset;
} rcondis_mp_set_request, *prcondis_mp_set_request;

/*
 * CoNdisIndicateStatus message
 */
typedef struct rcondis_indicate_status_ {
    RNDIS_HANDLE                            NdisVcHandle;
    RNDIS_STATUS                            Status;
    uint32_t                                StatusBufferLength;
    uint32_t                                StatusBufferOffset;
} rcondis_indicate_status, *prcondis_indicate_status;

/*
 * CONDIS Call/VC parameters
 */

typedef struct rcondis_specific_parameters_ {
    uint32_t                                ParameterType;
    uint32_t                                ParameterLength;
    uint32_t                                ParameterOffset;
} rcondis_specific_parameters, *Prcondis_specific_parameters;

typedef struct rcondis_media_parameters_ {
    uint32_t                                Flags;
    uint32_t                                Reserved1;
    uint32_t                                Reserved2;
    rcondis_specific_parameters             MediaSpecific;
} rcondis_media_parameters, *prcondis_media_parameters;


typedef struct rndis_flowspec_ {
    uint32_t                                TokenRate;
    uint32_t                                TokenBucketSize;
    uint32_t                                PeakBandwidth;
    uint32_t                                Latency;
    uint32_t                                DelayVariation;
    uint32_t                                ServiceType;
    uint32_t                                MaxSduSize;
    uint32_t                                MinimumPolicedSize;
} rndis_flowspec, *prndis_flowspec;

typedef struct rcondis_call_manager_parameters_ {
    rndis_flowspec                          Transmit;
    rndis_flowspec                          Receive;
    rcondis_specific_parameters             CallMgrSpecific;
} rcondis_call_manager_parameters, *prcondis_call_manager_parameters;

/*
 * CoNdisMiniportActivateVc message
 */
typedef struct rcondis_mp_activate_vc_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    uint32_t                                Flags;
    RNDIS_HANDLE                            DeviceVcHandle;
    uint32_t                                MediaParamsOffset;
    uint32_t                                MediaParamsLength;
    uint32_t                                CallMgrParamsOffset;
    uint32_t                                CallMgrParamsLength;
} rcondis_mp_activate_vc_request, *prcondis_mp_activate_vc_request;

/*
 * Response to CoNdisMiniportActivateVc
 */
typedef struct rcondis_mp_activate_vc_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
} rcondis_mp_activate_vc_complete, *prcondis_mp_activate_vc_complete;

/*
 * CoNdisMiniportDeactivateVc message
 */
typedef struct rcondis_mp_deactivate_vc_request_ {
    RNDIS_REQUEST_ID                        RequestId;
    uint32_t                                Flags;
    RNDIS_HANDLE                            DeviceVcHandle;
} rcondis_mp_deactivate_vc_request, *prcondis_mp_deactivate_vc_request;

/*
 * Response to CoNdisMiniportDeactivateVc
 */
typedef struct rcondis_mp_deactivate_vc_complete_ {
    RNDIS_REQUEST_ID                        RequestId;
    RNDIS_STATUS                            Status;
} rcondis_mp_deactivate_vc_complete, *prcondis_mp_deactivate_vc_complete;


/*
 * union with all of the RNDIS messages
 */
typedef union rndis_msg_container_ {
    rndis_packet                        Packet;
    rndis_initialize_request            InitializeRequest;
    rndis_halt_request                  HaltRequest;
    rndis_query_request                 QueryRequest;
    rndis_set_request                   SetRequest;
    rndis_reset_request                 ResetRequest;
    rndis_keepalive_request             KeepaliveRequest;
    rndis_indicate_status               IndicateStatus;
    rndis_initialize_complete           InitializeComplete;
    rndis_query_complete                QueryComplete;
    rndis_set_complete                  SetComplete;
    rndis_reset_complete                ResetComplete;
    rndis_keepalive_complete            KeepaliveComplete;
    rcondis_mp_create_vc                CoMiniportCreateVc;
    rcondis_mp_delete_vc                CoMiniportDeleteVc;
    rcondis_indicate_status             CoIndicateStatus;
    rcondis_mp_activate_vc_request      CoMiniportActivateVc;
    rcondis_mp_deactivate_vc_request    CoMiniportDeactivateVc;
    rcondis_mp_create_vc_complete       CoMiniportCreateVcComplete;
    rcondis_mp_delete_vc_complete       CoMiniportDeleteVcComplete;
    rcondis_mp_activate_vc_complete     CoMiniportActivateVcComplete;
    rcondis_mp_deactivate_vc_complete   CoMiniportDeactivateVcComplete;
} rndis_msg_container, *prndis_msg_container;

/*
 * Remote NDIS message format
 */
typedef /* __struct_bcount(MessageLength) */ struct _rndis_msg {
    uint32_t                                ndis_msg_type;

    /*
     * Total length of this message, from the beginning
     * of the rndis_msg struct, in bytes.
     */
    uint32_t                                msg_len;

    /* Actual message */
    rndis_msg_container                     msg;
} rndis_msg, *prndis_msg;


/*
 * Handy macros
 */

/*
 * get the size of an RNDIS message. Pass in the message type, 
 * rndis_set_request, rndis_packet for example
 */
#define RNDIS_MESSAGE_SIZE(Message)                             \
    (sizeof(Message) + (sizeof(rndis_msg) - sizeof(rndis_msg_container)))

/*
 * get pointer to info buffer with message pointer
 */
#define MESSAGE_TO_INFO_BUFFER(Message)                         \
    (((PUCHAR)(Message)) + Message->InformationBufferOffset)

/*
 * get pointer to status buffer with message pointer
 */
#define MESSAGE_TO_STATUS_BUFFER(Message)                       \
    (((PUCHAR)(Message)) + Message->StatusBufferOffset)

/*
 * get pointer to OOBD buffer with message pointer
 */
#define MESSAGE_TO_OOBD_BUFFER(Message)                         \
    (((PUCHAR)(Message)) + Message->OOBDataOffset)

/*
 * get pointer to data buffer with message pointer
 */
#define MESSAGE_TO_DATA_BUFFER(Message)                         \
    (((PUCHAR)(Message)) + Message->PerPacketInfoOffset)

/*
 * get pointer to contained message from NDIS_MESSAGE pointer
 */
#define RNDIS_MESSAGE_PTR_TO_MESSAGE_PTR(RndisMessage)          \
    ((PVOID) &RndisMessage->Message)

/*
 * get pointer to contained message from NDIS_MESSAGE pointer
 */
#define RNDIS_MESSAGE_RAW_PTR_TO_MESSAGE_PTR(RndisMessage)      \
    ((PVOID) RndisMessage)

#endif  /* __HV_RNDIS_H__ */

