#ifndef __HV_VSTORAGE_H__
#define __HV_VSTORAGE_H__
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

/*
 * hv_vstorage.h revision number.  This is used in the case of a version match,
 * to alert the user that structure sizes may be mismatched even though the
 * protocol versions match.
 */

#define REVISION_STRING(REVISION_) #REVISION_
#define FILL_VMSTOR_REVISION(RESULT_LVALUE_)                     \
{                                                                \
    char *rev_str = REVISION_STRING($Revision: 6 $) + 11; \
    RESULT_LVALUE_ = 0;                                          \
    while (*rev_str >= '0' && *rev_str <= '9')     \
    {                                                            \
        RESULT_LVALUE_ *= 10;                                    \
        RESULT_LVALUE_ += *rev_str - '0';                 \
        rev_str++;                                        \
    }                                                            \
}

//
// Major/minor macros.  Minor version is in LSB, meaning that earlier flat
// version numbers will be interpreted as "0.x" (i.e., 1 becomes 0.1).
//

#define VMSTOR_PROTOCOL_MAJOR(VERSION_)         (((VERSION_) >> 8) & 0xff)
#define VMSTOR_PROTOCOL_MINOR(VERSION_)         (((VERSION_)     ) & 0xff)
#define VMSTOR_PROTOCOL_VERSION(MAJOR_, MINOR_) ((((MAJOR_) & 0xff) << 8) | \
                                                 (((MINOR_) & 0xff)     ))

//
// Invalid version.
//

#define VMSTOR_INVALID_PROTOCOL_VERSION  -1

//
// Version history:
// V1 Beta                    0.1
// V1 RC < 2008/1/31          1.0
// V1 RC > 2008/1/31          2.0
//
#define VMSTOR_PROTOCOL_VERSION_CURRENT VMSTOR_PROTOCOL_VERSION(2, 0)


//
//  This will get replaced with the max transfer length that is possible on
//  the host adapter.
//  The max transfer length will be published when we offer a vmbus channel.
//

#define MAX_TRANSFER_LENGTH 0x40000
#define DEFAULT_PACKET_SIZE (sizeof(VMDATA_GPA_DIRECT) +   \
                             sizeof(struct vstor_packet) + \
                             (sizeof(uint64_t) * \
							  (MAX_TRANSFER_LENGTH / PAGE_SIZE)))



//
//  Packet structure describing virtual storage requests.
//

enum vstor_packet_ops {
    VSTOR_OPERATION_COMPLETEIO            = 1,
    VSTOR_OPERATION_REMOVEDEVICE          = 2,
    VSTOR_OPERATION_EXECUTESRB            = 3,
    VSTOR_OPERATION_RESETLUN              = 4,
    VSTOR_OPERATION_RESETADAPTER          = 5,
    VSTOR_OPERATION_RESETBUS              = 6,
    VSTOR_OPERATION_BEGININITIALIZATION   = 7,
    VSTOR_OPERATION_ENDINITIALIZATION     = 8,
    VSTOR_OPERATION_QUERYPROTOCOLVERSION  = 9,
    VSTOR_OPERATION_QUERYPROPERTIES       = 10,
    VSTOR_OPERATION_MAXIMUM               = 10
};


//
//  Platform neutral description of a scsi request -
//  this remains the same across the write regardless of 32/64 bit
//  note: it's patterned off the SCSI_PASS_THROUGH structure
//


#pragma pack(push,1)


#define CDB16GENERIC_LENGTH 0x10
#define SENSE_BUFFER_SIZE 0x12
#define MAX_DATA_BUFFER_LENGTH_WITH_PADDING 0x14


struct vmscsi_req {
    uint16_t length;
    uint8_t srb_status;
    uint8_t scsi_status;

    uint8_t port;
    uint8_t path_id;
    uint8_t target_id;
    uint8_t lun;

    uint8_t cdb_len;
    uint8_t sense_info_len;
    uint8_t data_in;
    uint8_t reserved;

    uint32_t transfer_len;

    union {
        uint8_t cdb[CDB16GENERIC_LENGTH];

        uint8_t sense_data[SENSE_BUFFER_SIZE];

        uint8_t reserved_array[MAX_DATA_BUFFER_LENGTH_WITH_PADDING];
    };

};


//
//  This structure is sent during the intialization phase to get the different
//  properties of the channel.
//

struct vmstor_chan_props
{
    uint16_t proto_ver;
    uint8_t  path_id;
    uint8_t  target_id;

    //
    // Note: port number is only really known on the client side
    //
    uint32_t  port;

    uint32_t  flags;

    uint32_t  max_transfer_bytes;

    //
    //  This id is unique for each channel and will correspond with
    //  vendor specific data in the inquirydata
    //

    uint64_t unique_id;

};


//
//  This structure is sent during the storage protocol negotiations.
//

struct vmstor_proto_ver
{
    //
    // Major (MSW) and minor (LSW) version numbers.
    //

    uint16_t major_minor;


    //
    // Revision number is auto-incremented whenever this file is changed
    // (See FILL_VMSTOR_REVISION macro above).  Mismatch does not definitely
    // indicate incompatibility--but it does indicate mismatched builds.
    //

    uint16_t revision;

};



//
// Channel Property Flags
//

#define STORAGE_CHANNEL_REMOVABLE_FLAG                  0x1
#define STORAGE_CHANNEL_EMULATED_IDE_FLAG               0x2


struct vstor_packet {
    //
    // Requested operation type
    //

    enum vstor_packet_ops operation;

    //
    //  Flags - see below for values
    //

    uint32_t     flags;

    //
    // Status of the request returned from the server side.
    //

    uint32_t     status;

    union
    {
        /*
		 * Structure used to forward SCSI commands from the client to the server.
		 */
        struct vmscsi_req vm_srb;

        /*
		 * Structure used to query channel properties.
		 */
        struct vmstor_chan_props chan_props;

        /*
		 * Used during version negotiations.
		 */
        struct vmstor_proto_ver version;
    };

};


//
//  Packet flags
//

//
//  This flag indicates that the server should send back a completion for this
//  packet.
//

#define REQUEST_COMPLETION_FLAG 0x1

//
//  This is the set of flags that the vsc can set in any packets it sends
//

#define VSC_LEGAL_FLAGS (REQUEST_COMPLETION_FLAG)


#pragma pack(pop)

#endif /* __HV_VSTORAGE_H__ */
