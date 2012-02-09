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
 * HyperV common header for Hyper-V ICs
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

#ifndef __HV_IC_H__
#define __HV_IC_H__

#include <sys/types.h>

/**
 * Common header for Hyper-V ICs
 */

#define ICMSGTYPE_NEGOTIATE 0
#define ICMSGTYPE_HEARTBEAT 1
#define ICMSGTYPE_KVPEXCHANGE 2
#define ICMSGTYPE_SHUTDOWN 3
#define ICMSGTYPE_TIMESYNC 4
#define ICMSGTYPE_VSS 5

#define ICMSGHDRFLAG_TRANSACTION 1
#define ICMSGHDRFLAG_REQUEST 2
#define ICMSGHDRFLAG_RESPONSE 4

struct vmbuspipe_hdr {
	uint32_t flags;
	uint32_t msgsize;
}__attribute__((packed));

struct ic_version {
	uint16_t major;
	uint16_t minor;
}__attribute__((packed));

struct icmsg_hdr {
	struct ic_version icverframe;
	uint16_t icmsgtype;
	struct ic_version icvermsg;
	uint16_t icmsgsize;
	uint32_t status;
	uint8_t ictransaction_id;
	uint8_t icflags;
	uint8_t reserved[2];
}__attribute__((packed));

struct icmsg_negotiate {
	uint16_t icframe_vercnt;
	uint16_t icmsg_vercnt;
	uint32_t reserved;
	struct ic_version icversion_data[1]; /* any size array */
}__attribute__((packed));

struct shutdown_msg_data {
	uint32_t reason_code;
	uint32_t timeout_seconds;
	uint32_t flags;
	uint8_t display_message[2048];
}__attribute__((packed));

struct heartbeat_msg_data {
	uint64_t seq_num;
	uint32_t reserved[8];
}__attribute__((packed));

#endif  /* __HV_IC_H__ */

