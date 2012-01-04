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

#include "hv_stor_vsc.c"

static const char* gBlkDriverName="blkvsc";

//{32412632-86cb-44a2-9b5c-50d1417354f5}
static const GUID gBlkVscDeviceType={
	.Data = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44, 0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

// Static routines
static int 
BlkVscOnDeviceAdd(
	DEVICE_OBJECT	*Device,
	void		*AdditionalInfo
	);


int 
BlkVscInitialize(
	DRIVER_OBJECT *Driver
	)
{
	STORVSC_DRIVER_OBJECT* storDriver = (STORVSC_DRIVER_OBJECT*)Driver;
	int ret=0;

	DPRINT_ENTER(BLKVSC);
		
	// Make sure we are at least 2 pages since 1 page is used for control
	ASSERT(storDriver->RingBufferSize >= (PAGE_SIZE << 1));

	Driver->name = gBlkDriverName;
	memcpy(&Driver->deviceType, &gBlkVscDeviceType, sizeof(GUID));

	storDriver->RequestExtSize			= sizeof(STORVSC_REQUEST_EXTENSION);
	// Divide the ring buffer data size (which is 1 page less than the ring buffer size since that page is reserved for the ring buffer indices)
	// by the max request size (which is VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER + VSTOR_PACKET + UINT64) 
	storDriver->MaxOutstandingRequestsPerChannel = 
		((storDriver->RingBufferSize - PAGE_SIZE) / ALIGN_UP(MAX_MULTIPAGE_BUFFER_PACKET + sizeof(VSTOR_PACKET) + sizeof(UINT64),sizeof(UINT64)));

	DPRINT_INFO(BLKVSC, "max io outstd %u", storDriver->MaxOutstandingRequestsPerChannel);

	// Setup the dispatch table
	storDriver->Base.OnDeviceAdd	= BlkVscOnDeviceAdd;
	storDriver->Base.OnDeviceRemove	= StorVscOnDeviceRemove;
	storDriver->Base.OnCleanup	= StorVscOnCleanup;

	storDriver->OnIORequest		= StorVscOnIORequest;

	DPRINT_EXIT(BLKVSC);

	return ret;
}

int 
BlkVscOnDeviceAdd(
	DEVICE_OBJECT	*Device,
	void		*AdditionalInfo
	)
{
	int ret=0;
// static  int once;
	STORVSC_DEVICE_INFO *deviceInfo = (STORVSC_DEVICE_INFO*)AdditionalInfo;

	DPRINT_ENTER(BLKVSC);

#if 0
	if (once++ > 5) {
	    printf("BlkVscOnDeviceAdd: Skipping first IDE\n");
	    return (-1);
 	}
#endif
	ret = StorVscOnDeviceAdd(Device, AdditionalInfo);

	if (ret != 0)
	{
		DPRINT_EXIT(BLKVSC);

		return ret;
	}
	
	// We need to use the device instance guid to set the path and target id. For IDE devices, the
	// device instance id is formatted as <bus id> - <device id> - 8899 - 000000000000.
	deviceInfo->PathId = Device->deviceInstance.Data[3] << 24 | Device->deviceInstance.Data[2] << 16 |
		Device->deviceInstance.Data[1] << 8 |Device->deviceInstance.Data[0];

	deviceInfo->TargetId = Device->deviceInstance.Data[5] << 8 | Device->deviceInstance.Data[4];

	DPRINT_EXIT(BLKVSC);

	return ret;
}
