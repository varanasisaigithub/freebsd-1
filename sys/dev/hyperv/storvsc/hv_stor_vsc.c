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
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>
#include <sys/bus.h>
#include <sys/mutex.h>
#include <hv_osd.h>
#include <hv_logging.h>

#include <hv_vmbus_var.h>
#include <hv_vmbus_api.h>
#include "hv_stor_vsc_api.h"
#include <hv_vmbus_packet_format.h>
#include "hv_vstorage.h"


//
// #defines
//

//
// Data types
//
typedef struct _STORVSC_REQUEST_EXTENSION {
	struct storvsc_request			*Request;
	DEVICE_OBJECT					*Device;

	// Synchronize the request/response if needed
	struct {
		struct mtx mtx;
	} event;

	VSTOR_PACKET					VStorPacket;
} STORVSC_REQUEST_EXTENSION;


// A storvsc device is a device object that contains a vmbus channel
typedef struct _STORVSC_DEVICE{
	DEVICE_OBJECT		*Device;

	int		RefCount; // 0 indicates the device is being destroyed

	int		reset;
	struct mtx 	lock;
	int		NumOutstandingRequests;

	//  Each unique Port/Path/Target represents 1 channel ie scsi 
        // controller. In reality, the pathid, targetid is always 0
	// and the port is set by us
	uint32_t		PortNumber;
	uint8_t			PathId;
	uint8_t			TargetId;

	// Used for vsc/vsp channel reset process
	STORVSC_REQUEST_EXTENSION	InitRequest; 

	STORVSC_REQUEST_EXTENSION	ResetRequest; 

} STORVSC_DEVICE;


//
// Globals
//
static const char* gStorDriverName="storvsc";
static const char* gBlkDriverName="blkvsc";

//{ba6163d9-04a1-4d29-b605-72e2ffb1dc7f}
static const GUID gStorVscDeviceType={
	.Data = {0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d, 0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc, 0x7f}
};
//{32412632-86cb-44a2-9b5c-50d1417354f5}
static const GUID gBlkVscDeviceType={
	.Data = {0x32, 0x26, 0x41, 0x32, 0xcb, 0x86, 0xa2, 0x44, 0x9b, 0x5c, 0x50, 0xd1, 0x41, 0x73, 0x54, 0xf5}
};

//
// Internal routines
//

static int BlkVscOnDeviceAdd( DEVICE_OBJECT *Device, void *AdditionalInfo);
static int StorVscOnDeviceAdd( DEVICE_OBJECT *Device, void *AdditionalInfo);
static int StorVscOnDeviceRemove( DEVICE_OBJECT	*Device);
static int StorVscOnIORequest( DEVICE_OBJECT *Device, struct storvsc_request *Request);
static int StorVscOnHostReset( DEVICE_OBJECT *Device);
static void StorVscOnCleanup( DRIVER_OBJECT *Device);
static void StorVscOnChannelCallback( PVOID Context);
static void StorVscOnIOCompletion( DEVICE_OBJECT *Device, VSTOR_PACKET *VStorPacket, STORVSC_REQUEST_EXTENSION *RequestExt);
static void StorVscOnReceive( DEVICE_OBJECT *Device, VSTOR_PACKET *VStorPacket, STORVSC_REQUEST_EXTENSION *RequestExt);
static int StorVscConnectToVsp( DEVICE_OBJECT	*Device);
static inline STORVSC_DEVICE* AllocStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *storDevice;

	storDevice = malloc(sizeof(STORVSC_DEVICE), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (storDevice == NULL) {
		return NULL;
	}

	// Set to 2 to allow both inbound and outbound traffics 
	// (ie GetStorDevice() and MustGetStorDevice()) to proceed.
	atomic_cmpset_int(&storDevice->RefCount, 0, 2);

	storDevice->Device = Device;
	storDevice->reset = 0;
	mtx_init(&storDevice->lock, "storvsc device lock", NULL, MTX_SPIN | MTX_RECURSE);
	Device->Extension = storDevice;

	return storDevice;
}

static inline void FreeStorDevice(STORVSC_DEVICE *Device)
{
	KASSERT(Device->RefCount == 0, ("no storvsc to free"));
	mtx_destroy(&Device->lock);
	free(&Device->lock, M_DEVBUF);
	free(Device, M_DEVBUF);
}

// Get the stordevice object iff exists and its refcount > 1
static inline STORVSC_DEVICE* GetStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *storDevice;

	storDevice = (STORVSC_DEVICE*)Device->Extension;
	mtx_lock(&storDevice->lock);

	if (storDevice->reset == 1) {
		mtx_unlock(&storDevice->lock);
		return NULL;
	} 

	if (storDevice && storDevice->RefCount > 1) {
		atomic_add_int(&storDevice->RefCount, 1);
	} else {
		storDevice = NULL;
	}

	mtx_unlock(&storDevice->lock);
	return storDevice;
}

// Get the stordevice object iff exists and its refcount > 0
static inline STORVSC_DEVICE* MustGetStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *storDevice;

	storDevice = (STORVSC_DEVICE*)Device->Extension;
	mtx_lock(&storDevice->lock);

	if (storDevice && storDevice->RefCount) {
		atomic_add_int(&storDevice->RefCount, 1);
	} else {
		storDevice = NULL;
	}

	mtx_unlock(&storDevice->lock);

	return storDevice;
}

static inline void PutStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *storDevice;

	storDevice = (STORVSC_DEVICE*)Device->Extension;
	KASSERT(storDevice, ("storDevice NULL"));

	atomic_subtract_int(&storDevice->RefCount, 1);
	KASSERT(storDevice->RefCount, ("no storvsc"));
}

/* Drop ref count to 1 to effectively disable GetStorDevice() */
static inline STORVSC_DEVICE* ReleaseStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *stordev;

	stordev = (STORVSC_DEVICE*)Device->Extension;
	KASSERT(stordev, ("stordev is NULL"));

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (atomic_cmpset_int(&stordev->RefCount, 2, 1) == 0) {
		DELAY(100);
	}

	return stordev;
}

/* Drop ref count to 0. No one can use StorDevice object. */
static inline STORVSC_DEVICE* FinalReleaseStorDevice(DEVICE_OBJECT *Device)
{
	STORVSC_DEVICE *stordev;

	stordev = (STORVSC_DEVICE*)Device->Extension;
	KASSERT(stordev, ("no stordev to release"));

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (atomic_cmpset_int(&stordev->RefCount, 1, 0) == 0) {
		DELAY(100);
	}

	Device->Extension = NULL;
	return stordev;
}

/*++;


Name: 
	StorVscInitialize()

Description:
	Main entry point

--*/
int 
StorVscInitialize( DRIVER_OBJECT *Driver)
{
	STORVSC_DRIVER_OBJECT* storDriver = (STORVSC_DRIVER_OBJECT*)Driver;
	int ret=0;

	DPRINT_ENTER(STORVSC);
		
	DPRINT_DBG(STORVSC, "sizeof(struct storvsc_request)=%ld sizeof(STORVSC_REQUEST_EXTENSION)=%ld sizeof(VSTOR_PACKET)=%ld, sizeof(VMSCSI_REQUEST)=%ld",
		sizeof(struct storvsc_request), sizeof(STORVSC_REQUEST_EXTENSION), sizeof(VSTOR_PACKET), sizeof(VMSCSI_REQUEST));

	// Make sure we are at least 2 pages since 1 page is used for control
	KASSERT(storDriver->RingBufferSize >= (PAGE_SIZE << 1), ("RingBufferSize is too big (%u)"));

	memcpy(&Driver->deviceType, &gStorVscDeviceType, sizeof(GUID));
	Driver->name			= gStorDriverName;
	storDriver->RequestExtSize	= sizeof(STORVSC_REQUEST_EXTENSION);

	// Divide the ring buffer data size (which is 1 page less than the ring buffer size since that page is reserved for the ring buffer indices)
	// by the max request size (which is VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER + VSTOR_PACKET + UINT64) 
	storDriver->MaxOutstandingRequestsPerChannel = 
		((storDriver->RingBufferSize - PAGE_SIZE) / ALIGN_UP(MAX_MULTIPAGE_BUFFER_PACKET + sizeof(VSTOR_PACKET) + sizeof(uint64_t),sizeof(uint64_t)));

	DPRINT_INFO(STORVSC, "max io %u, currently %u\n", storDriver->MaxOutstandingRequestsPerChannel, STORVSC_MAX_IO_REQUESTS);

	// Setup the dispatch table
	storDriver->Base.OnDeviceAdd	= StorVscOnDeviceAdd;
	storDriver->Base.OnDeviceRemove	= StorVscOnDeviceRemove;
	storDriver->Base.OnCleanup	= StorVscOnCleanup;

	storDriver->OnIORequest		= StorVscOnIORequest;
	storDriver->OnHostReset		= StorVscOnHostReset;

	DPRINT_EXIT(STORVSC);

	return ret;
}

/*++;


Name: 
	BlkVscInitialize()

Description:
	Main entry point

--*/

int 
BlkVscInitialize(DRIVER_OBJECT *Driver)
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
	// by the max request size (which is VMBUS_CHANNEL_PACKET_MULITPAGE_BUFFER + VSTOR_PACKET + uint64_t) 
	storDriver->MaxOutstandingRequestsPerChannel = 
		((storDriver->RingBufferSize - PAGE_SIZE) / ALIGN_UP(MAX_MULTIPAGE_BUFFER_PACKET + sizeof(VSTOR_PACKET) + sizeof(uint64_t),sizeof(uint64_t)));

	DPRINT_INFO(BLKVSC, "max io outstd %u", storDriver->MaxOutstandingRequestsPerChannel);

	// Setup the dispatch table
	storDriver->Base.OnDeviceAdd	= BlkVscOnDeviceAdd;
	storDriver->Base.OnDeviceRemove	= StorVscOnDeviceRemove;
	storDriver->Base.OnCleanup	= StorVscOnCleanup;

	storDriver->OnIORequest		= StorVscOnIORequest;

	DPRINT_EXIT(BLKVSC);

	return ret;
}

/*++

Name: 
	StorVscOnDeviceAdd()

Description:
	Callback when the device belonging to this driver is added

--*/
int
StorVscOnDeviceAdd(
	DEVICE_OBJECT	*Device,
	void			*AdditionalInfo
	)
{
	int ret=0;
	STORVSC_DEVICE *storDevice;
	//VMSTORAGE_CHANNEL_PROPERTIES *props;
	STORVSC_DEVICE_INFO *deviceInfo = (STORVSC_DEVICE_INFO*)AdditionalInfo;

	DPRINT_ENTER(STORVSC);

	storDevice = AllocStorDevice(Device);
	if (!storDevice)
	{
		ret = -1;
		goto Cleanup;
	}

	// Save the channel properties to our storvsc channel
	//props = (VMSTORAGE_CHANNEL_PROPERTIES*) channel->offerMsg.Offer.u.Standard.UserDefined;

	// FIXME: 
	// If we support more than 1 scsi channel, we need to set the port number here
	// to the scsi channel but how do we get the scsi channel prior to the bus scan
	/*storChannel->PortNumber = 0;
	storChannel->PathId = props->PathId;
	storChannel->TargetId = props->TargetId;*/

	storDevice->PortNumber = deviceInfo->PortNumber;
	// Send it back up
	ret = StorVscConnectToVsp(Device);

	//deviceInfo->PortNumber = storDevice->PortNumber;
	deviceInfo->PathId = storDevice->PathId;
	deviceInfo->TargetId = storDevice->TargetId;

	DPRINT_DBG(STORVSC, "assigned port %u, path %u target %u\n", storDevice->PortNumber, storDevice->PathId, storDevice->TargetId);

Cleanup:
	DPRINT_EXIT(STORVSC);

	return ret;
}


/*++

Name: 
	BlkVscOnDeviceAdd()

Description:
	Callback when the device belonging to this driver is added

--*/
int 
BlkVscOnDeviceAdd(DEVICE_OBJECT	*Device, void *AdditionalInfo)
{
	int ret = 0;
	STORVSC_DEVICE_INFO *deviceInfo = (STORVSC_DEVICE_INFO*)AdditionalInfo;

	DPRINT_ENTER(BLKVSC);

	ret = StorVscOnDeviceAdd(Device, AdditionalInfo);

	if (ret != 0) {
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


static int StorVscChannelInit(DEVICE_OBJECT *Device)
{
	int ret=0;
	STORVSC_DEVICE *storDevice;
	STORVSC_REQUEST_EXTENSION *request;
	VSTOR_PACKET *vstorPacket;

	storDevice = GetStorDevice(Device);
	if (!storDevice)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	request = &storDevice->InitRequest;
	vstorPacket = &request->VStorPacket;

	// Now, initiate the vsc/vsp initialization protocol on the open channel

	memset(request, 0, sizeof(STORVSC_REQUEST_EXTENSION));
	mtx_init(&request->event.mtx, "storvsc channel wait event mutex", NULL, MTX_DEF);

	vstorPacket->Operation = VStorOperationBeginInitialization;
	vstorPacket->Flags = REQUEST_COMPLETION_FLAG;

	DPRINT_INFO(STORVSC, "BEGIN_INITIALIZATION_OPERATION...");

	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
										vstorPacket, 
										sizeof(VSTOR_PACKET), 
										(uint64_t)request,
										VmbusPacketTypeDataInBand, 
										VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if ( ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto Cleanup;
	}

	mtx_lock(&request->event.mtx);
	msleep(&request->event, &request->event.mtx, PWAIT, "storvsc channel wait event", 0);
	mtx_unlock(&request->event.mtx);

	if (vstorPacket->Operation != VStorOperationCompleteIo || vstorPacket->Status != 0)
	{
		DPRINT_ERR(STORVSC, "BEGIN_INITIALIZATION_OPERATION failed (op %d status 0x%x)", vstorPacket->Operation, vstorPacket->Status);
		goto Cleanup;
	}

	DPRINT_DBG(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION...");

	// reuse the packet for version range supported
	memset(vstorPacket, 0, sizeof(VSTOR_PACKET));
	vstorPacket->Operation = VStorOperationQueryProtocolVersion;
	vstorPacket->Flags = REQUEST_COMPLETION_FLAG;

    vstorPacket->Version.MajorMinor = VMSTOR_PROTOCOL_VERSION_CURRENT;
    FILL_VMSTOR_REVISION(vstorPacket->Version.Revision);

	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
															vstorPacket, 
															sizeof(VSTOR_PACKET), 
															(uint64_t)request,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if ( ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto Cleanup;
	}
	
	mtx_lock(&request->event.mtx);
	msleep(&request->event, &request->event.mtx, PWAIT, "storvsc channel wait event", 0);
	mtx_unlock(&request->event.mtx);

	// TODO: Check returned version 
	if (vstorPacket->Operation != VStorOperationCompleteIo || vstorPacket->Status != 0)
	{
		DPRINT_ERR(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION failed (op %d status 0x%x)", vstorPacket->Operation, vstorPacket->Status);
		goto Cleanup;
	}

	// Query channel properties
	DPRINT_DBG(STORVSC, "QUERY_PROPERTIES_OPERATION...");

	memset(vstorPacket, 0, sizeof(VSTOR_PACKET));
    vstorPacket->Operation = VStorOperationQueryProperties;
	vstorPacket->Flags = REQUEST_COMPLETION_FLAG;
    vstorPacket->StorageChannelProperties.PortNumber = storDevice->PortNumber;

	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
															vstorPacket, 
															sizeof(VSTOR_PACKET), 
															(uint64_t)request,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if ( ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to send QUERY_PROPERTIES_OPERATION");
		goto Cleanup;
	}

	mtx_lock(&request->event.mtx);
	msleep(&request->event, &request->event.mtx, PWAIT, "storvsc channel wait event", 0);
	mtx_unlock(&request->event.mtx);

	// TODO: Check returned version 
	if (vstorPacket->Operation != VStorOperationCompleteIo || vstorPacket->Status != 0)
	{
		DPRINT_ERR(STORVSC, "QUERY_PROPERTIES_OPERATION failed (op %d status 0x%x)", vstorPacket->Operation, vstorPacket->Status);
		goto Cleanup;
	}

	//storDevice->PortNumber = vstorPacket->StorageChannelProperties.PortNumber;
	storDevice->PathId = vstorPacket->StorageChannelProperties.PathId;
	storDevice->TargetId = vstorPacket->StorageChannelProperties.TargetId;

	DPRINT_INFO(STORVSC,
				"VMSTORAGE_CHANNEL_PROPERTIES: channel flag 0x%x, max xfer len %d proto version 0x%x",
				vstorPacket->StorageChannelProperties.Flags,
				vstorPacket->StorageChannelProperties.MaxTransferBytes,
				vstorPacket->StorageChannelProperties.ProtocolVersion);
	
	DPRINT_INFO(STORVSC, "END_INITIALIZATION_OPERATION...");

	memset(vstorPacket, 0, sizeof(VSTOR_PACKET));
    vstorPacket->Operation = VStorOperationEndInitialization;
	vstorPacket->Flags = REQUEST_COMPLETION_FLAG;

	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
															vstorPacket, 
															sizeof(VSTOR_PACKET), 
															(uint64_t)request,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if ( ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to send END_INITIALIZATION_OPERATION");
		goto Cleanup;
	}
	
	mtx_lock(&request->event.mtx);
	msleep(&request->event, &request->event.mtx, PWAIT, "storvsc channel wait event", 0);
	mtx_unlock(&request->event.mtx);

	if (vstorPacket->Operation != VStorOperationCompleteIo || vstorPacket->Status != 0)
	{
		DPRINT_ERR(STORVSC, "END_INITIALIZATION_OPERATION failed (op %d status 0x%x)", vstorPacket->Operation, vstorPacket->Status);
		goto Cleanup;
	}

	DPRINT_INFO(STORVSC, "**** storage channel up and running!! ****");

Cleanup:
	PutStorDevice(Device);
	
	DPRINT_EXIT(STORVSC);
	return ret;
}


int
StorVscConnectToVsp(
	DEVICE_OBJECT	*Device
	)
{	
	int ret=0;
    VMSTORAGE_CHANNEL_PROPERTIES props;
		
	STORVSC_DRIVER_OBJECT *storDriver = (STORVSC_DRIVER_OBJECT*) Device->Driver;;

	memset(&props, 0, sizeof(VMSTORAGE_CHANNEL_PROPERTIES));

	// Open the channel
	ret = Device->Driver->VmbusChannelInterface.Open(Device,
		storDriver->RingBufferSize,
		storDriver->RingBufferSize,
		(PVOID)&props,
		sizeof(VMSTORAGE_CHANNEL_PROPERTIES),
		StorVscOnChannelCallback,
		Device
		);

	DPRINT_DBG(STORVSC, "storage props: path id %d, tgt id %d, max xfer %d", props.PathId, props.TargetId, props.MaxTransferBytes);

	if (ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to open channel: %d", ret);
		return -1;
	}

	ret = StorVscChannelInit(Device);

	return ret;
}

	
/*++

Name: 
	StorVscOnDeviceRemove()

Description:
	Callback when the our device is being removed

--*/
int
StorVscOnDeviceRemove(
	DEVICE_OBJECT *Device
	)
{
	STORVSC_DEVICE *storDevice;
	int ret=0;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "disabling storage device (%p)...", Device->Extension);

	storDevice = ReleaseStorDevice(Device);

	// At this point, all outbound traffic should be disable. We only allow inbound traffic (responses) to proceed 
	// so that outstanding requests can be completed.
	while (storDevice->NumOutstandingRequests)
	{
		DPRINT_INFO(STORVSC, "waiting for %d requests to complete...", storDevice->NumOutstandingRequests);

		DELAY(100);
	}

	DPRINT_INFO(STORVSC, "removing storage device (%p)...", Device->Extension);

	storDevice = FinalReleaseStorDevice(Device);

	DPRINT_INFO(STORVSC, "storage device (%p) safe to remove", storDevice);

	// Close the channel
	Device->Driver->VmbusChannelInterface.Close(Device);

	FreeStorDevice(storDevice);

	DPRINT_EXIT(STORVSC);
	return ret;
}


//static void
//StorVscOnTargetRescan(
//	void *Context
//	)
//{
//	DEVICE_OBJECT *device=(DEVICE_OBJECT*)Context;
//	STORVSC_DRIVER_OBJECT *storDriver;
//
//	DPRINT_ENTER(STORVSC);
//
//	storDriver = (STORVSC_DRIVER_OBJECT*) device->Driver;
//	storDriver->OnHostRescan(device);
//
//	DPRINT_EXIT(STORVSC);
//}

int
StorVscOnHostReset(
	DEVICE_OBJECT *Device
	)
{
	int ret=0;

	STORVSC_DEVICE *storDevice;
	STORVSC_REQUEST_EXTENSION *request;
	VSTOR_PACKET *vstorPacket;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "resetting host adapter...");

	storDevice = GetStorDevice(Device);
	if (!storDevice)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	mtx_lock(&storDevice->lock);
	storDevice->reset = 1;
	mtx_unlock(&storDevice->lock);

	/*
	 * Wait for traffic in transit to complete
	 */
	while (storDevice->NumOutstandingRequests != 0) {
		DELAY(1000);
	}

	request = &storDevice->ResetRequest;
	vstorPacket = &request->VStorPacket;

	mtx_init(&request->event.mtx, "storvsc on host reset wait event mutex", NULL, MTX_DEF);

    vstorPacket->Operation = VStorOperationResetBus;
    vstorPacket->Flags = REQUEST_COMPLETION_FLAG;
    vstorPacket->VmSrb.PathId = storDevice->PathId;

	ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
															vstorPacket, 
															sizeof(VSTOR_PACKET),
															(uint64_t)&storDevice->ResetRequest,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	if (ret != 0)
	{
		DPRINT_ERR(STORVSC, "Unable to send reset packet %p ret %d", vstorPacket, ret);
		goto Cleanup;
	}

	// XXX add timeout
	mtx_lock(&request->event.mtx);
	msleep(&request->event, &request->event.mtx, PWAIT, "storvsc host reset wait event", 0);
	mtx_unlock(&request->event.mtx);

	mtx_destroy(&request->event.mtx);
	DPRINT_INFO(STORVSC, "host adapter reset completed");

	// At this point, all outstanding requests in the adapter should have been flushed out and return to us

Cleanup:

	mtx_lock(&storDevice->lock);
	storDevice->reset = 0;
	mtx_unlock(&storDevice->lock);

	PutStorDevice(Device);
	DPRINT_EXIT(STORVSC);
	return ret;
}

/*++

Name: 
	StorVscOnIORequest()

Description:
	Callback to initiate an I/O request

--*/
int
StorVscOnIORequest( DEVICE_OBJECT *Device, struct storvsc_request *Request)
{
	STORVSC_DEVICE *storDevice;
	STORVSC_REQUEST_EXTENSION* requestExtension = (STORVSC_REQUEST_EXTENSION*) Request->Extension;
	VSTOR_PACKET* vstorPacket =&requestExtension->VStorPacket;
	int ret=0;

	DPRINT_ENTER(STORVSC);

	storDevice = GetStorDevice(Device);

	DPRINT_INFO(STORVSC, "enter - Device %p, DeviceExt %p, Request %p, Extension %p",
		Device, storDevice, Request, requestExtension);

	DPRINT_INFO(STORVSC, "req %p len %d bus %d, target %d, lun %d cdblen %d", 
		Request, Request->DataBuffer.Length, Request->Bus, Request->TargetId, Request->LunId, Request->CdbLen);

	if (!storDevice)
	{
		printf("unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -2;
	}

	//PrintBytes(Request->Cdb, Request->CdbLen);

	requestExtension->Request = Request;
	requestExtension->Device  = Device;
	
	memset(vstorPacket, 0 , sizeof(VSTOR_PACKET));

	vstorPacket->Flags |= REQUEST_COMPLETION_FLAG;

    vstorPacket->VmSrb.Length = sizeof(VMSCSI_REQUEST);

	vstorPacket->VmSrb.PortNumber = Request->Host;
    vstorPacket->VmSrb.PathId = Request->Bus;
    vstorPacket->VmSrb.TargetId = Request->TargetId;
    vstorPacket->VmSrb.Lun = Request->LunId;

	vstorPacket->VmSrb.SenseInfoLength = SENSE_BUFFER_SIZE;

	// Copy over the scsi command descriptor block
    vstorPacket->VmSrb.CdbLength = Request->CdbLen;   
	memcpy(&vstorPacket->VmSrb.Cdb, Request->Cdb, Request->CdbLen);

	vstorPacket->VmSrb.DataIn = Request->Type;
	vstorPacket->VmSrb.DataTransferLength = Request->DataBuffer.Length;

	vstorPacket->Operation = VStorOperationExecuteSRB;

	DPRINT_INFO(STORVSC, "srb - len %d port %d, path %d, target %d, lun %d senselen %d cdblen %d", 
		vstorPacket->VmSrb.Length, 
		vstorPacket->VmSrb.PortNumber,
		vstorPacket->VmSrb.PathId,
		vstorPacket->VmSrb.TargetId,
		vstorPacket->VmSrb.Lun,
		vstorPacket->VmSrb.SenseInfoLength,
		vstorPacket->VmSrb.CdbLength);

	if (requestExtension->Request->DataBuffer.Length)
	{
		ret = Device->Driver->VmbusChannelInterface.SendPacketMultiPageBuffer(Device,
				&requestExtension->Request->DataBuffer,
				vstorPacket, 
				sizeof(VSTOR_PACKET), 
				(uint64_t)requestExtension);
	}
	else
	{
		ret = Device->Driver->VmbusChannelInterface.SendPacket(Device,
															vstorPacket, 
															sizeof(VSTOR_PACKET),
															(uint64_t)requestExtension,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0)
	{
		printf("Unable to send packet %p ret %d", vstorPacket, ret);
	}

	atomic_add_int(&storDevice->NumOutstandingRequests, 1);

	PutStorDevice(Device);

	DPRINT_EXIT(STORVSC);
	return ret;
}

/*++

Name: 
	StorVscOnCleanup()

Description:
	Perform any cleanup when the driver is removed

--*/
void
StorVscOnCleanup(
	DRIVER_OBJECT *Driver
	)
{
	DPRINT_ENTER(STORVSC);
	DPRINT_EXIT(STORVSC);
}


static void
StorVscOnIOCompletion(
	DEVICE_OBJECT	*Device,
	VSTOR_PACKET	*VStorPacket,
	STORVSC_REQUEST_EXTENSION *RequestExt
	)
{
	struct storvsc_request *request;
	STORVSC_DEVICE *storDevice;

	DPRINT_ENTER(STORVSC);

	storDevice = MustGetStorDevice(Device);
	if (!storDevice)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	DPRINT_INFO(STORVSC, "IO_COMPLETE_OPERATION - request extension %p completed bytes xfer %u", 
				RequestExt, VStorPacket->VmSrb.DataTransferLength);

	KASSERT(RequestExt != NULL, ("RequestExt != NULL"));
	KASSERT(RequestExt->Request != NULL, ("RequestExt->Request != NULL"));

	request = RequestExt->Request;

	KASSERT(request->OnIOCompletion != NULL, ("request->OnIOCompletion != NULL"));

	// Copy over the status...etc
	request->Status = VStorPacket->VmSrb.ScsiStatus;

	if (request->Status != 0 || VStorPacket->VmSrb.SrbStatus != 1)
	{
		DPRINT_DBG(STORVSC, "cmd 0x%x scsi status 0x%x srb status 0x%x\n",
			request->Cdb[0],
			VStorPacket->VmSrb.ScsiStatus,
			VStorPacket->VmSrb.SrbStatus);
	}

	if ((request->Status & 0xFF) == 0x02) // CHECK_CONDITION
	{
		if (VStorPacket->VmSrb.SrbStatus & 0x80) // autosense data available
		{
			DPRINT_DBG(STORVSC, "storvsc pkt %p autosense data valid - len %d\n",
				RequestExt, VStorPacket->VmSrb.SenseInfoLength);
			
			KASSERT(VStorPacket->VmSrb.SenseInfoLength <=  request->SenseBufferSize,
				("VStorPacket->VmSrb.SenseInfoLength <=  request->SenseBufferSize"));
	
			memcpy(request->SenseBuffer, 
				VStorPacket->VmSrb.SenseData,
				VStorPacket->VmSrb.SenseInfoLength);

			request->SenseBufferSize = VStorPacket->VmSrb.SenseInfoLength;
		}
	}

	// TODO:  
	request->BytesXfer = VStorPacket->VmSrb.DataTransferLength;

	request->OnIOCompletion(request);

	atomic_subtract_int(&storDevice->NumOutstandingRequests, 1);

	PutStorDevice(Device);

	DPRINT_EXIT(STORVSC);
}


static void
StorVscOnReceive(
	DEVICE_OBJECT	*Device,
	VSTOR_PACKET	*VStorPacket,
	STORVSC_REQUEST_EXTENSION *RequestExt
	)
{
	switch(VStorPacket->Operation)
	{
		case VStorOperationCompleteIo:

			DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION");
			StorVscOnIOCompletion(Device, VStorPacket, RequestExt);
			break;
	
		//case ENUMERATE_DEVICE_OPERATION:

		//	DPRINT_INFO(STORVSC, "ENUMERATE_DEVICE_OPERATION");

		//	StorVscOnTargetRescan(Device);
		//	break;

        case VStorOperationRemoveDevice:

			DPRINT_INFO(STORVSC, "REMOVE_DEVICE_OPERATION");
			// TODO:
			break;
				
		default:
			DPRINT_INFO(STORVSC, "Unknown operation received - %d", VStorPacket->Operation);
			break;
	}
}

void
StorVscOnChannelCallback(
	PVOID Context
	)
{
	int ret=0;
	DEVICE_OBJECT *device = (DEVICE_OBJECT*)Context;
	STORVSC_DEVICE *storDevice;
	UINT32 bytesRecvd;
	uint64_t requestId;
	uint8_t packet[ALIGN_UP(sizeof(VSTOR_PACKET),8)];
	STORVSC_REQUEST_EXTENSION *request;

	DPRINT_ENTER(STORVSC);

	KASSERT(device, ("device"));

	storDevice = MustGetStorDevice(device);
	if (!storDevice)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	do
	{
		ret = device->Driver->VmbusChannelInterface.RecvPacket(device,
																packet, 
																ALIGN_UP(sizeof(VSTOR_PACKET),8), 
																&bytesRecvd, 
																&requestId);
		if (ret == 0 && bytesRecvd > 0)
		{
			DPRINT_DBG(STORVSC, "receive %d bytes - tid %lx", bytesRecvd, requestId);

			//ASSERT(bytesRecvd == sizeof(VSTOR_PACKET));
	
			request = (STORVSC_REQUEST_EXTENSION*)(uint64_t)requestId;
			KASSERT(request, ("request"));

			//if (vstorPacket.Flags & SYNTHETIC_FLAG)
			if ((request == &storDevice->InitRequest) || (request == &storDevice->ResetRequest))
			{
				//DPRINT_INFO(STORVSC, "reset completion - operation %u status %u", vstorPacket.Operation, vstorPacket.Status);

				memcpy(&request->VStorPacket, packet, sizeof(VSTOR_PACKET));

				mtx_lock(&request->event.mtx);
				wakeup(&request->event);
				mtx_unlock(&request->event.mtx);
			}
			else
			{			
				StorVscOnReceive(device, (VSTOR_PACKET*)packet, request);
			}
		}
		else
		{
			//DPRINT_DBG(STORVSC, "nothing else to read...");
			break;
		}
	} while (1);

	PutStorDevice(device);

	DPRINT_EXIT(STORVSC);
	return;
}
