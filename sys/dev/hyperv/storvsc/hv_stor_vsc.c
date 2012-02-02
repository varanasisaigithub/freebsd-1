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

struct hv_storvsc_dev{
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
	struct hv_storvsc_req_ext	InitRequest; 

	struct hv_storvsc_req_ext	ResetRequest; 

};

//
// Internal routines
//
static void hv_storvsc_on_channel_callback(void *context);
static void hv_storvsc_on_iocompletion(DEVICE_OBJECT *Device, VSTOR_PACKET *VStorPacket,
									   struct hv_storvsc_req_ext *RequestExt);
static int hv_storvsc_connect_vsp(DEVICE_OBJECT *Device);

static inline struct hv_storvsc_dev* hv_alloc_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *storDevice;

	storDevice = malloc(sizeof(struct hv_storvsc_dev), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (storDevice == NULL) {
		return NULL;
	}

	// Set to 2 to allow both inbound and outbound traffics 
	// (ie hv_get_storvsc_dev() and hv_must_get_storvsc_dev()) to proceed.
	atomic_cmpset_int(&storDevice->RefCount, 0, 2);

	storDevice->Device = Device;
	storDevice->reset = 0;
	mtx_init(&storDevice->lock, "storvsc device lock", NULL, MTX_SPIN | MTX_RECURSE);
	Device->Extension = storDevice;

	return storDevice;
}

static inline void hv_free_storvsc_dev(struct hv_storvsc_dev *Device)
{
	KASSERT(Device->RefCount == 0, ("no storvsc to free"));
	mtx_destroy(&Device->lock);
	free(&Device->lock, M_DEVBUF);
	free(Device, M_DEVBUF);
}

// Get the stordevice object iff exists and its refcount > 1
static inline struct hv_storvsc_dev* hv_get_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *storDevice;

	storDevice = (struct hv_storvsc_dev*)Device->Extension;
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
static inline struct hv_storvsc_dev* hv_must_get_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *storDevice;

	storDevice = (struct hv_storvsc_dev*)Device->Extension;
	mtx_lock(&storDevice->lock);

	if (storDevice && storDevice->RefCount) {
		atomic_add_int(&storDevice->RefCount, 1);
	} else {
		storDevice = NULL;
	}

	mtx_unlock(&storDevice->lock);

	return storDevice;
}

static inline void hv_put_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *storDevice;

	storDevice = (struct hv_storvsc_dev*)Device->Extension;
	KASSERT(storDevice, ("storDevice NULL"));

	atomic_subtract_int(&storDevice->RefCount, 1);
	KASSERT(storDevice->RefCount, ("no storvsc"));
}

/* Drop ref count to 1 to effectively disable hv_get_storvsc_dev() */
static inline struct hv_storvsc_dev* hv_release_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *stordev;

	stordev = (struct hv_storvsc_dev*)Device->Extension;
	KASSERT(stordev, ("stordev is NULL"));

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (atomic_cmpset_int(&stordev->RefCount, 2, 1) == 0) {
		DELAY(100);
	}

	return stordev;
}

/* Drop ref count to 0. No one can use StorDevice object. */
static inline struct hv_storvsc_dev* hv_final_release_storvsc_dev(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *stordev;

	stordev = (struct hv_storvsc_dev*)Device->Extension;
	KASSERT(stordev, ("no stordev to release"));

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (atomic_cmpset_int(&stordev->RefCount, 1, 0) == 0) {
		DELAY(100);
	}

	Device->Extension = NULL;
	return stordev;
}

/*++

Name: 
	hv_storvsc_on_deviceadd()

Description:
	Callback when the device belonging to this driver is added

--*/
int
hv_storvsc_on_deviceadd(
	DEVICE_OBJECT	*Device,
	void			*AdditionalInfo
	)
{
	int ret=0;
	struct hv_storvsc_dev *storDevice;
	//VMSTORAGE_CHANNEL_PROPERTIES *props;
	struct hv_storvsc_device_info *deviceInfo = (struct hv_storvsc_device_info*)AdditionalInfo;

	DPRINT_ENTER(STORVSC);

	storDevice = hv_alloc_storvsc_dev(Device);
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
	ret = hv_storvsc_connect_vsp(Device);

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
	hv_blkvsc_on_deviceadd()

Description:
	Callback when the device belonging to this driver is added

--*/
int 
hv_blkvsc_on_deviceadd(DEVICE_OBJECT	*Device, void *AdditionalInfo)
{
	int ret = 0;
	struct hv_storvsc_device_info *deviceInfo = (struct hv_storvsc_device_info*)AdditionalInfo;

	DPRINT_ENTER(BLKVSC);

	ret = hv_storvsc_on_deviceadd(Device, AdditionalInfo);

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


static int hv_storvsc_channel_init(DEVICE_OBJECT *Device)
{
	int ret=0;
	struct hv_storvsc_dev *storDevice;
	struct hv_storvsc_req_ext *request;
	VSTOR_PACKET *vstorPacket;

	storDevice = hv_get_storvsc_dev(Device);
	if (!storDevice)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	request = &storDevice->InitRequest;
	vstorPacket = &request->VStorPacket;

	// Now, initiate the vsc/vsp initialization protocol on the open channel

	memset(request, 0, sizeof(struct hv_storvsc_req_ext));
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
	hv_put_storvsc_dev(Device);
	
	DPRINT_EXIT(STORVSC);
	return ret;
}


int
hv_storvsc_connect_vsp(
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
		hv_storvsc_on_channel_callback,
		Device
		);

	DPRINT_DBG(STORVSC, "storage props: path id %d, tgt id %d, max xfer %d", props.PathId, props.TargetId, props.MaxTransferBytes);

	if (ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to open channel: %d", ret);
		return -1;
	}

	ret = hv_storvsc_channel_init(Device);

	return ret;
}

	
/*++

Name: 
	hv_storvsc_on_deviceremove()

Description:
	Callback when the our device is being removed

--*/
int
hv_storvsc_on_deviceremove(DEVICE_OBJECT *Device)
{
	struct hv_storvsc_dev *storDevice;
	int ret=0;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "disabling storage device (%p)...", Device->Extension);

	storDevice = hv_release_storvsc_dev(Device);

	// At this point, all outbound traffic should be disable. We only allow inbound traffic (responses) to proceed 
	// so that outstanding requests can be completed.
	while (storDevice->NumOutstandingRequests)
	{
		DPRINT_INFO(STORVSC, "waiting for %d requests to complete...", storDevice->NumOutstandingRequests);

		DELAY(100);
	}

	DPRINT_INFO(STORVSC, "removing storage device (%p)...", Device->Extension);

	storDevice = hv_final_release_storvsc_dev(Device);

	DPRINT_INFO(STORVSC, "storage device (%p) safe to remove", storDevice);

	// Close the channel
	Device->Driver->VmbusChannelInterface.Close(Device);

	hv_free_storvsc_dev(storDevice);

	DPRINT_EXIT(STORVSC);
	return ret;
}

int
hv_storvsc_host_reset(
	DEVICE_OBJECT *device
	)
{
	int ret=0;

	struct hv_storvsc_dev *storDevice;
	struct hv_storvsc_req_ext *request;
	VSTOR_PACKET *vstorPacket;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "resetting host adapter...");

	storDevice = hv_get_storvsc_dev(device);
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

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
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

	hv_put_storvsc_dev(device);
	DPRINT_EXIT(STORVSC);
	return ret;
}

/*++

Name: 
	hv_storvsc_io_request()

Description:
	Function to initiate an I/O request

--*/
int
hv_storvsc_io_request(DEVICE_OBJECT *device, struct hv_storvsc_request *request)
{
	struct hv_storvsc_dev *storDevice;
	struct hv_storvsc_req_ext* requestExtension = (struct hv_storvsc_req_ext*) &request->Extension;
	VSTOR_PACKET* vstorPacket =&requestExtension->VStorPacket;
	int ret=0;

	DPRINT_ENTER(STORVSC);

	storDevice = hv_get_storvsc_dev(device);

	DPRINT_INFO(STORVSC, "enter - device %p, DeviceExt %p, request %p, Extension %p",
		device, storDevice, request, requestExtension);

	DPRINT_INFO(STORVSC, "req %p len %d bus %d, target %d, lun %d cdblen %d", 
		request, request->DataBuffer.Length, request->Bus, request->TargetId, request->LunId, request->CdbLen);

	if (!storDevice)
	{
		printf("unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -2;
	}

	//PrintBytes(request->Cdb, request->CdbLen);

	requestExtension->Request = request;
	requestExtension->Device  = device;
	
	memset(vstorPacket, 0 , sizeof(VSTOR_PACKET));

	vstorPacket->Flags |= REQUEST_COMPLETION_FLAG;

    vstorPacket->VmSrb.Length = sizeof(VMSCSI_REQUEST);

	vstorPacket->VmSrb.PortNumber = request->Host;
    vstorPacket->VmSrb.PathId = request->Bus;
    vstorPacket->VmSrb.TargetId = request->TargetId;
    vstorPacket->VmSrb.Lun = request->LunId;

	vstorPacket->VmSrb.SenseInfoLength = SENSE_BUFFER_SIZE;

	// Copy over the scsi command descriptor block
    vstorPacket->VmSrb.CdbLength = request->CdbLen;   
	memcpy(&vstorPacket->VmSrb.Cdb, request->Cdb, request->CdbLen);

	vstorPacket->VmSrb.DataIn = request->Type;
	vstorPacket->VmSrb.DataTransferLength = request->DataBuffer.Length;

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
		ret = device->Driver->VmbusChannelInterface.SendPacketMultiPageBuffer(device,
				&requestExtension->Request->DataBuffer,
				vstorPacket, 
				sizeof(VSTOR_PACKET), 
				(uint64_t)requestExtension);
	}
	else
	{
		ret = device->Driver->VmbusChannelInterface.SendPacket(device,
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

	hv_put_storvsc_dev(device);

	DPRINT_EXIT(STORVSC);
	return ret;
}

/*++

Name: 
	hv_storvsc_on_cleanup()

Description:
	Perform any cleanup when the driver is removed

--*/
void
hv_storvsc_on_cleanup(DRIVER_OBJECT *Driver)
{
	DPRINT_ENTER(STORVSC);
	DPRINT_EXIT(STORVSC);
}


/*
 * hv_storvsc_on_iocompletion
 *
 * Process IO_COMPLETION_OPERATION and ready
 * the result to be completed for upper layer
 * processing by the CAM layer.
 */
static void
hv_storvsc_on_iocompletion(DEVICE_OBJECT *Device,
						   VSTOR_PACKET *VStorPacket,
						   struct hv_storvsc_req_ext *RequestExt)
{
	struct hv_storvsc_request *request;
	struct hv_storvsc_dev *storDevice;

	DPRINT_ENTER(STORVSC);

	storDevice = hv_must_get_storvsc_dev(Device);
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

	request->BytesXfer = VStorPacket->VmSrb.DataTransferLength;

	/* Complete request by passing to the CAM layer */
	storvsc_io_done(request);

	atomic_subtract_int(&storDevice->NumOutstandingRequests, 1);

	hv_put_storvsc_dev(Device);

	DPRINT_EXIT(STORVSC);
}

static void
hv_storvsc_on_channel_callback(void *context)
{
	int ret=0;
	DEVICE_OBJECT *device = (DEVICE_OBJECT*)context;
	struct hv_storvsc_dev *storDevice;
	UINT32 bytesRecvd;
	uint64_t requestId;
	uint8_t packet[ALIGN_UP(sizeof(VSTOR_PACKET),8)];
	struct hv_storvsc_req_ext *request;
	VSTOR_PACKET *vstor_packet;

	DPRINT_ENTER(STORVSC);

	KASSERT(device, ("device"));

	storDevice = hv_get_storvsc_dev(device);
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
	
			request = (struct hv_storvsc_req_ext*)(uint64_t)requestId;
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
				vstor_packet = (VSTOR_PACKET *)packet;
				switch(vstor_packet->Operation) {
				case VStorOperationCompleteIo:
					DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION");
					hv_storvsc_on_iocompletion(device, vstor_packet, request);
					break;
				case VStorOperationRemoveDevice:
					DPRINT_INFO(STORVSC, "REMOVE_DEVICE_OPERATION");
					// TODO:
					break;
				default:
					DPRINT_INFO(STORVSC, "Unknown operation received - %d", vstor_packet->Operation);
					break;
				}			
			}
		}
		else
		{
			//DPRINT_DBG(STORVSC, "nothing else to read...");
			break;
		}
	} while (1);

	hv_put_storvsc_dev(device);

	DPRINT_EXIT(STORVSC);
	return;
}
