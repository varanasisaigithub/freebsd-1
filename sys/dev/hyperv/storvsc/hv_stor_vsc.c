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


struct hv_storvsc_dev_ctx {
	DEVICE_OBJECT				*device;
	struct mtx 					lock;
	uint8_t						reset;
	uint32_t					ref_cnt;
	uint32_t					num_out_reqs;
	struct hv_storvsc_req_ext	init_req;
	struct hv_storvsc_req_ext	reset_req;
};

/*
 * Internal routines
 */
static void hv_storvsc_on_channel_callback(void *context);
static void hv_storvsc_on_iocompletion(DEVICE_OBJECT *device, struct vstor_packet *VStorPacket,
									   struct hv_storvsc_req_ext *RequestExt);
static int hv_storvsc_connect_vsp(DEVICE_OBJECT *device);

static inline struct hv_storvsc_dev_ctx* hv_alloc_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stor_dev;

	stor_dev = malloc(sizeof(struct hv_storvsc_dev_ctx), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (stor_dev == NULL) {
		return NULL;
	}

	// Set to 2 to allow both inbound and outbound traffics 
	// (ie hv_get_storvsc_dev() and hv_must_get_storvsc_dev()) to proceed.
	atomic_cmpset_int(&stor_dev->ref_cnt, 0, 2);

	stor_dev->device = device;
	stor_dev->reset = 0;
	mtx_init(&stor_dev->lock, "storvsc device lock", NULL, MTX_SPIN | MTX_RECURSE);
	device->Extension = stor_dev;

	return stor_dev;
}

static inline void hv_free_storvsc_dev(struct hv_storvsc_dev_ctx *device)
{
	KASSERT(device->ref_cnt == 0, ("no storvsc to free"));
	mtx_destroy(&device->lock);
	free(&device->lock, M_DEVBUF);
	free(device, M_DEVBUF);
}

// Get the stor_dev object iff exists and its refcount > 1
static inline struct hv_storvsc_dev_ctx* hv_get_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stor_dev;

	stor_dev = (struct hv_storvsc_dev_ctx*)device->Extension;
	mtx_lock(&stor_dev->lock);

	if (stor_dev->reset == 1) {
		mtx_unlock(&stor_dev->lock);
		return NULL;
	} 

	if (stor_dev && stor_dev->ref_cnt > 1) {
		atomic_add_int(&stor_dev->ref_cnt, 1);
	} else {
		stor_dev = NULL;
	}

	mtx_unlock(&stor_dev->lock);
	return stor_dev;
}

// Get the stor_dev object iff exists and its refcount > 0
static inline struct hv_storvsc_dev_ctx* hv_must_get_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stor_dev;

	stor_dev = (struct hv_storvsc_dev_ctx*)device->Extension;
	mtx_lock(&stor_dev->lock);

	if (stor_dev && stor_dev->ref_cnt) {
		atomic_add_int(&stor_dev->ref_cnt, 1);
	} else {
		stor_dev = NULL;
	}

	mtx_unlock(&stor_dev->lock);

	return stor_dev;
}

static inline void hv_put_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stor_dev;

	stor_dev = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stor_dev, ("stor_dev NULL"));

	atomic_subtract_int(&stor_dev->ref_cnt, 1);
	KASSERT(stor_dev->ref_cnt, ("no storvsc"));
}

/* Drop ref count to 1 to effectively disable hv_get_storvsc_dev() */
static inline struct hv_storvsc_dev_ctx* hv_release_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev;

	stordev = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stordev, ("stordev is NULL"));

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (atomic_cmpset_int(&stordev->ref_cnt, 2, 1) == 0) {
		DELAY(100);
	}

	return stordev;
}

/* Drop ref count to 0. No one can use Stor_Dev object. */
static inline struct hv_storvsc_dev_ctx* hv_final_release_storvsc_dev(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev;

	stordev = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stordev, ("no stordev to release"));

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (atomic_cmpset_int(&stordev->ref_cnt, 1, 0) == 0) {
		DELAY(100);
	}

	device->Extension = NULL;
	return stordev;
}

/*++

Name: 
	hv_storvsc_on_deviceadd()

Description:
	Callback when the device belonging to this driver is added

--*/
int
hv_storvsc_on_deviceadd(DEVICE_OBJECT *device)
{
	int ret = 0;
	struct hv_storvsc_dev_ctx *stor_dev;

	DPRINT_ENTER(STORVSC);

	stor_dev = hv_alloc_storvsc_dev(device);
	if (stor_dev == NULL) {
		ret = -1;
		goto Cleanup;
	}

	// Send it back up
	ret = hv_storvsc_connect_vsp(device);

Cleanup:
	DPRINT_EXIT(STORVSC);

	return ret;
}

static int hv_storvsc_channel_init(DEVICE_OBJECT *device)
{
	int ret = 0;
	struct hv_storvsc_dev_ctx *stor_dev;
	struct hv_storvsc_req_ext *request;
	struct vstor_packet *vstorPacket;

	stor_dev = hv_get_storvsc_dev(device);
	if (!stor_dev)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	request = &stor_dev->init_req;
	vstorPacket = &request->VStorPacket;

	// Now, initiate the vsc/vsp initialization protocol on the open channel

	memset(request, 0, sizeof(struct hv_storvsc_req_ext));
	mtx_init(&request->event.mtx, "storvsc channel wait event mutex", NULL, MTX_DEF);

	vstorPacket->operation = VStorOperationBeginInitialization;
	vstorPacket->flags = REQUEST_COMPLETION_FLAG;

	DPRINT_INFO(STORVSC, "BEGIN_INITIALIZATION_OPERATION...");

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
										vstorPacket, 
										sizeof(struct vstor_packet), 
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

	if (vstorPacket->operation != VStorOperationCompleteIo || vstorPacket->status != 0)
	{
		DPRINT_ERR(STORVSC, "BEGIN_INITIALIZATION_OPERATION failed (op %d status 0x%x)", vstorPacket->operation, vstorPacket->status);
		goto Cleanup;
	}

	DPRINT_DBG(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION...");

	// reuse the packet for version range supported
	memset(vstorPacket, 0, sizeof(struct vstor_packet));
	vstorPacket->operation = VStorOperationQueryProtocolVersion;
	vstorPacket->flags = REQUEST_COMPLETION_FLAG;

    vstorPacket->version.major_minor = VMSTOR_PROTOCOL_VERSION_CURRENT;
    FILL_VMSTOR_REVISION(vstorPacket->version.revision);

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
															vstorPacket, 
															sizeof(struct vstor_packet), 
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
	if (vstorPacket->operation != VStorOperationCompleteIo || vstorPacket->status != 0)
	{
		DPRINT_ERR(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION failed (op %d status 0x%x)", vstorPacket->operation, vstorPacket->status);
		goto Cleanup;
	}

	// Query channel properties
	DPRINT_DBG(STORVSC, "QUERY_PROPERTIES_OPERATION...");

	memset(vstorPacket, 0, sizeof(struct vstor_packet));
    vstorPacket->operation = VStorOperationQueryProperties;
	vstorPacket->flags = REQUEST_COMPLETION_FLAG;

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
															vstorPacket, 
															sizeof(struct vstor_packet), 
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
	if (vstorPacket->operation != VStorOperationCompleteIo || vstorPacket->status != 0)
	{
		DPRINT_ERR(STORVSC, "QUERY_PROPERTIES_OPERATION failed (op %d status 0x%x)", vstorPacket->operation, vstorPacket->status);
		goto Cleanup;
	}

	DPRINT_INFO(STORVSC,
				"Channel Properties: channel flag 0x%x, " \
				"max xfer len %d proto version 0x%x",
				vstorPacket->chan_props.flags,
				vstorPacket->chan_props.max_transfer_bytes,
				vstorPacket->chan_props.proto_ver);
	
	DPRINT_INFO(STORVSC, "END_INITIALIZATION_OPERATION...");

	memset(vstorPacket, 0, sizeof(struct vstor_packet));
    vstorPacket->operation = VStorOperationEndInitialization;
	vstorPacket->flags = REQUEST_COMPLETION_FLAG;

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
															vstorPacket, 
															sizeof(struct vstor_packet), 
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

	if (vstorPacket->operation != VStorOperationCompleteIo || vstorPacket->status != 0)
	{
		DPRINT_ERR(STORVSC, "END_INITIALIZATION_OPERATION failed (op %d status 0x%x)", vstorPacket->operation, vstorPacket->status);
		goto Cleanup;
	}

	DPRINT_INFO(STORVSC, "**** storage channel up and running!! ****");

Cleanup:
	hv_put_storvsc_dev(device);
	
	DPRINT_EXIT(STORVSC);
	return ret;
}


int
hv_storvsc_connect_vsp(DEVICE_OBJECT *device)
{	
	int ret = 0;
    struct vmstor_chan_props props;
		
	STORVSC_DRIVER_OBJECT *storDriver = (STORVSC_DRIVER_OBJECT*) device->Driver;;

	memset(&props, 0, sizeof(struct vmstor_chan_props));

	// Open the channel
	ret = device->Driver->VmbusChannelInterface.Open(device,
		storDriver->RingBufferSize,
		storDriver->RingBufferSize,
		(void *)&props,
		sizeof(struct vmstor_chan_props),
		hv_storvsc_on_channel_callback,
		device
		);

	DPRINT_DBG(STORVSC, "storage props: path id %d, tgt id %d, max xfer %d", props.path_id, props.target_id, props.max_transfer_bytes);

	if (ret != 0)
	{
		DPRINT_ERR(STORVSC, "unable to open channel: %d", ret);
		return -1;
	}

	ret = hv_storvsc_channel_init(device);

	return ret;
}

	
/*++

Name: 
	hv_storvsc_on_deviceremove()

Description:
	Callback when the our device is being removed

--*/
int
hv_storvsc_on_deviceremove(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stor_dev;
	int ret = 0;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "disabling storage device (%p)...", device->Extension);

	stor_dev = hv_release_storvsc_dev(device);

	// At this point, all outbound traffic should be disable. We only allow inbound traffic (responses) to proceed 
	// so that outstanding requests can be completed.
	while (stor_dev->num_out_reqs)
	{
		DPRINT_INFO(STORVSC, "waiting for %d requests to complete...", stor_dev->num_out_reqs);

		DELAY(100);
	}

	DPRINT_INFO(STORVSC, "removing storage device (%p)...", device->Extension);

	stor_dev = hv_final_release_storvsc_dev(device);

	DPRINT_INFO(STORVSC, "storage device (%p) safe to remove", stor_dev);

	// Close the channel
	device->Driver->VmbusChannelInterface.Close(device);

	hv_free_storvsc_dev(stor_dev);

	DPRINT_EXIT(STORVSC);
	return ret;
}

int
hv_storvsc_host_reset(DEVICE_OBJECT *device)
{
	int ret = 0;

	struct hv_storvsc_dev_ctx *stor_dev;
	struct hv_storvsc_req_ext *request;
	struct vstor_packet *vstorPacket;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "resetting host adapter...");

	stor_dev = hv_get_storvsc_dev(device);
	if (!stor_dev)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	mtx_lock(&stor_dev->lock);
	stor_dev->reset = 1;
	mtx_unlock(&stor_dev->lock);

	/*
	 * Wait for traffic in transit to complete
	 */
	while (stor_dev->num_out_reqs != 0) {
		DELAY(1000);
	}

	request = &stor_dev->reset_req;
	vstorPacket = &request->VStorPacket;

	mtx_init(&request->event.mtx, "storvsc on host reset wait event mutex", NULL, MTX_DEF);

    vstorPacket->operation = VStorOperationResetBus;
    vstorPacket->flags = REQUEST_COMPLETION_FLAG;

	ret = device->Driver->VmbusChannelInterface.SendPacket(device,
															vstorPacket, 
															sizeof(struct vstor_packet),
															(uint64_t)&stor_dev->reset_req,
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

	mtx_lock(&stor_dev->lock);
	stor_dev->reset = 0;
	mtx_unlock(&stor_dev->lock);

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
hv_storvsc_io_request(DEVICE_OBJECT *device,
					  struct hv_storvsc_request *request)
{
	struct hv_storvsc_dev_ctx *stor_dev;
	struct hv_storvsc_req_ext *requestExtension =
		(struct hv_storvsc_req_ext *) &request->Extension;
	struct vstor_packet *vstorPacket = &requestExtension->VStorPacket;
	int ret = 0;

	DPRINT_ENTER(STORVSC);

	stor_dev = hv_get_storvsc_dev(device);

	DPRINT_INFO(STORVSC, "enter - device %p, deviceExt %p, request %p, Extension %p",
		device, stor_dev, request, requestExtension);

	DPRINT_INFO(STORVSC, "req %p len %d bus %d, target %d, lun %d cdblen %d", 
		request, request->DataBuffer.Length, request->Bus, request->TargetId, request->LunId, request->CdbLen);

	if (!stor_dev)
	{
		printf("unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -2;
	}

	requestExtension->Request = request;
	requestExtension->device  = device;
	
	memset(vstorPacket, 0 , sizeof(struct vstor_packet));

	vstorPacket->flags |= REQUEST_COMPLETION_FLAG;

    vstorPacket->vm_srb.length = sizeof(struct vmscsi_req);

	vstorPacket->vm_srb.port = request->Host;
    vstorPacket->vm_srb.path_id = request->Bus;
    vstorPacket->vm_srb.target_id = request->TargetId;
    vstorPacket->vm_srb.lun = request->LunId;

	vstorPacket->vm_srb.sense_info_len = SENSE_BUFFER_SIZE;

	// Copy over the scsi command descriptor block
    vstorPacket->vm_srb.cdb_len = request->CdbLen;   
	memcpy(&vstorPacket->vm_srb.cdb, request->Cdb, request->CdbLen);

	vstorPacket->vm_srb.data_in = request->Type;
	vstorPacket->vm_srb.transfer_len = request->DataBuffer.Length;

	vstorPacket->operation = VStorOperationExecuteSRB;

	DPRINT_INFO(STORVSC, "srb - len %d port %d, path %d, target %d, lun %d senselen %d cdblen %d", 
		vstorPacket->vm_srb.length, 
		vstorPacket->vm_srb.port,
		vstorPacket->vm_srb.path_id,
		vstorPacket->vm_srb.target_id,
		vstorPacket->vm_srb.lun,
		vstorPacket->vm_srb.sense_info_len,
		vstorPacket->vm_srb.cdb_len);

	if (requestExtension->Request->DataBuffer.Length)
	{
		ret = device->Driver->VmbusChannelInterface.SendPacketMultiPageBuffer(device,
				&requestExtension->Request->DataBuffer,
				vstorPacket, 
				sizeof(struct vstor_packet), 
				(uint64_t)requestExtension);
	}
	else
	{
		ret = device->Driver->VmbusChannelInterface.SendPacket(device,
															vstorPacket, 
															sizeof(struct vstor_packet),
															(uint64_t)requestExtension,
															VmbusPacketTypeDataInBand, 
															VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0)
	{
		printf("Unable to send packet %p ret %d", vstorPacket, ret);
	}

	atomic_add_int(&stor_dev->num_out_reqs, 1);

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
hv_storvsc_on_iocompletion(DEVICE_OBJECT *device,
						   struct vstor_packet *VStorPacket,
						   struct hv_storvsc_req_ext *RequestExt)
{
	struct hv_storvsc_request *request;
	struct hv_storvsc_dev_ctx *stor_dev;

	DPRINT_ENTER(STORVSC);

	stor_dev = hv_must_get_storvsc_dev(device);
	if (!stor_dev)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	DPRINT_INFO(STORVSC, "IO_COMPLETE_OPERATION - request extension %p completed bytes xfer %u", 
				RequestExt, VStorPacket->vm_srb.transfer_len);

	KASSERT(RequestExt != NULL, ("RequestExt != NULL"));
	KASSERT(RequestExt->Request != NULL, ("RequestExt->Request != NULL"));

	request = RequestExt->Request;

	// Copy over the status...etc
	request->Status = VStorPacket->vm_srb.scsi_status;

	if (request->Status != 0 || VStorPacket->vm_srb.srb_status != 1)
	{
		DPRINT_DBG(STORVSC, "cmd 0x%x scsi status 0x%x srb status 0x%x\n",
			request->Cdb[0],
			VStorPacket->vm_srb.scsi_status,
			VStorPacket->vm_srb.srb_status);
	}

	if ((request->Status & 0xFF) == 0x02) // CHECK_CONDITION
	{
		if (VStorPacket->vm_srb.srb_status & 0x80) // autosense data available
		{
			DPRINT_DBG(STORVSC, "storvsc pkt %p autosense data valid - len %d\n",
				RequestExt, VStorPacket->vm_srb.sense_info_len);
			
			KASSERT(VStorPacket->vm_srb.sense_info_len <= request->SenseBufferSize,
				("VStorPacket->vm_srb.sense_info_len <= request->SenseBufferSize"));
	
			memcpy(request->SenseBuffer, 
				   VStorPacket->vm_srb.sense_data,
				   VStorPacket->vm_srb.sense_info_len);

			request->SenseBufferSize = VStorPacket->vm_srb.sense_info_len;
		}
	}

	request->BytesXfer = VStorPacket->vm_srb.transfer_len;

	/* Complete request by passing to the CAM layer */
	storvsc_io_done(request);

	atomic_subtract_int(&stor_dev->num_out_reqs, 1);

	hv_put_storvsc_dev(device);

	DPRINT_EXIT(STORVSC);
}

static void
hv_storvsc_on_channel_callback(void *context)
{
	int ret = 0;
	DEVICE_OBJECT *device = (DEVICE_OBJECT*)context;
	struct hv_storvsc_dev_ctx *stor_dev;
	uint32_t bytesRecvd;
	uint64_t requestId;
	uint8_t packet[ALIGN_UP(sizeof(struct vstor_packet),8)];
	struct hv_storvsc_req_ext *request;
	struct vstor_packet *vstor_packet;

	DPRINT_ENTER(STORVSC);

	KASSERT(device, ("device"));

	stor_dev = hv_get_storvsc_dev(device);
	if (stor_dev == NULL) {
		DPRINT_ERR(STORVSC,
				   "unable to get stor device...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	do {
		ret = device->Driver->VmbusChannelInterface.RecvPacket(device,
																packet, 
																ALIGN_UP(sizeof(struct vstor_packet),8), 
																&bytesRecvd, 
																&requestId);
		if (ret == 0 && bytesRecvd > 0) {
			DPRINT_DBG(STORVSC, "receive %d bytes - tid %lx",
					   bytesRecvd, requestId);

			request = (struct hv_storvsc_req_ext*)(uint64_t)requestId;
			KASSERT(request, ("request"));

			if ((request == &stor_dev->init_req) ||
				(request == &stor_dev->reset_req)) {
				memcpy(&request->VStorPacket, packet, sizeof(struct vstor_packet));

				mtx_lock(&request->event.mtx);
				wakeup(&request->event);
				mtx_unlock(&request->event.mtx);
			} else {
				vstor_packet = (struct vstor_packet *)packet;
				switch(vstor_packet->operation) {
				case VStorOperationCompleteIo:
					DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION");
					hv_storvsc_on_iocompletion(device, vstor_packet, request);
					break;
				case VStorOperationRemoveDevice:
					DPRINT_INFO(STORVSC, "REMOVE_DEVICE_OPERATION");
					// TODO:
					break;
				default:
					DPRINT_INFO(STORVSC, "Unknown operation received - %d",
								vstor_packet->operation);
					break;
				}			
			}
		} else {
			break;
		}
	} while (1);

	hv_put_storvsc_dev(device);

	DPRINT_EXIT(STORVSC);
	return;
}
