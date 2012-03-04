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
#include <hv_logging.h>

#include <hv_channel.h>
#include <hv_vmbus_var.h>
#include "hv_stor_vsc_api.h"
#include "hv_vstorage.h"

/* Storvsc device context structure */
struct hv_storvsc_dev_ctx {
	DEVICE_OBJECT				*device;
	struct mtx			*hs_lockp;
	uint8_t						reset;
	uint32_t					ref_cnt;
	uint32_t					num_out_reqs;
	struct hv_storvsc_request	init_req;
	struct hv_storvsc_request	reset_req;
};

/*
 * Internal routines
 */
static void hv_storvsc_on_channel_callback(void *context);
static void hv_storvsc_on_iocompletion(DEVICE_OBJECT *device, struct vstor_packet *vstor_packet,
									   struct hv_storvsc_request *request);
static int hv_storvsc_connect_vsp(DEVICE_OBJECT *device);

static inline struct hv_storvsc_dev_ctx* hv_alloc_storvsc_dev_ctx(
			DEVICE_OBJECT *device,
			struct mtx *lockp)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = malloc(sizeof(struct hv_storvsc_dev_ctx), M_DEVBUF, M_WAITOK|M_ZERO);
	// Set to 2 to allow both inbound and outbound traffics 
	// (ie hv_get_storvsc_dev() and hv_must_get_storvsc_dev()) to proceed.
	atomic_cmpset_int(&stordev_ctx->ref_cnt, 0, 2);

	stordev_ctx->device = device;
	stordev_ctx->reset = 0;
	stordev_ctx->hs_lockp = lockp;
	device->Extension = stordev_ctx;

	return stordev_ctx;
}

static inline void hv_free_storvsc_dev_ctx(struct hv_storvsc_dev_ctx *device)
{
	KASSERT(device->ref_cnt == 0, ("no storvsc to free"));
	free(device, M_DEVBUF);
}

// Get the stor_dev object iff exists and its refcount > 1
static inline struct hv_storvsc_dev_ctx* hv_get_storvsc_dev_ctx(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = (struct hv_storvsc_dev_ctx*)device->Extension;
	if (stordev_ctx == NULL) {
		return NULL;
	}

	mtx_lock(stordev_ctx->hs_lockp);

	if (stordev_ctx->reset == 1) {
		mtx_unlock(stordev_ctx->hs_lockp);
		return NULL;
	} 

	if (stordev_ctx->ref_cnt > 1) {
		atomic_add_int(&stordev_ctx->ref_cnt, 1);
	}

	mtx_unlock(stordev_ctx->hs_lockp);
	return stordev_ctx;
}

// Get the stordev_ctx object iff exists and its refcount > 0
static inline struct hv_storvsc_dev_ctx* hv_must_get_storvsc_dev_ctx(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = (struct hv_storvsc_dev_ctx*)device->Extension;
	if (stordev_ctx == NULL) {
		return NULL;
	}
	mtx_lock(stordev_ctx->hs_lockp);

	if (stordev_ctx->ref_cnt) {
		atomic_add_int(&stordev_ctx->ref_cnt, 1);
	}

	mtx_unlock(stordev_ctx->hs_lockp);

	return stordev_ctx;
}

static inline void hv_put_storvsc_dev_ctx(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stordev_ctx, ("stordev_ctx NULL"));

	atomic_subtract_int(&stordev_ctx->ref_cnt, 1);
	KASSERT(stordev_ctx->ref_cnt, ("no storvsc"));
}

/* Drop ref count to 1 to effectively disable hv_get_storvsc_dev_ctx() */
static inline struct hv_storvsc_dev_ctx* hv_release_storvsc_dev_ctx(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stordev_ctx, ("stordev_ctx is NULL"));

	/* Busy wait until the ref drop to 2, then set it to 1 */
	while (atomic_cmpset_int(&stordev_ctx->ref_cnt, 2, 1) == 0) {
		DELAY(100);
	}

	return stordev_ctx;
}

/* Drop ref count to 0. No one can use the hv_storvsc_dev_ctx object. */
static inline struct hv_storvsc_dev_ctx* hv_final_release_storvsc_dev_ctx(DEVICE_OBJECT *device)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;

	stordev_ctx = (struct hv_storvsc_dev_ctx*)device->Extension;
	KASSERT(stordev_ctx, ("no stordev_ctx to release"));

	/* Busy wait until the ref drop to 1, then set it to 0 */
	while (atomic_cmpset_int(&stordev_ctx->ref_cnt, 1, 0) == 0) {
		DELAY(100);
	}

	device->Extension = NULL;
	return stordev_ctx;
}

/*++

Name: 
	hv_storvsc_on_deviceadd()

Description:
	Callback when the device belonging to this driver is added

--*/
int
hv_storvsc_on_deviceadd(DEVICE_OBJECT *device, struct mtx *lockp)
{
	int ret = 0;
	struct hv_storvsc_dev_ctx *stordev_ctx;

	DPRINT_ENTER(STORVSC);

	stordev_ctx = hv_alloc_storvsc_dev_ctx(device, lockp);
	if (stordev_ctx == NULL) {
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
	struct hv_storvsc_dev_ctx *stordev_ctx;
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	stordev_ctx = hv_get_storvsc_dev_ctx(device);
	if (stordev_ctx == NULL)
	{
		DPRINT_ERR(STORVSC, "unable to get stor device context...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	request = &stordev_ctx->init_req;
	vstor_packet = &request->vstor_packet;

	// Now, initiate the vsc/vsp initialization protocol on the open channel

	memset(request, 0, sizeof(struct hv_storvsc_request));

	cv_init(&request->event.cv, "storvsc channel cv");
	mtx_init(&request->event.mtx, "storvsc channel wait event mutex", NULL, MTX_DEF);

	vstor_packet->operation = VSTOR_OPERATION_BEGININITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	DPRINT_INFO(STORVSC, "BEGIN_INITIALIZATION_OPERATION...");

	mtx_lock(&request->event.mtx);
	ret = hv_vmbus_channel_send_packet(
			(VMBUS_CHANNEL *)device->context,
			vstor_packet,
			sizeof(struct vstor_packet),
			(uint64_t)request,
			VmbusPacketTypeDataInBand,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC, "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto Cleanup;
	}

	cv_wait(&request->event.cv, &request->event.mtx);

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
		vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "BEGIN_INITIALIZATION_OPERATION failed (op %d status 0x%x)",
				   vstor_packet->operation, vstor_packet->status);
		goto Cleanup;
	}

	DPRINT_DBG(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION...");

	// reuse the packet for version range supported
	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERYPROTOCOLVERSION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	vstor_packet->version.major_minor = VMSTOR_PROTOCOL_VERSION_CURRENT;
	FILL_VMSTOR_REVISION(vstor_packet->version.revision);

	ret = hv_vmbus_channel_send_packet(
			(VMBUS_CHANNEL *)device->context,
			vstor_packet,
			sizeof(struct vstor_packet),
			(uint64_t)request,
			VmbusPacketTypeDataInBand,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC, "unable to send BEGIN_INITIALIZATION_OPERATION");
		goto Cleanup;
	}
	
	cv_wait(&request->event.cv, &request->event.mtx);

	// TODO: Check returned version 
	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
		vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "QUERY_PROTOCOL_VERSION_OPERATION failed (op %d status 0x%x)",
				   vstor_packet->operation, vstor_packet->status);
		goto Cleanup;
	}

	// Query channel properties
	DPRINT_DBG(STORVSC, "QUERY_PROPERTIES_OPERATION...");

	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_QUERYPROPERTIES;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = hv_vmbus_channel_send_packet(
				(VMBUS_CHANNEL *)device->context,
				vstor_packet,
				sizeof(struct vstor_packet),
				(uint64_t)request,
				VmbusPacketTypeDataInBand,
				VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if ( ret != 0) {
		DPRINT_ERR(STORVSC, "unable to send QUERY_PROPERTIES_OPERATION");
		goto Cleanup;
	}

	cv_wait(&request->event.cv, &request->event.mtx);

	// TODO: Check returned version 
	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
		vstor_packet->status != 0) {
		DPRINT_ERR(STORVSC, "QUERY_PROPERTIES_OPERATION failed (op %d status 0x%x)",
				   vstor_packet->operation, vstor_packet->status);
		goto Cleanup;
	}

	DPRINT_INFO(STORVSC,
				"Channel Properties: channel flag 0x%x, " \
				"max xfer len %d proto version 0x%x",
				vstor_packet->chan_props.flags,
				vstor_packet->chan_props.max_transfer_bytes,
				vstor_packet->chan_props.proto_ver);
	
	DPRINT_INFO(STORVSC, "END_INITIALIZATION_OPERATION...");

	memset(vstor_packet, 0, sizeof(struct vstor_packet));
	vstor_packet->operation = VSTOR_OPERATION_ENDINITIALIZATION;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = hv_vmbus_channel_send_packet(
				(VMBUS_CHANNEL *)device->context,
				vstor_packet,
				sizeof(struct vstor_packet),
				(uint64_t)request,
				VmbusPacketTypeDataInBand,
				VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC, "unable to send END_INITIALIZATION_OPERATION");
		goto Cleanup;
	}
	
	cv_wait(&request->event.cv, &request->event.mtx);

	if (vstor_packet->operation != VSTOR_OPERATION_COMPLETEIO ||
		vstor_packet->status != 0)	{
		DPRINT_ERR(STORVSC, "END_INITIALIZATION_OPERATION failed (op %d status 0x%x)",
				   vstor_packet->operation, vstor_packet->status);
		goto Cleanup;
	}

	DPRINT_INFO(STORVSC, "**** storage channel up and running!! ****");

Cleanup:
	mtx_unlock(&request->event.mtx);
	mtx_destroy(&request->event.mtx);
	cv_destroy(&request->event.cv);
	hv_put_storvsc_dev_ctx(device);
	
	DPRINT_EXIT(STORVSC);
	return ret;
}


int
hv_storvsc_connect_vsp(DEVICE_OBJECT *device)
{	
	int ret = 0;
    struct vmstor_chan_props props;
		
	struct storvsc_driver_object *storDriver =
		(struct storvsc_driver_object *) device->Driver;

	memset(&props, 0, sizeof(struct vmstor_chan_props));

	// Open the channel

	ret = hv_vmbus_channel_open(
		(VMBUS_CHANNEL *)device->context,
		storDriver->ringbuffer_size,
		storDriver->ringbuffer_size,
		(void *)&props,
		sizeof(struct vmstor_chan_props),
		hv_storvsc_on_channel_callback,
		device);

	DPRINT_DBG(STORVSC, "storage props: path id %d, tgt id %d, max xfer %d", props.path_id, props.target_id, props.max_transfer_bytes);

	if (ret != 0) {
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
	struct hv_storvsc_dev_ctx *stordev_ctx;
	int ret = 0;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "disabling storage device (%p)...", device->Extension);

	stordev_ctx = hv_release_storvsc_dev_ctx(device);

	// At this point, all outbound traffic should be disable. We only allow inbound traffic (responses) to proceed 
	// so that outstanding requests can be completed.
	while (stordev_ctx->num_out_reqs) {
		DPRINT_INFO(STORVSC, "waiting for %d requests to complete...", stordev_ctx->num_out_reqs);
		DELAY(100);
	}

	DPRINT_INFO(STORVSC, "removing storage device (%p)...", device->Extension);

	stordev_ctx = hv_final_release_storvsc_dev_ctx(device);

	DPRINT_INFO(STORVSC, "storage device (%p) safe to remove", stordev_ctx);

	hv_vmbus_channel_close((VMBUS_CHANNEL *)device->context);
	hv_free_storvsc_dev_ctx(stordev_ctx);

	DPRINT_EXIT(STORVSC);
	return ret;
}

int
hv_storvsc_host_reset(DEVICE_OBJECT *device)
{
	int ret = 0;

	struct hv_storvsc_dev_ctx *stordev_ctx;
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	DPRINT_ENTER(STORVSC);

	DPRINT_INFO(STORVSC, "resetting host adapter...");

	stordev_ctx = hv_get_storvsc_dev_ctx(device);
	if (stordev_ctx == NULL) {
		DPRINT_ERR(STORVSC, "unable to get stor device context...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -1;
	}

	mtx_lock(stordev_ctx->hs_lockp);
	stordev_ctx->reset = 1;
	mtx_unlock(stordev_ctx->hs_lockp);

	/*
	 * Wait for traffic in transit to complete
	 */
	while (stordev_ctx->num_out_reqs != 0) {
		DELAY(1000);
	}

	request = &stordev_ctx->reset_req;
	vstor_packet = &request->vstor_packet;

	cv_init(&request->event.cv, "storvsc host reset cv");
	mtx_init(&request->event.mtx, "storvsc on host reset wait event mutex", NULL, MTX_DEF);

	vstor_packet->operation = VSTOR_OPERATION_RESETBUS;
	vstor_packet->flags = REQUEST_COMPLETION_FLAG;

	ret = hv_vmbus_channel_send_packet((VMBUS_CHANNEL *)device->context,
			vstor_packet,
			sizeof(struct vstor_packet),
			(uint64_t)&stordev_ctx->reset_req,
			VmbusPacketTypeDataInBand,
			VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);

	if (ret != 0) {
		DPRINT_ERR(STORVSC, "Unable to send reset packet %p ret %d", vstor_packet, ret);
		goto Cleanup;
	}

	// XXX add timeout
	cv_wait(&request->event.cv, &request->event.mtx);

	DPRINT_INFO(STORVSC, "host adapter reset completed");

	// At this point, all outstanding requests in the adapter should have been flushed out and return to us

Cleanup:
	mtx_unlock(&request->event.mtx);
	mtx_destroy(&request->event.mtx);
	cv_destroy(&request->event.cv);

	mtx_lock(stordev_ctx->hs_lockp);
	stordev_ctx->reset = 0;
	mtx_unlock(stordev_ctx->hs_lockp);

	hv_put_storvsc_dev_ctx(device);
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
	struct hv_storvsc_dev_ctx *stordev_ctx;
	struct vstor_packet *vstor_packet = &request->vstor_packet;
	int ret = 0;

	DPRINT_ENTER(STORVSC);

	stordev_ctx = hv_get_storvsc_dev_ctx(device);

	DPRINT_INFO(STORVSC, "enter - device %p, deviceExt %p, request %p",
				device, stordev_ctx, request);

	if (stordev_ctx == NULL) {
		printf("unable to get stor device context...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return -2;
	}

	vstor_packet->flags |= REQUEST_COMPLETION_FLAG;

    vstor_packet->vm_srb.length = sizeof(struct vmscsi_req);
	
	vstor_packet->vm_srb.sense_info_len = SENSE_BUFFER_SIZE;

	vstor_packet->vm_srb.transfer_len = request->data_buf.Length;

	vstor_packet->operation = VSTOR_OPERATION_EXECUTESRB;

	DPRINT_INFO(STORVSC, "srb - len %d port %d, path %d, target %d, lun %d senselen %d cdblen %d", 
		vstor_packet->vm_srb.length, 
		vstor_packet->vm_srb.port,
		vstor_packet->vm_srb.path_id,
		vstor_packet->vm_srb.target_id,
		vstor_packet->vm_srb.lun,
		vstor_packet->vm_srb.sense_info_len,
		vstor_packet->vm_srb.cdb_len);

	if (request->data_buf.Length) {
		ret = hv_vmbus_channel_send_packet_multipagebuffer(
				(VMBUS_CHANNEL *)device->context,
				&request->data_buf,
				vstor_packet, 
				sizeof(struct vstor_packet), 
				(uint64_t)request);

	} else {
		ret = hv_vmbus_channel_send_packet(
				(VMBUS_CHANNEL *)device->context,
				vstor_packet,
				sizeof(struct vstor_packet),
				(uint64_t)request,
				VmbusPacketTypeDataInBand,
				VMBUS_DATA_PACKET_FLAG_COMPLETION_REQUESTED);
	}

	if (ret != 0) {
		printf("Unable to send packet %p ret %d", vstor_packet, ret);
	}

	atomic_add_int(&stordev_ctx->num_out_reqs, 1);

	hv_put_storvsc_dev_ctx(device);

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
			   struct vstor_packet *vstor_packet,
			   struct hv_storvsc_request *request)
{
	struct hv_storvsc_dev_ctx *stordev_ctx;
	struct vmscsi_req *vm_srb;

	DPRINT_ENTER(STORVSC);

	stordev_ctx = hv_must_get_storvsc_dev_ctx(device);
	if (stordev_ctx == NULL) {
		DPRINT_ERR(STORVSC, "unable to get stor device context...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	DPRINT_INFO(STORVSC, "IO_COMPLETE_OPERATION - request %p completed bytes xfer %u", 
				request, vstor_packet->vm_srb.transfer_len);

	KASSERT(request != NULL, ("request != NULL"));

	vm_srb = &vstor_packet->vm_srb;
	if ((vm_srb->scsi_status != SCSI_STATUS_OK) ||
			(vm_srb->srb_status != SRB_STATUS_SUCCESS)) {
		DPRINT_DBG(STORVSC, "cmd 0x%x scsi status 0x%x srb status 0x%x\n",
				   vm_srb->cdb[0],
				   vm_srb->scsi_status,
				   vm_srb->srb_status);
	}

	request->sense_info_len = 0;
	if (((vm_srb->scsi_status & 0xFF) == SCSI_STATUS_CHECK_COND) &&
			(vm_srb->srb_status & SRB_STATUS_AUTOSENSE_VALID)) {
		/* Autosense data available */
		DPRINT_DBG(STORVSC, "storvsc pkt %p autosense data valid - len %d\n",
				request, vm_srb->sense_info_len);

		KASSERT(vm_srb->sense_info_len <= request->sense_info_len,
				("vm_srb->sense_info_len <= "
				 "request->sense_info_len"));

		memcpy(request->sense_data, vm_srb->sense_data,
				vm_srb->sense_info_len);

		request->sense_info_len = vm_srb->sense_info_len;
	}

	/* Complete request by passing to the CAM layer */
	storvsc_io_done(request);

	atomic_subtract_int(&stordev_ctx->num_out_reqs, 1);

	hv_put_storvsc_dev_ctx(device);

	DPRINT_EXIT(STORVSC);
}

static void
hv_storvsc_on_channel_callback(void *context)
{
	int ret = 0;
	DEVICE_OBJECT *device = (DEVICE_OBJECT*)context;
	struct hv_storvsc_dev_ctx *stordev_ctx;
	uint32_t bytes_recvd;
	uint64_t request_id;
	uint8_t packet[roundup2(sizeof(struct vstor_packet), 8)];
	struct hv_storvsc_request *request;
	struct vstor_packet *vstor_packet;

	DPRINT_ENTER(STORVSC);

	KASSERT(device, ("device"));

	stordev_ctx = hv_get_storvsc_dev_ctx(device);
	if (stordev_ctx == NULL) {
		DPRINT_ERR(STORVSC,
				   "unable to get stor device context...device being destroyed?");
		DPRINT_EXIT(STORVSC);
		return;
	}

	do {
		ret = hv_vmbus_channel_recv_packet(
				(VMBUS_CHANNEL *)device->context,
				packet,
				roundup2(sizeof(struct vstor_packet), 8),
				&bytes_recvd,
				&request_id);

		if (ret == 0 && bytes_recvd > 0) {
			DPRINT_DBG(STORVSC, "receive %d bytes - tid %lx",
					   bytes_recvd, request_id);

			request = (struct hv_storvsc_request *)(uint64_t)request_id;
			KASSERT(request, ("request"));

			if ((request == &stordev_ctx->init_req) ||
				(request == &stordev_ctx->reset_req)) {
				memcpy(&request->vstor_packet, packet, sizeof(struct vstor_packet));

				mtx_lock(&request->event.mtx);
				cv_signal(&request->event.cv);
				mtx_unlock(&request->event.mtx);
			} else {
				vstor_packet = (struct vstor_packet *)packet;
				switch(vstor_packet->operation) {
				case VSTOR_OPERATION_COMPLETEIO:
					DPRINT_DBG(STORVSC, "IO_COMPLETE_OPERATION");
					hv_storvsc_on_iocompletion(device, vstor_packet, request);
					break;
				case VSTOR_OPERATION_REMOVEDEVICE:
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

	hv_put_storvsc_dev_ctx(device);

	DPRINT_EXIT(STORVSC);
	return;
}
