/*
 * hv_heartbeat_drv_freebsd.c
 *
 *  Created on: Dec 15, 2011
 *      Author: Larry Melia
 */

// TODO--remove includes that aren't needed

#include <sys/types.h>
#include <sys/param.h>
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
#include <vm/vm.h>
#include <vm/pmap.h>

#include <hv_osd.h>
#include <hv_ic.h>
#include <hv_vmbus_packet_format.h>
#include <hv_channel_messages.h>
#include <hv_channel_mgmt.h>
#include <hv_vmbus_var.h>
#include <hv_vmbus_api.h>
#include <hv_vmbus.h>
#include <hv_logging.h>

#define heartbeat_DEVNAME "heartbeat"

typedef struct heartbeat_softc {
	//DEVICE_OBJECT *device_object;
} heartbeat_softc;


static
void heartbeat_onchannelcallback_cb(void *context);

static VMBUS_CHANNEL_INTERFACE vmbus_channel_interface;

// prototypes
static void heartbeat_init(void);
static int heartbeat_probe(device_t dev);
static int heartbeat_attach(device_t dev);
static int heartbeat_detach(device_t dev);
static int heartbeat_shutdown(device_t dev);

static void heartbeat_init(void)
{   DPRINT_ENTER(VMBUS_UTILITY);
    printf("heartbeat initializing.... ");
    vmbus_get_interface(&vmbus_channel_interface);
    DPRINT_EXIT(VMBUS_UTILITY);
}

static int heartbeat_probe(device_t dev)
{
	static const GUID gheartbeatDeviceType={
			.Data = // VMBus channel type GUID {57164f39-9115-4e78-ab55-382f3bd5422d}
				0x39, 0x4f, 0x16, 0x57, 0x15, 0x91, 0x78, 0x4e,
				0xab, 0x55, 0x38, 0x2f, 0x3b, 0xd5, 0x42, 0x2d
	};

	int rtn_value = ENXIO;

	const char *p = vmbus_get_type(dev);
	if (!memcmp(p, &gheartbeatDeviceType.Data, sizeof(GUID))) {
		device_set_desc(dev, "vmbus-heartbeat support");
		printf("heartbeat_probe: vmbus-heartbeat detected\n");
		rtn_value = 0;
	}

	return rtn_value;
}

static int heartbeat_attach(device_t dev)
{
	DPRINT_INFO(VMBUS_UTILITY, "heartbeat_attach");

	DPRINT_INFO(VMBUS, "Opening heartbeat channel...");
	struct device_context *device_ctx = vmbus_get_devctx(dev);
	DPRINT_INFO(VMBUS, "heartbeat_attach: channel addr: %p", device_ctx->device_obj.context);
	int stat = VmbusChannelOpen(device_ctx->device_obj.context,
			10*PAGE_SIZE, 10*PAGE_SIZE, NULL, 0,
		    heartbeat_onchannelcallback_cb, device_ctx->device_obj.context);
	if(stat == 0)
       DPRINT_INFO(VMBUS, "Opened heartbeat channel successfully");

	return 0;
}

static int heartbeat_detach(device_t dev)
{
	return 0;
}

static int heartbeat_shutdown(device_t dev)
{
    return 0;
}

static
void heartbeat_onchannelcallback_cb(void *context)
{
	VMBUS_CHANNEL *channel = context;
	u8 *buf;
	u32 buflen, recvlen;
	u64 requestid;

	struct heartbeat_msg_data *heartbeat_msg;

	struct icmsg_hdr *icmsghdrp;
	struct icmsg_negotiate *negop;

	DPRINT_ENTER(VMBUS);

	buflen = PAGE_SIZE;
	buf = MemAllocAtomic(buflen);

	VmbusChannelRecvPacket(channel, buf, buflen, &recvlen, &requestid);

	if (recvlen > 0)
	{
		DPRINT_DBG(VMBUS, "heartbeat packet: len=%d, requestid=%ld",
			   recvlen, requestid);

	//	printf("heartbeat packet: len=%d, requestid=%ld",
	//		   recvlen, requestid);

		icmsghdrp = (struct icmsg_hdr *)&buf[
			sizeof(struct vmbuspipe_hdr)];

		if(icmsghdrp->icmsgtype == ICMSGTYPE_NEGOTIATE)
		{
			icmsghdrp->icmsgsize = 0x10;

			negop = (struct icmsg_negotiate *)&buf[
				sizeof(struct vmbuspipe_hdr) +
				sizeof(struct icmsg_hdr)];

			if(negop->icframe_vercnt == 2 &&
			   negop->icversion_data[1].major == 3) {
				negop->icversion_data[0].major = 3;
				negop->icversion_data[0].minor = 0;
				negop->icversion_data[1].major = 3;
				negop->icversion_data[1].minor = 0;
			} else {
				negop->icversion_data[0].major = 1;
				negop->icversion_data[0].minor = 0;
				negop->icversion_data[1].major = 1;
				negop->icversion_data[1].minor = 0;
			}

			negop->icframe_vercnt = 1;
			negop->icmsg_vercnt = 1;
		} else {
			heartbeat_msg = (struct heartbeat_msg_data *)&buf[
				sizeof(struct vmbuspipe_hdr) +
				sizeof(struct icmsg_hdr)];

		DPRINT_DBG(VMBUS, "heartbeat seq = %ld",
			   heartbeat_msg->seq_num);
		// printf("heartbeat seq = %lld",
		//	   heartbeat_msg->seq_num);

			heartbeat_msg->seq_num += 1;
		}

		icmsghdrp->icflags = ICMSGHDRFLAG_TRANSACTION
			| ICMSGHDRFLAG_RESPONSE;

		VmbusChannelSendPacket(channel, buf,
				       recvlen, requestid,
				       VmbusPacketTypeDataInBand, 0);
	}

	MemFree(buf);

	DPRINT_EXIT(VMBUS);
}


/**********************************************************************************/

static device_method_t heartbeat_methods[] = { /* Device interface */
        DEVMETHOD(device_probe,         heartbeat_probe),
        DEVMETHOD(device_attach,        heartbeat_attach),
        DEVMETHOD(device_detach,        heartbeat_detach),
        DEVMETHOD(device_shutdown,      heartbeat_shutdown),
        { 0, 0 }
};

static driver_t heartbeat_driver = {
		heartbeat_DEVNAME,
        heartbeat_methods,
        sizeof(heartbeat_softc)
};

static devclass_t heartbeat_devclass;

DRIVER_MODULE(heartbeat, vmbus, heartbeat_driver, heartbeat_devclass, 0, 0);

SYSINIT(heartbeat_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1, heartbeat_init, NULL);

