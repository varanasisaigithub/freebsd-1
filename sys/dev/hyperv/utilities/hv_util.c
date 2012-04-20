/*
 *  A common driver for all hyper-V util services.*
 *  Created on: Dec 15, 2011
 *  Consolidation done on March 5th, 2012
 *      Author: Larry Melia
 *	Author: K. Y. Srinivasan
 */


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/reboot.h>
#include <sys/timetc.h>

#include "../include/hyperv.h"

#define MAX_UTIL_SERVICES 4

#define SHUT_DOWN 0
#define TIME_SYNCH 1
#define HEART_BEAT 2
#define KVP 3

struct util_service {
	hv_guid guid;
        uint8_t *recv_buffer;
        char *name;
        struct hv_work_queue *workq;
        void (*cb)(void *);
        int  (*init)(struct util_service *);
        void (*deinit)(void);
};

static void shutdown_cb(void *context);
static void heartbeat_cb(void *context);
static void timesync_cb(void *context);
static void kvp_cb(void *context);

static int timesync_init(struct util_service *serv);
 
static  struct util_service  service_table[] = {
	/* Shutdown Service */
	{ .guid.data = {0x31, 0x60, 0x0B, 0X0E, 0x13, 0x52, 0x34, 0x49,
			0x81, 0x8B, 0x38, 0XD9, 0x0C, 0xED, 0x39, 0xDB},
	  .cb = shutdown_cb,
	  .name  = "Hyper-V Shutdown Service\n",
	},

        /* Time Synch Service */
        { .guid.data = {0x30, 0xe6, 0x27, 0x95, 0xae, 0xd0, 0x7b, 0x49,
			0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf},
	  .cb = timesync_cb,
	  .name = "Hyper-V Timesynch Service\n",
	  .init = timesync_init,
	},

        /* Heartbeat Service */
        { .guid.data = {0x39, 0x4f, 0x16, 0x57, 0x15, 0x91, 0x78, 0x4e,
			0xab, 0x55, 0x38, 0x2f, 0x3b, 0xd5, 0x42, 0x2d},
          .cb = heartbeat_cb,
	  .name = "Hyper-V Heartbeat Service\n",
	},

        /* KVP Service */
        { .guid.data = {0xe7, 0xf4, 0xa0, 0xa9, 0x45, 0x5a, 0x96, 0x4d,
			0xb8, 0x27, 0x8a, 0x84, 0x1e, 0x8c, 0x3,  0xe6},
	  .cb = kvp_cb,
	  .name = "Hyper-V KVP Service\n",
	},
};
 

struct ictimesync_data {
	uint64_t	parenttime;
	uint64_t	childtime;
	uint64_t	roundtriptime;
        uint8_t		flags;
} __packed;

#define WLTIMEDELTA     116444736000000000L     /* in 100ns unit */
#define ICTIMESYNCFLAG_PROBE                    0
#define ICTIMESYNCFLAG_SYNC                     1
#define ICTIMESYNCFLAG_SAMPLE                   2


static int timesync_init(struct util_service *serv)
{
	serv->workq = hv_work_queue_create("Time Synch");
	if (!serv->workq)
		return -ENOMEM;
	return 0;
}


static void negotiate_version(struct hv_vmbus_icmsg_hdr *icmsghdrp,
                               struct hv_vmbus_icmsg_negotiate *negop, uint8_t *buf)
{
	icmsghdrp->icmsgsize = 0x10;

	negop = (struct hv_vmbus_icmsg_negotiate *)&buf[
		sizeof(struct hv_vmbus_pipe_hdr) +
		sizeof(struct hv_vmbus_icmsg_hdr)];

	if (negop->icframe_vercnt == 2 &&
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
}

static void kvp_cb(void *context)
{
}


#define NANO_SEC  1000000000L            /* 10^ 9 nanosecs = 1 sec */

static void hv_set_host_time(void *context)
{
	uint64_t hosttime = (uint64_t)context;
	struct timespec ts, host_ts;
	int64_t tns, host_tns, tmp, tsec;


	nanotime(&ts);
	tns = ts.tv_sec * NANO_SEC + ts.tv_nsec;
	host_tns = (hosttime - WLTIMEDELTA) * 100;

	tmp = host_tns;
	tsec = tmp / NANO_SEC;
	host_ts.tv_nsec = (long) (tmp - (tsec * NANO_SEC));
	host_ts.tv_sec = tsec;

	/* force time sync with host after reboot, restore, etc. */
	mtx_lock(&Giant);
	tc_setclock(&host_ts);
	resettodr();
	mtx_unlock(&Giant);
}

/*
 * Synchronize time with host after reboot, restore, etc.
 *
 * ICTIMESYNCFLAG_SYNC flag bit indicates reboot, restore events of the VM.
 * After reboot the flag ICTIMESYNCFLAG_SYNC is included in the first time
 * message after the timesync channel is opened. Since the hv_utils module is
 * loaded after hv_vmbus, the first message is usually missed. The other
 * thing is, systime is automatically set to emulated hardware clock which may
 * not be UTC time or in the same time zone. So, to override these effects, we
 * use the first 50 time samples for initial system time setting.
 */
static inline void adj_guesttime(uint64_t hosttime, uint8_t flags)
{
	static int scnt = 50;

	if ((flags & ICTIMESYNCFLAG_SYNC) != 0) {
		hv_queue_work_item(service_table[TIME_SYNCH].workq,
			 hv_set_host_time, (void *)hosttime);
		return;
	}

	if ((flags & ICTIMESYNCFLAG_SAMPLE) != 0 && scnt > 0) {
		scnt--;
		hv_queue_work_item(service_table[TIME_SYNCH].workq,
			 hv_set_host_time, (void *)hosttime);
	}
}

/*
 * Time Sync Channel message handler.
 */
static void timesync_cb(void *context)
{
	VMBUS_CHANNEL *channel = context;
	uint32_t recvlen;
	uint64_t requestid;
	struct hv_vmbus_icmsg_hdr *icmsghdrp;
	struct ictimesync_data *timedatap;
	uint8_t *time_buf = service_table[TIME_SYNCH].recv_buffer;
	int ret;

	ret = hv_vmbus_channel_recv_packet(channel, time_buf,
			PAGE_SIZE, &recvlen, &requestid);

	if ((ret == 0) && recvlen > 0) {
		icmsghdrp = (struct hv_vmbus_icmsg_hdr *)&time_buf[
				sizeof(struct hv_vmbus_pipe_hdr)];

		if (icmsghdrp->icmsgtype == HV_ICMSGTYPE_NEGOTIATE) {
			negotiate_version(icmsghdrp, NULL, time_buf);
		} else {
			timedatap = (struct ictimesync_data *)&time_buf[
				sizeof(struct hv_vmbus_pipe_hdr) +
				sizeof(struct hv_vmbus_icmsg_hdr)];
			adj_guesttime(timedatap->parenttime, timedatap->flags);
		}

		icmsghdrp->icflags = HV_ICMSGHDRFLAG_TRANSACTION
				| HV_ICMSGHDRFLAG_RESPONSE;

		hv_vmbus_channel_send_packet(channel, time_buf,
				recvlen, requestid,
				HV_VMBUS_PACKET_TYPE_DATA_IN_BAND, 0);
	}
}

static void shutdown_cb(void *context) 
{
	VMBUS_CHANNEL *channel = context;
	uint8_t *buf;
	int ret;
	uint32_t recvlen;
	uint64_t  requestid;
	uint8_t execute_shutdown = 0;
	struct hv_shutdown_msg_data *shutdown_msg;
	struct hv_vmbus_icmsg_hdr *icmsghdrp;
	buf = service_table[SHUT_DOWN].recv_buffer;

        ret = hv_vmbus_channel_recv_packet(channel, buf, PAGE_SIZE,
					&recvlen, &requestid);

	if ((ret == 0) && recvlen > 0) {

		icmsghdrp = (struct hv_vmbus_icmsg_hdr *)
				&buf[sizeof(struct hv_vmbus_pipe_hdr)];

		if (icmsghdrp->icmsgtype == HV_ICMSGTYPE_NEGOTIATE) {
			negotiate_version(icmsghdrp, NULL, buf);

		} else {
			shutdown_msg =
				(struct hv_shutdown_msg_data *)
				 &buf[sizeof(struct hv_vmbus_pipe_hdr) +
				sizeof(struct hv_vmbus_icmsg_hdr)];

			switch (shutdown_msg->flags) {
			case 0:
			case 1:
				icmsghdrp->status = HV_S_OK;
				execute_shutdown = 1;
				printf("Shutdown request received -"
				" graceful shutdown initiated\n");
				break;
			default:
				icmsghdrp->status = HV_E_FAIL;
				execute_shutdown = 0;

				printf("Shutdown request received -"
					" Invalid request\n");
				break;
			}
		}

		icmsghdrp->icflags = HV_ICMSGHDRFLAG_TRANSACTION
				| HV_ICMSGHDRFLAG_RESPONSE;

		hv_vmbus_channel_send_packet(channel, buf,
				recvlen, requestid,
				HV_VMBUS_PACKET_TYPE_DATA_IN_BAND, 0);
	}

	if (execute_shutdown)
		 shutdown_nice(RB_POWEROFF);
}

static void heartbeat_cb(void *context) 
{
	VMBUS_CHANNEL *channel = context;
	uint8_t *buf;
	uint32_t recvlen;
	uint64_t requestid;
	int ret;

	struct hv_vmbus_heartbeat_msg_data *heartbeat_msg;

	struct hv_vmbus_icmsg_hdr *icmsghdrp;

	buf = service_table[HEART_BEAT].recv_buffer;;

	ret = hv_vmbus_channel_recv_packet(channel, buf, PAGE_SIZE, &recvlen,
			&requestid);

	if ((ret == 0) && recvlen > 0) {

		icmsghdrp = (struct hv_vmbus_icmsg_hdr *)
				&buf[sizeof(struct hv_vmbus_pipe_hdr)];

		if (icmsghdrp->icmsgtype == HV_ICMSGTYPE_NEGOTIATE) {
			negotiate_version(icmsghdrp, NULL, buf);

		} else {
			heartbeat_msg =
				(struct hv_vmbus_heartbeat_msg_data *) &buf[sizeof(struct hv_vmbus_pipe_hdr)
					+ sizeof(struct hv_vmbus_icmsg_hdr)];

				heartbeat_msg->seq_num += 1;
		}
		icmsghdrp->icflags = HV_ICMSGHDRFLAG_TRANSACTION
			| HV_ICMSGHDRFLAG_RESPONSE;

		hv_vmbus_channel_send_packet(channel, buf, recvlen, requestid,
				HV_VMBUS_PACKET_TYPE_DATA_IN_BAND, 0);
	}

}


static int
util_probe(device_t dev) {
	int rtn_value = ENXIO;
	int i;

	for (i = 0; i < MAX_UTIL_SERVICES; i++) {
		const char *p = vmbus_get_type(dev);
		if (!memcmp(p, &service_table[i].guid, sizeof(hv_guid))) {
			device_set_softc(dev, (void *)(&service_table[i])); 
			rtn_value = 0;
		}
	}

	return rtn_value;

}

static int
util_attach(device_t dev) 
{
	int ret;
	struct util_service *service;
	struct hv_device *hv_dev;
	
	
	hv_dev = vmbus_get_devctx(dev);
	service = device_get_softc(dev);

	printf("Hyper-V Service attaching: %s\n", service->name);
	service->recv_buffer = malloc(PAGE_SIZE,  M_DEVBUF, M_ZERO);
	if (!service->recv_buffer)
		return -ENOMEM;

	if (service->init) {
		ret = service->init(service);
		if (ret) {
			ret = -ENODEV;
			goto error0;
		}
	}

	ret = hv_vmbus_channel_open(hv_dev->channel, 2 * PAGE_SIZE,
				2 * PAGE_SIZE, NULL, 0,
				service->cb, hv_dev->channel);
	if (ret)
		goto error1;

	return 0;

error1:
	if (service->deinit)
		service->deinit();

error0:
	free(service->recv_buffer, M_DEVBUF);
	return ret;
}

static int util_detach(device_t dev)
{
	struct util_service *service;
	struct hv_device *hv_dev;
	
	hv_dev = vmbus_get_devctx(dev);

	hv_vmbus_channel_close(hv_dev->channel);
	service = device_get_softc(dev);

	if (service->deinit)
		service->deinit();

	if (service->workq)
		hv_work_queue_close(service->workq);

	free(service->recv_buffer, M_DEVBUF);
	return 0;
}

static void util_init(void)
{
}

static int util_modevent(module_t mod, int what, void *arg) 
{

	switch (what) {
        case MOD_LOAD:
                break;
        case MOD_UNLOAD:
                break;
	default:
		break;
        }
        return (0);
}

static device_method_t util_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, util_probe),
	DEVMETHOD(device_attach, util_attach),
	DEVMETHOD(device_detach, util_detach),
	DEVMETHOD(device_shutdown, bus_generic_shutdown),
	{ 0, 0 } }
;

static driver_t util_driver = { "hyperv-utils", util_methods, 0 };

static devclass_t util_devclass;

DRIVER_MODULE(hv_utils, vmbus, util_driver, util_devclass, util_modevent, 0);
MODULE_VERSION(hv_utils, 1);
MODULE_DEPEND(hv_utils, vmbus, 1, 1, 1);

SYSINIT(hv_util_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1,
	util_init, NULL);
