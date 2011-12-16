/*
 * hv_timesync_drv_freebsd.c
 *
 *  Created on: Dec 15, 2011
 *      Author: Larry Melia
 */

#include <sys/param.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>

#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include <include/hv_osd.h>
#include <include/hv_logging.h>

#define HEARTBEAT_DEVNAME "heartbeat"

static const GUID gtimesyncDeviceType={ //{9527E630-D0AE-497b-ADCE-E80AB0175CAF}
		 .Data = {
		                0x30, 0xe6, 0x27, 0x95, 0xae, 0xd0, 0x7b, 0x49,
		                0xad, 0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf
		        }
};

static void timesync_init(void)
{
}

static int timesync_probe(device_t dev)
{
	const char *p = vmbus_get_type(dev);

	if (!memcmp(p, &gtimesyncDeviceType.Data, sizeof(GUID))) {
		device_set_desc(dev, "vmbus-timesync support");
		printf("vmbus-timesync detected\n");
		// return (0);
	}

	return (ENXIO);
}

static int timesync_attach(device_t dev)
{
	printf("timesync_attach\n");
	return 0;
}

static int timesync_detach(device_t dev)
{
	printf("timesync_detach\n");
	return 0;
}

static void timesync_shutdown(device_t dev)
{
   printf("timesync_shutdown\n");
}

//static unsigned int
//timesync_recv_callback(DEVICE_OBJECT *device_obj, timesync_PACKET* packet)
//{
//	struct device_context *device_ctx = to_device_context(device_obj);
//	hn_softc_t *sc = (hn_softc_t *)device_get_softc(device_ctx->device);
//
//	return 0;
//}

static device_method_t timesync_methods[] = {
        /* Device interface */
        DEVMETHOD(device_probe,         timesync_probe),
        DEVMETHOD(device_attach,        timesync_attach),
        DEVMETHOD(device_detach,        timesync_detach),
	/* Fixme:  warning: assignment from incompatible pointer type */
        DEVMETHOD(device_shutdown,      timesync_shutdown),
        { 0, 0 }
};

static driver_t timesync_driver = {
		HEARTBEAT_DEVNAME,
        timesync_methods,
        sizeof(hn_softc_t)
};

static devclass_t timesync_devclass;

DRIVER_MODULE(heartbeat, vmbus, timesync_driver, timesync_devclass, 0, 0);

//SYSINIT(timesync_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1, timesync_init, NULL);

