/*
 * hv_timesync_drv_freebsd.c
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
#include <hv_vmbus_var.h>
#include <hv_vmbus_api.h>
#include <hv_vmbus.h>
#include <hv_logging.h>
#include <hv_channel.h>

#include "hv_timesync_ic.h"

#define TIMESYNC_DEVNAME "timesync"

typedef struct timesync_softc {
//DEVICE_OBJECT *device_object;
} timesync_softc;


// prototypes
static void timesync_init(void);
static int timesync_probe(device_t dev);
static int timesync_attach(device_t dev);
static int timesync_detach(device_t dev);
static int timesync_shutdown(device_t dev);

static void
timesync_init(void) {
	DPRINT_ENTER(VMBUS_UTILITY);
	printf("timesync initializing.... ");
        // nothing to do
	DPRINT_EXIT(VMBUS_UTILITY);
}

static int
timesync_probe(device_t dev) {
	static const GUID gtimesyncDeviceType = { //{9527E630-D0AE-497b-ADCE-E80AB0175CAF}
		.Data = { 0x30, 0xe6, 0x27, 0x95, 0xae, 0xd0, 0x7b, 0x49, 0xad,
			  0xce, 0xe8, 0x0a, 0xb0, 0x17, 0x5c, 0xaf } };

	int rtn_value = ENXIO;

	const char *p = vmbus_get_type(dev);
	if (!memcmp(p, &gtimesyncDeviceType.Data, sizeof(GUID))) {
		device_set_desc(dev, "vmbus-timesync support");
		printf("timesync_probe: vmbus-timesync detected\n");
		rtn_value = 0;
	}

	return (rtn_value);
}

static int
timesync_attach(device_t dev) {
	DPRINT_INFO(VMBUS_UTILITY, "timesync_attach");

	DPRINT_INFO(VMBUS, "Opening Timesync channel...");
	struct device_context *device_ctx = vmbus_get_devctx(dev);
	DPRINT_INFO(VMBUS, "timesync_attach: channel addr: %p",
		device_ctx->device_obj.context);
	int stat = hv_vmbus_channel_open(device_ctx->device_obj.context,
		10 * PAGE_SIZE, 10 * PAGE_SIZE, NULL, 0, timesync_channel_cb,
		device_ctx->device_obj.context);
	if (stat == 0)
		DPRINT_INFO(VMBUS, "Opened Timesync channel successfully");

	return (0);
}

static int
timesync_detach(device_t dev) {
	return (0);
}

static int
timesync_shutdown(device_t dev) {
	return (0);
}

/************************************************************************************/

static device_method_t timesync_methods[] = { /* Device interface */
DEVMETHOD(device_probe, timesync_probe),
	DEVMETHOD(device_attach, timesync_attach),
	DEVMETHOD(device_detach, timesync_detach),
	DEVMETHOD(device_shutdown, timesync_shutdown), { 0, 0 } };

static driver_t timesync_driver = { TIMESYNC_DEVNAME, timesync_methods,
	sizeof(timesync_softc) };

static devclass_t timesync_devclass;

DRIVER_MODULE(timesync, vmbus, timesync_driver, timesync_devclass, 0, 0);
MODULE_VERSION(timesync, 1);
MODULE_DEPEND(heartbeat,vmbus, 1, 1, 1);

SYSINIT(timesync_initx, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE + 1,
	timesync_init, NULL);

