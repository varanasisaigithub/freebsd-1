/*****************************************************************************
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
 * Copyright (c) 2010-2011, Citrix, Inc.
 *
 * HyperV FreeBSD vmbus driver implementation
 *
 *****************************************************************************/

/*
 Name:	vmbus_drv.c

 Desc:	vmbus driver implementation

 --*/

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/rtprio.h>
#include <sys/interrupt.h>
#include <sys/sx.h>
#include <sys/taskqueue.h>

#include <machine/resource.h>
#include <sys/rman.h>

#include <machine/stdarg.h>
#include <machine/intr_machdep.h>
#include <sys/pcpu.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include "hv_hv.h"
#include "hv_vmbus_var.h"
#include "hv_vmbus_api.h"
#include "hv_vmbus.h"
//#include <sys/timetc.h>
//#include <sys/mutex.h>

#define VMBUS_IRQ				0x5

struct vmbus_softc {
	device_t vmbus_dev;
};

#if 0
struct vmbus_device_vars {
	GUID vd_type;
	GUID vd_instance;
	struct device_context *vd_dev_ctx;
	device_t vd_dev;
};
#endif

struct vmbus_driver_context {
	struct driver_context drv_ctx;
	VMBUS_DRIVER_OBJECT drv_obj;
	struct device_context device_ctx;
	device_t vmb_dev;
	struct resource *intr_res;
	void *msg_dpc;
	void *event_dpc;
	struct intr_event *hv_message_intr_event;
	struct intr_event *hv_event_intr_event;
};

static void vmbus_exit(void);
static void vmbus_bus_exit(void);
static int vmbus_bus_init(PFN_DRIVERINITIALIZE pfn_drv_init);
static int vmbus_modevent(module_t mod, int what, void *arg);

static int vmbus_irq = VMBUS_IRQ;
static struct vmbus_driver_context g_vmbus_drv;
static void *vmbus_cookiep;
static int vmbus_rid = 0;

static int vmbus_read_ivar(device_t dev, device_t child, int index,
		uintptr_t *result) {
	struct device_context *child_dev_ctx = device_get_ivars(child);

	switch (index) {

	case VMBUS_IVAR_TYPE:
		*result = (uintptr_t) &child_dev_ctx->class_id;
		return (0);
	case VMBUS_IVAR_INSTANCE:
		*result = (uintptr_t) &child_dev_ctx->device_id;
		return (0);
	case VMBUS_IVAR_DEVCTX:
		*result = (uintptr_t) child_dev_ctx;
		return (0);
	case VMBUS_IVAR_NODE:
		*result = (uintptr_t) child_dev_ctx->device;
		return (0);
	}
	return (ENOENT);
}

static int vmbus_write_ivar(device_t dev, device_t child, int index,
		uintptr_t value) {
	switch (index) {

	case VMBUS_IVAR_TYPE:
	case VMBUS_IVAR_INSTANCE:
	case VMBUS_IVAR_DEVCTX:
	case VMBUS_IVAR_NODE:
		/* read-only */
		return (EINVAL);
	}
	return (ENOENT);
}

/*++

 Name:   vmbus_msg_dpc()

 Desc:   Tasklet routine to handle hypervisor messages

 --*/
static void vmbus_msg_dpc(void *data) {
	VMBUS_DRIVER_OBJECT* vmbus_drv_obj = (VMBUS_DRIVER_OBJECT*) data;

	DPRINT_ENTER(VMBUS_DRV);

	ASSERT(vmbus_drv_obj->OnMsgDpc != NULL);

	// Call to bus driver to handle interrupt
	vmbus_drv_obj->OnMsgDpc(&vmbus_drv_obj->Base);

	DPRINT_EXIT(VMBUS_DRV);
}

static void vmbus_event_dpc(void *data) {
	VMBUS_DRIVER_OBJECT* vmbus_drv_obj = (VMBUS_DRIVER_OBJECT*) data;

	DPRINT_ENTER(VMBUS_DRV);

	ASSERT(vmbus_drv_obj->OnEventDpc != NULL);

	// Call to bus driver to handle interrupt
	vmbus_drv_obj->OnEventDpc(&vmbus_drv_obj->Base);

	DPRINT_EXIT(VMBUS_DRV);
}

/*
 * Fixme -- this rather dubious technique inspired by the igb driver
 */
#if __FreeBSD_version < 700000
#define INTR_STRAY
#define INTR_HANDLED
#else
#define INTR_STRAY      1
#define INTR_HANDLED    1
#endif

#if __FreeBSD_version < 700000
static void
#else
static int
#endif
hv_vmbus_isr(void *p) {
	int ret = 0;
	VMBUS_DRIVER_OBJECT* vmbus_driver_obj = &g_vmbus_drv.drv_obj;

	DPRINT_ENTER(VMBUS_DRV);

	ASSERT(vmbus_driver_obj->OnIsr != NULL);

	// Call to bus driver to handle interrupt
	ret = vmbus_driver_obj->OnIsr(&vmbus_driver_obj->Base);

	// Schedules a dpc if necessary
	if (ret > 0) {
		if (BitTest(&ret, 0)) {
			swi_sched(g_vmbus_drv.msg_dpc, 0);
		}
		if (BitTest(&ret, 1)) {
			swi_sched(g_vmbus_drv.event_dpc, 0);
		}

		DPRINT_EXIT(VMBUS_DRV);
		return INTR_HANDLED;
	} else {
		DPRINT_EXIT(VMBUS_DRV);
		return INTR_STRAY;
	}
}

static DEVICE_OBJECT* vmbus_child_device_create(GUID type, GUID instance,
		void* context) {
	struct device_context *child_device_ctx;
	DEVICE_OBJECT* child_device_obj;

	DPRINT_ENTER(VMBUS_DRV);

	// Allocate the new child device
	child_device_ctx = malloc(sizeof(struct device_context), M_DEVBUF, M_ZERO);
	if (!child_device_ctx) {
		DPRINT_ERR(VMBUS_DRV,
				"unable to allocate device_context for child device");
		DPRINT_EXIT(VMBUS_DRV);

		return NULL;
	}

	DPRINT_DBG(
			VMBUS_DRV,
			"child device (%p) allocated - "
			"type {%02x%02x%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x%02x%02x},"
			"id {%02x%02x%02x%02x-%02x%02x-%02x%02x-"
			"%02x%02x%02x%02x%02x%02x%02x%02x}",
			&child_device_ctx->device, type.Data[3], type.Data[2], type.Data[1], type.Data[0], type.Data[5], type.Data[4], type.Data[7], type.Data[6], type.Data[8], type.Data[9], type.Data[10], type.Data[11], type.Data[12], type.Data[13], type.Data[14], type.Data[15], instance.Data[3], instance.Data[2], instance.Data[1], instance.Data[0], instance.Data[5], instance.Data[4], instance.Data[7], instance.Data[6], instance.Data[8], instance.Data[9], instance.Data[10], instance.Data[11], instance.Data[12], instance.Data[13], instance.Data[14], instance.Data[15]);

	child_device_obj = &child_device_ctx->device_obj;
	child_device_obj->context = context;
	memcpy(&child_device_obj->deviceType, &type, sizeof(GUID));
	memcpy(&child_device_obj->deviceInstance, &instance, sizeof(GUID));

	memcpy(&child_device_ctx->class_id, &type, sizeof(GUID));
	memcpy(&child_device_ctx->device_id, &instance, sizeof(GUID));

	DPRINT_INFO(VMBUS_DRV, "Create Device: thr: %p, ctx: %p, obj: %p",
			curthread, child_device_ctx, child_device_obj);

	DPRINT_EXIT(VMBUS_DRV);

	return child_device_obj;
	// Fixme
	return NULL;
}

static void vmbus_child_device_destroy(DEVICE_OBJECT* device_obj) {
	DPRINT_INFO(VMBUS_DRV, "Destroy Device: obj: %p", device_obj);
}

static int vmbus_child_device_register(DEVICE_OBJECT* root_device_obj,
		DEVICE_OBJECT* child_device_obj) {
	struct device_context *root_device_ctx = to_device_context(root_device_obj);
	struct device_context *child_device_ctx = to_device_context(
			child_device_obj);
	device_t child;
	int ret = 0;

	DPRINT_INFO(VMBUS_DRV, "Register Device: thr: %p, obj: %p\n",
			curthread, child_device_obj);

	//	ivars = malloc(sizeof(struct vmbus_device_ivars),
	//				M_DEVBUS, M_ZERO|M_WAITOK);

	//	memcpy(&ivars->vd_type, &child_device_ctx->classid, sizeof(GUID));
	//	memcpy(&ivars->vd_instance, &child_device_ctx->device_id, sizeof(GUID));
	//	ivars->vd_dev_ctx = child_device_ctx;

	child = device_add_child(root_device_ctx->device, NULL, -1);
	child_device_ctx->device = child;
	device_set_ivars(child, child_device_ctx);

	ret = device_probe_and_attach(child);

	return 0;
}

static void vmbus_child_device_unregister(DEVICE_OBJECT* device_obj) {
	DPRINT_INFO(VMBUS_DRV, "Unregister Device: thr: %p, obj: %p\n",
			curthread, device_obj);
}

void vmbus_child_driver_register(struct driver_context* driver_ctx) {
}

static int vmbus_print_child(device_t dev, device_t child) {
	int retval = 0;

	retval += bus_print_child_header(dev, child);
	retval += bus_print_child_footer(dev, child);

	return (retval);
}

/* 
 * Get the vmbus channel interface.  This is invoked by child/client 
 * driver that sits above vmbus
 */
void vmbus_get_interface(VMBUS_CHANNEL_INTERFACE *interface) {
	VMBUS_DRIVER_OBJECT *vmbus_drv_obj = &g_vmbus_drv.drv_obj;

	vmbus_drv_obj->GetChannelInterface(interface);
}

static void vmbus_identify(driver_t *driver, device_t parent) {
	BUS_ADD_CHILD(parent, 0, "vmbus", 0);
}

static int vmbus_probe(device_t dev) {
	printf("vmbus_probe\n");

	if (!HvQueryHypervisorPresence())
		return (ENXIO);

	device_set_desc(dev, "Vmbus Devices");

	return (0);
}

static int vmbus_attach(device_t dev) {
	struct vmbus_softc *sc = device_get_softc(dev);
	printf("vmbus_attach: dev: %p\n", dev);
	sc->vmbus_dev = dev;
	g_vmbus_drv.vmb_dev = dev;

	/* Actual Attach is deferred to vmbus_init() */

	return 0;
}

/*++

 Name:   vmbus_bus_init()

 Desc:   Main vmbus driver initialization routine. Here, we
 - initialize the vmbus driver context
 - setup various driver entry points
 - invoke the vmbus hv main init routine
 - get the irq resource
 - invoke the vmbus to add the vmbus root device
 - setup the vmbus root device
 - retrieve the channel offers
 --*/

static int vmbus_bus_init(PFN_DRIVERINITIALIZE pfn_drv_init) {
	int ret = -1;
	unsigned int vector = 0;
	struct intsrc *isrc;

	struct vmbus_driver_context *vmbus_drv_ctx = &g_vmbus_drv;
	VMBUS_DRIVER_OBJECT *vmbus_drv_obj = &g_vmbus_drv.drv_obj;

	struct device_context *dev_ctx = &g_vmbus_drv.device_ctx;

	DPRINT_INFO(VMBUS_DRV, "vmbus_bus_init");

	DPRINT_ENTER(VMBUS_DRV);

	// Set this up to allow lower layer to callback to add/remove
	// child devices on the bus
	vmbus_drv_obj->OnChildDeviceCreate = vmbus_child_device_create;
	vmbus_drv_obj->OnChildDeviceDestroy = vmbus_child_device_destroy;
	vmbus_drv_obj->OnChildDeviceAdd = vmbus_child_device_register;
	vmbus_drv_obj->OnChildDeviceRemove = vmbus_child_device_unregister;

	// Call to bus driver to initialize
	ret = pfn_drv_init(&vmbus_drv_obj->Base);
	if (ret != 0) {
		DPRINT_ERR(VMBUS_DRV, "Unable to initialize vmbus (%d)", ret);
		goto cleanup;
	}

	// Sanity checks
	if (!vmbus_drv_obj->Base.OnDeviceAdd) {
		DPRINT_ERR(VMBUS_DRV, "OnDeviceAdd() routine not set");
		goto cleanup;
	}

	if (swi_add(&g_vmbus_drv.hv_message_intr_event, "hv_msg", vmbus_msg_dpc,
			vmbus_drv_obj, SWI_CLOCK, 0, &vmbus_drv_ctx->msg_dpc)) {
		goto cleanup;
	}

	if (intr_event_bind(g_vmbus_drv.hv_message_intr_event, 0)) {
		goto cleanup1;
	}

	if (swi_add(&g_vmbus_drv.hv_event_intr_event, "hv_event", vmbus_event_dpc,
			vmbus_drv_obj, SWI_CLOCK, 0, &vmbus_drv_ctx->event_dpc)) {
		goto cleanup1;
	}

	if (intr_event_bind(g_vmbus_drv.hv_event_intr_event, 0)) {
		goto cleanup2;
	}

	g_vmbus_drv.intr_res = bus_alloc_resource(g_vmbus_drv.vmb_dev, SYS_RES_IRQ,
			&vmbus_rid, vmbus_irq, vmbus_irq, 1, RF_ACTIVE);

	if (g_vmbus_drv.intr_res == NULL) {
		DPRINT_ERR(VMBUS_DRV, "ERROR - Unable to request IRQ %d", vmbus_irq);
		goto cleanup2;
	}

	/*
	 * Fixme:  Changed for port to FreeBSD 8.2.  Make sure this works.
	 */
	ret = bus_setup_intr(g_vmbus_drv.vmb_dev, g_vmbus_drv.intr_res,
			INTR_TYPE_NET | INTR_FAST, hv_vmbus_isr,
#if __FreeBSD_version >= 700000
			NULL,
#endif
			NULL, &vmbus_cookiep);

	if (ret != 0) {
		/* Fixme:  Probably not appropriate */
		DPRINT_ERR(VMBUS_DRV, "ERROR - Unable to setup intr handler");
		goto cleanup3;
	}

	ret = bus_bind_intr(g_vmbus_drv.vmb_dev, g_vmbus_drv.intr_res, 0);
	if (ret != 0) {
		DPRINT_ERR(VMBUS_DRV, "ERROR - Unable to bind intr to cpu(0) ");
		goto cleanup4;
	}

	isrc = intr_lookup_source(vmbus_irq);
	if ((isrc == NULL) || (isrc->is_event == NULL)) {
		if (isrc) {
			DPRINT_ERR(VMBUS_DRV, "ERROR - Unable to find intr event");
		} else {
			DPRINT_ERR(VMBUS_DRV, "ERROR - Unable to find intr src");
		}
		goto cleanup4;
	}

	vector = isrc->is_event->ie_vector;
	printf("VMBUS: irq 0x%x vector 0x%x\n", vmbus_irq, vector);

	// Call to bus driver to add the root device
	memset(dev_ctx, 0, sizeof(struct device_context));

	dev_ctx->device = g_vmbus_drv.vmb_dev;
	ret = vmbus_drv_obj->Base.OnDeviceAdd(&dev_ctx->device_obj, &vector);
	if (ret != 0) {
		DPRINT_ERR(VMBUS_DRV, "ERROR: Unable to add vmbus root device");
		goto cleanup4;
	}

	//	sprintf(dev_ctx->device.bus_id, "vmbus_0_0");
	memcpy(&dev_ctx->class_id, &dev_ctx->device_obj.deviceType, sizeof(GUID));
	memcpy(&dev_ctx->device_id, &dev_ctx->device_obj.deviceInstance,
			sizeof(GUID));

	vmbus_drv_obj->GetChannelOffers();

	ret = 0;
	goto cleanup;

	cleanup4:
	/* remove swi, bus and intr resource */
	bus_teardown_intr(g_vmbus_drv.vmb_dev, g_vmbus_drv.intr_res, vmbus_cookiep);

	cleanup3: bus_release_resource(g_vmbus_drv.vmb_dev, SYS_RES_IRQ, vmbus_rid,
			g_vmbus_drv.intr_res);

	cleanup2: swi_remove(vmbus_drv_ctx->event_dpc);

	cleanup1: swi_remove(vmbus_drv_ctx->msg_dpc);

	cleanup: DPRINT_EXIT(VMBUS_DRV);

	return ret;
}

static void vmbus_init(void) {
	DPRINT_ENTER(VMBUS_DRV);

	DPRINT_INFO(VMBUS_DRV,
			"Vmbus initializing.... current log level 0x%x (%x,%x)",
			vmbus_loglevel, HIWORD(vmbus_loglevel), LOWORD(vmbus_loglevel));

	(void) vmbus_bus_init(VmbusInitialize);

	DPRINT_EXIT(VMBUS_DRV);
}

static int vmbus_detach(device_t dev) {
	vmbus_exit();
	return 0;
}

static void vmbus_bus_exit(void) {
	struct vmbus_driver_context *vmbus_drv_ctx = &g_vmbus_drv;
	VMBUS_DRIVER_OBJECT *vmbus_drv_obj = &g_vmbus_drv.drv_obj;
	struct device_context *dev_ctx = &g_vmbus_drv.device_ctx;

	DPRINT_ENTER(VMBUS_DRV);

	// Remove the root device
	if (vmbus_drv_obj->Base.OnDeviceRemove)
		vmbus_drv_obj->Base.OnDeviceRemove(&dev_ctx->device_obj);

	if (vmbus_drv_obj->Base.OnCleanup)
		vmbus_drv_obj->Base.OnCleanup(&vmbus_drv_obj->Base);

	// Unregister the root bus device
	// device_unregister(&dev_ctx->device);

	// bus_unregister(&vmbus_drv_ctx->bus);

	/* remove swi, bus and intr resource */
	bus_teardown_intr(g_vmbus_drv.vmb_dev, g_vmbus_drv.intr_res, vmbus_cookiep);

	bus_release_resource(g_vmbus_drv.vmb_dev, SYS_RES_IRQ, vmbus_rid,
			g_vmbus_drv.intr_res);

	swi_remove(vmbus_drv_ctx->msg_dpc);
	swi_remove(vmbus_drv_ctx->event_dpc);

	DPRINT_EXIT(VMBUS_DRV);

	return;
}

static void vmbus_exit(void) {
	DPRINT_ENTER(VMBUS_DRV);

	DPRINT_INFO(VMBUS_DRV, "Vmbus exit");
	vmbus_bus_exit();

	DPRINT_EXIT(VMBUS_DRV);

	return;
}

static void vmbus_mod_load(void) {
	printf("Vmbus load\n");
}

static void vmbus_mod_unload(void) {
	printf("Vmbus unload\n");
	//	vmbus_exit();
}

static int vmbus_modevent(module_t mod, int what, void *arg) {
	switch (what) {

	case MOD_LOAD:
		vmbus_mod_load();
		break;
	case MOD_UNLOAD:
		vmbus_mod_unload();
		break;
	}

	return (0);
}

static device_method_t vmbus_methods[] = {
		/* Device interface */DEVMETHOD(device_identify, vmbus_identify),
		DEVMETHOD(device_probe, vmbus_probe),
		DEVMETHOD(device_attach, vmbus_attach),
		DEVMETHOD(device_detach, vmbus_detach),
		DEVMETHOD(device_shutdown, bus_generic_shutdown),
		DEVMETHOD(device_suspend, bus_generic_suspend),
		DEVMETHOD(device_resume, bus_generic_resume),

		/* Bus interface */DEVMETHOD(bus_add_child, bus_generic_add_child),
		DEVMETHOD(bus_print_child, vmbus_print_child),
		DEVMETHOD(bus_read_ivar, vmbus_read_ivar),
		DEVMETHOD(bus_write_ivar, vmbus_write_ivar),

		{ 0, 0 } };

static char driver_name[] = "vmbus";
static driver_t vmbus_driver = { driver_name, vmbus_methods,
		sizeof(struct vmbus_softc), };

unsigned int vmbus_loglevel = (ALL_MODULES << 16 | INFO_LVL);
//unsigned int vmbus_loglevel = (ALL_MODULES << 16 | DEBUG_LVL);

devclass_t vmbus_devclass;

DRIVER_MODULE(vmbus, nexus, vmbus_driver, vmbus_devclass, vmbus_modevent, 0);
MODULE_VERSION(vmbus,1);

SYSINIT(vmb_init, SI_SUB_RUN_SCHEDULER, SI_ORDER_MIDDLE, vmbus_init, NULL);

