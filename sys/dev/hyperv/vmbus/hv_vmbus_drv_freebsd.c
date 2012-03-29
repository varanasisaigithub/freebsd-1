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
#include <sys/mutex.h>
#include <sys/smp.h>

#include <machine/resource.h>
#include <sys/rman.h>

#include <machine/stdarg.h>
#include <machine/intr_machdep.h>
#include <sys/pcpu.h>

#include "../include/hyperv.h"
#include "vmbus_priv.h"


#define VMBUS_IRQ				0x5

static struct intr_event *hv_message_intr_event;
static struct intr_event *hv_event_intr_event;
static void *msg_dpc;
static void *event_dpc;
static device_t vmbus_devp;
static void *vmbus_cookiep;
static int vmbus_rid;
struct resource *intr_res;
static int vmbus_irq = VMBUS_IRQ;
static int vmbus_inited;


/*++

 Name:
 vmbus_msg_dpc()

 Description:
 DPC routine to handle messages from the hypervisior

 --*/

static void vmbus_msg_dpc(void *arg)
{
	int cpu;
	void *page_addr;
	HV_MESSAGE *msg;
	HV_MESSAGE *copied;

	cpu = PCPU_GET(cpuid);
	page_addr = gHvContext.synICMessagePage[cpu];
	msg = (HV_MESSAGE*) page_addr + VMBUS_MESSAGE_SINT;
	while (1) {
		if (msg->Header.MessageType == HvMessageTypeNone) // no msg
			{
			break;
		} else {
			copied = malloc(sizeof(HV_MESSAGE), M_DEVBUF, M_NOWAIT);
			if (copied == NULL) {
				continue;
			}

			memcpy(copied, msg, sizeof(HV_MESSAGE));
			queue_work_item(gVmbusConnection.WorkQueue,
				VmbusOnChannelMessage, copied);
		}

		msg->Header.MessageType = HvMessageTypeNone;

		// Make sure the write to MessageType (ie set to HvMessageTypeNone) happens
		// before we read the MessagePending and EOMing. Otherwise, the EOMing will not deliver
		// any more messages since there is no empty slot
		wmb();

		if (msg->Header.MessageFlags.MessagePending) {
			// This will cause message queue rescan to possibly deliver another msg from the hypervisor
			WriteMsr(HV_X64_MSR_EOM, 0);
		}
	}
}

static int hv_vmbus_isr(void *unused) 
{
	int cpu;
	void *page_addr;
	HV_MESSAGE* msg;
	HV_SYNIC_EVENT_FLAGS* event;

	cpu = PCPU_GET(cpuid);

	/*
	 * Check for events before checking for messages. This is the order
	 * in which events and messages are checked in Windows guests on Hyper-V
	 * and the Windows team suggested we do the same here.
	 */

	page_addr = gHvContext.synICEventPage[cpu];
	event = (HV_SYNIC_EVENT_FLAGS*) page_addr + VMBUS_MESSAGE_SINT;

	// Since we are a child, we only need to check bit 0
	if (synch_test_and_clear_bit(0, &event->Flags32[0]))
		swi_sched(event_dpc, 0);

	// Check if there are actual msgs to be process
	page_addr = gHvContext.synICMessagePage[cpu];
	msg = (HV_MESSAGE*) page_addr + VMBUS_MESSAGE_SINT;

	if (msg->Header.MessageType != HvMessageTypeNone)
		swi_sched(msg_dpc, 0);

	return 0x2; //KYS
}

static int vmbus_read_ivar(device_t dev, device_t child, int index,
	uintptr_t *result) {
	struct hv_device *child_dev_ctx = device_get_ivars(child);

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

struct hv_device *vmbus_child_device_create(GUID type,
						GUID instance,
						VMBUS_CHANNEL *channel ) 
{
	struct hv_device *child_dev;

	// Allocate the new child device
	child_dev = malloc(sizeof(struct hv_device), M_DEVBUF,
			M_NOWAIT |  M_ZERO);
	if (!child_dev) 
		return NULL;

	child_dev->channel = channel;
	memcpy(&child_dev->class_id, &type, sizeof(GUID));
	memcpy(&child_dev->device_id, &instance, sizeof(GUID));

	return child_dev;
}

static void print_dev_guid(struct hv_device *hv_dev)
{
        int i;
	unsigned char guid_name[100];
        for (i = 0; i < 32; i += 2)
                sprintf(&guid_name[i], "%02x", hv_dev->class_id.Data[i/2]);
	printf("Class ID: %s\n", guid_name);
}


int vmbus_child_device_register(struct hv_device *child_dev)
{
	device_t child;
	int ret = 0;

	print_dev_guid(child_dev);


	child = device_add_child(vmbus_devp, NULL, -1);
	child_dev->device = child;
	device_set_ivars(child, child_dev);

	mtx_lock(&Giant);
	ret = device_probe_and_attach(child);
	mtx_unlock(&Giant);

	return 0;
}

int vmbus_child_device_unregister(struct hv_device *child_dev)
{
	/*
	 * XXXKYS: Ensure that this is the opposite of
	 * device_add_child()
	 */
	return(device_delete_child(vmbus_devp, child_dev->device));
}

static int vmbus_print_child(device_t dev, device_t child) {
	int retval = 0;

	retval += bus_print_child_header(dev, child);
	retval += bus_print_child_footer(dev, child);

	return (retval);
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

static int vmbus_bus_init(void) 
{
	int ret;
	unsigned int vector = 0;
	struct intsrc *isrc;

	if (vmbus_inited)
		return 0;

	vmbus_inited = 1;

	ret = HvInit();

	if (ret) {
		printf("Hypervisor Initialization Failed\n");
		return ret;
	}

	ret = swi_add(&hv_message_intr_event, "hv_msg", vmbus_msg_dpc,
		NULL, SWI_CLOCK, 0, &msg_dpc);

	if (ret)
		goto cleanup;

	ret = intr_event_bind(hv_message_intr_event, 0);

	if (ret)
		goto cleanup1;

	ret = swi_add(&hv_event_intr_event, "hv_event", vmbus_on_events,
		NULL, SWI_CLOCK, 0, &event_dpc);

	if (ret)
		goto cleanup1;

	ret = intr_event_bind(hv_event_intr_event, 0);

	if (ret)
		goto cleanup2;

	intr_res = bus_alloc_resource(vmbus_devp,
		SYS_RES_IRQ, &vmbus_rid, vmbus_irq, vmbus_irq, 1, RF_ACTIVE);

	if (intr_res == NULL) {
		ret = -ENOMEM; /* XXXKYS: Need a better errno */
		goto cleanup2;
	}

	/*
	 * Fixme:  Changed for port to FreeBSD 8.2.  Make sure this works.
	 */
	ret = bus_setup_intr(vmbus_devp, intr_res,
		INTR_TYPE_NET | INTR_FAST, hv_vmbus_isr,
#if __FreeBSD_version >= 700000
		NULL,
#endif
		NULL, &vmbus_cookiep);

	if (ret != 0)
		goto cleanup3;

	ret = bus_bind_intr(vmbus_devp, intr_res, 0);
	if (ret != 0) 
		goto cleanup4;

	isrc = intr_lookup_source(vmbus_irq);
	if ((isrc == NULL) || (isrc->is_event == NULL)) {
		ret = -EINVAL;
		goto cleanup4;
	}

	vector = isrc->is_event->ie_vector;
	printf("VMBUS: irq 0x%x vector 0x%x\n", vmbus_irq, vector);

	/*
	 * Notify the hypervisor of our irq.
	 */

	smp_rendezvous(NULL, HvSynicInit, NULL, &vector);

	// Connect to VMBus in the root partition
	ret = VmbusConnect();

	if (ret)
		goto cleanup4;

	VmbusChannelRequestOffers();
	return ret;

cleanup4:

	/* remove swi, bus and intr resource */
	bus_teardown_intr(vmbus_devp, intr_res,
		vmbus_cookiep);

cleanup3:

	bus_release_resource(vmbus_devp, SYS_RES_IRQ,
		vmbus_rid, intr_res);

cleanup2: 
	swi_remove(event_dpc);

cleanup1:
	swi_remove(msg_dpc);

cleanup:
	HvCleanup();

	return ret;
}

static int vmbus_attach(device_t dev) {
	printf("vmbus_attach: dev: %p\n", dev);
	vmbus_devp = dev;

	/* 
	 * If the system has already booted and thread
	 * scheduling is possible indicated by the global
	 * cold set to zero, we just call the driver
	 * initialization directly.
	 *
	 * XXXKYS: Need to cleanup this initialization!!
	 * What comes first: attach or SYSINIT call
	 * How does this playout when vmbus is a module.
	 */

	if (!cold) {
		vmbus_bus_init();
	}

	return 0;
}

static void vmbus_init(void) 
{
	/* 
	 * If the system has already booted and thread
	 * scheduling is possible indicated by the global
	 * cold set to zero, we just call the driver
	 * initialization directly.
	 *
	 * XXXKYS: Need to cleanup this initialization!!
	 */
	if (!cold) {
		vmbus_bus_init();
	}
}

static void vmbus_bus_exit(void) 
{

	VmbusChannelReleaseUnattachedChannels();
	VmbusDisconnect();

	smp_rendezvous(NULL, HvSynicCleanup, NULL, NULL);

	HvCleanup();

	/* remove swi, bus and intr resource */
	bus_teardown_intr(vmbus_devp, intr_res, vmbus_cookiep);

	bus_release_resource(vmbus_devp, SYS_RES_IRQ, vmbus_rid, intr_res);

	swi_remove(msg_dpc);
	swi_remove(event_dpc);

	return;
}

static void vmbus_exit(void) 
{
	vmbus_bus_exit();

}

static int vmbus_detach(device_t dev) 
{
	vmbus_exit();
	return 0;
}

static void vmbus_mod_load(void) 
{
	printf("Vmbus load\n");
	vmbus_init();
}

static void vmbus_mod_unload(void) 
{
	printf("Vmbus unload\n");
	vmbus_exit();
}

static int vmbus_modevent(module_t mod, int what, void *arg) 
{
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
	0, };


devclass_t vmbus_devclass;

DRIVER_MODULE(vmbus, nexus, vmbus_driver, vmbus_devclass, vmbus_modevent, 0);
MODULE_VERSION(vmbus,1);

// TODO: We want to be earlier than SI_SUB_VFS
SYSINIT(vmb_init, SI_SUB_VFS, SI_ORDER_MIDDLE, vmbus_init, NULL);

