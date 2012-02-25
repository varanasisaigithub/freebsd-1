/*-
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
 * Copyright (c) 2010-2012, Citrix, Inc.
 *
 * Ported from lis21 code drop
 *
 * Implements low-level interactions with windows hypervisor
 *
 */

/*-
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

/*++

 File:
 Hv.c

 Description:
 Implements low-level interactions with windows hypervisor

 --*/

/* Fixme:  Added these includes to get memset, MAXCPU */
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/time.h>
#include <sys/pcpu.h>

#include <dev/hyperv/include/hv_osd.h>
#include <dev/hyperv/include/hv_logging.h>
#include "hv_support.h"
#include "hv_hv.h"
#include "hv_vmbus_var.h"
#include "hv_vmbus_api.h"
#include <dev/hyperv/include/hv_list.h>
#include "hv_ring_buffer.h"
#include <dev/hyperv/include/hv_vmbus_channel_interface.h>
#include <dev/hyperv/include/hv_vmbus_packet_format.h>
#include <dev/hyperv/include/hv_channel_messages.h>
#include "hv_channel_mgmt.h"
#include "hv_channel.h"
#include "hv_channel_interface.h"
#include "hv_vmbus_private.h"
#include <dev/hyperv/include/hv_config.h>

static inline void do_cpuid_inline(unsigned int op, unsigned int *eax,
	unsigned int *ebx, unsigned int *ecx, unsigned int *edx) {
	__asm__ __volatile__("cpuid" : "=a" (*eax), "=b" (*ebx), "=c" (*ecx),
			     "=d" (*edx) : "0" (op), "c" (ecx));
}

//
// Globals
//

// The one and only
HV_CONTEXT gHvContext = {
	.SynICInitialized = FALSE,
	.HypercallPage = NULL,
	.SignalEventParam = NULL,
	.SignalEventBuffer = NULL, };

/*++

 Name:
 HvQueryHypervisorPresence()

 Description:
 Query the cpuid for presense of windows hypervisor

 --*/
int
HvQueryHypervisorPresence(void) {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int op;

	eax = 0;
	ebx = 0;
	ecx = 0;
	edx = 0;
	op = HvCpuIdFunctionVersionAndFeatures;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	return (ecx & HV_PRESENT_BIT);
}

/*++

 Name:
 HvQueryHypervisorInfo()

 Description:
 Get version info of the windows hypervisor

 --*/
static int
HvQueryHypervisorInfo(void) {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int maxLeaf;
	unsigned int op;

	//
	// Its assumed that this is called after confirming that Viridian is present.
	// Query id and revision.
	//

	eax = 0;
	ebx = 0;
	ecx = 0;
	edx = 0;
	op = HvCpuIdFunctionHvVendorAndMaxFunction;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	DPRINT_INFO(
		VMBUS,
		"Vendor ID: %c%c%c%c%c%c%c%c%c%c%c%c",
		(ebx & 0xFF), ((ebx >> 8) & 0xFF), ((ebx >> 16) & 0xFF), ((ebx >> 24) & 0xFF), (ecx & 0xFF), ((ecx >> 8) & 0xFF), ((ecx >> 16) & 0xFF), ((ecx >> 24) & 0xFF), (edx & 0xFF), ((edx >> 8) & 0xFF), ((edx >> 16) & 0xFF), ((edx >> 24) & 0xFF));

	maxLeaf = eax;
	eax = 0;
	ebx = 0;
	ecx = 0;
	edx = 0;
	op = HvCpuIdFunctionHvInterface;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	DPRINT_INFO(
		VMBUS,
		"Interface ID: %c%c%c%c",
		(eax & 0xFF), ((eax >> 8) & 0xFF), ((eax >> 16) & 0xFF), ((eax >> 24) & 0xFF));

	if (maxLeaf >= HvCpuIdFunctionMsHvVersion) {
		eax = 0;
		ebx = 0;
		ecx = 0;
		edx = 0;
		op = HvCpuIdFunctionMsHvVersion;
		do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);
		DPRINT_INFO(
			VMBUS,
			"OS Build:%d-%d.%d-%d-%d.%d",
			eax, ebx >> 16, ebx & 0xFFFF, ecx, edx >> 24, edx & 0xFFFFFF);
	}
	return maxLeaf;
}

/*++

 Name:
 HvDoHypercall()

 Description:
 Invoke the specified hypercall

 --*/
static uint64_t
HvDoHypercall(uint64_t Control, void* Input, void* Output) {
#ifdef __x86_64__
	uint64_t hvStatus = 0;
	uint64_t inputAddress = (Input) ? GetPhysicalAddress(Input) : 0;
	uint64_t outputAddress = (Output) ? GetPhysicalAddress(Output) : 0;
	volatile void* hypercallPage = gHvContext.HypercallPage;

	DPRINT_DBG(
		VMBUS,
		"Hypercall <control %lx input phys %lx virt %p output phys %lx virt %p hypercall %p>",
		Control, inputAddress, Input, outputAddress, Output, hypercallPage);

	__asm__ __volatile__ ("mov %0, %%r8" : : "r" (outputAddress): "r8");
	__asm__ __volatile__ ("call *%3" : "=a"(hvStatus): "c" (Control), "d" (inputAddress), "m" (hypercallPage));

	DPRINT_DBG(VMBUS, "Hypercall <return %lx>", hvStatus);

	return hvStatus;

#else

	uint32_t controlHi = Control >> 32;
	uint32_t controlLo = Control & 0xFFFFFFFF;
	uint32_t hvStatusHi = 1;
	uint32_t hvStatusLo = 1;
	uint64_t inputAddress = (Input) ? GetPhysicalAddress(Input) : 0;
	uint32_t inputAddressHi = inputAddress >> 32;
	uint32_t inputAddressLo = inputAddress & 0xFFFFFFFF;
	uint64_t outputAddress = (Output) ?GetPhysicalAddress(Output) : 0;
	uint32_t outputAddressHi = outputAddress >> 32;
	uint32_t outputAddressLo = outputAddress & 0xFFFFFFFF;
	volatile void* hypercallPage = gHvContext.HypercallPage;

	DPRINT_DBG(VMBUS, "Hypercall <control %lx input %p output %p>",
		Control,
		Input,
		Output);

	__asm__ __volatile__ ("call *%8" : "=d"(hvStatusHi), "=a"(hvStatusLo) : "d" (controlHi), "a" (controlLo), "b" (inputAddressHi), "c" (inputAddressLo), "D"(outputAddressHi), "S"(outputAddressLo), "m" (hypercallPage));

	DPRINT_DBG(VMBUS, "Hypercall <return %lx>", hvStatusLo | ((uint64_t)hvStatusHi << 32));

	return (hvStatusLo | ((uint64_t)hvStatusHi << 32));
#endif // __x86_64__
}

/*++

 Name:
 HvInit()

 Description:
 Main initialization routine. This routine must be called
 before any other routines in here are called

 --*/

int
HvInit(void) {
	int ret = 0;
	int maxLeaf;
	HV_X64_MSR_HYPERCALL_CONTENTS hypercallMsr;
	void* virtAddr = 0;

	DPRINT_ENTER(VMBUS);

	memset(gHvContext.synICEventPage, 0, sizeof(HANDLE) * MAX_NUM_CPUS);
	memset(gHvContext.synICMessagePage, 0, sizeof(HANDLE) * MAX_NUM_CPUS);

	if (!HvQueryHypervisorPresence()) {
		DPRINT_ERR(VMBUS, "No Windows hypervisor detected!!");
		goto Cleanup;
	}

	DPRINT_INFO(VMBUS,
		"Windows hypervisor detected! Retrieving more info...");

	maxLeaf = HvQueryHypervisorInfo();
	//HvQueryHypervisorFeatures(maxLeaf);

	// Determine if we are running on xenlinux (ie x2v shim) or native linux
	gHvContext.GuestId = ReadMsr(HV_X64_MSR_GUEST_OS_ID);

	if (gHvContext.GuestId == 0) {
		DPRINT_INFO(VMBUS, "Setting Guest OS Id to HV_LINUX_GUEST_ID");
		// Write our OS info
		WriteMsr(HV_X64_MSR_GUEST_OS_ID, HV_LINUX_GUEST_ID);

		gHvContext.GuestId = HV_LINUX_GUEST_ID;
	}

	// See if the hypercall page is already set
	hypercallMsr.as_uint64_t = ReadMsr(HV_X64_MSR_HYPERCALL);

	if (gHvContext.GuestId == HV_LINUX_GUEST_ID) {
		DPRINT_INFO(VMBUS, "Guest OS Id is HV_LINUX_GUEST_ID");
		// Allocate the hypercall page memory
		//virtAddr = hv_page_contigmalloc(1);
		virtAddr = VirtualAllocExec(PAGE_SIZE);

		if (!virtAddr) {
			DPRINT_ERR(VMBUS,
				"unable to allocate hypercall page!!");
			goto Cleanup;
		}

		hypercallMsr.Enable = 1;
		//hypercallMsr.GuestPhysicalAddress = Logical2PhysicalAddr(virtAddr) >> PAGE_SHIFT;
		hypercallMsr.GuestPhysicalAddress = Virtual2Physical(
			virtAddr) >> PAGE_SHIFT;
		WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);

		// Confirm that hypercall page did get set up.
		hypercallMsr.as_uint64_t = 0;
		hypercallMsr.as_uint64_t = ReadMsr(HV_X64_MSR_HYPERCALL);

		if (!hypercallMsr.Enable) {
			DPRINT_ERR(VMBUS, "unable to set hypercall page!!");
			goto Cleanup;
		}

		gHvContext.HypercallPage = virtAddr;
	} else {
		DPRINT_ERR(VMBUS, "Unknown guest id (0x%lx)!!",
			gHvContext.GuestId);
		goto Cleanup;
	}

	DPRINT_INFO(
		VMBUS,
		"Hypercall page VA=%p, PA=0x%0lx",
		gHvContext.HypercallPage, (unsigned long)hypercallMsr.GuestPhysicalAddress << PAGE_SHIFT);

	// Setup the global signal event param for the signal event hypercall
	gHvContext.SignalEventBuffer =
		malloc(sizeof(HV_INPUT_SIGNAL_EVENT_BUFFER), M_DEVBUF, M_NOWAIT);

	if (!gHvContext.SignalEventBuffer) {
		goto Cleanup;
	}

	gHvContext.SignalEventParam =
		(PHV_INPUT_SIGNAL_EVENT) (ALIGN_UP((unsigned long)gHvContext.SignalEventBuffer, HV_HYPERCALL_PARAM_ALIGN));
	gHvContext.SignalEventParam->ConnectionId.Asuint32_t = 0;
	gHvContext.SignalEventParam->ConnectionId.u.Id =
		VMBUS_EVENT_CONNECTION_ID;
	gHvContext.SignalEventParam->FlagNumber = 0;
	gHvContext.SignalEventParam->RsvdZ = 0;

	//DPRINT_DBG(VMBUS, "My id %lu", HvGetCurrentPartitionId());

	DPRINT_EXIT(VMBUS);

	return ret;

	Cleanup: if (virtAddr) {
		if (hypercallMsr.Enable) {
			hypercallMsr.as_uint64_t = 0;
			WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);
		}

		VirtualFree(virtAddr);
	}
	ret = -1;
	DPRINT_EXIT(VMBUS);

	return ret;
}

/*++

 Name:
 HvCleanup()

 Description:
 Cleanup routine. This routine is called normally during driver unloading or exiting.

 --*/
void
HvCleanup(void) {
	HV_X64_MSR_HYPERCALL_CONTENTS hypercallMsr;

	DPRINT_ENTER(VMBUS);

	if (gHvContext.SignalEventBuffer) {
		free(gHvContext.SignalEventBuffer, M_DEVBUF);
		gHvContext.SignalEventBuffer = NULL;
		gHvContext.SignalEventParam = NULL;
	}

	if (gHvContext.GuestId == HV_LINUX_GUEST_ID) {
		if (gHvContext.HypercallPage) {
			hypercallMsr.as_uint64_t = 0;
			WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);
			VirtualFree(gHvContext.HypercallPage);
			gHvContext.HypercallPage = NULL;
		}
	}

	DPRINT_EXIT(VMBUS);

}

/*++

 Name:
 HvPostMessage()

 Description:
 Post a message using the hypervisor message IPC. This
 involves a hypercall.

 --*/
HV_STATUS
HvPostMessage(HV_CONNECTION_ID	connectionId,
	      HV_MESSAGE_TYPE	messageType,
	      void		*payload,
	      size_t		payloadSize) {
	struct alignedInput {
		uint64_t alignment8;
		HV_INPUT_POST_MESSAGE msg;
	};

	PHV_INPUT_POST_MESSAGE alignedMsg;
	HV_STATUS status;
	size_t addr;

	if (payloadSize > HV_MESSAGE_PAYLOAD_BYTE_COUNT) {
		return -1;
	}

	addr = (size_t)malloc(sizeof(struct alignedInput), M_DEVBUF, M_NOWAIT);
	if (!addr) {
		return -1;
	}

	alignedMsg = (PHV_INPUT_POST_MESSAGE)
					(ALIGN_UP(addr, HV_HYPERCALL_PARAM_ALIGN));

	alignedMsg->ConnectionId = connectionId;
	alignedMsg->MessageType = messageType;
	alignedMsg->PayloadSize = payloadSize;
	memcpy((void*)alignedMsg->Payload, payload, payloadSize);

//	if (((unsigned int)alignedMsg & ~0x0fff) != ((unsigned int)((char *)alignedMsg+sizeof(HV_INPUT_POST_MESSAGE)-1) & ~0xfff)) {
//		printf("alignedMsg: %p, %p\n", alignedMsg, &alignedMsg[1]);
//	}
	status = HvDoHypercall(HvCallPostMessage, alignedMsg, 0) & 0xFFFF;

	free((void *) addr, M_DEVBUF);
	return status;
}

/*++

 Name:
 HvSignalEvent()

 Description:
 Signal an event on the specified connection using the hypervisor event IPC. This
 involves a hypercall.

 --*/
HV_STATUS
HvSignalEvent() {
	HV_STATUS status;

	status = HvDoHypercall(HvCallSignalEvent, gHvContext.SignalEventParam,
		0) & 0xFFFF;

	return status;
}

/*++

 Name:
 HvSynicInit()

 Description:
 Initialize the Synthethic Interrupt Controller. If it is already initialized by
 another entity (ie x2v shim), we need to retrieve the initialized message and event pages.
 Otherwise, we create and initialize the message and event pages.

 --*/
/* Fixme:  Added for NetScaler, then FreeBSD port */
#ifdef DPRINT_DBG
#undef DPRINT_DBG
#define DPRINT_DBG(...)
#endif
#ifdef DPRINT_ENTER
#undef DPRINT_ENTER
#define DPRINT_ENTER(mod)
#endif
#ifdef DPRINT_EXIT
#undef DPRINT_EXIT
#define DPRINT_EXIT(mod)
#endif

void
HvSynicInit(void *irqArg) {
	uint64_t version;
	HV_SYNIC_SIMP simp;
	HV_SYNIC_SIEFP siefp;
	HV_SYNIC_SINT sharedSint;
#ifdef REMOVED
	/* Fixme:  Removed to mitigate warning */
	HV_SYNIC_SINT sharedSint1;
#endif
	HV_SYNIC_SCONTROL sctrl;
#ifdef REMOVED
	/* Fixme:  Removed to mitigate warning */
	uint64_t guestID;
#endif
	uint32_t irqVector = *((uint32_t *) (irqArg));
	int cpu = PCPU_GET(cpuid);

	DPRINT_ENTER(VMBUS);

	if (!gHvContext.HypercallPage) {
		DPRINT_EXIT(VMBUS);
		return;
	}

	if (cpu != 0) {
		DPRINT_EXIT(VMBUS);
		return;
	}

	// Check the version
	version = ReadMsr(HV_X64_MSR_SVERSION);

//	DPRINT_INFO(VMBUS, "SynIC version: %llx", version);

	{
//		DPRINT_INFO(VMBUS, "set up SIMP and SIEFP.");

		/*
		 * Fixme:  lis21 code allocates the following here.  In
		 * our code, the caller of this function allocates these
		 * before the call.
		 */

#ifdef REMOVED
		gHvContext.synICMessagePage[cpu] = PageAllocAtomic();
		if (gHvContext.synICMessagePage[cpu] == NULL)
		{
			DPRINT_ERR(VMBUS, "unable to allocate SYNIC message page!!");
			goto Cleanup;
		}

		gHvContext.synICEventPage[cpu] = PageAllocAtomic();
		if (gHvContext.synICEventPage[cpu] == NULL)
		{
			DPRINT_ERR(VMBUS, "unable to allocate SYNIC event page!!");
			goto Cleanup;
		}
#endif

		//
		// Setup the Synic's message page
		//
		simp.as_uint64_t = ReadMsr(HV_X64_MSR_SIMP);
		simp.SimpEnabled = 1;
		simp.BaseSimpGpa = GetPhysicalAddress(
			gHvContext.synICMessagePage[cpu]) >> PAGE_SHIFT;

		DPRINT_DBG(VMBUS, "HV_X64_MSR_SIMP msr set to: %lx",
			simp.as_uint64_t);

		WriteMsr(HV_X64_MSR_SIMP, simp.as_uint64_t);

		//
		// Setup the Synic's event page
		//
		siefp.as_uint64_t = ReadMsr(HV_X64_MSR_SIEFP);
		siefp.SiefpEnabled = 1;
		siefp.BaseSiefpGpa = GetPhysicalAddress(
			gHvContext.synICEventPage[cpu]) >> PAGE_SHIFT;

		DPRINT_DBG(VMBUS, "HV_X64_MSR_SIEFP msr set to: %lx",
			siefp.as_uint64_t);

		WriteMsr(HV_X64_MSR_SIEFP, siefp.as_uint64_t);
	}
	//
	// Set up the interception SINT.
	//
	//WriteMsr((HV_X64_MSR_SINT0 + HV_SYNIC_INTERCEPTION_SINT_INDEX),
	//             interceptionSint.as_uint64_t);

	//
	// Set up the shared SINT.
	// 
//	DPRINT_INFO(VMBUS, "setup shared SINT.");
	sharedSint.as_uint64_t = ReadMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);

	sharedSint.as_uint64_t = 0;
	sharedSint.Vector = irqVector; //HV_SHARED_SINT_IDT_VECTOR + 0x20;
	sharedSint.Masked = FALSE;
	sharedSint.AutoEoi = FALSE;

	DPRINT_DBG(VMBUS, "HV_X64_MSR_SINT1 msr set to: %lx", sharedSint.as_uint64_t);

	WriteMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sharedSint.as_uint64_t);

	// Enable the global synic bit
	sctrl.as_uint64_t = ReadMsr(HV_X64_MSR_SCONTROL);
	sctrl.Enable = 1;

	WriteMsr(HV_X64_MSR_SCONTROL, sctrl.as_uint64_t);

	gHvContext.SynICInitialized = TRUE;

//	sharedSint1.as_uint64_t = ReadMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);
//	printf("HV: Vec: %x, Masked: %x, EOI: %x\n",
//	    sharedSint1.Vector, sharedSint1.Masked, sharedSint1.AutoEoi);

	DPRINT_EXIT(VMBUS);

	return;

#ifdef REMOVED
	/* Fixme:  Removed to mitigate warning */
	Cleanup:
#endif
	DPRINT_EXIT(VMBUS);

	return;
}

/*++

 Name:
 HvSynicCleanup()

 Description:
 Cleanup routine for HvSynicInit().

 --*/
void HvSynicCleanup(void *arg) {
	HV_SYNIC_SINT sharedSint;
	HV_SYNIC_SIMP simp;
	HV_SYNIC_SIEFP siefp;
	int cpu = PCPU_GET(cpuid);

	DPRINT_ENTER(VMBUS);

	if (!gHvContext.SynICInitialized) {
		DPRINT_EXIT(VMBUS);
		return;
	}

	if (cpu != 0) {
		DPRINT_EXIT(VMBUS);
		return;
	}

	sharedSint.as_uint64_t = ReadMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);

	sharedSint.Masked = 1;

	//KYS: Need to correctly cleanup in the case of SMP!!!
	// Disable the interrupt
	WriteMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sharedSint.as_uint64_t);

	// Disable and free the resources only if we are running as native linux
	// since in xenlinux, we are sharing the resources with the x2v shim
	if (gHvContext.GuestId == HV_LINUX_GUEST_ID) {
		simp.as_uint64_t = ReadMsr(HV_X64_MSR_SIMP);
		simp.SimpEnabled = 0;
		simp.BaseSimpGpa = 0;

		WriteMsr(HV_X64_MSR_SIMP, simp.as_uint64_t);

		siefp.as_uint64_t = ReadMsr(HV_X64_MSR_SIEFP);
		siefp.SiefpEnabled = 0;
		siefp.BaseSiefpGpa = 0;

		WriteMsr(HV_X64_MSR_SIEFP, siefp.as_uint64_t);

		hv_page_contigfree(gHvContext.synICMessagePage[cpu], 1);
		hv_page_contigfree(gHvContext.synICEventPage[cpu], 1);
	}

	DPRINT_EXIT(VMBUS);
}

