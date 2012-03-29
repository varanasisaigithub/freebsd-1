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
 *   K. Y. Srinivasan <kys@microsoft.com>
 */

/*++

 File:
 Hv.c

 Description:
 Implements low-level interactions with windows hypervisor

 --*/

/* Fixme:  Added these includes to get memset, MAXCPU */

#include <sys/types.h>
#include <machine/bus.h>
#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/pcpu.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include "../include/hyperv.h"
#include "vmbus_priv.h"

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
	.SynICInitialized = false,
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
HvQueryHypervisorPresence(void) 
{
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
HvQueryHypervisorInfo(void) 
{
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

	maxLeaf = eax;
	eax = 0;
	ebx = 0;
	ecx = 0;
	edx = 0;
	op = HvCpuIdFunctionHvInterface;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	if (maxLeaf >= HvCpuIdFunctionMsHvVersion) {
		eax = 0;
		ebx = 0;
		ecx = 0;
		edx = 0;
		op = HvCpuIdFunctionMsHvVersion;
		do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);
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
HvDoHypercall(uint64_t Control, void* Input, void* Output) 
{
#ifdef __x86_64__
	uint64_t hvStatus = 0;
	uint64_t inputAddress = (Input) ? get_phys_addr(Input) : 0;
	uint64_t outputAddress = (Output) ? get_phys_addr(Output) : 0;
	volatile void* hypercallPage = gHvContext.HypercallPage;

	__asm__ __volatile__ ("mov %0, %%r8" : : "r" (outputAddress): "r8");
	__asm__ __volatile__ ("call *%3" : "=a"(hvStatus):
				"c" (Control), "d" (inputAddress),
				"m" (hypercallPage));

	return hvStatus;

#else

	uint32_t controlHi = Control >> 32;
	uint32_t controlLo = Control & 0xFFFFFFFF;
	uint32_t hvStatusHi = 1;
	uint32_t hvStatusLo = 1;
	uint64_t inputAddress = (Input) ? get_phys_addr(Input) : 0;
	uint32_t inputAddressHi = inputAddress >> 32;
	uint32_t inputAddressLo = inputAddress & 0xFFFFFFFF;
	uint64_t outputAddress = (Output) ? get_phys_addr(Output) : 0;
	uint32_t outputAddressHi = outputAddress >> 32;
	uint32_t outputAddressLo = outputAddress & 0xFFFFFFFF;
	volatile void* hypercallPage = gHvContext.HypercallPage;

	__asm__ __volatile__ ("call *%8" : "=d"(hvStatusHi),
				"=a"(hvStatusLo) : "d" (controlHi),
				"a" (controlLo), "b" (inputAddressHi),
				"c" (inputAddressLo), "D"(outputAddressHi),
				"S"(outputAddressLo), "m" (hypercallPage));


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
HvInit(void) 
{
	int maxLeaf;
	HV_X64_MSR_HYPERCALL_CONTENTS hypercallMsr;
	void* virtAddr = 0;

	memset(gHvContext.synICEventPage, 0, sizeof(HANDLE) * MAXCPU);
	memset(gHvContext.synICMessagePage, 0, sizeof(HANDLE) * MAXCPU);

	if (!HvQueryHypervisorPresence())
		goto Cleanup;

	maxLeaf = HvQueryHypervisorInfo();

	// Write our OS info
	WriteMsr(HV_X64_MSR_GUEST_OS_ID, HV_LINUX_GUEST_ID);
	gHvContext.GuestId = HV_LINUX_GUEST_ID;

	// See if the hypercall page is already set
	hypercallMsr.Asuint64_t = ReadMsr(HV_X64_MSR_HYPERCALL);
	virtAddr = malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);

	if (!virtAddr)
		goto Cleanup;

	hypercallMsr.Enable = 1;
	hypercallMsr.GuestPhysicalAddress =
		(get_phys_addr(virtAddr) >> PAGE_SHIFT);
	WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.Asuint64_t);

	// Confirm that hypercall page did get set up.
	hypercallMsr.Asuint64_t = 0;
	hypercallMsr.Asuint64_t = ReadMsr(HV_X64_MSR_HYPERCALL);

	if (!hypercallMsr.Enable)
		goto Cleanup;

	gHvContext.HypercallPage = virtAddr;

	// Setup the global signal event param for the signal event hypercall
	gHvContext.SignalEventBuffer =
		malloc(sizeof(HV_INPUT_SIGNAL_EVENT_BUFFER), M_DEVBUF,
			M_ZERO | M_NOWAIT);

	if (!gHvContext.SignalEventBuffer) {
		goto Cleanup;
	}

	gHvContext.SignalEventParam =
		(PHV_INPUT_SIGNAL_EVENT)
		 (ALIGN_UP((unsigned long)
			gHvContext.SignalEventBuffer,
			 HV_HYPERCALL_PARAM_ALIGN));
	gHvContext.SignalEventParam->ConnectionId.Asuint32_t = 0;
	gHvContext.SignalEventParam->ConnectionId.u.Id =
		VMBUS_EVENT_CONNECTION_ID;
	gHvContext.SignalEventParam->FlagNumber = 0;
	gHvContext.SignalEventParam->RsvdZ = 0;


	return 0;

Cleanup: 
	if (virtAddr) {
		if (hypercallMsr.Enable) {
			hypercallMsr.Asuint64_t = 0;
			WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.Asuint64_t);
		}

		free(virtAddr, M_DEVBUF);
	}
	return -ENOTSUP;
}

/*++

 Name:
 HvCleanup()

 Description:
 Cleanup routine. This routine is called normally during driver unloading or exiting.

 --*/
void
HvCleanup(void) 
{
	HV_X64_MSR_HYPERCALL_CONTENTS hypercallMsr;


	if (gHvContext.SignalEventBuffer) {
		free(gHvContext.SignalEventBuffer, M_DEVBUF);
		gHvContext.SignalEventBuffer = NULL;
		gHvContext.SignalEventParam = NULL;
	}

	if (gHvContext.GuestId == HV_LINUX_GUEST_ID) {
		if (gHvContext.HypercallPage) {
			hypercallMsr.Asuint64_t = 0;
			WriteMsr(HV_X64_MSR_HYPERCALL, hypercallMsr.Asuint64_t);
			free(gHvContext.HypercallPage, M_DEVBUF);
			gHvContext.HypercallPage = NULL;
		}
	}
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
	      size_t		payloadSize) 
{
	struct alignedInput {
		uint64_t alignment8;
		HV_INPUT_POST_MESSAGE msg;
	};

	PHV_INPUT_POST_MESSAGE alignedMsg;
	HV_STATUS status;
	size_t addr;

	if (payloadSize > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
		return -EMSGSIZE;

	addr = (size_t)malloc(sizeof(struct alignedInput), M_DEVBUF,
			M_ZERO | M_NOWAIT);
	if (!addr)
		return -ENOMEM;

	alignedMsg = (PHV_INPUT_POST_MESSAGE)
			(ALIGN_UP(addr, HV_HYPERCALL_PARAM_ALIGN));

	alignedMsg->ConnectionId = connectionId;
	alignedMsg->MessageType = messageType;
	alignedMsg->PayloadSize = payloadSize;
	memcpy((void*)alignedMsg->Payload, payload, payloadSize);

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
HvSignalEvent()
{
	HV_STATUS status;

	status = HvDoHypercall(HvCallSignalEvent, gHvContext.SignalEventParam,
		0) & 0xFFFF;

	return status;
}

/*++

 Name:
 HvSynicInit()

 --*/

void
HvSynicInit(void *irqArg) 
{
	uint64_t version;
	HV_SYNIC_SIMP simp;
	HV_SYNIC_SIEFP siefp;
	HV_SYNIC_SINT sharedSint;
	HV_SYNIC_SCONTROL sctrl;

	uint32_t irqVector = *((uint32_t *) (irqArg));
	int cpu = PCPU_GET(cpuid);

	if (!gHvContext.HypercallPage)
		return;

	/*
	 * KYS: Looks like we can only initialize on cpu0; don't we support
	 * SMP guests?
	 */

	if (cpu != 0)
		return;

	// Check the version
	version = ReadMsr(HV_X64_MSR_SVERSION);

	gHvContext.synICMessagePage[cpu] =
		malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (gHvContext.synICMessagePage[cpu] == NULL)
		goto cleanup;

	gHvContext.synICEventPage[cpu] = 
		malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (gHvContext.synICEventPage[cpu] == NULL)
		goto cleanup;

	//
	// Setup the Synic's message page
	//

	simp.Asuint64_t = ReadMsr(HV_X64_MSR_SIMP);
	simp.SimpEnabled = 1;
	simp.BaseSimpGpa = ((get_phys_addr(
			gHvContext.synICMessagePage[cpu])) >> PAGE_SHIFT);

	WriteMsr(HV_X64_MSR_SIMP, simp.Asuint64_t);

	//
	// Setup the Synic's event page
	//
	siefp.Asuint64_t = ReadMsr(HV_X64_MSR_SIEFP);
	siefp.SiefpEnabled = 1;
	siefp.BaseSiefpGpa = ((get_phys_addr(
			gHvContext.synICEventPage[cpu])) >> PAGE_SHIFT);

	WriteMsr(HV_X64_MSR_SIEFP, siefp.Asuint64_t);

	sharedSint.Vector = irqVector; //HV_SHARED_SINT_IDT_VECTOR + 0x20;
	sharedSint.Masked = false;
	sharedSint.AutoEoi = false;

	WriteMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sharedSint.Asuint64_t);

	// Enable the global synic bit
	sctrl.Asuint64_t = ReadMsr(HV_X64_MSR_SCONTROL);
	sctrl.Enable = 1;

	WriteMsr(HV_X64_MSR_SCONTROL, sctrl.Asuint64_t);

	gHvContext.SynICInitialized = true;

	return;

cleanup:
	free(gHvContext.synICMessagePage[cpu], M_DEVBUF); 
	free(gHvContext.synICMessagePage[cpu], M_DEVBUF); 
}

/*++

 Name:
 HvSynicCleanup()

 Description:
 Cleanup routine for HvSynicInit().

 --*/
void HvSynicCleanup(void *arg) 
{
	HV_SYNIC_SINT sharedSint;
	HV_SYNIC_SIMP simp;
	HV_SYNIC_SIEFP siefp;
	int cpu = PCPU_GET(cpuid);

	if (!gHvContext.SynICInitialized)
		return;

	if (cpu != 0) 
		return; //XXXKYS: SMP?

	sharedSint.Asuint64_t = ReadMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT);

	sharedSint.Masked = 1;

	// Disable the interrupt
	WriteMsr(HV_X64_MSR_SINT0 + VMBUS_MESSAGE_SINT, sharedSint.Asuint64_t);

	simp.Asuint64_t = ReadMsr(HV_X64_MSR_SIMP);
	simp.SimpEnabled = 0;
	simp.BaseSimpGpa = 0;

	WriteMsr(HV_X64_MSR_SIMP, simp.Asuint64_t);

	siefp.Asuint64_t = ReadMsr(HV_X64_MSR_SIEFP);
	siefp.SiefpEnabled = 0;
	siefp.BaseSiefpGpa = 0;

	WriteMsr(HV_X64_MSR_SIEFP, siefp.Asuint64_t);

	contigfree(gHvContext.synICMessagePage[cpu], PAGE_SIZE,  M_DEVBUF);
	contigfree(gHvContext.synICEventPage[cpu], PAGE_SIZE,  M_DEVBUF);
}
