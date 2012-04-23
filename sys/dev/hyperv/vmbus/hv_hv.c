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

#include "hyperv.h"
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
hv_vmbus_context hv_vmbus_g_context = {
	.syn_ic_initialized = false,
	.hypercall_page = NULL,
	.signal_event_param = NULL,
	.signal_event_buffer = NULL, };

/*++

 Name:
 hv_vmbus_query_hypervisor_presence()

 Description:
 Query the cpuid for presense of windows hypervisor

 --*/
int
hv_vmbus_query_hypervisor_presence(void) 
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
	op = HV_CPU_ID_FUNCTION_VERSION_AND_FEATURES;
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
	op = HV_CPU_ID_FUNCTION_HV_VENDOR_AND_MAX_FUNCTION;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	maxLeaf = eax;
	eax = 0;
	ebx = 0;
	ecx = 0;
	edx = 0;
	op = HV_CPU_ID_FUNCTION_HV_INTERFACE;
	do_cpuid_inline(op, &eax, &ebx, &ecx, &edx);

	if (maxLeaf >= HV_CPU_ID_FUNCTION_MS_HV_VERSION) {
		eax = 0;
		ebx = 0;
		ecx = 0;
		edx = 0;
		op = HV_CPU_ID_FUNCTION_MS_HV_VERSION;
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
	uint64_t inputAddress = (Input) ? hv_get_phys_addr(Input) : 0;
	uint64_t outputAddress = (Output) ? hv_get_phys_addr(Output) : 0;
	volatile void* hypercallPage = hv_vmbus_g_context.hypercall_page;

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
	uint64_t inputAddress = (Input) ? hv_get_phys_addr(Input) : 0;
	uint32_t inputAddressHi = inputAddress >> 32;
	uint32_t inputAddressLo = inputAddress & 0xFFFFFFFF;
	uint64_t outputAddress = (Output) ? hv_get_phys_addr(Output) : 0;
	uint32_t outputAddressHi = outputAddress >> 32;
	uint32_t outputAddressLo = outputAddress & 0xFFFFFFFF;
	volatile void* hypercallPage = hv_vmbus_g_context.hypercall_page;

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
 hv_vmbus_init()

 Description:
 Main initialization routine. This routine must be called
 before any other routines in here are called

 --*/

int
hv_vmbus_init(void) 
{
	int maxLeaf;
	hv_vmbus_x64_msr_hypercall_contents hypercallMsr;
	void* virtAddr = 0;

	memset(hv_vmbus_g_context.syn_ic_event_page, 0, sizeof(hv_vmbus_handle) * MAXCPU);
	memset(hv_vmbus_g_context.syn_ic_message_page, 0, sizeof(hv_vmbus_handle) * MAXCPU);

	if (!hv_vmbus_query_hypervisor_presence())
		goto Cleanup;

	maxLeaf = HvQueryHypervisorInfo();

	// Write our OS info
	hv_vmbus_write_msr(HV_X64_MSR_GUEST_OS_ID, HV_LINUX_GUEST_ID);
	hv_vmbus_g_context.guest_id = HV_LINUX_GUEST_ID;

	// See if the hypercall page is already set
	hypercallMsr.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_HYPERCALL);
	virtAddr = malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);

	if (!virtAddr)
		goto Cleanup;

	hypercallMsr.enable = 1;
	hypercallMsr.guest_physical_address =
		(hv_get_phys_addr(virtAddr) >> PAGE_SHIFT);
	hv_vmbus_write_msr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);

	// Confirm that hypercall page did get set up.
	hypercallMsr.as_uint64_t = 0;
	hypercallMsr.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_HYPERCALL);

	if (!hypercallMsr.enable)
		goto Cleanup;

	hv_vmbus_g_context.hypercall_page = virtAddr;

	// Setup the global signal event param for the signal event hypercall
	hv_vmbus_g_context.signal_event_buffer =
		malloc(sizeof(hv_vmbus_input_signal_event_buffer), M_DEVBUF,
			M_ZERO | M_NOWAIT);

	if (!hv_vmbus_g_context.signal_event_buffer) {
		goto Cleanup;
	}

	hv_vmbus_g_context.signal_event_param =
		(hv_vmbus_input_signal_event*)
		 (HV_ALIGN_UP((unsigned long)
			hv_vmbus_g_context.signal_event_buffer,
			 HV_HYPERCALL_PARAM_ALIGN));
	hv_vmbus_g_context.signal_event_param->connection_id.as_uint32_t = 0;
	hv_vmbus_g_context.signal_event_param->connection_id.u.id =
		HV_VMBUS_EVENT_CONNECTION_ID;
	hv_vmbus_g_context.signal_event_param->flag_number = 0;
	hv_vmbus_g_context.signal_event_param->rsvd_z = 0;
	return 0;

Cleanup: 
	if (virtAddr) {
		if (hypercallMsr.enable) {
			hypercallMsr.as_uint64_t = 0;
			hv_vmbus_write_msr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);
		}

		free(virtAddr, M_DEVBUF);
	}
	return -ENOTSUP;
}

/*++

 Name:
 hv_vmbus_cleanup()

 Description:
 Cleanup routine. This routine is called normally during driver unloading or exiting.

 --*/
void
hv_vmbus_cleanup(void) 
{
	hv_vmbus_x64_msr_hypercall_contents hypercallMsr;


	if (hv_vmbus_g_context.signal_event_buffer) {
		free(hv_vmbus_g_context.signal_event_buffer, M_DEVBUF);
		hv_vmbus_g_context.signal_event_buffer = NULL;
		hv_vmbus_g_context.signal_event_param = NULL;
	}

	if (hv_vmbus_g_context.guest_id == HV_LINUX_GUEST_ID) {
		if (hv_vmbus_g_context.hypercall_page) {
			hypercallMsr.as_uint64_t = 0;
			hv_vmbus_write_msr(HV_X64_MSR_HYPERCALL, hypercallMsr.as_uint64_t);
			free(hv_vmbus_g_context.hypercall_page, M_DEVBUF);
			hv_vmbus_g_context.hypercall_page = NULL;
		}
	}
}

/*++

 Name:
 hv_vmbus_post_message()

 Description:
 Post a message using the hypervisor message IPC. This
 involves a hypercall.

 --*/
hv_vmbus_status
hv_vmbus_post_message_via_msg_ipc(
	hv_vmbus_connection_id	connectionId,
	hv_vmbus_message_type	messageType,
	void			*payload,
	size_t			payloadSize)
{
	struct alignedInput {
		uint64_t alignment8;
		hv_vmbus_input_post_message msg;
	};

	hv_vmbus_input_post_message* alignedMsg;
	hv_vmbus_status status;
	size_t addr;

	if (payloadSize > HV_MESSAGE_PAYLOAD_BYTE_COUNT)
		return -EMSGSIZE;

	addr = (size_t)malloc(sizeof(struct alignedInput), M_DEVBUF,
			M_ZERO | M_NOWAIT);
	if (!addr)
		return -ENOMEM;

	alignedMsg = (hv_vmbus_input_post_message*)
			(HV_ALIGN_UP(addr, HV_HYPERCALL_PARAM_ALIGN));

	alignedMsg->connection_id = connectionId;
	alignedMsg->message_type = messageType;
	alignedMsg->payload_size = payloadSize;
	memcpy((void*)alignedMsg->payload, payload, payloadSize);

	status = HvDoHypercall(HV_CALL_POST_MESSAGE, alignedMsg, 0) & 0xFFFF;

	free((void *) addr, M_DEVBUF);
	return status;
}

/*++

 Name:
 hv_vmbus_signal_event()

 Description:
 Signal an event on the specified connection using the hypervisor event IPC. This
 involves a hypercall.

 --*/
hv_vmbus_status
hv_vmbus_signal_event()
{
	hv_vmbus_status status;

	status = HvDoHypercall(HV_CALL_SIGNAL_EVENT, hv_vmbus_g_context.signal_event_param,
		0) & 0xFFFF;

	return status;
}

/*++

 Name:
 hv_vmbus_synic_init()

 --*/

void
hv_vmbus_synic_init(void *irqArg) 
{
	uint64_t version;
	hv_vmbus_synic_simp simp;
	hv_vmbus_synic_siefp siefp;
	hv_vmbus_synic_sint sharedSint;
	hv_vmbus_synic_scontrol sctrl;

	uint32_t irqVector = *((uint32_t *) (irqArg));
	int cpu = PCPU_GET(cpuid);

	if (!hv_vmbus_g_context.hypercall_page)
		return;

	/*
	 * KYS: Looks like we can only initialize on cpu0; don't we support
	 * SMP guests?
	 */

	if (cpu != 0)
		return;

	// Check the version
	version = hv_vmbus_read_msr(HV_X64_MSR_SVERSION);

	hv_vmbus_g_context.syn_ic_message_page[cpu] =
		malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (hv_vmbus_g_context.syn_ic_message_page[cpu] == NULL)
		goto cleanup;

	hv_vmbus_g_context.syn_ic_event_page[cpu] = 
		malloc(PAGE_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (hv_vmbus_g_context.syn_ic_event_page[cpu] == NULL)
		goto cleanup;

	//
	// Setup the Synic's message page
	//

	simp.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SIMP);
	simp.simp_enabled = 1;
	simp.base_simp_gpa = ((hv_get_phys_addr(
			hv_vmbus_g_context.syn_ic_message_page[cpu])) >> PAGE_SHIFT);

	hv_vmbus_write_msr(HV_X64_MSR_SIMP, simp.as_uint64_t);

	//
	// Setup the Synic's event page
	//
	siefp.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SIEFP);
	siefp.siefp_enabled = 1;
	siefp.base_siefp_gpa = ((hv_get_phys_addr(
			hv_vmbus_g_context.syn_ic_event_page[cpu])) >> PAGE_SHIFT);

	hv_vmbus_write_msr(HV_X64_MSR_SIEFP, siefp.as_uint64_t);

	sharedSint.Vector = irqVector; //HV_SHARED_SINT_IDT_VECTOR + 0x20;
	sharedSint.Masked = false;
	sharedSint.AutoEoi = false;

	hv_vmbus_write_msr(HV_X64_MSR_SINT0 + HV_VMBUS_MESSAGE_SINT, sharedSint.as_uint64_t);

	// Enable the global synic bit
	sctrl.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SCONTROL);
	sctrl.enable = 1;

	hv_vmbus_write_msr(HV_X64_MSR_SCONTROL, sctrl.as_uint64_t);

	hv_vmbus_g_context.syn_ic_initialized = true;

	return;

cleanup:
	free(hv_vmbus_g_context.syn_ic_message_page[cpu], M_DEVBUF); 
	free(hv_vmbus_g_context.syn_ic_message_page[cpu], M_DEVBUF); 
}

/*++

 Name:
 hv_vmbus_synic_cleanup()

 Description:
 Cleanup routine for hv_vmbus_synic_init().

 --*/
void hv_vmbus_synic_cleanup(void *arg)
{
	hv_vmbus_synic_sint sharedSint;
	hv_vmbus_synic_simp simp;
	hv_vmbus_synic_siefp siefp;
	int cpu = PCPU_GET(cpuid);

	if (!hv_vmbus_g_context.syn_ic_initialized)
		return;

	if (cpu != 0) 
		return; //XXXKYS: SMP?

	sharedSint.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SINT0 + HV_VMBUS_MESSAGE_SINT);

	sharedSint.Masked = 1;

	// Disable the interrupt
	hv_vmbus_write_msr(HV_X64_MSR_SINT0 + HV_VMBUS_MESSAGE_SINT, sharedSint.as_uint64_t);

	simp.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SIMP);
	simp.simp_enabled = 0;
	simp.base_simp_gpa = 0;

	hv_vmbus_write_msr(HV_X64_MSR_SIMP, simp.as_uint64_t);

	siefp.as_uint64_t = hv_vmbus_read_msr(HV_X64_MSR_SIEFP);
	siefp.siefp_enabled = 0;
	siefp.base_siefp_gpa = 0;

	hv_vmbus_write_msr(HV_X64_MSR_SIEFP, siefp.as_uint64_t);

	contigfree(hv_vmbus_g_context.syn_ic_message_page[cpu], PAGE_SIZE,  M_DEVBUF);
	contigfree(hv_vmbus_g_context.syn_ic_event_page[cpu], PAGE_SIZE,  M_DEVBUF);
}
