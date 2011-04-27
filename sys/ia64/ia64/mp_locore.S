/*-
 * Copyright (c) 2011 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <machine/asm.h>
#include <machine/ia64_cpu.h>
#include <machine/pte.h>
#include <assym.s>

/*
 * AP wake-up entry point. The handoff state is similar as for the BSP,
 * as described on page 3-9 of the IPF SAL Specification. The difference
 * lies in the contents of register b0. For APs this register holds the
 * return address into the SAL rendezvous routine.
 *
 * Note that we're responsible for clearing the IRR bit by reading cr.ivr
 * and issuing the EOI to the local SAPIC.
 */
	.align	32
ENTRY_NOPROFILE(os_boot_rendez,0)
	mov	r16=cr.ivr	// clear IRR bit
	;;
	srlz.d
	mov	cr.eoi=r0	// ACK the wake-up
	;;
	srlz.d
	rsm	IA64_PSR_IC|IA64_PSR_I
	;;
	mov     r16 = (4<<8)|(16<<2)
	movl    r17 = 4<<61
	;;
	mov     rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (5<<8)|(PAGE_SHIFT<<2)|1
	movl	r17 = 5<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (6<<8)|(PAGE_SHIFT<<2)
	movl	r17 = 6<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r16 = (7<<8)|(PAGE_SHIFT<<2)
	movl	r17 = 7<<61
	;;
	mov	rr[r17] = r16
	;;
	srlz.d
	mov	r18 = 28<<2
	movl	r16 = PTE_PRESENT+PTE_MA_WB+PTE_ACCESSED+PTE_DIRTY+ \
			PTE_PL_KERN+PTE_AR_RWX+PTE_ED
	;;
	mov	cr.ifa = r17
	mov	cr.itir = r18
	ptr.d	r17, r18
	ptr.i	r17, r18
	;;
	srlz.i
	;;
	itr.d	dtr[r0] = r16
	mov	r18 = IA64_DCR_DEFAULT
	;;
	itr.i	itr[r0] = r16
	mov	cr.dcr = r18
	;;
	srlz.i
	;;
1:	mov	r16 = ip
	add	r17 = 2f-1b, r17
	movl	r18 = (IA64_PSR_AC|IA64_PSR_BN|IA64_PSR_DFH|IA64_PSR_DT|IA64_PSR_IC|IA64_PSR_IT|IA64_PSR_RT)
	;;
	add	r17 = r17, r16
	mov	cr.ipsr = r18
	mov	cr.ifs = r0
	;;
	mov	cr.iip = r17
	;;
	rfi

	.align	32
2:
{	.mlx
	mov	ar.rsc = 0
	movl	r16 = ia64_vector_table			// set up IVT early
	;;
}
{	.mlx
	mov	cr.iva = r16
	movl	r16 = ap_stack
	;;
}
{	.mmi
	srlz.i
	;;
	ld8	r16 = [r16]
	mov	r18 = KSTACK_PAGES*PAGE_SIZE-SIZEOF_PCB-SIZEOF_TRAPFRAME-16
	;;
}
{	.mlx
	mov	ar.bspstore = r16
	movl	gp = __gp
	;;
}
{	.mmi
	loadrs
	;;
	alloc	r17 = ar.pfs, 0, 0, 0, 0
	add	sp = r18, r16
	;;
}
{	.mib
	mov	ar.rsc = 3
	nop	0
	br.call.sptk.few rp = ia64_ap_startup
	;;
}
	/* NOT REACHED */
9:
{	.mib
	nop	0
	nop	0
	br.sptk	9b
	;;
}
END(os_boot_rendez)
