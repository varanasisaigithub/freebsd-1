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
{	.mmi
	mov	r8 = cr.ivr		// clear IRR bit
	;;
	srlz.d
	mov	r16 = (IA64_PBVM_RR << 8) | (IA64_PBVM_PAGE_SHIFT << 2)
}
{	.mmi
	mov	cr.eoi = r0		// ACK the wake-up
	;;
	srlz.d
	dep.z	r17 = IA64_PBVM_RR, 61, 3
	;;
}
{	.mmi
	rsm	IA64_PSR_IC | IA64_PSR_I
	mov     rr[r17] = r16
	add	r2 = 8, r1
	;;
}
{	.mlx
	srlz.i
	movl	r16 = IA64_PBVM_PGTBL
	;;
}
{	.mmi
	ld8	r17 = [r1], 16		// as_pgtbl_pte
	ld8	r18 = [r2], 16		// as_pgtbl_itir
	mov	r8 = r0
	;;
}
{	.mmi
	mov	cr.ifa = r16
	mov	cr.itir = r18
	mov	r9 = r0
	;;
}
{	.mmi
	srlz.d
	ptr.d	r16, r18
	nop	0
	;;
}
{	.mmi
	srlz.d
	itr.d	dtr[r8] = r17
	nop	0
	;;
}
{	.mmi
	srlz.d
	ld8	r16 = [r1], 16		// as_text_va
	add	r8 = 1, r8
	;;
}
{	.mmi
	ld8	r17 = [r2], 16		// as_text_pte
	ld8	r18 = [r1], 16		// as_text_itir
	nop	0
	;;
}
{	.mmi
	mov	cr.ifa = r16
	mov	cr.itir = r18
	nop	0
	;;
}
{	.mmi
	srlz.d
	ptr.d	r16, r18
	nop	0
	;;
}
{	.mmi
	srlz.d
	itr.d	dtr[r8] = r17
	nop	0
	;;
}
{	.mmi
	srlz.d
	ptr.i	r16, r18
	add	r8 = 1, r8
	;;
}
{	.mmi
	srlz.i
	;;
	itr.i	itr[r9] = r17
	nop	0
	;;
}
{	.mmi
	srlz.i
	;;
	ld8	r16 = [r2], 16          // as_data_va
	add	r9 = 1, r9
	;;
}
{	.mmi
	ld8	r17 = [r1], 16		// as_data_pte
	ld8	r18 = [r2], 16		// as_data_itir
	nop	0
	;;
}
{	.mmi
	mov	cr.ifa = r16
	mov	cr.itir = r18
	nop	0
	;;
}
{	.mmi
	srlz.d
	ptr.d	r16, r18
	nop	0
	;;
}
{	.mmi
	srlz.d
	itr.d	dtr[r8] = r17
	mov	r19 = IA64_DCR_DEFAULT
	;;
}
{	.mmi
	srlz.d
	ld8	r16 = [r1], 16		// as_kstack
	add	r8 = 1, r8
	;;
}
{	.mmi
	ld8	r17 = [r2], 16		// as_kstack_top
	mov	cr.dcr = r19
	nop	0
	;;
}
{	.mlx
	srlz.i
	movl	r18 = IA64_PSR_BN | IA64_PSR_IT | IA64_PSR_DT | IA64_PSR_IC | \
			IA64_PSR_RT | IA64_PSR_DFH
	;;
}
1:
{	.mii
	mov	cr.ipsr = r18
	mov	r19 = ip
	;;
	add	r19 = 2f-1b, r19
	;;
}
{	.mmi
	mov	cr.ifs = r0
	mov	cr.iip = r19
	nop	0
	;;
}

	rfi
	;;

	.align	32
2:
{	.mlx
	mov	ar.rsc = 0
	movl	r18 = ia64_vector_table		// set up IVT early
	;;
}
{	.mmi
	mov	cr.iva = r18
	;;
	srlz.i
	nop	0
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
	alloc	r18 = ar.pfs, 0, 0, 0, 0
	add	sp = -16, r17
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
