/*-
 * Copyright (c) 2000 Doug Rabson
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
 *	$FreeBSD$
 */

#include <machine/asm.h>
#include <machine/pmap.h>
#include <assym.s>

/*
 * ar.k7 = curproc
 * ar.k6 = ksp
 * ar.k5 = globalp
 */

/*
 * Call exception_save_regs to preserve the interrupted state in a
 * trapframe and call trap() with the value of _n_ as an argument. We
 * arrange for trap() to return to exception_return which will restore 
 * the interrupted state before executing an rfi to resume it.
 */
#define TRAP(_n_)					\
	mov	r16=b0;					\
	br.call.sptk.few b0=exception_save_regs;	\
	alloc	r16=ar.pfs,0,0,2,0;			\
	movl	r17=exception_return;			\
	mov	out0=_n_;				\
	mov	out1=sp;;				\
	add	sp=-16,sp;;				\
	mov	rp=r17;					\
	br.call.sptk.few b6=trap
	
/*
 * The IA64 Interrupt Vector Table (IVT) contains 20 slots with 64
 * bundles per vector and 48 slots with 16 bundles per vector.
 */

	.section .text.ivt,"ax"

	.align	32768
	.global ia64_vector_table
ia64_vector_table:

/* 0x0000:	VHPT Translation vector */	

	TRAP(0)
	.align	1024

/* 0x0400:	Instruction TLB vector */

	mov	r16=cr.ifa
	mov	r17=pr
	;;
	thash	r18=r16
	ttag	r19=r16
	;;
	add	r20=24,r18		// collision chain
	;; 
	ld8	r20=[r20]		// first entry
	;; 
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
1:	cmp.eq	p1,p2=r0,r20		// done?
(p1)	br.cond.spnt.few 9f		// bail if done
	;;
	add	r21=16,r20		// tag location
	;;
	ld8	r21=[r21]		// read tag
	;;
	cmp.eq	p1,p2=r21,r19		// compare tags
(p2)	br.cond.sptk.few 2f		// if not, read next in chain
	;;
	ld8	r21=[r20],8		// read pte
	;; 
	ld8	r22=[r20]		// read rest of pte
	;;
	dep	r18=0,r18,61,3		// convert vhpt ptr to physical
	;;
	add	r20=16,r18		// address of tag
	;;
	ld8.acq	r23=[r20]		// read old tag
	movl	r24=(1<<63)		// ti bit
	;;
	or	r23=r23,r24		// set ti bit
	;;
	st8.rel	[r20]=r23		// store old tag + ti
	;;
	mf				// make sure everyone sees
	;;
	st8	[r18]=r21,8		// store pte
	;;
	st8	[r18]=r22,8
	;;
	st8.rel	[r18]=r19		// store new tag
	;; 
	mov	pr=r17,0x1ffff		// restore predicates
	;;
	rfi				// walker will retry the access
	
2:	add	r20=24,r20		// next in chain
	;;
	ld8	r20=[r20]		// read chain
	br.cond.sptk.few 1b		// loop

9:	mov	pr=r17,0x1ffff		// restore predicates
	TRAP(1)				// die horribly

	.align	1024

/* 0x0800:	Data TLB vector */

	mov	r16=cr.ifa
	mov	r17=pr
	;;
	thash	r18=r16
	ttag	r19=r16
	;;
	add	r20=24,r18		// collision chain
	;; 
	ld8	r20=[r20]		// first entry
	;; 
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
1:	cmp.eq	p1,p2=r0,r20		// done?
(p1)	br.cond.spnt.few 9f		// bail if done
	;;
	add	r21=16,r20		// tag location
	;;
	ld8	r21=[r21]		// read tag
	;;
	cmp.eq	p1,p2=r21,r19		// compare tags
(p2)	br.cond.sptk.few 2f		// if not, read next in chain
	;;
	ld8	r21=[r20],8		// read pte
	;; 
	ld8	r22=[r20]		// read rest of pte
	;;
	dep	r18=0,r18,61,3		// convert vhpt ptr to physical
	;;
	add	r20=16,r18		// address of tag
	;;
	ld8.acq	r23=[r20]		// read old tag
	movl	r24=(1<<63)		// ti bit
	;;
	or	r23=r23,r24		// set ti bit
	;;
	st8.rel	[r20]=r23		// store old tag + ti
	;;
	mf				// make sure everyone sees
	;;
	st8	[r18]=r21,8		// store pte
	;;
	st8	[r18]=r22,8
	;;
	st8.rel	[r18]=r19		// store new tag
	;; 
	mov	pr=r17,0x1ffff		// restore predicates
	;;
	rfi				// walker will retry the access
	
2:	add	r20=24,r20		// next in chain
	;;
	ld8	r20=[r20]		// read chain
	br.cond.sptk.few 1b		// loop

9:	mov	pr=r17,0x1ffff		// restore predicates
	TRAP(2)				// die horribly

	.align	1024

/* 0x0c00:	Alternate Instruction TLB vector */

	mov	r16=cr.ifa		// where did it happen
	;; 
	mov	r18=pr			// save predicates
	;;
	extr.u	r17=r16,61,3		// get region number
	;;
	cmp.eq	p1,p2=7,r17		// RR7->p1, RR6->p2
	;;
(p1)	movl	r17=PTE_P+PTE_MA_WB+PTE_A+PTE_D+PTE_PL_KERN+PTE_AR_RX
(p2)	movl	r17=PTE_P+PTE_MA_UC+PTE_A+PTE_D+PTE_PL_KERN+PTE_AR_RX
	;;
	dep	r16=0,r16,50,14		// clear bits above PPN
	;;
	dep	r16=r17,r17,0,12	// put pte bits in 0..11
	;;
	itc.i	r16
	mov	pr=r18,0x1ffff		// restore predicates
	;;
	rfi

	.align	1024

/* 0x1000:	Alternate Data TLB vector */

	mov	r16=cr.ifa		// where did it happen
	mov	r18=pr			// save predicates
	;;
	extr.u	r17=r16,61,3		// get region number
	;;
	cmp.eq	p1,p2=7,r17		// RR7->p1, RR6->p2
	;;
(p1)	movl	r17=PTE_P+PTE_MA_WB+PTE_A+PTE_D+PTE_PL_KERN+PTE_AR_RW
(p2)	movl	r17=PTE_P+PTE_MA_UC+PTE_A+PTE_D+PTE_PL_KERN+PTE_AR_RW
	;;
	dep	r16=0,r16,50,14		// clear bits above PPN
	;;
	dep	r16=r17,r17,0,12	// put pte bits in 0..11
	;;
	itc.d	r16
	mov	pr=r18,0x1ffff		// restore predicates
	;;
	rfi

	.align	1024

/* 0x1400:	Data Nested TLB vector */

	TRAP(5)
	.align	1024

/* 0x1800:	Instruction Key Miss vector */

	TRAP(6)
	.align	1024
	
/* 0x1c00:	Data Key Miss vector */

	TRAP(7)
	.align	1024

/* 0x2000:	Dirty-Bit vector */

	mov	r16=cr.ifa
	mov	r17=pr
	mov	r20=12<<2		// XXX get page size from VHPT
	;;
	ptc.l	r16,r20			// purge TLB
	thash	r18=r16
	ttag	r19=r16
	;;
	srlz.d
	add	r20=24,r18		// collision chain
	;; 
	ld8	r20=[r20]		// first entry
	;; 
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
1:	cmp.eq	p1,p2=r0,r20		// done?
(p1)	br.cond.spnt.few 9f		// bail if done
	;;
	add	r21=16,r20		// tag location
	;;
	ld8	r21=[r21]		// read tag
	;;
	cmp.eq	p1,p2=r21,r19		// compare tags
(p2)	br.cond.sptk.few 2f		// if not, read next in chain
	;;
	ld8	r21=[r20]		// read pte
	mov	r22=PTE_D
	;;
	or	r21=r22,r21		// set dirty bit
	;;
	st8	[r20]=r21		// store back
	;; 
	ld8	r22=[r20]		// read rest of pte
	;;
	dep	r18=0,r18,61,3		// convert vhpt ptr to physical
	;;
	add	r20=16,r18		// address of tag
	;;
	ld8.acq	r23=[r20]		// read old tag
	movl	r24=(1<<63)		// ti bit
	;;
	or	r23=r23,r24		// set ti bit
	;;
	st8.rel	[r20]=r23		// store old tag + ti
	;;
	mf				// make sure everyone sees
	;;
	st8	[r18]=r21,8		// store pte
	;;
	st8	[r18]=r22,8
	;;
	st8.rel	[r18]=r19		// store new tag
	;; 
	mov	pr=r17,0x1ffff		// restore predicates
	;;
	rfi				// walker will retry the access
	
2:	add	r20=24,r20		// next in chain
	;;
	ld8	r20=[r20]		// read chain
	br.cond.sptk.few 1b		// loop

9:	mov	pr=r17,0x1ffff		// restore predicates
	TRAP(8)				// die horribly
	.align	1024

/* 0x2400:	Instruction Access-Bit vector */

	mov	r16=cr.ifa
	mov	r17=pr
	mov	r20=12<<2		// XXX get page size from VHPT
	;;
	ptc.l	r16,r20			// purge TLB
	thash	r18=r16
	ttag	r19=r16
	;;
	srlz.d
	add	r20=24,r18		// collision chain
	;; 
	ld8	r20=[r20]		// first entry
	;; 
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
1:	cmp.eq	p1,p2=r0,r20		// done?
(p1)	br.cond.spnt.few 9f		// bail if done
	;;
	add	r21=16,r20		// tag location
	;;
	ld8	r21=[r21]		// read tag
	;;
	cmp.eq	p1,p2=r21,r19		// compare tags
(p2)	br.cond.sptk.few 2f		// if not, read next in chain
	;;
	ld8	r21=[r20]		// read pte
	mov	r22=PTE_A
	;;
	or	r21=r22,r21		// set accessed bit
	;;
	st8	[r20]=r21		// store back
	;; 
	ld8	r22=[r20]		// read rest of pte
	;;
	dep	r18=0,r18,61,3		// convert vhpt ptr to physical
	;;
	add	r20=16,r18		// address of tag
	;;
	ld8.acq	r23=[r20]		// read old tag
	movl	r24=(1<<63)		// ti bit
	;;
	or	r23=r23,r24		// set ti bit
	;;
	st8.rel	[r20]=r23		// store old tag + ti
	;;
	mf				// make sure everyone sees
	;;
	st8	[r18]=r21,8		// store pte
	;;
	st8	[r18]=r22,8
	;;
	st8.rel	[r18]=r19		// store new tag
	;; 
	mov	pr=r17,0x1ffff		// restore predicates
	;;
	rfi				// walker will retry the access
	
2:	add	r20=24,r20		// next in chain
	;;
	ld8	r20=[r20]		// read chain
	br.cond.sptk.few 1b		// loop

9:	mov	pr=r17,0x1ffff		// restore predicates
	TRAP(9)
	.align	1024

/* 0x2800:	Data Access-Bit vector */

	mov	r16=cr.ifa
	mov	r17=pr
	mov	r20=12<<2		// XXX get page size from VHPT
	;;
	ptc.l	r16,r20			// purge TLB
	thash	r18=r16
	ttag	r19=r16
	;;
	srlz.d
	add	r20=24,r18		// collision chain
	;; 
	ld8	r20=[r20]		// first entry
	;; 
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
1:	cmp.eq	p1,p2=r0,r20		// done?
(p1)	br.cond.spnt.few 9f		// bail if done
	;;
	add	r21=16,r20		// tag location
	;;
	ld8	r21=[r21]		// read tag
	;;
	cmp.eq	p1,p2=r21,r19		// compare tags
(p2)	br.cond.sptk.few 2f		// if not, read next in chain
	;;
	ld8	r21=[r20]		// read pte
	mov	r22=PTE_A
	;;
	or	r21=r22,r21		// set accessed bit
	;;
	st8	[r20]=r21		// store back
	;; 
	ld8	r22=[r20]		// read rest of pte
	;;
	dep	r18=0,r18,61,3		// convert vhpt ptr to physical
	;;
	add	r20=16,r18		// address of tag
	;;
	ld8.acq	r23=[r20]		// read old tag
	movl	r24=(1<<63)		// ti bit
	;;
	or	r23=r23,r24		// set ti bit
	;;
	st8.rel	[r20]=r23		// store old tag + ti
	;;
	mf				// make sure everyone sees
	;;
	st8	[r18]=r21,8		// store pte
	;;
	st8	[r18]=r22,8
	;;
	st8.rel	[r18]=r19		// store new tag
	;; 
	mov	pr=r17,0x1ffff		// restore predicates
	;;
	rfi				// walker will retry the access
	
2:	add	r20=24,r20		// next in chain
	;;
	ld8	r20=[r20]		// read chain
	br.cond.sptk.few 1b		// loop

9:	mov	pr=r17,0x1ffff		// restore predicates
	TRAP(10)
	.align	1024

/* 0x2c00:	Break Instruction vector */

	TRAP(11)
	.align	1024
		
/* 0x3000:	External Interrupt vector */

	TRAP(12)
	.align	1024
		
/* 0x3400:	Reserved */

	TRAP(13)
	.align	1024
		
/* 0x3800:	Reserved */

	TRAP(14)
	.align	1024
		
/* 0x3c00:	Reserved */

	TRAP(15)
	.align	1024
		
/* 0x4000:	Reserved */

	TRAP(16)
	.align	1024
		
/* 0x4400:	Reserved */

	TRAP(17)
	.align	1024
		
/* 0x4800:	Reserved */

	TRAP(18)
	.align	1024
		
/* 0x4c00:	Reserved */

	TRAP(19)
	.align	1024
		
/* 0x5000:	Page Not Present vector */

	TRAP(20)
	.align	256
		
/* 0x5100:	Key Permission vector */

	TRAP(21)
	.align	256
		
/* 0x5200:	Instruction Access Rights vector */

	TRAP(22)
	.align	256
		
/* 0x5300:	Data Access Rights vector */

	TRAP(23)
	.align	256
		
/* 0x5400:	General Exception vector */

	TRAP(24)
	.align	256
		
/* 0x5500:	Disabled FP-Register vector */

	TRAP(25)
	.align	256
		
/* 0x5600:	NaT Consumption vector */

	TRAP(26)
	.align	256
		
/* 0x5700:	Speculation vector */

	TRAP(27)
	.align	256
		
/* 0x5800:	Reserved */

	TRAP(28)
	.align	256
		
/* 0x5900:	Debug vector */

	TRAP(29)
	.align	256
		
/* 0x5a00:	Unaligned Reference vector */

	TRAP(30)
	.align	256
		
/* 0x5b00:	Unsupported Data Reference vector */

	TRAP(31)
	.align	256
		
/* 0x5c00:	Floating-point Fault vector */

	TRAP(32)
	.align	256
		
/* 0x5d00:	Floating-point Trap vector */

	TRAP(33)
	.align	256
		
/* 0x5e00:	Lower-Privilege Transfer Trap vector */

	TRAP(34)
	.align	256
		
/* 0x5f00:	Taken Branch Trap vector */

	TRAP(35)
	.align	256
		
/* 0x6000:	Single Step Trap vector */

	TRAP(36)
	.align	256
		
/* 0x6100:	Reserved */

	TRAP(37)
	.align	256
		
/* 0x6200:	Reserved */

	TRAP(38)
	.align	256
		
/* 0x6300:	Reserved */

	TRAP(39)
	.align	256
		
/* 0x6400:	Reserved */

	TRAP(40)
	.align	256
		
/* 0x6500:	Reserved */

	TRAP(41)
	.align	256
		
/* 0x6600:	Reserved */

	TRAP(42)
	.align	256
		
/* 0x6700:	Reserved */

	TRAP(43)
	.align	256
		
/* 0x6800:	Reserved */

	TRAP(44)
	.align	256
		
/* 0x6900:	IA-32 Exception vector */

	TRAP(45)
	.align	256
		
/* 0x6a00:	IA-32 Intercept vector */

	TRAP(46)
	.align	256
		
/* 0x6b00:	IA-32 Interrupt vector */

	TRAP(47)
	.align	256
	
/* 0x6c00:	Reserved */

	TRAP(48)
	.align	256
	
/* 0x6d00:	Reserved */

	TRAP(49)
	.align	256
	
/* 0x6e00:	Reserved */

	TRAP(50)
	.align	256
	
/* 0x6f00:	Reserved */

	TRAP(51)
	.align	256
	
/* 0x7000:	Reserved */

	TRAP(52)
	.align	256
	
/* 0x7100:	Reserved */

	TRAP(53)
	.align	256
	
/* 0x7200:	Reserved */

	TRAP(54)
	.align	256
	
/* 0x7300:	Reserved */

	TRAP(55)
	.align	256
	
/* 0x7400:	Reserved */

	TRAP(56)
	.align	256
	
/* 0x7500:	Reserved */

	TRAP(57)
	.align	256
	
/* 0x7600:	Reserved */

	TRAP(58)
	.align	256
	
/* 0x7700:	Reserved */

	TRAP(59)
	.align	256
	
/* 0x7800:	Reserved */

	TRAP(60)
	.align	256
	
/* 0x7900:	Reserved */

	TRAP(61)
	.align	256
	
/* 0x7a00:	Reserved */

	TRAP(62)
	.align	256

/* 0x7b00:	Reserved */

	TRAP(63)
	.align	256
	
/* 0x7c00:	Reserved */

	TRAP(64)
	.align	256
	
/* 0x7d00:	Reserved */

	TRAP(65)
	.align	256
	
/* 0x7e00:	Reserved */

	TRAP(66)
	.align	256
	
/* 0x7f00:	Reserved */

	TRAP(67)
	.align	256

	.section .data.vhpt,"aw"

	.global ia64_vhpt
	
	.align	32768
ia64_vhpt:	.quad 0
	.align	32768

	.text

#define rIIP	r31
#define rIPSR	r30
#define rISR	r29
#define rIFA	r28
#define rPR	r27
#define rSP	r26
#define rIFS	r25
#define rR1	r24
#define rR2	r23
#define rBSPSTORE r22
#define rRNAT	r21
#define rBSP	r27		/* overlay rPR */
#define rRSC	r20
#define rPFS	r19
#define rB0	r31		/* overlay rIIP */

/*
 * exception_return:	restore interrupted state
 *	
 * Arguments:
 *	sp+16	trapframe pointer
 *
 */
ENTRY(exception_return, 0)

	rsm	psr.ic|psr.dt		// disable interrupt collection and vm
	add	r3=16,sp;
	;;
	srlz.d
	dep	r3=0,r3,61,3		// physical address
	;; 
	extr.u	r16=rIPSR,32,2		// extract ipsr.cpl
	;;
	cmp.eq	p1,p2=r0,r16		// test for return to kernel mode
	;;
(p1)	add	r16=SIZEOF_TRAPFRAME+16,sp  // restore ar.k6 (kernel sp)
	;; 
(p1)	mov	ar.k6=r16
	add	r1=SIZEOF_TRAPFRAME-16,r3 // r1=&tf_f[FRAME_F15]
	add	r2=SIZEOF_TRAPFRAME-32,r3 // r2=&tf_f[FRAME_F14]
	;;
	ldf.fill f15=[r1],-32		// r1=&tf_f[FRAME_F13]
	ldf.fill f14=[r2],-32		// r2=&tf_f[FRAME_F12]
	;;
	ldf.fill f13=[r1],-32		// r1=&tf_f[FRAME_F11]
	ldf.fill f12=[r2],-32		// r2=&tf_f[FRAME_F10]
	;;
	ldf.fill f11=[r1],-32		// r1=&tf_f[FRAME_F9]
	ldf.fill f10=[r2],-32		// r2=&tf_f[FRAME_F8]
	;;
	ldf.fill f9=[r1],-32		// r1=&tf_f[FRAME_F7]
	ldf.fill f8=[r2],-32		// r2=&tf_f[FRAME_F6]
	;; 
	ldf.fill f7=[r1],-32		// r1=&tf_r[FRAME_R31]
	ldf.fill f6=[r2],-24		// r2=&tf_r[FRAME_R30]
	;; 
	ld8.fill r31=[r1],-16		// r1=&tf_r[FRAME_R29]
	ld8.fill r30=[r2],-16		// r2=&tf_r[FRAME_R28]
	;; 
	ld8.fill r29=[r1],-16		// r1=&tf_r[FRAME_R27]
	ld8.fill r28=[r2],-16		// r2=&tf_r[FRAME_R26]
	;; 
	ld8.fill r27=[r1],-16		// r1=&tf_r[FRAME_R25]
	ld8.fill r26=[r2],-16		// r2=&tf_r[FRAME_R24]
	;; 
	ld8.fill r25=[r1],-16		// r1=&tf_r[FRAME_R23]
	ld8.fill r24=[r2],-16		// r2=&tf_r[FRAME_R22]
	;; 
	ld8.fill r23=[r1],-16		// r1=&tf_r[FRAME_R21]
	ld8.fill r22=[r2],-16		// r2=&tf_r[FRAME_R20]
	;; 
	ld8.fill r21=[r1],-16		// r1=&tf_r[FRAME_R19]
	ld8.fill r20=[r2],-16		// r2=&tf_r[FRAME_R18]
	;; 
	ld8.fill r19=[r1],-16		// r1=&tf_r[FRAME_R17]
	ld8.fill r18=[r2],-16		// r2=&tf_r[FRAME_R16]
	;; 
	ld8.fill r17=[r1],-16		// r1=&tf_r[FRAME_R15]
	ld8.fill r16=[r2],-16		// r2=&tf_r[FRAME_R14]
	;;
	bsw.0				// switch to bank 0
	;;
	ld8.fill r15=[r1],-16		// r1=&tf_r[FRAME_R13]
	ld8.fill r14=[r2],-16		// r2=&tf_r[FRAME_R12]
	;;
	ld8.fill r13=[r1],-16		// r1=&tf_r[FRAME_R11]
	ld8.fill r12=[r2],-16		// r2=&tf_r[FRAME_R10]
	;;
	ld8.fill r11=[r1],-16		// r1=&tf_r[FRAME_R9]
	ld8.fill r10=[r2],-16		// r2=&tf_r[FRAME_R8]
	;;
	ld8.fill r9=[r1],-16		// r1=&tf_r[FRAME_R7]
	ld8.fill r8=[r2],-16		// r2=&tf_r[FRAME_R6]
	;;
	ld8.fill r7=[r1],-16		// r1=&tf_r[FRAME_R5]
	ld8.fill r6=[r2],-16		// r2=&tf_r[FRAME_R4]
	;;
	ld8.fill r5=[r1],-16		// r1=&tf_r[FRAME_R3]
	ld8.fill r4=[r2],-16		// r2=&tf_r[FRAME_R2]
	;;
	ld8.fill r3=[r1],-16		// r1=&tf_r[FRAME_R1]
	ld8.fill rR2=[r2],-16		// r2=&tf_b[7]
	;;
	ld8.fill rR1=[r1],-16		// r1=&tf_b[6]
	ld8	r16=[r2],-16		// r2=&tf_b[5]
	;;
	mov	b7=r16
	ld8	r18=[r1],-16		// r1=&tf_b[4]
	ld8	r19=[r2],-16		// r2=&tf_b[3]
	;;
	mov	b6=r18
	mov	b5=r19
	ld8	r16=[r1],-16		// r1=&tf_b[2]
	ld8	r17=[r2],-16		// r2=&tf_b[1]
	;;
	mov	b4=r16
	mov	b3=r17
	ld8	r18=[r1],-16		// r1=&tf_b[0]
	ld8	r19=[r2],-16		// r2=&tf_ar_fpsr
	;;
	mov	b2=r18
	mov	b1=r19
	ld8	r16=[r1],-16		// r1=&tf_ar_ccv
	ld8	r17=[r2],-16		// r2=&tf_ar_unat
	;;
	mov	b0=r16
	mov	ar.fpsr=r17
	ld8	r18=[r1],-16		// r1=&tf_ar_bsp
	ld8	r19=[r2],-16		// r2=&tf_ar_rnat
	;;
	mov	ar.ccv=r18
	mov	ar.unat=r19
	ld8	rBSP=[r1],-16		// r1=&tf_ar_bspstore
	ld8	rRNAT=[r2],-16		// r2=&tf_cr_ifs
	;;
	ld8	rBSPSTORE=[r1],-16	// r1=&tf_cr_pfs
	ld8	rIFS=[r2],-16		// r2=&tf_ar_rsc
	;;
	ld8	rPFS=[r1],-16		// r1=&tf_pr
	ld8	rRSC=[r2],-16		// r2=&tf_cr_ifa
	;;
	ld8	rPR=[r1],-16		// r1=&tf_cr_isr
	ld8	rIFA=[r2],-16		// r2=&tf_cr_ipsr
	;;
	ld8	rIIP=[r1]
	ld8	rIPSR=[r2]
	;;
	extr.u	r16=rIPSR,32,2		// extract ipsr.cpl
	;;
	cmp.eq	p1,p2=r0,r17		// test for kernel mode
	;;
(p2)	br.cond.dpnt.few 1f		// don't switch bs if not user
	;;
	sub	r16=rBSP,rBSPSTORE	// how many bytes to load?
	;;
	shl	r16=r16,16		// value for ar.rsc
	;;
	mov	ar.rsc=r16		// setup for loadrs
	;;
	loadrs				// load user regs from kernel bs
	;;
	mov	ar.bspstore=rBSPSTORE
	;;
	mov	ar.rnat=rRNAT

1:	mov	r1=rR1
	mov	r2=rR2
	mov	cr.ifs=rIFS
	mov	ar.rsc=rRSC
	mov	pr=rPR,0x1ffff
	mov	cr.ifa=rIFA
	mov	cr.iip=rIIP
	mov	cr.ipsr=rIPSR
	;;
	rfi

	END(exception_return)
	

/*
 * exception_save_regs: save interrupted state
 *
 * Arguments:
 *	b0	return address
 *	r16	saved b0
 *
 * Return:
 *	sp	kernel stack pointer
 */
ENTRY(exception_save_regs, 0)
	rsm	psr.dt			// turn off data translations
	;;
	srlz.d				// serialize
	;;
	mov	rIIP=cr.iip
	mov	rIPSR=cr.ipsr
	mov	rISR=cr.isr
	mov	rIFA=cr.ifa
	mov	rPR=pr
	;; 
	extr.u	r17=rIPSR,32,2		// extract ipsr.cpl
	;;
	cmp.eq	p1,p2=r0,r17		// test for kernel mode
	;;
	mov	rSP=sp			// save sp
	;; 
(p2)	mov	sp=ar.k6		// and switch to kernel stack
	mov	r16=SIZEOF_TRAPFRAME
	;;
	sub	sp=sp,r16		// reserve trapframe
	;;
	mov	rR1=r1
	mov	rR2=r2
	;; 
	dep	r1=0,sp,61,3		// r1=&tf_cr_iip
	;;
	add	r2=8,r1			// r2=&tf_cr_ipsr
	;; 
	st8	[r1]=rIIP,16		// r1=&tf_cr_isr
	st8	[r2]=rIPSR,16		// r2=&tf_cr_ifa
	;; 
	st8	[r1]=rISR,16		// r1=&tf_pr
	st8	[r2]=rIFA,16		// r2=&tf_ar_rsc
	;; 
	st8	[r1]=rPR,16		// r1=&tf_cr_pfs

	mov	rB0=r16
	mov	rRSC=ar.rsc
	mov	rPFS=ar.pfs
	cover
(p2)	mov	r16=ar.k7		// curproc
	mov	rIFS=cr.ifs
	;; 
(p2)	add	r16=P_ADDR,r16		// &curproc->p_addr
	mov	ar.rsc=0
	;; 
(p2)	ld8	r16=[r16]		// curproc->p_addr
	mov	rBSPSTORE=ar.bspstore
	;; 
(p2)	add	r16=SIZEOF_USER,r16	// kernel backing store
	mov	rRNAT=ar.rnat
	mov	rBSP=ar.bsp
	;; 
(p2)	mov	ar.bspstore=r16		// switch bspstore
	st8	[r2]=rRSC,16		// r2=&tf_cr_ifs
	;; 
	st8	[r1]=rPFS,16		// r1=&tf_ar_bspstore
	st8	[r2]=rIFS,16		// r2=&tf_ar_rnat
	;; 
	st8	[r1]=rBSPSTORE,16	// r1=&tf_ar_bsp
	st8	[r2]=rRNAT,16		// r2=&tf_ar_unat
	;; 
	st8	[r1]=rBSP,16		// r1=&tf_ar_ccv
	mov	ar.rsc=3		// switch RSE back on
	mov	r16=ar.unat
	;; 
	mov	r17=ar.ccv
	st8	[r2]=r16,16		// r2=&tf_ar_fpsr
	mov	r18=ar.fpsr
	;; 
	st8	[r1]=r17,16		// r1=&tf_b[0]
	st8	[r2]=r18,16		// r2=&tf_b[1]
	mov	r17=b1
	;; 
	st8	[r1]=rB0,16		// r1=&tf_b[2]
	mov	r18=b2
	st8	[r2]=r17,16		// r2=&tf_b[3]
	;; 
	mov	r17=b3
	st8	[r1]=r18,16		// r1=&tf_b[4]
	;; 
	mov	r18=b4
	st8	[r2]=r17,16		// r2=&tf_b[5]
	;; 
	mov	r17=b5
	st8	[r1]=r18,16		// r1=&tf_b[6]
	;; 
	mov	r18=b6
	st8	[r2]=r17,16		// r2=&tf_b[7]
	;; 
	mov	r17=b7
	st8	[r1]=r18,16		// r1=&tf_r[FRAME_R1]
	;; 
	st8	[r2]=r17,16		// r2=&tf_r[FRAME_R2]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=rR1,16		// r1=&tf_r[FRAME_R3]
	.mem.offset 8,0
	st8.spill [r2]=rR2,16		// r2=&tf_r[FRAME_R4]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r3,16		// r1=&tf_r[FRAME_R5]
	.mem.offset 8,0
	st8.spill [r2]=r4,16		// r2=&tf_r[FRAME_R6]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r5,16		// r1=&tf_r[FRAME_R7]
	.mem.offset 8,0
	st8.spill [r2]=r6,16		// r2=&tf_r[FRAME_R8]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r7,16		// r1=&tf_r[FRAME_R9]
	.mem.offset 8,0
	st8.spill [r2]=r8,16		// r2=&tf_r[FRAME_R10]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r9,16		// r1=&tf_r[FRAME_R11]
	.mem.offset 8,0
	st8.spill [r2]=r10,16		// r2=&tf_r[FRAME_SP]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r11,16		// r1=&tf_r[FRAME_R13]
	.mem.offset 8,0
	st8.spill [r2]=rSP,16		// r2=&tf_r[FRAME_R14]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r13,16		// r1=&tf_r[FRAME_R15]
	.mem.offset 8,0
	st8.spill [r2]=r14,16		// r2=&tf_r[FRAME_R16]
	;; 
	.mem.offset 0,0
	st8.spill [r1]=r15,16		// r1=&tf_r[FRAME_R17]
	;; 
	bsw.1				// switch to bank 1
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r16,16		// r2=&tf_r[FRAME_R18]
	.mem.offset 0,0
	st8.spill [r1]=r17,16		// r1=&tf_r[FRAME_R19]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r18,16		// r2=&tf_r[FRAME_R20]
	.mem.offset 0,0
	st8.spill [r1]=r19,16		// r1=&tf_r[FRAME_R21]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r20,16		// r2=&tf_r[FRAME_R22]
	.mem.offset 0,0
	st8.spill [r1]=r21,16		// r1=&tf_r[FRAME_R23]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r22,16		// r2=&tf_r[FRAME_R24]
	.mem.offset 0,0
	st8.spill [r1]=r23,16		// r1=&tf_r[FRAME_R25]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r24,16		// r2=&tf_r[FRAME_R26]
	.mem.offset 0,0
	st8.spill [r1]=r25,16		// r1=&tf_r[FRAME_R27]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r26,16		// r2=&tf_r[FRAME_R28]
	.mem.offset 0,0
	st8.spill [r1]=r27,16		// r1=&tf_r[FRAME_R29]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r28,16		// r2=&tf_r[FRAME_R30]
	.mem.offset 0,0
	st8.spill [r1]=r29,16		// r1=&tf_r[FRAME_R31]
	;; 
	.mem.offset 8,0
	st8.spill [r2]=r30,24		// r2=&tf_f[FRAME_F6]
	.mem.offset 0,0
	st8.spill [r1]=r31,32		// r1=&tf_f[FRAME_F7]
	;; 
	stf.spill [r2]=f6,32		// r2=&tf_f[FRAME_F8]
	stf.spill [r1]=f7,32		// r1=&tf_f[FRAME_F9]
	;; 
	stf.spill [r2]=f8,32		// r2=&tf_f[FRAME_F10]
	stf.spill [r1]=f9,32		// r1=&tf_f[FRAME_F11]
	;; 
	stf.spill [r2]=f10,32		// r2=&tf_f[FRAME_F12]
	stf.spill [r1]=f11,32		// r1=&tf_f[FRAME_F13]
	;; 
	stf.spill [r2]=f12,32		// r2=&tf_f[FRAME_F14]
	stf.spill [r1]=f13,32		// r1=&tf_f[FRAME_F15]
	;; 
	stf.spill [r2]=f14		// 
	stf.spill [r1]=f15		// 
	;; 
	movl	r1=__gp			// kernel globals
	mov	r13=ar.k5		// processor globals
	ssm	psr.ic|psr.dt		// enable interrupts & translation
	;;
	srlz.d				// serialize

	br.ret.sptk.few b0

	END(exception_save_regs)
	

