/*-
 * Copyright 2003-2011 Netlogic Microsystems (Netlogic). All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY Netlogic Microsystems ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NETLOGIC OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * NETLOGIC_BSD */

#ifndef __NLM_USB_H__
#define __NLM_USB_H__

#define XLP_USB_CTL0			0x41
#define XLP_USB_PHY0			0x4A
#define USBPHYRESET			0x01
#define USBPHYPORTRESET0		0x10
#define USBPHYPORTRESET1		0x20
#define USBCONTROLLERRESET		0x01
#define XLP_USB_INT_STATUS		0x4E
#define XLP_USB_INT_EN			0x4F
#define USB_PHY_INTERRUPT_EN		0x01
#define USB_OHCI_INTERRUPT_EN		0x02
#define USB_OHCI_INTERRUPT1_EN		0x04
#define USB_OHCI_INTERRUPT12_EN		0x08
#define USB_CTRL_INTERRUPT_EN		0x10


#if !defined(LOCORE) && !defined(__ASSEMBLY__)

#define nlm_rdreg_usb(b, r)		nlm_read_reg_kseg(b,r)
#define nlm_wreg_usb(b, r, v)		nlm_write_reg_kseg(b,r,v)
#define	nlm_pcibase_usb(node, inst)	nlm_pcicfg_base(XLP_IO_USB_OFFSET(node, inst))
#define	nlm_base_usb_pcibar(node, inst)	nlm_pcibar0_base_xkphys(nlm_pcibase_usb(node, inst))
#define	nlm_regbase_usb(node, inst)	(nlm_pcibase_usb(node, inst))

#endif
#endif
