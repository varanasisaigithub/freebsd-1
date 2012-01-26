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
 * HyperV netvsc API header
 *
 */

#ifndef __HV_NET_VSC_API_H__
#define __HV_NET_VSC_API_H__


typedef void (*PFN_ON_SENDRECVCOMPLETION)(void *);

#define NETVSC_DEVICE_RING_BUFFER_SIZE   (64 * PAGE_SIZE)
#define NETVSC_PACKET_MAXPAGE            4

typedef struct netvsc_packet_ {
	DLIST_ENTRY             ListEntry;
	DEVICE_OBJECT           *Device;
	bool                    IsDataPacket;  // One byte
	XFERPAGE_PACKET         *XferPagePacket;
	
	union {
		struct {
			uint64_t ReceiveCompletionTid;
			void	*ReceiveCompletionContext;
			PFN_ON_SENDRECVCOMPLETION OnReceiveCompletion;
		} Recv;	
		struct {
			uint64_t SendCompletionTid;
			void	*SendCompletionContext;
			PFN_ON_SENDRECVCOMPLETION   OnSendCompletion;
		} Send;	
	} Completion;

	void		*Extension;
	uint32_t	TotalDataBufferLength;
	uint32_t	PageBufferCount;
	PAGE_BUFFER PageBuffers[NETVSC_PACKET_MAXPAGE];
} netvsc_packet;


typedef struct netvsc_driver_object_ {
	DRIVER_OBJECT	Base;
	uint32_t	RingBufferSize;
	uint32_t	RequestExtSize;
	uint32_t	AdditionalRequestPageBufferCount;
	int32_t		(*OnReceiveCallback)(DEVICE_OBJECT *, netvsc_packet *);
	void		(*OnLinkStatusChanged)(DEVICE_OBJECT *, uint32_t) ;
	int32_t		(*OnOpen)(DEVICE_OBJECT *);
	int32_t		(*OnClose)(DEVICE_OBJECT *);
	int32_t		(*OnSend)(DEVICE_OBJECT *, netvsc_packet *);
	void		*context;
} netvsc_driver_object;	

typedef struct {
	uint8_t         MacAddr[6];  //Assumption unsigned long 
	bool            LinkState;
} netvsc_device_info;


/*
 * ported from sys/nic/ns_hn.h (NetScaler-only file)
 * Fixme:  May need some pruning.
 */

typedef struct hn_softc {
	struct ifnet    *hn_ifp;
	struct arpcom   arpcom;
	device_t        hn_dev;
	uint8_t         hn_unit;
	int             hn_carrier;
	int             hn_if_flags;
	struct mtx      hn_lock;
	vm_offset_t     hn_vaddr;
	int             hn_initdone;
	int             hn_xc;
	DEVICE_OBJECT   *hn_dev_obj;
	int             hn_cb_status;
	uint64_t        hn_sts_err_tx_nobufs;
	uint64_t        hn_sts_err_tx_enxio; //device not ready to xmit
	uint64_t        hn_sts_err_tx_eio;   //device not ready to xmit
} hn_softc_t;


/*
 * Externs
 */
extern int promisc_mode;

extern void
hv_nv_on_receive_completion(void *Context);

extern int
hv_net_vsc_initialize(DRIVER_OBJECT *drv);

#endif  /* __HV_NET_VSC_API_H__ */

