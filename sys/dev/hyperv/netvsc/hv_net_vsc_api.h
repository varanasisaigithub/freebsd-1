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


typedef void (*pfn_on_send_rx_completion)(void *);

#define NETVSC_DEVICE_RING_BUFFER_SIZE   (64 * PAGE_SIZE)
#define NETVSC_PACKET_MAXPAGE            4

typedef struct netvsc_packet_ {
	/*
	 * List used when enqueued on &net_dev->rx_packet_list,
	 * and when enqueued within the netvsc code
	 */
	STAILQ_ENTRY(netvsc_packet_) mylist_entry;
	DEVICE_OBJECT           *device;
	bool                    is_data_pkt;      /* One byte */
	xfer_page_packet        *xfer_page_pkt;

	/* Completion */
	union {
		struct {
			uint64_t rx_completion_tid;
			void	*rx_completion_context;
			/* This is no longer used */
			pfn_on_send_rx_completion   on_rx_completion;
		} rx;
		struct {
			uint64_t send_completion_tid;
			void	*send_completion_context;
			/* Still used in netvsc and filter code */
			pfn_on_send_rx_completion   on_send_completion;
		} send;
	} compl;

	void		*extension;
	uint32_t	tot_data_buf_len;
	uint32_t	page_buf_count;
	PAGE_BUFFER	page_buffers[NETVSC_PACKET_MAXPAGE];
} netvsc_packet;


typedef struct netvsc_driver_object_ {
	DRIVER_OBJECT	base;
	uint32_t	ring_buf_size;
	uint32_t	request_ext_size;
	uint32_t	additional_request_page_buf_cnt;
	void		*context;
} netvsc_driver_object;

typedef struct {
	uint8_t         mac_addr[6];  /* Assumption unsigned long */
	bool            link_state;
} netvsc_device_info;

/*
 * Device-specific softc structure
 */
typedef struct hn_softc {
	struct ifnet    *hn_ifp;
	struct arpcom   arpcom;
	device_t        hn_dev;
	uint8_t         hn_unit;
	int             hn_carrier;
	int             hn_if_flags;
	struct mtx      hn_lock;
//	vm_offset_t     hn_vaddr;
	int             hn_initdone;
//	int             hn_xc;
	DEVICE_OBJECT   *hn_dev_obj;
//	int             hn_cb_status;
//	uint64_t        hn_sts_err_tx_nobufs;
//	uint64_t        hn_sts_err_tx_enxio; /* device not ready to xmit */
//	uint64_t        hn_sts_err_tx_eio;   /* device not ready to xmit */
} hn_softc_t;


/*
 * Externs
 */
extern int promisc_mode;

extern void hv_nv_on_receive_completion(void *context);
extern int  hv_net_vsc_initialize(DRIVER_OBJECT *drv);
extern void netvsc_linkstatus_callback(DEVICE_OBJECT *device_obj,
				       uint32_t status);
extern int  netvsc_recv_callback(DEVICE_OBJECT *device_obj,
				 netvsc_packet *packet);
extern int  hv_nv_on_device_add(DEVICE_OBJECT *device, void *additional_info);
extern int  hv_nv_on_device_remove(DEVICE_OBJECT *device);
extern void hv_nv_on_cleanup(DRIVER_OBJECT *driver);
extern int  hv_nv_on_send(DEVICE_OBJECT *device, netvsc_packet *pkt);


#endif  /* __HV_NET_VSC_API_H__ */

