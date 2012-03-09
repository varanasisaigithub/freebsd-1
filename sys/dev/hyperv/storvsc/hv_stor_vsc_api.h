#ifndef __HV_STORVSC_API_H__
#define __HV_STORVSC_API_H__

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/condvar.h>

#include "hv_vstorage.h"

#include <cam/cam.h>
#include <cam/cam_ccb.h>

#define MAX_MULTIPAGE_BUFFER_PACKET (4096)
#define STORVSC_RINGBUFFER_SIZE		(20*PAGE_SIZE)
#define STORVSC_MAX_LUNS_PER_TARGET	(64)
#define STORVSC_MAX_IO_REQUESTS		(STORVSC_MAX_LUNS_PER_TARGET * 2)
#define BLKVSC_MAX_IDE_DISKS_PER_TARGET	(1)
#define BLKVSC_MAX_IO_REQUESTS		STORVSC_MAX_IO_REQUESTS
#define STORVSC_MAX_TARGETS		(1)

struct storvsc_softc;

enum storvsc_request_type {
	WRITE_TYPE,
	READ_TYPE,
	UNKNOWN_TYPE
};

struct hv_storvsc_request {
	LIST_ENTRY(hv_storvsc_request) link;
	struct vstor_packet	vstor_packet;
	MULTIPAGE_BUFFER data_buf;
	void *sense_data;
	uint8_t sense_info_len;
	uint8_t retries;
	union ccb *ccb;
	struct storvsc_softc *softc;
	struct callout callout;

	// Synchronize the request/response if needed
	struct {
		struct cv  cv;
		struct mtx mtx;
	} event;
};

struct storvsc_driver_object {
	DRIVER_OBJECT Base;
	uint32_t ringbuffer_size;
};

struct storvsc_softc {
        DEVICE_OBJECT *storvsc_dev;
        LIST_HEAD(, hv_storvsc_request) free_list;
        struct mtx       hs_lock;
        struct storvsc_driver_object  drv_obj;
        struct storvsc_driver_props      *drv_props;
        int unit;
        uint32_t         hs_frozen;
        struct cam_sim  *hs_sim;
        struct cam_path *hs_path;
};


extern void storvsc_io_done(struct hv_storvsc_request *reqp);
extern int hv_storvsc_on_deviceadd(DEVICE_OBJECT *device,
				   struct storvsc_softc *sc);
extern int hv_storvsc_on_deviceremove(DEVICE_OBJECT *device);
extern void hv_storvsc_on_cleanup(DRIVER_OBJECT *driver);
extern int hv_storvsc_host_reset(DEVICE_OBJECT *device);
extern int hv_storvsc_io_request(DEVICE_OBJECT *device,
								 struct hv_storvsc_request *request);

#endif /* __HV_STORVSC_API_H__ */
