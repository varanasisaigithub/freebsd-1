#ifndef __HV_STORVSC_API_H__
#define __HV_STORVSC_API_H__
/*
 * File referenced in MS Hyper-v code, but missing.
 */

#include <hv_osd.h>
#include <hv_vmbus_api.h>
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

struct storvsc_request {
	LIST_ENTRY(storvsc_request) link;
	void *Extension;
	uint32_t Host;
	uint8_t TargetId;
	uint8_t PathId;
	uint8_t LunId;
	uint8_t Bus;
	uint8_t CdbLen;
	uint8_t Cdb[CDB16GENERIC_LENGTH];
	enum storvsc_request_type Type;
	MULTIPAGE_BUFFER DataBuffer;
	uint8_t Status;
	uint8_t SenseBufferSize;
	void *SenseBuffer;
	union ccb *Ccb;
	struct storvsc_softc *Softc;
	uint32_t BytesXfer;
};
typedef struct storvsc_driver_object_s {
	DRIVER_OBJECT Base;
	uint32_t RingBufferSize;
	uint32_t RequestExtSize;
	uint32_t MaxOutstandingRequestsPerChannel;
} STORVSC_DRIVER_OBJECT;

typedef struct storvsc_device_info STORVSC_DEVICE_INFO;
struct storvsc_device_info {
	uint32_t PortNumber;
	uint8_t PathId;
	uint8_t TargetId;
};

extern void hv_storvsc_io_completion(struct storvsc_request *reqp);
extern int hv_storvsc_host_reset(DEVICE_OBJECT *Device);
extern int hv_storvsc_io_request(DEVICE_OBJECT *Device, struct storvsc_request *request);

#endif /* __HV_STORVSC_API_H__ */
