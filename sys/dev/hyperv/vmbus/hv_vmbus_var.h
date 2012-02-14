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
 * HyperV vmbus header file
 *
 */

#ifndef __HV_VMBUS_VAR_H__
#define __HV_VMBUS_VAR_H__

#include <dev/hyperv/include/hv_osd.h>

#define BLKVSC_RING_BUFFER_SIZE 32

typedef struct {
	int Length; //channel.c :->897->936
	int Offset; //channel.c :->937
	uint64_t Pfn;    //channel.c:-> 938
} PAGE_BUFFER; //channel.c : 897

#define MAX_MULTIPAGE_BUFFER_COUNT 32

typedef struct { // Channel.c : 980
	int Length;  // channel.c :1019
	int Offset;  //channel.c :1020
	uint64_t PfnArray[MAX_MULTIPAGE_BUFFER_COUNT]; //channel.c : 1022
} MULTIPAGE_BUFFER;

typedef struct {
	int InterruptMask;
	int ReadIndex;
	int WriteIndex;
	int BytesAvailToRead;
	int BytesAvailToWrite;
} BOUND;

typedef struct {
	int ChannelId; //ChannelInterface.c:  188
	int ChannelState; //ChannelInterface.c 189
	int ChannelType;  //ChannelInterface.c 190
	int ChannelInstance;
	int MonitorId;
	int ServerMonitorPending;
	int ServerMonitorLatency;
	int ServerMonitorConnectionId;
	int ClientMonitorPending;
	int ClientMonitorLatency;
	int ClientMonitorConnectionId;
	BOUND Inbound, Outbound;
} DEVICE_INFO;

typedef void (*VMBUS_CHANNEL_CALLBACK)(void *context);

struct _DRIVER_OBJECT;
typedef struct {
	struct _DRIVER_OBJECT *Driver;  //332
	char name[64];
	GUID deviceType;  //'' ''   : 281->:: vmbus.c ->257
	GUID deviceInstance; //,, ,, : 282 ->:: vmbus.c ->258
	void *context; // vmbus_drv_obj : 280->
	void *Extension; // :172
} DEVICE_OBJECT;

typedef struct { //ChannelInterface.c : 160
	int (*Open)(DEVICE_OBJECT*, uint32_t, uint32_t, void *, uint32_t,
		VMBUS_CHANNEL_CALLBACK, void *);
	void (*Close)(DEVICE_OBJECT *); //42
	int (*SendPacket)(DEVICE_OBJECT *, void *, uint32_t, uint64_t, uint32_t,
		uint32_t);        //50
	int (*SendPacketPageBuffer)(DEVICE_OBJECT *, PAGE_BUFFER *, uint32_t,
		void *, uint32_t, uint64_t);
	int (*SendPacketMultiPageBuffer)(DEVICE_OBJECT *, MULTIPAGE_BUFFER *,
		void *, uint32_t, uint64_t);
	int (*RecvPacket)(DEVICE_OBJECT *, void *, uint32_t, uint32_t*, uint64_t*);
	int (*RecvPacketRaw)(DEVICE_OBJECT *, void *, uint32_t, uint32_t*, uint64_t*);
	int (*EstablishGpadl)(DEVICE_OBJECT *, void *, uint32_t, uint32_t*);
	int (*TeardownGpadl)(DEVICE_OBJECT *, uint32_t);
	void (*GetInfo)(DEVICE_OBJECT *, DEVICE_INFO *);
} VMBUS_CHANNEL_INTERFACE;

typedef struct _DRIVER_OBJECT {        //BlkVsc.c : 56
	const char *name;  //67 : 39
	GUID	deviceType; //68 :
	int	(*OnDeviceAdd)(DEVICE_OBJECT *, void*);
	int	(*OnDeviceRemove)(DEVICE_OBJECT *);
	char 	**(*OnGetDeviceIds)(void);
	void 	(*OnCleanup)(struct _DRIVER_OBJECT *);
	// replace indirect calls with direct ones
	//VMBUS_CHANNEL_INTERFACE VmbusChannelInterface;
} DRIVER_OBJECT;

#define PDEVICE_OBJECT DEVICE_OBJECT*
#define PDRIVER_OBJECT DRIVER_OBJECT*

extern int hv_storvsc_init(PDRIVER_OBJECT);
extern int hv_blkvsc_init(PDRIVER_OBJECT);

extern void shutdown_onchannelcallback(void *); // drivers/closed/vmbus/ChannelMgmt.c

typedef struct _XFERPAGE {
	DLIST_ENTRY ListEntry;
	uint32_t Count;
} XFERPAGE_PACKET;

typedef int (*PFN_DRIVERINITIALIZE)(DRIVER_OBJECT*);
typedef int (*PFN_DRIVEREXIT)(DRIVER_OBJECT*);

#endif  /* __HV_VMBUS_VAR_H__ */

