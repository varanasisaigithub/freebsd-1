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
 * HyperV vmbus API header file
 *
 */

#ifndef __HV_VMBUS_API_H__
#define __HV_VMBUS_API_H__

typedef struct {
	DRIVER_OBJECT Base;
	DEVICE_OBJECT *(*OnChildDeviceCreate)(GUID,GUID,void *);
	void (*OnChildDeviceDestroy)(DEVICE_OBJECT *);
	int  (*OnChildDeviceAdd)(DEVICE_OBJECT *,DEVICE_OBJECT *);
	void (*OnChildDeviceRemove)(DEVICE_OBJECT *);
	int  (*OnIsr)(DRIVER_OBJECT *);
	void (*OnMsgDpc)(DRIVER_OBJECT *);
	void (*OnEventDpc)(DRIVER_OBJECT *);
	void (*GetChannelOffers)(void );
	void (*GetChannelInterface)(VMBUS_CHANNEL_INTERFACE *);
	void (*GetChannelInfo)(DEVICE_OBJECT *,DEVICE_INFO *);
} VMBUS_DRIVER_OBJECT;

int VmbusInitialize(DRIVER_OBJECT* drv);
#define memcpy(dst, src, size) __builtin_memcpy((dst), (src), (size))

#endif  /* __HV_VMBUS_API_H__ */

