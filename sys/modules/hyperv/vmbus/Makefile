# $FreeBSD$

.PATH:	${.CURDIR}/../../../dev/hyperv/vmbus \
	${.CURDIR}/../../../dev/hyperv/vmbus/utilities

KMOD=	 hv_vmbus

SRCS =  hv_channel.c \
	hv_channel_interface.c \
	hv_channel_mgmt.c \
	hv_connection.c \
	hv_hv.c \
	hv_ring_buffer.c \
	hv_osd_freebsd.c \
	hv_vmbus.c \
	hv_vmbus_drv_freebsd.c \
	hv_channel.h \
	hv_channel_interface.h \
	hv_channel_mgmt.h \
	hv_connection.h \
	hv_hv.h \
	hv_ic.h \
	hv_ring_buffer.h \
	hv_version_info.h \
	hv_vmbus.h \
	hv_vmbus_api.h \
	hv_vmbus_private.h \
	hv_vmbus_var.h



CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus \
	 -I${.CURDIR}/../../../dev/hyperv/vmmbus/utilities

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}


.include <bsd.kmod.mk>
