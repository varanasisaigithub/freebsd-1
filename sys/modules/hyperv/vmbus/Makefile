# $FreeBSD$

.PATH:	${.CURDIR}/../../../dev/hyperv/vmbus \
	${.CURDIR}/../../../dev/hyperv/vmbus/utilities

KMOD=	 hv_vmbus

SRCS =  hv_channel.c \
	hv_channel_mgmt.c \
	hv_connection.c \
	hv_hv.c \
	hv_ring_buffer.c \
	hv_vmbus_drv_freebsd.c \
	hv_vmbus_priv.h \

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus \
	 -I${.CURDIR}/../../../dev/hyperv/vmmbus/utilities \
	 -I /usr/src/sys/sys/

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}

.include <bsd.kmod.mk>
