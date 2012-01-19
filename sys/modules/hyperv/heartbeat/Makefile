#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/hyperv/vmbus/utilities

KMOD=	hv_heartbeat

SRCS =  hv_heartbeat_drv_freebsd.c

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus	\
	 -I${.CURDIR}/../../../dev/hyperv/vmbus/utilities

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}

.include <bsd.kmod.mk>
