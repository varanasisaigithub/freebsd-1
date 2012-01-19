#$FreeBSD$

.PATH:  ${.CURDIR}/../../../dev/hyperv/storvsc

KMOD=	 hv_storvsc

SRCS =  hv_stor_vsc.c \
	hv_storvsc_drv_freebsd.c \
	hv_stor_vsc_api.h \
	hv_vstorage.h

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I${.CURDIR}/../../../dev/hyperv/vmbus	\
	 -I${.CURDIR}/../../../dev/hyperv/storvsc

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}

.include <bsd.kmod.mk>
