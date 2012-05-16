# $FreeBSD$

.PATH:	${.CURDIR}/../../../dev/hyperv/utilities

KMOD=	 hv_utils

SRCS =  hv_util.c

CFLAGS+= -I${.CURDIR}/../../../dev/hyperv/include \
	 -I /usr/src/sys/sys/

CFLAGS  += -fms-extensions -fformat-extensions ${.IMPSRC}


.include <bsd.kmod.mk>
