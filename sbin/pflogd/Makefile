# $FreeBSD$

.PATH:	${.CURDIR}/../../contrib/pf/pflogd

PROG=	pflogd
SRCS= 	pflogd.c pidfile.c privsep.c privsep_fdpass.c
MAN=	pflogd.8

LDADD=	-lpcap -lutil
DPADD=	${LIBPCAP} ${LIBUTIL}

WARNS?=	2

.include <bsd.prog.mk>
