#	@(#)Makefile.inc	8.1 (Berkeley) 6/8/93
# $FreeBSD$

.include <bsd.own.mk>

BINDIR?=	/sbin
WARNS?=	2

.if ${MK_DYNAMICROOT} == "no"
NO_SHARED?=	YES
.endif
