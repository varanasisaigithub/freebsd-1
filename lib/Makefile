#	@(#)Makefile	8.1 (Berkeley) 6/4/93
# $FreeBSD$

.include <bsd.own.mk>

# To satisfy shared library or ELF linkage when only the libraries being
# built are visible:
#
# csu must be built before all shared libaries for ELF.
# libc must be built before all other shared libraries.
# libbsm must be built before ibauditd.
# libcom_err must be built before libpam.
# libcrypt must be built before libpam.
# libkvm must be built before libdevstat.
# msun must be built before libg++ and libstdc++.
# libmd must be built before libatm, libopie, libradius, and libtacplus.
# ncurses must be built before libdialog, libedit and libreadline.
# libnetgraph must be built before libbsnmp/modules/snmp_netgraph.
# libopie must be built before libpam.
# libradius must be built before libpam.
# librpcsvc must be built before libpam.
# libsbuf must be built before libcam.
# libtacplus must be built before libpam.
# libutil must be built before libpam.
# libypclnt must be built before libpam.
# libgssapi must be built before librpcsec_gss
#
# Otherwise, the SUBDIR list should be in alphabetical order.
#
# Except it appears bind needs to be compiled last

SUBDIR_ORDERED=	${_csu} \
	libc \
	libbsm \
	libauditd \
	libcom_err \
	libcrypt \
	libelf \
	libkvm \
	msun \
	libmd \
	ncurses \
	${_libnetgraph} \
	libradius \
	librpcsvc \
	libsbuf \
	libtacplus \
	libutil \
	${_libypclnt}

SUBDIR= ${SUBDIR_ORDERED} \
	libalias \
	libarchive \
	${_libatm} \
	libbegemot \
	${_libbluetooth} \
	${_libbsnmp} \
	libbz2 \
	libcalendar \
	libcam \
	libcompat \
	libdevinfo \
	libdevstat \
	libdisk \
	libdwarf \
	libedit \
	libexpat \
	libfetch \
	libftpio \
	libgeom \
	${_libgpib} \
	${_libgssapi} \
	${_librpcsec_gss} \
	libipsec \
	${_libipx} \
	libjail \
	libkiconv \
	liblzma \
	libmagic \
	libmemstat \
	${_libmilter} \
	${_libmp} \
	${_libncp} \
	${_libngatm} \
	libopie \
	libpam \
	libpcap \
	${_libpmc} \
	${_libproc} \
	librt \
	${_librtld_db} \
	${_libsdp} \
	${_libsm} \
	${_libsmb} \
	${_libsmdb} \
	${_libsmutil} \
	libstand \
	${_libtelnet} \
	${_libthr} \
	libthread_db \
	libufs \
	libugidfw \
	${_libusbhid} \
	${_libusb} \
	${_libvgl} \
	libwrap \
	liby \
	libz \
	${_bind}

.if exists(${.CURDIR}/csu/${MACHINE_ARCH}-elf)
_csu=csu/${MACHINE_ARCH}-elf
.elif exists(${.CURDIR}/csu/${MACHINE_ARCH}/Makefile)
_csu=csu/${MACHINE_ARCH}
.else
_csu=csu
.endif

# NB: keep these sorted by MK_* knobs

.if ${MK_ATM} != "no"
_libngatm=	libngatm
.endif

.if ${MK_BIND} != "no"
_bind=		bind
.endif

.if ${MK_BLUETOOTH} != "no"
_libbluetooth=	libbluetooth
_libsdp=	libsdp
.endif

.if ${MK_BSNMP} != "no"
_libbsnmp=	libbsnmp
.endif

.if ${MK_GPIB} != "no"
_libgpib=	libgpib
.endif

.if ${MK_GSSAPI} != "no"
_libgssapi=	libgssapi
_librpcsec_gss=	librpcsec_gss
.endif

.if ${MK_IPX} != "no"
_libipx=	libipx
.endif

.if ${MK_LIBTHR} != "no"
_libthr=	libthr
.endif

.if ${MK_NETGRAPH} != "no"
_libnetgraph=	libnetgraph
.endif

.if ${MK_NIS} != "no"
_libypclnt=	libypclnt
.endif

.if ${MACHINE_ARCH} == "i386" || ${MACHINE_ARCH} == "amd64"
.if ${MK_NCP} != "no"
_libncp=	libncp
.endif
_libsmb=	libsmb
_libvgl=	libvgl
_libproc=	libproc
_librtld_db=	librtld_db
.endif

.if ${MACHINE_ARCH} == "ia64"
_libsmb=	libsmb
.endif

.if ${MACHINE_ARCH} == "powerpc"
_libsmb=	libsmb
.endif

.if ${MK_OPENSSL} != "no"
_libmp=		libmp
.endif

.if ${MK_PMC} != "no"
_libpmc=	libpmc
.endif

.if ${MK_SENDMAIL} != "no"
_libmilter=	libmilter
_libsm=		libsm
_libsmdb=	libsmdb
_libsmutil=	libsmutil
.endif

.if ${MK_TELNET} != "no"
_libtelnet=	libtelnet
.endif

.if ${MK_USB} != "no"
_libusbhid=	libusbhid
_libusb=	libusb
.endif

.include <bsd.subdir.mk>
