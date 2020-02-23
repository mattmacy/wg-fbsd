.if !defined(WITH_CTF)
WITH_CTF=1
.endif

.include <bsd.sys.mk>

SRCDIR= ${.CURDIR}/module
INCDIR=${.CURDIR}/include
ZINCDIR= ${SRCDIR}/crypto/zinc

KMOD=   if_wg

.PATH: ${SRCDIR}
.PATH: ${ZINCDIR}

CFLAGS+= -I${INCDIR}

CFLAGS+= -D__KERNEL__ -D__BSD_VISIBLE=1
CFLAGS+= -ferror-limit=5
CFLAGS+= -include ${INCDIR}/sys/support.h

.if defined(WITH_DEBUG) && ${WITH_DEBUG} == "true"
CFLAGS+= -DINVARIANTS -DWITNESS -g -O0
.else
CFLAGS += -DNDEBUG
.endif

DEBUG_FLAGS=-g

SRCS+= opt_inet.h opt_inet6.h device_if.h bus_if.h ifdi_if.h

#SRCS+= module.c cookie.c noise.c peer.c whitelist.c
SRCS+= if_wg_session.c module.c curve25519.c blake2s.c
.include <bsd.kmod.mk>
