BIN_TARGETS := \
s6-connlimit \
s6-getservbyname \
s6-ioconnect \
s6-ident-client \
s6-ipcclient \
s6-ipcserver \
s6-tcpclient \
s6-tcpserver4 \
s6-tcpserver6 \
s6-tcpserver \
s6-accessrules-cdb-from-fs \
s6-accessrules-fs-from-cdb \
s6-ipcserver-access \
s6-tcpserver-access \
seekablepipe \
s6-sudo \
s6-sudoc \
s6-sudod \
s6-clockadd \
s6-clockview \
s6-sntpclock \
s6-taiclock \
s6-taiclockd \
minidentd

LIBEXEC_TARGETS :=

ifdef DO_SHARED
SHARED_LIBS := libs6net.so
endif

ifdef DO_STATIC
STATIC_LIBS := libs6net.a
endif

EXTRA_TARGETS := src/minidentd/mgetuid.c

src/minidentd/mgetuid.c: src/minidentd/mgetuid-linux.c src/minidentd/mgetuid-default.c
	if grep -iF -- -linux- $(sysdeps)/target ; then \
	  ln -sf mgetuid-linux.c src/minidentd/mgetuid.c ; \
	else \
	  ln -sf mgetuid-default.c src/minidentd/mgetuid.c ; \
	fi
