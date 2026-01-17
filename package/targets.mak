BIN_TARGETS := \
proxy-server \
s6-getservbyname \
s6-ident-client \
s6-tcpclient \
s6-tcpserver \
s6-tcpserver-socketbinder \
s6-tcpserverd \
s6-tcpserver-access \
s6-clockadd \
s6-clockview \
s6-sntpclock \
s6-taiclock \
s6-taiclockd

LIBEXEC_TARGETS :=

LIB_DEFS := S6NET=s6net
S6NET_DESCRIPTION := A client library implementing various networking protocols

ifneq ($(SSL_IMPL),)

BIN_TARGETS += s6-tlsclient s6-tlsc s6-tlsc-io s6-tlsserver s6-tlsd s6-tlsd-io s6-ucspitlsc s6-ucspitlsd

ifeq ($(SSL_IMPL),tls)

LIB_DEFS += CRYPTOSUPPORT=stls
CRYPTOSUPPORT_DESCRIPTION := A TLS tunnel library, using libtls as backend
CRYPTO_LIB := -ltls -lssl -lcrypto -lpthread
EXTRA_TARGETS += libsbearssl.a.xyzzy libsbearssl.so libsbearssl.pc

else ifeq ($(SSL_IMPL),bearssl)

LIB_DEFS += CRYPTOSUPPORT=sbearssl
CRYPTOSUPPORT_DESCRIPTION := A TLS tunnel library, using BearSSL as backend
CRYPTO_LIB := -lbearssl
EXTRA_TARGETS += libstls.a.xyzzy libstls.so libstls.pc

else

CRYPTO_LIB := $(error invalid SSL_IMPL. Please configure with --enable-ssl=bearssl or --enable-ssl=libtls.)

endif
endif
