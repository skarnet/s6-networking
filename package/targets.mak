BIN_TARGETS := \
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

ifneq ($(SSL_IMPL),)

BIN_TARGETS += s6-tlsclient s6-tlsc s6-tlsc-io s6-tlsserver s6-tlsd s6-tlsd-io s6-ucspitlsc s6-ucspitlsd

ifeq ($(SSL_IMPL),tls)

LIB_DEFS += CRYPTOSUPPORT=stls
CRYPTO_LIB := -ltls -lssl -lcrypto -lpthread

else ifeq ($(SSL_IMPL),bearssl)

LIB_DEFS += CRYPTOSUPPORT=sbearssl
CRYPTO_LIB := -lbearssl

else

CRYPTO_LIB := $(error invalid SSL_IMPL. Please configure with --enable-ssl=bearssl or --enable-ssl=libtls.)

endif
endif
