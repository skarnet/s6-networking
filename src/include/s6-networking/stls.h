/* ISC license. */

#ifndef STLS_H
#define STLS_H

#include <stdint.h>

#include <tls.h>

#include <skalibs/gccattributes.h>
#include <skalibs/tai.h>

#define STLS_BUFSIZE (16384 + 325 + 1)


 /* Engine */

extern int stls_send_environment (struct tls *, int) ;
extern void stls_run (struct tls *, int *, uint32_t, unsigned int) gccattr_noreturn ;


 /* s6-tlsc-io and s6-tlsd-io */

struct tls *stls_client_init_and_handshake (int const *, tain_t const *, uint32_t, char const *) ;
struct tls *stls_server_init_and_handshake (int const *, tain_t const *, uint32_t) ;

#endif
