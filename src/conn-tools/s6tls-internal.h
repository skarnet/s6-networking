/* ISC license */

#ifndef S6TLS_INTERNAL_H
#define S6TLS_INTERNAL_H

#include <stdint.h>
#include <unistd.h>

#include <skalibs/gccattributes.h>

#define s6tls_envvars "CADIR\0CAFILE\0KEYFILE\0CERTFILE\0TLS_UID\0TLS_GID"

extern void s6tls_exec_tlscio (int const *, uint32_t, unsigned int, unsigned int, char const *) gccattr_noreturn ;
extern void s6tls_exec_tlsdio (int const *, uint32_t, unsigned int, unsigned int) gccattr_noreturn ;
extern void s6tls_sync_and_exec_app (char const *const *, int const [4][2], pid_t, uint32_t) gccattr_noreturn ;
extern void s6tls_ucspi_exec_app (char const *const *, int const [4][2], uint32_t) gccattr_noreturn ;

#endif
