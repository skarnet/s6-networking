/* ISC license */

#ifndef S6TLS_INTERNAL_H
#define S6TLS_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>

#define S6TLS_PREP_IO_ARGC 15
#define S6TLS_PREP_IO_BUFLEN (5 * UINT_FMT)

extern pid_t s6tls_io_spawn (char const *const *argv, int const *, int) ;
extern void s6tls_prep_tlscio (char const **, char *, int const *, uint32_t, unsigned int, unsigned int, char const *) ;
extern void s6tls_prep_tlsdio (char const **, char *, int const *, uint32_t, unsigned int, unsigned int, unsigned int) ;
extern void s6tls_sync_and_exec_app (char const *const *, int const *, pid_t, uint32_t) gccattr_noreturn ;
extern void s6tls_ucspi_exec_app (char const *const *, int const *, uint32_t) gccattr_noreturn ;
extern void s6tls_clean_and_exec (char const *const *, uint32_t, char const *, size_t) gccattr_noreturn ;

#endif
