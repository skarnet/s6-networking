/* ISC license. */

#ifndef STLS_H
#define STLS_H

#include <sys/types.h>
#include <stdint.h>
#include <tls.h>
#include <skalibs/tai.h>

#define STLS_BUFSIZE (16384 + 325 + 1)


 /* Engine */

extern int stls_run (struct tls *, int *, pid_t, unsigned int, uint32_t, tain_t const *) ;


 /* s6-tlsc and s6-tlsd implementations */

extern int stls_s6tlsc (char const *const *, char const *const *, tain_t const *, uint32_t, uint32_t, uid_t, gid_t, unsigned int, char const *, int *) ;
extern int stls_s6tlsd (char const *const *, char const *const *, tain_t const *, uint32_t, uint32_t, uid_t, gid_t, unsigned int) ;

#endif
