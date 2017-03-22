/* ISC license. */

#ifndef STLS_INTERNAL_H
#define STLS_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

extern pid_t stls_prep_spawn_drop (char const *const *, char const *const *, int *, uid_t, gid_t, uint32_t) ;

#endif
