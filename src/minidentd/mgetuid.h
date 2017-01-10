/* ISC license. */

#ifndef MGETUID_H
#define MGETUID_H

#include <sys/types.h>
#include <stdint.h>
#include <skalibs/ip46.h>

extern uid_t mgetuid (ip46_t const *, uint16_t, ip46_t const *, uint16_t) ;

#endif
