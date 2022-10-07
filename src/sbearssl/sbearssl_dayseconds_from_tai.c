/* ISC license. */

#include <errno.h>

#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>

#include <s6-networking/sbearssl.h>

int sbearssl_dayseconds_from_tai (uint32_t *days, uint32_t *seconds, tai const *t)
{
  uint64_t u, d ;
  if (!utc_from_tai(&u, t)) return 0 ;
  u -= TAI_MAGIC ;
  d = u / 86400 + 719528 ;
  if (d >= 0xffffffffUL) return (errno = EOVERFLOW, 0) ;
  *days = d ;
  *seconds = u % 86400 ;
  return 1 ;
}
