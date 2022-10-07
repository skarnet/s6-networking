/* ISC license. */

#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>

#include <s6-networking/sbearssl.h>

int sbearssl_tai_from_dayseconds (tai *t, uint32_t days, uint32_t seconds)
{
  return tai_from_utc(t, TAI_MAGIC + (uint64_t)86400 * (uint64_t)days + 719528 + seconds) ; 
}
