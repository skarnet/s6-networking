/* ISC license. */

#include <stdint.h>
#include <bearssl.h>

#include <skalibs/tai.h>

#include <s6-networking/sbearssl.h>

int sbearssl_x509_time_check (void *ctx, uint32_t nbd, uint32_t nbs, uint32_t nad, uint32_t nas)
{
  uint32_t days, seconds ;
  if (!sbearssl_dayseconds_from_tai(&days, &seconds, (tai *)ctx)) return -2 ;
  if (days < nbd || (days == nbd && seconds < nbs)) return -1 ;
  return days > nad || (days == nad && seconds > nas) ;
}
