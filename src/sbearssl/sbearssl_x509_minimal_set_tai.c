/* ISC license. */

#include <sys/types.h>
#include <bearssl.h>
#include <skalibs/uint64.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>
#include <s6-networking/sbearssl.h>

int sbearssl_x509_minimal_set_tai (br_x509_minimal_context *ctx, tai_t const *t)
{
  uint64 u ;
  if (!utc_from_tai(&u, t)) return 0 ;
  u -= TAI_MAGIC ;
  br_x509_minimal_set_time(ctx, (uint32_t)(u / 86400 + 719528), u % 86400) ;
  return 1 ;
}
