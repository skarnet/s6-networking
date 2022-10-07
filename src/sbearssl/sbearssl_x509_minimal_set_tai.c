/* ISC license. */

#include <stdint.h>
#include <bearssl.h>

#include <s6-networking/sbearssl.h>

int sbearssl_x509_minimal_set_tai (br_x509_minimal_context *ctx, tai const *t)
{
  uint32_t days, seconds ;
  if (!sbearssl_dayseconds_from_tai(&days, &seconds, t)) return 0 ;
  br_x509_minimal_set_time(ctx, days, seconds) ;
  return 1 ;
}
