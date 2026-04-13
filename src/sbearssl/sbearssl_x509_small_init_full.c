/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_x509_small_init_full (sbearssl_x509_small_context *ctx, br_x509_trust_anchor *btas, size_t n, sbearssl_dn *eedn, uint8_t *eltstatus, char *eehash)
{
  return sbearssl_x509_small_init_full_options(ctx, btas, n, eedn, eltstatus, eehash, 0) ;
}
