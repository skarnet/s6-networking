/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

void sbearssl_ta_to (sbearssl_ta const *sta, br_x509_trust_anchor *bta, char *s)
{
  bta->dn = (unsigned char *)s + sta->dn ;
  bta->dn_len = sta->dnlen ;
  bta->flags = sta->flags ;
  sbearssl_pkey_to(&sta->pkey, &bta->pkey, s) ;
}
