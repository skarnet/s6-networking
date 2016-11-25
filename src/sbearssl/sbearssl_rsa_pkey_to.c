/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

void sbearssl_rsa_pkey_ro (sbearssl_rsa_pkey const *l, br_rsa_public_key *k, char const *s)
{
  k->n = s + l->n ;
  k->nlen = l->nlen ;
  k->e = s + l->e ;
  k->elen = l->elen ;
}
