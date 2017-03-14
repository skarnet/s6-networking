/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_rsa_pkey_to (sbearssl_rsa_pkey const *l, br_rsa_public_key *k, char *s)
{
  k->n = (unsigned char *)s + l->n ;
  k->nlen = l->nlen ;
  k->e = (unsigned char *)s + l->e ;
  k->elen = l->elen ;
}
