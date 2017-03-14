/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_ec_pkey_to (sbearssl_ec_pkey const *l, br_ec_public_key *k, char *s)
{
  k->curve = l->curve ;
  k->q = (unsigned char *)s + l->q ;
  k->qlen = l->qlen ;
}
