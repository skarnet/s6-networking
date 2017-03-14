/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_ec_skey_to (sbearssl_ec_skey const *l, br_ec_private_key *k, char *s)
{
  k->curve = l->curve ;
  k->x = (unsigned char *)s + l->x ;
  k->xlen = l->xlen ;
}
