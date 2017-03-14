/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ec_skey_from (sbearssl_ec_skey *l, br_ec_private_key const *k, stralloc *sa)
{
  if (!stralloc_catb(sa, (char const *)k->x, k->xlen)) return 0 ;
  l->curve = k->curve ;
  l->x = sa->len - k->xlen ;
  l->xlen = k->xlen ;
  return 1 ;
}
