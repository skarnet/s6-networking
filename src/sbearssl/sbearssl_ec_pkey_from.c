/* ISC license. */

#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ec_pkey_from (sbearssl_ec_pkey *l, br_ec_public_key const *k, stralloc *sa)
{
  if (!stralloc_catb(sa, (char const *)k->q, k->qlen)) return 0 ;
  l->curve = k->curve ;
  l->q = sa->len - k->qlen ;
  l->qlen = k->qlen ;
  return 1 ;
}
