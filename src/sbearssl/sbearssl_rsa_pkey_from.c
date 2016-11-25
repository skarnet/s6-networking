/* ISC license. */

#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_rsa_pkey_from (sbearssl_rsa_pkey *l, br_rsa_public_key const *k, stralloc *sa)
{
  if (!stralloc_readyplus(sa, k->nlen + k->elen)) return 0 ;
  l->n = sa->len ;
  stralloc_catb(sa, (char const *)k->n, k->nlen) ;
  l->nlen = k->nlen ;
  l->e = sa->len ;
  stralloc_catb(sa, (char const *)k->e, k->elen) ;
  l->elen = k->elen ;
  return 1 ;
}
