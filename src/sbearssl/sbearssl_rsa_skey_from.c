/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_rsa_skey_from (sbearssl_rsa_skey *l, br_rsa_private_key const *k, stralloc *sa)
{
  if (!stralloc_readyplus(sa, k->plen + k->qlen + k->dplen + k->dqlen + k->iqlen)) return 0 ;
  l->n_bitlen = k->n_bitlen ;
  l->p = sa->len ;
  stralloc_catb(sa, (char const *)k->p, k->plen) ;
  l->plen = k->plen ;
  l->q = sa->len ;
  stralloc_catb(sa, (char const *)k->q, k->qlen) ;
  l->qlen = k->qlen ;
  l->dp = sa->len ;
  stralloc_catb(sa, (char const *)k->dp, k->dplen) ;
  l->dplen = k->dplen ;
  l->dq = sa->len ;
  stralloc_catb(sa, (char const *)k->dq, k->dqlen) ;
  l->dqlen = k->dqlen ;
  l->iq = sa->len ;
  stralloc_catb(sa, (char const *)k->iq, k->iqlen) ;
  l->iqlen = k->iqlen ;
  return 1 ;
}
