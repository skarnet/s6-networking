/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

void sbearssl_rsa_skey (sbearssl_rsa_skey const *l, br_rsa_private_key *k, char const *s)
{
  k->n_bitlen = l->n_bitlen ;
  k->p = s + l->p ;
  k->plen = l->plen ;
  k->q = s + l->q ;
  k->qlen = l->qlen ;
  k->dp = s + l->dp ;
  k->dplen = l->dplen ;
  k->dq = s + l->dq ;
  k->dqlen = l->dqlen ;
  k->iq = s + l->iq ;
  k->iqlen = l->iqlen ;
}
