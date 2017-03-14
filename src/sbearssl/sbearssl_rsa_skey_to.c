/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_rsa_skey_to (sbearssl_rsa_skey const *l, br_rsa_private_key *k, char *s)
{
  k->n_bitlen = l->n_bitlen ;
  k->p = (unsigned char *)s + l->p ;
  k->plen = l->plen ;
  k->q = (unsigned char *)s + l->q ;
  k->qlen = l->qlen ;
  k->dp = (unsigned char *)s + l->dp ;
  k->dplen = l->dplen ;
  k->dq = (unsigned char *)s + l->dq ;
  k->dqlen = l->dqlen ;
  k->iq = (unsigned char *)s + l->iq ;
  k->iqlen = l->iqlen ;
}
