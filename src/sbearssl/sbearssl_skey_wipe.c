/* ISC license. */

#include <bearssl.h>

#include <skalibs/bytestr.h>

#include <s6-networking/sbearssl.h>

void sbearssl_skey_wipe (sbearssl_skey *key, char *s)
{
  switch (key->type)
  {
    case BR_KEYTYPE_RSA :
      byte_zzero(s + key->rsa.p, key->rsa.plen) ;
      byte_zzero(s + key->rsa.q, key->rsa.qlen) ;
      byte_zzero(s + key->rsa.dp, key->rsa.dplen) ;
      byte_zzero(s + key->rsa.dq, key->rsa.dqlen) ;
      byte_zzero(s + key->rsa.iq, key->rsa.iqlen) ;
      break ;
    case BR_KEYTYPE_EC :
      byte_zzero(s + key->ec.x, key->ec.xlen) ;
      break ;
    default : break ;
  }
  byte_zzero(key, sizeof(sbearssl_skey)) ;
}
