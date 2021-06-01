/* ISC license. */

#include <bearssl.h>

#include <skalibs/bytestr.h>

#include <s6-networking/sbearssl.h>

void sbearssl_skey_wipe (sbearssl_skey *key, char *s)
{
  switch (key->type)
  {
    case BR_KEYTYPE_RSA :
      byte_zzero(s + key->data.rsa.p, key->data.rsa.plen) ;
      byte_zzero(s + key->data.rsa.q, key->data.rsa.qlen) ;
      byte_zzero(s + key->data.rsa.dp, key->data.rsa.dplen) ;
      byte_zzero(s + key->data.rsa.dq, key->data.rsa.dqlen) ;
      byte_zzero(s + key->data.rsa.iq, key->data.rsa.iqlen) ;
      break ;
    case BR_KEYTYPE_EC :
      byte_zzero(s + key->data.ec.x, key->data.ec.xlen) ;
      break ;
    default : break ;
  }
  byte_zzero((char *)key, sizeof(sbearssl_skey)) ;
}
