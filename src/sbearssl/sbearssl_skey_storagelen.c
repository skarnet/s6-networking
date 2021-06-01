/* ISC license. */

#include <s6-networking/sbearssl.h>

size_t sbearssl_skey_storagelen (sbearssl_skey const *l)
{
  switch (l->type)
  {
    case BR_KEYTYPE_RSA :
      return l->data.rsa.plen + l->data.rsa.qlen + l->data.rsa.dplen + l->data.rsa.dqlen + l->data.rsa.iqlen ;
    case BR_KEYTYPE_EC :
      return l->data.ec.xlen ;
    default :
      return 0 ;
  }
}
