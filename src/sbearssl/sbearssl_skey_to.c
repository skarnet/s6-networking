/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

int sbearssl_skey_to (sbearssl_skey const *l, br_skey *k, char *s)
{
  switch (l->type)
  {
    case BR_KEYTYPE_RSA :
      sbearssl_rsa_skey_to(&l->data.rsa, &k->data.rsa, s) ;
      break ;
    case BR_KEYTYPE_EC :
      sbearssl_ec_skey_to(&l->data.ec, &k->data.ec, s) ;
      break ;
    default :
      return 0 ;
  }
  k->type = l->type ;
  return 1 ;
}
