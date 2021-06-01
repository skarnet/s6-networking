/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

int sbearssl_pkey_to (sbearssl_pkey const *l, br_x509_pkey *k, char *s)
{
  switch (l->type)
  {
    case BR_KEYTYPE_RSA :
      sbearssl_rsa_pkey_to(&l->data.rsa, &k->key.rsa, s) ;
      break ;
    case BR_KEYTYPE_EC :
      sbearssl_ec_pkey_to(&l->data.ec, &k->key.ec, s) ;
      break ;
    default :
      return 0 ;
  }
  k->key_type = l->type ;
  return 1 ;
}
