/* ISC license. */

#include <errno.h>
#include <bearssl.h>
#include <s6-networking/sbearssl.h>

int sbearssl_skey_to (sbearssl_skey const *l, br_skey *k, char const *s)
{
  switch (l->type)
  {
    case BR_KEYTYPE_RSA :
      sbearssl_rsa_pkey_to(&l->data.rsa, &k->data.rsa, s) ;
      break ;
    case BR_KEYTYPE_EC :
      sbearssl_ec_pkey_to(&l->data.ec, &k->data.ec, s) ;
      break ;
    default :
      return (errno = EINVAL, 0) ;
  }
  k->type = l->type ;
  return 1 ;
}
