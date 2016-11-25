/* ISC license. */

#include <errno.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_pkey_from (sbearssl_pkey *l, br_x509_pkey const *k, stralloc *sa)
{
  switch (k->key_type)
  {
    case BR_KEYTYPE_RSA :
      if (!sbearssl_rsa_pkey_from(&l->data.rsa, &k->key.rsa, sa)) return 0 ;
      break ;
    case BR_KEYTYPE_EC :
      if (!sbearssl_ec_pkey_from(&l->data.ec, &k->key.ec, sa)) return 0 ;
      break ;
    default :
      return (errno = EINVAL, 0) ;
  }
  l->type = k->key_type ;
  return 1 ;
}
