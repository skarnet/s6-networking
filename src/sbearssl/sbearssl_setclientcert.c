/* ISC license. */

#include <sys/types.h>
#include <bearssl.h>
#include <s6-networking/sbearssl.h>

int sbearssl_setclientcert (br_ssl_client_context *cc, br_x509_certificate const *certs, size_t certlen, br_skey const *key)
{
  if (!certlen) return 0 ;
  switch (key.type)
  {
    case BR_KEYTYPE_RSA :
      br_ssl_client_set_single_rsa(cc, certs, certlen, &key->rsa, &br_rsa_i31_pkcs1_sign) ;
      break ;
    case BR_KEYTYPE_EC :
    {
      int kt, r ;
      r = sbearssl_ec_issuer_keytype(&kt, &certs[0]) ;
      if (r) return r ;
      br_ssl_client_set_single_ec(cc, certs, certlen, &key->ec, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, kt, &br_ec_prime_i31, ) ;
      break ;
    }
    default :
    strerr_dief1x(96, "unsupported private key type") ;
  }


  return 0 ;
}
