/* ISC license. */

#include <bearssl.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_choose_algos_ec (br_ssl_server_context const *sc, br_ssl_server_choices *choices, unsigned int usages, int kt)
{
  size_t n ;
  br_suite_translated const *st = br_ssl_server_get_client_suites(sc, &n) ;
  unsigned int hash_id = sbearssl_choose_hash(br_ssl_server_get_client_hashes(sc) >> 8) ;
  if (sc->eng.session.version < BR_TLS12) hash_id = br_sha1_ID ;
  for (size_t i = 0 ; i < n ; i++)
  {
    unsigned int tt = st[i][1] ;
    switch (tt >> 12)
    {
      case BR_SSLKEYX_ECDH_RSA :
        if ((usages & BR_KEYTYPE_KEYX) && kt == BR_KEYTYPE_RSA)
        {
          choices->cipher_suite = st[i][0] ;
          return 1 ;
        }
        break ;
      case BR_SSLKEYX_ECDH_ECDSA :
        if ((usages & BR_KEYTYPE_KEYX) && kt == BR_KEYTYPE_EC)
        {
          choices->cipher_suite = st[i][0] ;
          return 1 ;
        }
        break ;
      case BR_SSLKEYX_ECDHE_ECDSA :
        if ((usages & BR_KEYTYPE_SIGN) && hash_id)
        {
          choices->cipher_suite = st[i][0] ;
          choices->algo_id = hash_id + 0xff00 ;
          return 1 ;
        }
        break ;
    }
  }
  return 0 ;
}
