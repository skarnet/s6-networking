/* ISC license. */

#include <bearssl.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_choose_algos_rsa (br_ssl_server_context const *sc, br_ssl_server_choices *choices, unsigned int usages)
{
  size_t n ;
  unsigned int hash_id = 0 ;
  int fh ;
  br_suite_translated const *st = br_ssl_server_get_client_suites(sc, &n) ;
  if (sc->eng.session.version < BR_TLS12) fh = 1 ;
  else
  {
    hash_id = sbearssl_choose_hash(br_ssl_server_get_client_hashes(sc)) ;
    fh = !!hash_id ;
  }
  for (size_t i = 0 ; i < n ; i++)
  {
    unsigned int tt = st[i][1] ;
    switch (tt >> 12)
    {
      case BR_SSLKEYX_RSA :
        if (usages & BR_KEYTYPE_KEYX)
        {
          choices->cipher_suite = st[i][0] ;
          return 1 ;
        }
        break ;
      case BR_SSLKEYX_ECDHE_RSA :
        if ((usages & BR_KEYTYPE_SIGN) && fh)
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
