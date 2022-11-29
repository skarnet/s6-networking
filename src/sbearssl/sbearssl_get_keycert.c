/* ISC license. */

#include <stdlib.h>

#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

size_t sbearssl_get_keycert (sbearssl_skey *skey, genalloc *certs, stralloc *storage)
{
  size_t chainlen ;
  int r ;
  char const *x = getenv("CERTFILE") ;
  if (!x) strerr_dienotset(100, "CERTFILE") ;
  r = sbearssl_cert_readbigpem(x, certs, storage) ;
  if (r < 0)
    strerr_diefu2sys(111, "read certificate chain in ", x) ;
  else if (r)
    strerr_diefu4sys(96, "read certificate chain in ", x, ": ", sbearssl_error_str(r)) ;
  chainlen = genalloc_len(sbearssl_cert, certs) ;
  if (!chainlen)
    strerr_diefu2x(96, "find a certificate in ", x) ;

  x = getenv("KEYFILE") ;
  if (!x) strerr_dienotset(100, "KEYFILE") ;
  r = sbearssl_skey_readfile(x, skey, storage) ;
  if (r < 0)
    strerr_diefu2sys(111, "read private key in ", x) ;
  else if (r)
    strerr_diefu4x(96, "decode private key in ", x, ": ", sbearssl_error_str(r)) ;

  return chainlen ;
}
