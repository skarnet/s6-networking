/* ISC license. */

#include <stdlib.h>

#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

size_t sbearssl_get_tas (genalloc *tas, stralloc *storage)
{
  size_t talen ;
  int r ;
  char const *x = getenv("CADIR") ;
  if (x) r = sbearssl_ta_readdir(x, tas, storage) ;
  else
  {
    x = getenv("CAFILE") ;
    if (!x) strerr_dienotset(100, "CADIR or CAFILE") ;
    r = sbearssl_ta_readfile(x, tas, storage) ;
  }

  if (r < 0)
    strerr_diefu2sys(111, "read trust anchors in ", x) ;
  else if (r)
    strerr_diefu4x(96, "read trust anchors in ", x, ": ", sbearssl_error_str(r)) ;

  talen = genalloc_len(sbearssl_ta, tas) ;
  if (!talen) strerr_dief2x(96, "no trust anchor found in ", x) ;
  return talen ;
}
