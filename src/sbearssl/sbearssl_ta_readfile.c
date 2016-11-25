/* ISC license. */

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_ta_readfile (char const *file, genalloc *taga, stralloc *tasa)
{
  stralloc certsa = STRALLOC_ZERO ;
  genalloc certga = GENALLOC_ZERO ;
  int r = sbearssl_ta_readfile_internal(file, taga, tasa, &certsa, &certga) ;
  genalloc_free(sbearssl_ta, &certga) ;
  stralloc_free(&certsa) ;
  return r ;
}
