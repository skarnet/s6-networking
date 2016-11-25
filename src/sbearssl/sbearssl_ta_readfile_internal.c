/* ISC license. */

#include <sys/types.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_ta_readfile_internal (char const *file, genalloc *taga, stralloc *tasa, genalloc *certga, stralloc *certsa)
{
  size_t i = 0 ;
  size_t certsabase = certsa->len ;
  size_t certgabase = genalloc_len(sbearssl_ta, certga) ;
  size_t tasabase = tasa->len ;
  size_t tagabase = genalloc_len(sbearssl_ta, taga) ;
  int tasawasnull = !tasa->s ;
  int tagawasnull = !genalloc_s(sbearssl_ta, taga) ;
  int r = sbearssl_cert_read(file, certga, certsa) ;
  sbearssl_cert *p = genalloc_s(sbearssl_cert, certga) ;
  size_t n = genalloc_len(sbearssl_cert, certga) ;
  if (r) return r ;
  
  for (; i < n ; i++)
  {
    sbearssl_ta ta ;
    r = sbearssl_ta_cert(&ta, p + i, certsa->s, tasa) ;
    if (r) goto fail ;
    if (!genalloc_append(sbearssl_ta, taga, &ta)) goto rfail ;
  }

  genalloc_setlen(sbearssl_ta, certga, certgabase) ;
  certsa->len = certsabase ;
  return 0 ;

 rfail:
  r = -1 ;
 fail:
  genalloc_setlen(sbearssl_ta, certga, certgabase) ;
  certsa->len = certsabase ;
  if (tagawasnull) genalloc_free(sbearssl_ta, taga) ;
  else genalloc_setlen(sbearssl_ta, taga, tagabase) ;
  if (tasawasnull) stralloc_free(tasa) ;
  else tasa->len = tasabase ;
  return r ;
}
