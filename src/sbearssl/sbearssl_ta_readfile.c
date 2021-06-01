/* ISC license. */

#include <sys/types.h>
#include <errno.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>

int sbearssl_ta_readfile (char const *file, genalloc *taga, stralloc *tasa)
{
  stralloc certsa = STRALLOC_ZERO ;
  genalloc certga = GENALLOC_ZERO ;
  size_t tasabase = tasa->len ;
  size_t tagabase = genalloc_len(sbearssl_ta, taga) ;
  int tasawasnull = !tasa->s ;
  int tagawasnull = !genalloc_s(sbearssl_ta, taga) ;
  int r = sbearssl_cert_readbigpem(file, &certga, &certsa) ;
  if (r) return r ;
  r = sbearssl_ta_certs(taga, tasa, genalloc_s(sbearssl_cert, &certga), genalloc_len(sbearssl_cert, &certga), certsa.s) ;
  if (r) goto fail ;

  genalloc_free(sbearssl_ta, &certga) ;
  stralloc_free(&certsa) ;
  return 0 ;

 fail:
  {
    int e = errno ;
    genalloc_free(sbearssl_cert, &certga) ;
    stralloc_free(&certsa) ;
    if (tagawasnull) genalloc_free(sbearssl_ta, taga) ;
    else genalloc_setlen(sbearssl_ta, taga, tagabase) ;
    if (tasawasnull) stralloc_free(tasa) ;
    else tasa->len = tasabase ;
    errno = e ;
  }
  return r ;
}
