/* ISC license. */

#include <sys/types.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ta_certs (genalloc *taga, stralloc *tasa, sbearssl_cert const *certs, size_t certn, char const *certstorage)
{
  size_t tagabase = genalloc_len(sbearssl_ta, taga) ;
  size_t tasabase = tasa->len ;
  size_t i = 0 ;
  int tagawasnull = !genalloc_s(sbearssl_ta, taga) ;
  int tasawasnull = !tasa->s ;
  int r ;

  for (; i < certn ; i++)
  {
    sbearssl_ta ta ;
    r = sbearssl_ta_cert(&ta, certs + i, certstorage, tasa) ;
    if (r) goto fail ;
    if (!genalloc_append(sbearssl_ta, taga, &ta)) goto rfail ;
  }

  return 0 ;

 rfail:
  r = -1 ;
 fail:
  if (tagawasnull) genalloc_free(sbearssl_ta, taga) ;
  else genalloc_setlen(sbearssl_ta, taga, tagabase) ;
  if (tasawasnull) stralloc_free(tasa) ;
  else tasa->len = tasabase ;
  return r ;
}
