/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <skalibs/uint32.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/direntry.h>
#include <skalibs/djbunix.h>

#include <s6-networking/sbearssl.h>

int sbearssl_ta_readdir (char const *dirfn, genalloc *taga, stralloc *tasa)
{
  size_t tasabase = tasa->len ;
  size_t tagabase = genalloc_len(sbearssl_ta, taga) ;
  size_t dirfnlen = strlen(dirfn) ;
  int tasawasnull = !tasa->s ;
  int tagawasnull = !genalloc_s(sbearssl_ta, taga) ;
  stralloc certsa = STRALLOC_ZERO ;
  genalloc certga = GENALLOC_ZERO ;
  DIR *dir = opendir(dirfn) ;
  char fn[dirfnlen + 12] ;
  if (!dir) return -1 ;
  memcpy(fn, dirfn, dirfnlen) ;
  fn[dirfnlen] = '/' ;

  for (;;)
  {
    direntry *d ;
    uint32_t dummy ;
    errno = 0 ;
    d = readdir(dir) ;
    if (!d) break ;

   /* only process files with valid hash names */
    if (uint32_xscan(d->d_name, &dummy) != 8 || d->d_name[8] != '.' || d->d_name[9] != '0' || d->d_name[10]) continue ;

    memcpy(fn + dirfnlen + 1, d->d_name, 11) ;
    genalloc_setlen(sbearssl_cert, &certga, 0) ;
    certsa.len = 0 ;
    if (sbearssl_cert_readfile(fn, &certga, &certsa)) continue ;
    sbearssl_ta_certs(taga, tasa, genalloc_s(sbearssl_cert, &certga), genalloc_len(sbearssl_cert, &certga), certsa.s) ;
  }
  if (errno) goto fail ;

  dir_close(dir) ;
  genalloc_free(sbearssl_cert, &certga) ;
  stralloc_free(&certsa) ;
  return 0 ;

 fail:
  dir_close(dir) ;
  genalloc_free(sbearssl_cert, &certga) ;
  stralloc_free(&certsa) ;
  if (tagawasnull) genalloc_free(sbearssl_ta, taga) ;
  else genalloc_setlen(sbearssl_ta, taga, tagabase) ;
  if (tasawasnull) stralloc_free(tasa) ;
  else tasa->len = tasabase ;
  return -1 ;
}
