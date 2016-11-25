/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/bytestr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/direntry.h>
#include <skalibs/djbunix.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ta_readdir (char const *dirfn, genalloc *taga, stralloc *tasa)
{
  stralloc certsa = STRALLOC_ZERO ;
  genalloc certga = GENALLOC_ZERO ;
  size_t tasabase = tasa->len ;
  size_t tagabase = genalloc_len(sbearssl_ta, taga) ;
  size_t dirfnlen = str_len(dirfn) ;
  int tasawasnull = !tasa->s ;
  int tagawasnull = !genalloc_s(sbearssl_ta, taga) ;
  DIR *dir = opendir(dirfn) ;
  if (!dir) return -1 ;

  for (;;)
  {
    direntry *d ;
    errno = 0 ;
    d = readdir(dir) ;
    if (!d) break ;
    if (d->d_name[0] == '.') continue ;
    {
      size_t dlen = str_len(d->d_name) ;
      char fn[dirfnlen + dlen + 2] ;
      byte_copy(fn, dirfnlen, dirfn) ;
      fn[dirfnlen] = '/' ;
      byte_copy(fn + dirfnlen + 1, dlen, d->d_name) ;
      fn[dirfnlen + 1 + dlen] = 0 ;
      sbearssl_ta_readfile_internal(fn, taga, tasa, &certga, &certsa) ;
    }
  }
  if (errno) goto fail ;

  dir_close(dir) ;
  genalloc_free(sbearssl_cert, &certga) ;
  stralloc_free(&certsa) ;
  return 0 ;

 fail:
  {
    int e = errno ;
    dir_close(dir) ;
    genalloc_free(sbearssl_cert, &certga) ;
    stralloc_free(&certsa) ;
    if (tagawasnull) genalloc_free(sbearssl_ta, taga) ;
    else genalloc_setlen(sbearssl_ta, taga, tagabase) ;
    if (tasawasnull) stralloc_free(tasa) ;
    else tasa->len = tasabase ;
    errno = e ;
  }
  return -1 ;
}
