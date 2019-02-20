/* ISC license. */

#include <errno.h>

#include <bearssl.h>

#include <skalibs/posixishard.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_pem_decode_from_string (char const *s, size_t len, genalloc *list, stralloc *sa)
{
  br_pem_decoder_context ctx ;
  sbearssl_pemobject po ;
  sbearssl_strallocerr blah = { .sa = sa, .err = 0 } ;
  size_t listbase = genalloc_len(sbearssl_pemobject, list) ;
  size_t sabase = sa->len ;
  int listwasnull = !genalloc_s(sbearssl_pemobject, list) ;
  int sawasnull = !sa->s ;
  int inobj = 0 ;
  int r ;

  br_pem_decoder_init(&ctx) ;
  r = sbearssl_pem_push(&ctx, s, len, &po, list, &blah, &inobj) ;
  if (r) goto fail ;
  if (!inobj) return 0 ;
 
  errno = EPROTO ;
 fail:
  if (listwasnull) genalloc_free(sbearssl_pemobject, list) ;
  else genalloc_setlen(sbearssl_pemobject, list, listbase) ;
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  return r ;
}
