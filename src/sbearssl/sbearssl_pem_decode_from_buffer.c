/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/error.h>
#include <skalibs/siovec.h>
#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_pem_decode_from_buffer (buffer *b, genalloc *list, stralloc *sa)
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
  for (;;)
  {
    siovec_t v[2] ;
    r = buffer_fill(b) ;
    if (r < 0) goto fail ;
    if (!r) break ;
    buffer_rpeek(b, v) ;
    r = sbearssl_pem_push(&ctx, v[0].s, v[0].len, &po, list, &blah, &inobj) ;
    if (r) goto fail ;
    if (v[1].len)
    {
      r = sbearssl_pem_push(&ctx, v[1].s, v[1].len, &po, list, &blah, &inobj) ;
      if (r) goto fail ;
    }
    buffer_rseek(b, v[0].len + v[1].len) ;
  }
  if (!inobj) return 0 ;

  r = -1 ;
  errno = EPROTO ;
 fail:
  if (listwasnull) genalloc_free(sbearssl_pemobject, list) ;
  else genalloc_setlen(sbearssl_pemobject, list, listbase) ;
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  return r ;
}
