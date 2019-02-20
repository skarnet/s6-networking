/* ISC license. */

#include <sys/uio.h>
#include <errno.h>

#include <bearssl.h>

#include <skalibs/posixishard.h>
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
  int r = -1 ;

  br_pem_decoder_init(&ctx) ;
  for (;;)
  {
    struct iovec v[2] ;
    ssize_t rr = buffer_fill(b) ;
    if (rr < 0) goto rfail ;
    if (!rr) break ;
    buffer_rpeek(b, v) ;
    r = sbearssl_pem_push(&ctx, v[0].iov_base, v[0].iov_len, &po, list, &blah, &inobj) ;
    if (r) goto fail ;
    if (v[1].iov_len)
    {
      r = sbearssl_pem_push(&ctx, v[1].iov_base, v[1].iov_len, &po, list, &blah, &inobj) ;
      if (r) goto fail ;
    }
    buffer_rseek(b, v[0].iov_len + v[1].iov_len) ;
  }
  if (!inobj) return 0 ;

  errno = EPROTO ;
 rfail:
  r = -1 ;
 fail:
  if (listwasnull) genalloc_free(sbearssl_pemobject, list) ;
  else genalloc_setlen(sbearssl_pemobject, list, listbase) ;
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  return r ;
}
