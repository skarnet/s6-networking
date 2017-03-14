/* ISC license. */

#include <errno.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include "sbearssl-internal.h"

int sbearssl_pem_push (br_pem_decoder_context *ctx, char const *s, size_t len, sbearssl_pemobject *po, genalloc *list, sbearssl_strallocerr *blah, int *inobj)
{
  while (len)
  {
    size_t tlen = br_pem_decoder_push(ctx, s, len) ;
    if (blah->err) return (errno = blah->err, -1) ;
    s += tlen ; len -= tlen ;
    switch (br_pem_decoder_event(ctx))
    {
      case BR_PEM_BEGIN_OBJ :
        po->name = blah->sa->len ;
        if (!stralloc_cats(blah->sa, br_pem_decoder_name(ctx)) || !stralloc_0(blah->sa)) return -1 ;
        po->data = blah->sa->len ;
        br_pem_decoder_setdest(ctx, &sbearssl_append, blah) ;
        *inobj = 1 ;
        break ;
      case BR_PEM_END_OBJ :
        if (*inobj)
        {
          po->datalen = blah->sa->len - po->data ;
          if (!genalloc_append(sbearssl_pemobject, list, po)) return 0 ;
          *inobj = 0 ;
        }
        break ;
      case BR_PEM_ERROR : return (errno = EINVAL, -1) ;
    }
  }
  return 0 ;
}
