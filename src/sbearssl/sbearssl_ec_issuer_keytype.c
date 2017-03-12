/* ISC license. */

#include <errno.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_ec_issuer_keytype (int *kt, br_x509_certificate const *cert)
{
  br_x509_decoder_context ctx ;
  stralloc sa = STRALLOC_ZERO ;
  struct sbearssl_strallocerr_s blah = { .sa = &sa } ;
  int r = -1 ;

  br_x509_decoder_init(&ctx, &sbearssl_append, &blah) ;
  br_x509_decoder_push(&ctx, cert->data, cert->data_len) ;
  if (blah.err)
  {
    errno = blah.err ;
    goto fail ;
  }
  r = br_x509_decoder_last_error(&ctx) ;
  if (r) goto fail ;
  r = br_x509_decoder_get_signer_key_type(&ctx) ;
  if (!r)
  {
    r = -2 ;
    goto fail ;
  }

  stralloc_free(&sa) ;
  *kt = r ;
  return 0 ;

 fail:
  stralloc_free(&sa) ;
  return r ;
}
