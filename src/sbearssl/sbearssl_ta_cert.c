/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ta_cert (sbearssl_ta *ta, sbearssl_cert const *cert, char const *certstorage, stralloc *tastorage)
{
  br_x509_decoder_context ctx ;
  sbearssl_ta tta = { .dn = tastorage->len, .flags = 0 } ;
  struct sbearssl_strallocerr_s blah = { .sa = tastorage } ;
  size_t tastoragebase = tastorage->len ;
  int tastoragewasnull = !tastorage->s ;
  br_x509_pkey bpk ;
  int r ;

  br_x509_decoder_init(&ctx, &sbearssl_append, &blah) ;
  br_x509_decoder_push(&ctx, certstorage + cert->data, cert->datalen) ;
  if (blah->err)
  {
    r = -1 ;
    errno = blah->err ;
    goto fail ;
  }
  bpk = br_x509_decoder_get_pkey(&ctx) ;
  if (!bpk)
  {
    r = br_x509_decoder_last_error(&ctx) ;
    goto fail ;
  }
  tta.dnlen = tastorage->len - tastoragebase ;
  if (br_x509_decoder_isCA(&ctx)) tta.flags |= BR_X509_TA_CA ;
  if (!sbearssl_pkey_from(&tta.pkey, bpk, tastorage)) goto fail ;
  *ta = tta ;
  return 0 ;

 fail:
  if (tastoragewasnull) stralloc_free(tastorage) ;
  else tastorage->len = tastoragebase ;
  return r ;
}
