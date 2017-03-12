/* ISC license. */

#include <string.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/djbunix.h>
#include <s6-networking/sbearssl.h>

static int decode_key (sbearssl_skey *key, char const *s, size_t len, stralloc *sa)
{
  br_skey_decoder_context ctx ;
  int ktype ;
  br_skey_decoder_init(&ctx) ;
  br_skey_decoder_push(&ctx, s, len) ;
  ktype = br_skey_decoder_key_type(&ctx) ;
  switch (ktype)
  {
    case 0 : return br_skey_decoder_last_error(&ctx) ;
    case BR_KEYTYPE_RSA :
      if (!sbearssl_rsa_skey_from(&key->data.rsa, &ctx.key.rsa, sa)) return -1 ;
      break ;
    case BR_KEYTYPE_EC :
      if (!sbearssl_ec_skey_from(&key->data.ec, &ctx.key.ec, sa)) return -1 ;
      break ;
  }
  key->type = ktype ;
  return 0 ;
}

int sbearssl_skey_readfile (char const *fn, sbearssl_skey *key, stralloc *sa)
{
  char buf[SBEARSSL_MAXSKEYFILESIZE] ;
  stralloc tmp = STRALLOC_ZERO ;
  genalloc list = GENALLOC_ZERO ;
  sbearssl_pemobject *p ;
  size_t n ;
  size_t i = 0 ;
  int r = openreadnclose(fn, buf, SBEARSSL_MAXSKEYFILESIZE) ; /* fits in an int */
  if (r < 0) return r ;
  n = r ;
  if (sbearssl_isder((unsigned char *)buf, n)) return decode_key(key, buf, n, sa) ;
  r = sbearssl_pem_decode_from_string(buf, n, &list, &tmp) ;
  if (r) return r ;
  p = genalloc_s(sbearssl_pemobject, &list) ;
  n = genalloc_len(sbearssl_pemobject, &list) ;
  for (; i < n ; i++)
  {
    char const *name = tmp.s + p[i].name ;
    if (!strcmp(name, "RSA PRIVATE KEY")
     || !strcmp(name, "EC PRIVATE KEY")
     || !strcmp(name, "PRIVATE KEY"))
    {
      r = decode_key(key, tmp.s + p[i].data, p[i].datalen, sa) ;
      if (r) goto fail ;
      break ;
    }
  }
  stralloc_free(&tmp) ;
  if (i < n) return 0 ;

  r = -1 ; errno = EINVAL ;
 fail:
  stralloc_free(&tmp) ;
  genalloc_free(sbearssl_pemobject, &list) ;
  return r ;
}
