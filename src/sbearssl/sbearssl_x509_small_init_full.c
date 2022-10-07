/* ISC license. */

#include <stddef.h>
#include <stdint.h>

#include <bearssl.h>

#include <skalibs/tai.h>

#include <s6-networking/sbearssl.h>

struct eltinfo_s
{
  size_t offset ;
  size_t size ;
  unsigned char oid[4] ;
} ;

static struct eltinfo_s const eltinfo[6] =
{
  { .offset = offsetof(sbearssl_dn, c),  .size = sizeof(((sbearssl_dn *)0)->c),  .oid = "\x03\x55\x04\x06" },
  { .offset = offsetof(sbearssl_dn, st), .size = sizeof(((sbearssl_dn *)0)->st), .oid = "\x03\x55\x04\x08" },
  { .offset = offsetof(sbearssl_dn, l),  .size = sizeof(((sbearssl_dn *)0)->l),  .oid = "\x03\x55\x04\x07" },
  { .offset = offsetof(sbearssl_dn, o),  .size = sizeof(((sbearssl_dn *)0)->o),  .oid = "\x03\x55\x04\x0a" },
  { .offset = offsetof(sbearssl_dn, ou), .size = sizeof(((sbearssl_dn *)0)->ou), .oid = "\x03\x55\x04\x0b" },
  { .offset = offsetof(sbearssl_dn, cn), .size = sizeof(((sbearssl_dn *)0)->cn), .oid = "\x03\x55\x04\x03" }
} ;

void sbearssl_x509_small_init_full (sbearssl_x509_small_context *ctx, br_x509_trust_anchor *btas, size_t n, sbearssl_dn *eedn, uint8_t *eltstatus, char *eehash)
{
  ctx->vtable = &sbearssl_x509_small_vtable ;
  br_x509_minimal_init_full(&ctx->minimal, btas, n) ;
#ifdef BR_FEATURE_X509_TIME_CALLBACK
  br_x509_minimal_set_time_callback(&ctx->minimal, tain_secp(&STAMP), &sbearssl_x509_time_check) ;
#endif
  for (unsigned int i = 0 ; i < 6 ; i++)
  {
    ctx->elts[i].oid = eltinfo[i].oid ;
    ctx->elts[i].buf = (char *)eedn + eltinfo[i].offset ;
    ctx->elts[i].len = eltinfo[i].size ;
  }
  br_x509_minimal_set_name_elements(&ctx->minimal, ctx->elts, 6) ;
  ctx->eltstatus = eltstatus ;
  ctx->eehash = eehash ;
}
