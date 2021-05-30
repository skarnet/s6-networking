/* ISC license. */

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

#define INSTANCE(c) ((sbearssl_x509_small_context *)(c))

static void start_chain (br_x509_class const **c, char const *server_name)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  ctx->minimal.vtable->start_chain(&ctx->minimal.vtable, server_name) ;

  ctx->i = 0 ;
}

static void start_cert (br_x509_class const **c, uint32_t len)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  ctx->minimal.vtable->start_cert(&ctx->minimal.vtable, len) ;

  if (!ctx->i) br_sha256_init(&ctx->hashctx) ;
}

static void append (br_x509_class const **c, unsigned char const *s, size_t len)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  ctx->minimal.vtable->append(&ctx->minimal.vtable, s, len) ;

  if (!ctx->i) br_sha256_update(&ctx->hashctx, s, len) ;
}

static void end_cert (br_x509_class const **c)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  ctx->minimal.vtable->end_cert(&ctx->minimal.vtable) ;

  if (!ctx->i) br_sha256_out(&ctx->hashctx, ctx->eehash) ;
  ctx->i++ ;
}

static unsigned int end_chain (br_x509_class const **c)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  unsigned int r = ctx->minimal.vtable->end_chain(&ctx->minimal.vtable) ;
  if (!r)
  {
    uint8_t mask = 1 ;
    for (unsigned int i = 0 ; i < 6 ; i++, mask <<= 1)
      if (ctx->elts[i].status)
        *ctx->eltstatus |= ctx->elts[i].status < 0 ? 128 : mask ;
  }
  return r ;
}

static br_x509_pkey const *get_pkey(br_x509_class const *const *c, unsigned int *usages)
{
  sbearssl_x509_small_context *ctx = INSTANCE(c) ;
  return ctx->minimal.vtable->get_pkey(&ctx->minimal.vtable, usages) ;
}

br_x509_class const sbearssl_x509_small_vtable =
{
  .context_size = sizeof(sbearssl_x509_small_context),
  .start_chain = &start_chain,
  .start_cert = &start_cert,
  .append = &append,
  .end_cert = &end_cert,
  .end_chain = &end_chain,
  .get_pkey = &get_pkey,
} ;
