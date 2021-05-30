/* ISC license. */

#include <errno.h>

#include <bearssl.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>

#include <s6-networking/sbearssl.h>

#define INSTANCE(c) ((sbearssl_sni_policy_context *)(c))

static int choose (br_ssl_server_policy_class const **pctx, br_ssl_server_context const *sc, br_ssl_server_choices *choices)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  uint32_t n ;
  char const *servername = br_ssl_engine_get_server_name(&sc->eng) ;
  if (!avltree_search(&pol->map, servername, &n)
   && (!servername[0] || !avltree_search(&pol->map, "", &n)))
    return 0 ;
  avltree_free(&pol->map) ;
  copy_and_free(pol, n) ;
}

static uint32_t do_keyx (br_ssl_server_policy_class const **pctx, unsigned char *data, size_t *len)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  switch (pol->skey.type)
  {
    case BR_KEYTYPE_RSA : return kx_rsa(pol, data, len) ;
    case BR_KEYTYPE_EC : return kx_ec(pol, data, len) ;
    default : return 0 ;
  }
}

static size_t do_sign (br_ssl_server_policy_class const **pctx, unsigned int algo_id, unsigned char *data, size_t hv_len, size_t len)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  switch (pol->skey.type)
  {
    case BR_KEYTYPE_RSA : return sign_rsa(pol, algo_id, data, hv_len, len) ;
    case BR_KEYTYPE_EC : return sign_ec(pol, algo_id, data, hv_len, len) ;
    default : return 0 ;
  }
}

static br_ssl_server_policy_class const vtable =
{
  .context_size = sizeof(sbearssl_sni_policy_context),
  .choose = &choose,
  .do_keyx = &do_keyx,
  .do_sign = &do_sign
} ;

static void *sbearssl_sni_policy_node_dtok (uint32_t d, void *data)
{
  return ((sbearssl_sni_policy_context *)data)->storage.s + d ;
}

static int sbearssl_sni_policy_node_cmp (void const *a, void const *b, void *data)
{
  (void)data ;
  return strcmp((char const *)a, (char const *)b) ;
}

void sbearssl_sni_policy_init (sbearssl_sni_policy_context *pol)
{
  pol->vtable = &vtable ;
  pol->map = avltree_zero ;
  pol->mapga = genalloc_zero ;
  pol->certga = genalloc_zero ;
  pol->storage = GENALLOC_ZERO ;
}
