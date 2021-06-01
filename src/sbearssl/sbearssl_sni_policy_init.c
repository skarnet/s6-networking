/* ISC license. */

#include <string.h>

#include <bearssl.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

static void *sbearssl_sni_policy_node_dtok (uint32_t d, void *data)
{
  sbearssl_sni_policy_context *pol = data ;
  return pol->storage.s + genalloc_s(sbearssl_sni_policy_node, &pol->mapga)[d].servername ;
}

static int sbearssl_sni_policy_node_cmp (void const *a, void const *b, void *data)
{
  (void)data ;
  return strcmp((char const *)a, (char const *)b) ;
}

void sbearssl_sni_policy_init (sbearssl_sni_policy_context *pol)
{
  avltree_init(&pol->map, 3, 3, 8, &sbearssl_sni_policy_node_dtok, &sbearssl_sni_policy_node_cmp, pol) ;
  pol->mapga = genalloc_zero ;
  pol->certga = genalloc_zero ;
  pol->storage = stralloc_zero ;
  pol->vtable = &sbearssl_sni_policy_vtable ;
}
