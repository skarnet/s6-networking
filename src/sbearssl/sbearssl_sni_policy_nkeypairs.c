/* ISC license. */

#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

size_t sbearssl_sni_policy_nkeypairs (sbearssl_sni_policy_context const *pol)
{
  return genalloc_len(sbearssl_sni_policy_node, &pol->mapga) ;
}
