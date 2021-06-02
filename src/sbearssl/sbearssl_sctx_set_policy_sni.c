/* ISC license. */

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

void sbearssl_sctx_set_policy_sni (br_ssl_server_context *sc, sbearssl_sni_policy_context *pol)
{
  sc->chain_handler.vtable = pol->vtable ;
  sc->policy_vtable = &pol->vtable ;
}
