/* ISC license. */

#include <stdlib.h>

#include <tls.h>

#include <skalibs/strerr2.h>

#include <s6-networking/stls.h>
#include "stls-internal.h"

#define diecfg(cfg, s) strerr_diefu3x(96, (s), ": ", tls_config_error(cfg))
#define diectx(e, ctx, s) strerr_diefu3x(e, (s), ": ", tls_error(ctx))

struct tls *stls_client_init_and_handshake (int const *fds, uint32_t preoptions, char const *servername)
{
  struct tls *ctx ;
  struct tls_config *cfg ;
  char const *x ;

  if (tls_init() < 0) strerr_diefu1sys(111, "tls_init") ;
  cfg = tls_config_new() ;
  if (!cfg) strerr_diefu1sys(111, "tls_config_new") ;

  x = getenv("CADIR") ;
  if (x)
  {
    if (tls_config_set_ca_path(cfg, x) < 0)
      diecfg(cfg, "tls_config_set_ca_path") ;
  }
  else
  {
    x = getenv("CAFILE") ;
    if (x)
    {
      if (tls_config_set_ca_file(cfg, x) < 0)
        diecfg(cfg, "tls_config_set_ca_file") ;
    }
    else strerr_dief1x(100, "no trust anchor found - please set CADIR or CAFILE") ;
  }

  if (preoptions & 1)
  {
    x = getenv("CERTFILE") ;
    if (!x) strerr_dienotset(100, "CERTFILE") ;
    if (tls_config_set_cert_file(cfg, x) < 0)
      diecfg(cfg, "tls_config_set_cert_file") ;

    x = getenv("KEYFILE") ;
    if (!x) strerr_dienotset(100, "KEYFILE") ;
    if (tls_config_set_key_file(cfg, x) < 0)
      diecfg(cfg, "tls_config_set_key_file") ;
  }

  stls_drop() ;

  if (tls_config_set_ciphers(cfg, "secure") < 0)
    diecfg(cfg, "tls_config_set_ciphers") ;

  if (tls_config_set_dheparams(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_dheparams") ;

  if (tls_config_set_ecdhecurve(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_ecdhecurve") ;

  tls_config_verify(cfg) ;
  tls_config_set_protocols(cfg, TLS_PROTOCOLS_ALL) ;
  tls_config_prefer_ciphers_server(cfg) ;
  if (!servername) tls_config_insecure_noverifyname(cfg) ;

  ctx = tls_client() ;
  if (!ctx) strerr_diefu1sys(111, "tls_client") ;
  if (tls_configure(ctx, cfg) < 0) diectx(97, ctx, "tls_configure") ;

  if (tls_connect_fds(ctx, fds[0], fds[1], servername) < 0)
    diectx(97, ctx, "tls_connect_fds") ;
  tls_config_free(cfg) ;
  if (tls_handshake(ctx) < 0) diectx(97, ctx, "perform SSL handshake") ;
  return ctx ;
}
