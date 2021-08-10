/* ISC license. */

#include <stdlib.h>

#include <tls.h>

#include <skalibs/posixplz.h>
#include <skalibs/bytestr.h>
#include <skalibs/strerr2.h>

#include <s6-networking/stls.h>
#include "stls-internal.h"

#define diecfg(cfg, s) strerr_diefu3x(96, (s), ": ", tls_config_error(cfg))
#define diectx(e, ctx, s) strerr_diefu3x(e, (s), ": ", tls_error(ctx))

struct tls *stls_server_init_and_handshake (int const *fds, tain const *tto, uint32_t preoptions)
{
  struct tls *ctx = 0 ;
  struct tls *sctx ;
  struct tls_config *cfg ;
  char const *x ;
  int got = 0 ;

  if (tls_init() < 0) strerr_diefu1sys(111, "tls_init") ;
  cfg = tls_config_new() ;
  if (!cfg) strerr_diefu1sys(111, "tls_config_new") ;

  if (!(preoptions & 8)) /* snilevel < 2 */
  {
    char const *y = getenv("CERTFILE") ;
    if (!y) strerr_dienotset(100, "CERTFILE") ;
    x = getenv("KEYFILE") ;
    if (!x) strerr_dienotset(100, "KEYFILE") ;
    if (tls_config_set_keypair_file(cfg, y, x) < 0)
      diecfg(cfg, "tls_config_set_keypair_file") ;
    got = 1 ;
  }
  if (preoptions & 4) /* snilevel > 0 */
  {
    char const *const *envp = (char const *const *)environ ;
    for (; *envp ; envp++)
    {
      if (str_start(*envp, "KEYFILE:"))
      {
        size_t len = strlen(*envp) ;
        size_t kequal = byte_chr(*envp, len, '=') ;
        if (kequal == len) strerr_dief1x(100, "invalid environment") ;
        if (kequal != 8)
        {
          char certvar[len - kequal + 10] ;
          memcpy(certvar, "CERTFILE:", 9) ;
          memcpy(certvar + 9, *envp + 8, kequal - 8) ;
          certvar[kequal + 1] = 0 ;
          x = getenv(certvar) ;
          if (!x)
            strerr_dief3x(96, "environment variable KEYFILE:", certvar + 9, " not paired with the corresponding CERTFILE") ;
          else if (!got)
          {
            if (tls_config_set_keypair_file(cfg, x, *envp + kequal + 1) < 0)
              diecfg(cfg, "tls_config_set_keypair_file") ;
            got = 1 ;
          }
          else if (tls_config_add_keypair_file(cfg, x, *envp + kequal + 1) < 0)
            diecfg(cfg, "tls_config_add_keypair_file") ;
        }
      }
    }
  }

  stls_drop() ;

  if (tls_config_set_ciphers(cfg, "secure") < 0)
    diecfg(cfg, "tls_config_set_ciphers") ;

  if (tls_config_set_dheparams(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_dheparams") ;

  if (tls_config_set_ecdhecurve(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_ecdhecurve") ;

  if (preoptions & 1)
  {
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
      else strerr_dienotset(100, "CADIR or CAFILE") ;
    }
    if (preoptions & 2) tls_config_verify_client(cfg) ;
    else tls_config_verify_client_optional(cfg) ;
  }
  else tls_config_insecure_noverifycert(cfg) ;

  tls_config_set_protocols(cfg, TLS_PROTOCOLS_DEFAULT) ;
  tls_config_prefer_ciphers_server(cfg) ;

  sctx = tls_server() ;
  if (!sctx) strerr_diefu1sys(111, "tls_server") ;
  if (tls_configure(sctx, cfg) < 0) diectx(97, ctx, "tls_configure") ;
  tls_config_free(cfg) ;
  if (tls_accept_fds(sctx, &ctx, fds[0], fds[1]) < 0)
    diectx(97, sctx, "tls_accept_fds") ;
  /* We can't free sctx, ctx has pointers into it! Stupid API. We let sctx leak. */
  /* tls_free(sctx) ; */
  stls_handshake(ctx, tto) ;
  return ctx ;
}
