/* ISC license. */

#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <tls.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <s6-networking/stls.h>
#include "stls-internal.h"

#define diecfg(cfg, s) strerr_diefu3x(96, (s), ": ", tls_config_error(cfg))
#define diectx(e, ctx, s) strerr_diefu3x(e, (s), ": ", tls_error(ctx))

int stls_s6tlsd (char const *const *argv, char const *const *envp, tain_t const *tto, uint32_t preoptions, uint32_t options, uid_t uid, gid_t gid, unsigned int verbosity)
{
  int fds[5] = { 0, 1, 0, 1 } ;
  struct tls *cctx ;
  struct tls *ctx ;
  struct tls_config *cfg ;
  pid_t pid ;
  char const *x ;
  int wstat ;

  if (tls_init() < 0) strerr_diefu1sys(111, "tls_init") ;
  cfg = tls_config_new() ;
  if (!cfg) strerr_diefu1sys(111, "tls_config_new") ;

  x = env_get2(envp, "CERTFILE") ;
  if (!x) strerr_dienotset(100, "CERTFILE") ;
  if (tls_config_set_cert_file(cfg, x) < 0)
    diecfg(cfg, "tls_config_set_cert_file") ;

  x = env_get2(envp, "KEYFILE") ;
  if (!x) strerr_dienotset(100, "KEYFILE") ;
  if (tls_config_set_key_file(cfg, x) < 0)
    diecfg(cfg, "tls_config_set_key_file") ;

  if (tls_config_set_ciphers(cfg, "secure") < 0)
    diecfg(cfg, "tls_config_set_ciphers") ;

  if (tls_config_set_dheparams(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_dheparams") ;

  if (tls_config_set_ecdhecurve(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_ecdhecurve") ;

  if (preoptions & 1)
  {
    x = env_get2(envp, "CADIR") ;
    if (x)
    {
      if (tls_config_set_ca_path(cfg, x) < 0)
        diecfg(cfg, "tls_config_set_ca_path") ;
    }
    else
    {
      x = env_get2(envp, "CAFILE") ;
      if (x)
      {
        if (tls_config_set_ca_file(cfg, x) < 0)
          diecfg(cfg, "tls_config_set_ca_file") ;
      }
      else strerr_dienotset(100, "CADIR or CAFILE") ;
    }
    if (preoptions & 4) tls_config_verify_client(cfg) ;
    else tls_config_verify_client_optional(cfg) ;
  }
  else tls_config_insecure_noverifycert(cfg) ;

  tls_config_set_protocols(cfg, TLS_PROTOCOLS_DEFAULT) ;
  tls_config_prefer_ciphers_server(cfg) ;

  ctx = tls_server() ;
  if (!ctx) strerr_diefu1sys(111, "tls_server") ;
  if (tls_configure(ctx, cfg) < 0) diectx(97, ctx, "tls_configure") ;
  tls_config_free(cfg) ;

  pid = stls_prep_spawn_drop(argv, envp, fds, uid, gid, !!(preoptions & 2)) ;

  if (tls_accept_fds(ctx, &cctx, fds[2], fds[3]) < 0)
    diectx(97, ctx, "tls_accept_fds") ;
  tls_free(ctx) ;
  if (tls_handshake(cctx) < 0) diectx(97, cctx, "perform SSL handshake") ;

  wstat = stls_run(cctx, fds, pid, verbosity, options, tto) ;
  if (wstat < 0 && wait_pid(pid, &wstat) < 0) strerr_diefu1sys(111, "wait_pid") ;
  return wait_estatus(wstat) ;
}
