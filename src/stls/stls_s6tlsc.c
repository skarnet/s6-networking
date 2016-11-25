/* ISC license. */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <tls.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <s6-networking/stls.h>

#define diecfg(cfg, s) strerr_diefu3x(96, (s), ": ", tls_config_error(cfg))
#define diectx(e, ctx, s) strerr_diefu3x(e, (s), ": ", tls_error(ctx))

int stls_s6tlsc (char const *const *argv, char const *const *envp, tain_t const *tto, uint32_t preoptions, uint32_t options, uid_t uid, gid_t gid, unsigned int verbosity, int *sfd)
{
  int fds[4] = { sfd[0], sfd[1], sfd[0], sfd[1] } ;
  struct tls *cctx ;
  struct tls *ctx ;
  struct tls_config *cfg ;
  pid_t pid ;
  char const *x ;

  if (tls_init() < 0) strerr_diefu1sys(111, "tls_init") ;
  cfg = tls_config_new() ;
  if (!cfg) strerr_diefu1sys(111, "tls_config_new") ;

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
    else strerr_dief1x(100, "no trust anchor found - please set CADIR or CAFILE") ;
  }

  if (preoptions & 1)
  {
    x = env_get2(envp, "CERTFILE") ;
    if (!x) strerr_dienotset(100, "CERTFILE") ;
    if (tls_config_set_cert_file(cfg, x) < 0)
      diecfg(cfg, "tls_config_set_cert_file") ;

    x = env_get2(envp, "KEYFILE") ;
    if (!x) strerr_dienotset(100, "KEYFILE") ;
    if (tls_config_set_key_file(cfg, x) < 0)
      diecfg(cfg, "tls_config_set_cert_file") ;
  }

  if (tls_config_set_ciphers(cfg, "secure") < 0)
    diecfg(cfg, "tls_config_set_ciphers") ;

  if (tls_config_set_dheparams(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_dheparams") ;

  if (tls_config_set_ecdhecurve(cfg, "auto") < 0)
    diecfg(cfg, "tls_config_set_ecdhecurve") ;

  tls_config_verify(cfg) ;
  tls_config_set_protocols(cfg, TLS_PROTOCOLS_DEFAULT) ;
  tls_config_prefer_ciphers_server(cfg) ;

  ctx = tls_client() ;
  if (!ctx) strerr_diefu1sys(111, "tls_client") ;
  if (tls_configure(ctx, cfg) < 0) diectx(97, ctx, "tls_configure") ;
  tls_config_free(cfg) ;

  pid = child_spawn2(argv[0], argv, envp, fds) ;
  if (!pid) strerr_diefu2sys(111, "spawn ", argv[0]) ;
  if (gid && setgid(gid) < 0) strerr_diefu1sys(111, "setgid") ;
  if (uid && setuid(uid) < 0) strerr_diefu1sys(111, "setuid") ;

  if (tls_accept_fds(ctx, &cctx, fds[2], fds[3]) < 0)
    diectx(97, ctx, "tls_accept_fds") ;

  tls_free(ctx) ;

  {
    int wstat ;
    int r = stls_run(cctx, fds, verbosity, options, tto) ;
    if (r < 0) strerr_diefu1sys(111, "run SSL engine") ;
    else if (r) diectx(98, cctx, "run SSL engine") ;
    if (wait_pid(pid, &wstat) < 0) strerr_diefu1sys(111, "wait_pid") ;
    return wait_estatus(wstat) ;
  }
}
