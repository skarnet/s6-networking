/* ISC license. */

#include <unistd.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/djbunix.h>
#include <skalibs/random.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_s6tlsc (char const *const *argv, char const *const *envp, tain_t const *tto, uint32_t preoptions, uint32_t options, uid_t uid, gid_t gid, unsigned int verbosity, char const *servername, int *sfd)
{
  int fds[5] = { sfd[0], sfd[1], sfd[0], sfd[1] } ;
  stralloc storage = STRALLOC_ZERO ;
  genalloc tas = GENALLOC_ZERO ;
  size_t talen ;
  pid_t pid ;

  if (preoptions & 1)
    strerr_dief1x(100, "client certificates are not supported yet") ;

  {
    int r ;
    char const *x = env_get2(envp, "CADIR") ;
    if (x)
      r = sbearssl_ta_readdir(x, &tas, &storage) ;
    else
    {
      x = env_get2(envp, "CAFILE") ;
      if (!x) strerr_dienotset(100, "CADIR or CAFILE") ;
      r = sbearssl_ta_readfile(x, &tas, &storage) ;
    }

    if (r < 0)
      strerr_diefu2sys(111, "read trust anchors in ", x) ;
    else if (r)
      strerr_diefu4x(96, "read trust anchors in ", x, ": ", sbearssl_error_str(r)) ;

    talen = genalloc_len(sbearssl_ta, &tas) ;
    if (!talen)
      strerr_dief2x(96, "no trust anchor found in ", x) ;
  }

  if (!random_init()) strerr_diefu1sys(111, "initialize random generator") ;

  pid = sbearssl_prep_spawn_drop(argv, envp, fds, uid, gid, !!(preoptions & 2)) ;

  {
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;
    br_x509_minimal_context xc ;
    br_ssl_client_context cc ;
    br_x509_trust_anchor btas[talen] ;
    size_t i = talen ;
    int wstat ;

    stralloc_shrink(&storage) ;
    while (i--)
      sbearssl_ta_to(genalloc_s(sbearssl_ta, &tas) + i, btas + i, storage.s) ;
    genalloc_free(sbearssl_ta, &tas) ;
    br_ssl_client_init_full(&cc, &xc, btas, talen) ;
    random_string((char *)buf, 32) ;
    br_ssl_engine_inject_entropy(&cc.eng, buf, 32) ;
    random_finish() ;
    br_ssl_engine_set_buffer(&cc.eng, buf, sizeof(buf), 1) ;
    if (!br_ssl_client_reset(&cc, servername, 0))
      strerr_diefu2x(97, "reset client context: ", sbearssl_error_str(br_ssl_engine_last_error(&cc.eng))) ;
    tain_now_g() ;
    if (!sbearssl_x509_minimal_set_tain(&xc, &STAMP))
      strerr_diefu1sys(111, "initialize validation time") ;

    wstat = sbearssl_run(&cc.eng, fds, pid, verbosity, options, tto) ;
    if (wstat < 0 && wait_pid(pid, &wstat) < 0) strerr_diefu1sys(111, "wait_pid") ;
    return wait_estatus(wstat) ;
  }
}
