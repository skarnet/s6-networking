/* ISC license. */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/env.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/djbunix.h>
#include <skalibs/random.h>
#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_s6tlsd (char const *const *argv, char const *const *envp, tain_t const *tto, uint32_t preoptions, uint32_t options, uid_t uid, gid_t gid, unsigned int verbosity)
{
  stralloc storage = STRALLOC_ZERO ;
  sbearssl_skey skey ;
  genalloc certs = GENALLOC_ZERO ;
  size_t chainlen ;

  if (preoptions & 1)
    strerr_dief1x(100, "client certificates are not supported by BearSSL yet") ;

  {
    char const *x = env_get2(envp, "KEYFILE") ;
    int r ;
    if (!x) strerr_dienotset(100, "KEYFILE") ;
    r = sbearssl_skey_readfile(x, &skey, &storage) ;
    if (r < 0)
      strerr_diefu2sys(111, "read private key in ", x) ;
    else if (r)
      strerr_diefu4x(96, "decode private key in ", x, ": ", sbearssl_error_str(r)) ;

    x = env_get2(envp, "CERTFILE") ;
    if (!x) strerr_dienotset(100, "CERTFILE") ;
    r = sbearssl_cert_readbigpem(x, &certs, &storage) ;
    if (r < 0)
      strerr_diefu2sys(111, "read certificate chain in ", x) ;
    else if (r)
      strerr_diefu4sys(96, "read certificate chain in ", x, ": ", sbearssl_error_str(r)) ;
    chainlen = genalloc_len(sbearssl_cert, &certs) ;
    if (!chainlen)
      strerr_diefu2x(96, "find a certificate in ", x) ;
  }

  {
    int fds[4] = { 0, 1, 0, 1 } ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;
    br_ssl_server_context sc ;
    union br_skey_u key ;
    br_x509_certificate chain[chainlen] ;
    size_t i = chainlen ;
    pid_t pid ;

    stralloc_shrink(&storage) ;
    while (i--)
      sbearssl_cert_to(genalloc_s(sbearssl_cert, &certs) + i, chain + i, storage.s) ;
    genalloc_free(sbearssl_cert, &certs) ;

    switch (skey.type)
    {
      case BR_KEYTYPE_RSA :
        sbearssl_rsa_skey_to(&skey.data.rsa, &key.rsa, storage.s) ;
        br_ssl_server_init_full_rsa(&sc, chain, chainlen, &key.rsa) ;
        break ;
      case BR_KEYTYPE_EC :
      {
        int kt, r ;
        sbearssl_ec_skey_to(&skey.data.ec, &key.ec, storage.s) ;
        r = sbearssl_ec_issuer_keytype(&kt, &chain[0]) ;
        switch (r)
        {
          case -2 : strerr_dief1x(96, "certificate issuer key type not recognized") ;
          case -1 : strerr_diefu1sys(111, "get certificate issuer key type") ;
          case 0 : break ;
          default : strerr_diefu3x(96, "get certificate issuer key type", ": ", sbearssl_error_str(r)) ;
        }
        br_ssl_server_init_full_ec(&sc, chain, chainlen, kt, &key.ec) ;
        break ;
      }
      default :
      strerr_dief1x(96, "unsupported private key type") ;
    }

    if (!random_init())
      strerr_diefu1sys(111, "initialize random generator") ;
    random_string((char *)buf, 32) ;
    br_ssl_engine_inject_entropy(&sc.eng, buf, 32) ;
    random_finish() ;

    pid = sbearssl_clean_tls_and_spawn(argv, envp, fds, !!(preoptions & 2)) ;
    if (!pid) strerr_diefu2sys(111, "spawn ", argv[0]) ;
    if (gid && setgid(gid) < 0) strerr_diefu1sys(111, "setgid") ;
    if (uid && setuid(uid) < 0) strerr_diefu1sys(111, "setuid") ;

    br_ssl_engine_set_buffer(&sc.eng, buf, sizeof(buf), 1) ;
    br_ssl_server_reset(&sc) ;
    tain_now_g() ;

    {
      int wstat ;
      int r = sbearssl_run(&sc.eng, fds, verbosity, options, tto) ;
      if (r < 0) strerr_diefu1sys(111, "run SSL engine") ;
      else if (r) strerr_diefu2x(98, "establish or maintain SSL connection to peer: ", sbearssl_error_str(r)) ;
      if (wait_pid(pid, &wstat) < 0) strerr_diefu1sys(111, "wait_pid") ;
      return wait_estatus(wstat) ;
    }
  }
}
