/* ISC license. */

#include <stdint.h>
#include <stdlib.h>

#include <bearssl.h>

#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/random.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

void sbearssl_server_init_and_run (int *fds, tain_t const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, sbearssl_handshake_cb_t_ref cb, unsigned int notif)
{
  stralloc storage = STRALLOC_ZERO ;
  sbearssl_skey skey ;
  genalloc certs = GENALLOC_ZERO ;
  size_t chainlen ;

  if (preoptions & 1)
    strerr_dief1x(100, "client certificates are not supported yet") ;

  {
    char const *x = getenv("KEYFILE") ;
    int r ;
    if (!x) strerr_dienotset(100, "KEYFILE") ;
    r = sbearssl_skey_readfile(x, &skey, &storage) ;
    if (r < 0)
      strerr_diefu2sys(111, "read private key in ", x) ;
    else if (r)
      strerr_diefu4x(96, "decode private key in ", x, ": ", sbearssl_error_str(r)) ;

    x = getenv("CERTFILE") ;
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

  sbearssl_drop() ;

  {
    sbearssl_handshake_cb_context_t cbarg = { .notif = notif } ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;
    br_ssl_server_context sc ;
    union br_skey_u key ;
    br_x509_certificate chain[chainlen] ;
    size_t i = chainlen ;

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

    {
      uint32_t flags = BR_OPT_ENFORCE_SERVER_PREFERENCES | BR_OPT_NO_RENEGOTIATION ;
      if (preoptions & 1)
      {
        /* br_ssl_server_set_trust_anchor_names(&sc, x500names, x500n) ; */
        if (!(preoptions & 2)) flags |= BR_OPT_TOLERATE_NO_CLIENT_AUTH ;
      }
      br_ssl_engine_add_flags(&sc.eng, flags) ;
    }

    random_string((char *)buf, 32) ;
    random_finish() ;
    br_ssl_engine_inject_entropy(&sc.eng, buf, 32) ;
    br_ssl_engine_set_buffer(&sc.eng, buf, sizeof(buf), 1) ;
    br_ssl_server_reset(&sc) ;
    sbearssl_run(&sc.eng, fds, tto, options, verbosity, cb, &cbarg) ;
  }
}
