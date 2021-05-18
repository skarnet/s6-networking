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
  sbearssl_skey skey ;
  genalloc certs = GENALLOC_ZERO ;  /* sbearssl_cert */
  genalloc tas = GENALLOC_ZERO ;  /* sbearssl_ta */
  stralloc storage = STRALLOC_ZERO ;
  size_t chainlen = sbearssl_get_keycert(&skey, &certs, &storage) ;
  size_t n = preoptions & 1 ? sbearssl_get_tas(&tas, &storage) : 0 ;

  sbearssl_drop() ;
  stralloc_shrink(&storage) ;

  {
    sbearssl_handshake_cb_context_t cbarg = { .notif = notif } ;
    union br_skey_u key ;
    br_ssl_server_context sc ;
    br_x509_minimal_context xc ;
    br_x509_certificate chain[chainlen] ;
    br_x509_trust_anchor btas[n ? n : 1] ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;

    for (size_t i = 0 ; i < chainlen ; i++)
      sbearssl_cert_to(genalloc_s(sbearssl_cert, &certs) + i, chain + i, storage.s) ;
    genalloc_free(sbearssl_cert, &certs) ;

    for (size_t i = 0 ; i < n ; i++)
      sbearssl_ta_to(genalloc_s(sbearssl_ta, &tas) + i, btas + i, storage.s) ;
    genalloc_free(sbearssl_ta, &tas) ;

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
      if (!(preoptions & 2)) flags |= BR_OPT_TOLERATE_NO_CLIENT_AUTH ;
      br_ssl_engine_add_flags(&sc.eng, flags) ;
    }

    if (n)
    {
      sbearssl_x509_minimal_init_with_engine(&xc, &sc.eng, btas, n) ;
      if (!sbearssl_x509_minimal_set_tain(&xc, &STAMP))
        strerr_diefu1sys(111, "initialize validation time") ;
      br_ssl_server_set_trust_anchor_names_alt(&sc, btas, n) ;
    }

    random_string((char *)buf, 32) ;
    random_finish() ;
    br_ssl_engine_inject_entropy(&sc.eng, buf, 32) ;
    br_ssl_engine_set_buffer(&sc.eng, buf, sizeof(buf), 1) ;
    if (!br_ssl_server_reset(&sc))
      strerr_diefu2x(97, "reset server context: ", sbearssl_error_str(br_ssl_engine_last_error(&sc.eng))) ;

    sbearssl_run(&sc.eng, fds, tto, options, verbosity, cb, &cbarg) ;
  }
}
