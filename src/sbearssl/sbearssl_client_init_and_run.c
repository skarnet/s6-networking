/* ISC license. */

#include <stddef.h>
#include <stdlib.h>

#include <bearssl.h>

#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/random.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

void sbearssl_client_init_and_run (int *fds, tain const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, sbearssl_handshake_cbfunc_ref cb, sbearssl_handshake_cbarg *cbarg)
{
  sbearssl_skey skey ;
  genalloc certs = GENALLOC_ZERO ;  /* sbearssl_cert */
  genalloc tas = GENALLOC_ZERO ;  /* sbearssl_ta */
  stralloc storage = STRALLOC_ZERO ;
  size_t chainlen = preoptions & 1 ? sbearssl_get_keycert(&skey, &certs, &storage) : 0 ;
  size_t n = sbearssl_get_tas(&tas, &storage) ;

  sbearssl_drop() ;
  stralloc_shrink(&storage) ;

  {
    union br_skey_u key ;
    br_ssl_client_context cc ;
    sbearssl_x509_small_context xc ;
    br_x509_certificate chain[chainlen ? chainlen : 1] ;
    br_x509_trust_anchor btas[n] ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;

    for (size_t i = 0 ; i < chainlen ; i++)
      sbearssl_cert_to(genalloc_s(sbearssl_cert, &certs) + i, chain + i, storage.s) ;
    genalloc_free(sbearssl_cert, &certs) ;

    for (size_t i = 0 ; i < n ; i++)
      sbearssl_ta_to(genalloc_s(sbearssl_ta, &tas) + i, btas + i, storage.s) ;
    genalloc_free(sbearssl_ta, &tas) ;
    {
      br_x509_minimal_context dummy ; /* wasteful but the only simple API we have */
      br_ssl_client_init_full(&cc, &dummy, btas, n) ;
    }
    sbearssl_x509_small_init_full(&xc, btas, n, &cbarg->eedn, &cbarg->eltstatus, cbarg->eehash) ;
    if (!sbearssl_x509_small_set_tain_g(&xc))
      strerr_diefu1sys(111, "initialize validation time") ;
    br_ssl_engine_set_x509(&cc.eng, &xc.vtable) ;
    cbarg->exportmask |= 3 ;

    if (chainlen)
    {
      switch (skey.type)
      {
        case BR_KEYTYPE_RSA :
          sbearssl_rsa_skey_to(&skey.data.rsa, &key.rsa, storage.s) ;
          br_ssl_client_set_single_rsa(&cc, chain, chainlen, &key.rsa, br_rsa_pkcs1_sign_get_default()) ;
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
          br_ssl_client_set_single_ec(&cc, chain, chainlen, &key.ec, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, kt, br_ec_get_default(), br_ecdsa_sign_asn1_get_default()) ;
          break ;
        }
        default :
          strerr_dief1x(96, "unsupported private key type") ;
      }
    }

    br_ssl_engine_add_flags(&cc.eng, BR_OPT_NO_RENEGOTIATION) ;
    random_buf((char *)buf, 32) ;
    br_ssl_engine_inject_entropy(&cc.eng, buf, 32) ;
    br_ssl_engine_set_buffer(&cc.eng, buf, sizeof(buf), 1) ;
    if (!br_ssl_client_reset(&cc, servername, 0))
      strerr_diefu2x(97, "reset client context: ", sbearssl_error_str(br_ssl_engine_last_error(&cc.eng))) ;

    sbearssl_run(&cc.eng, fds, tto, options, verbosity, cb, cbarg) ;
  }
}
