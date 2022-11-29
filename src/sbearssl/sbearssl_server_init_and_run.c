/* ISC license. */

#include <stdint.h>
#include <stdlib.h>

#include <bearssl.h>

#include <skalibs/posixplz.h>
#include <skalibs/bytestr.h>
#include <skalibs/strerr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/random.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

void sbearssl_server_init_and_run (int *fds, tain const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, sbearssl_handshake_cbfunc_ref cb, sbearssl_handshake_cbarg *cbarg)
{
  sbearssl_sni_policy_context pol ;
  sbearssl_sni_policy_init(&pol) ;

  if (!(preoptions & 8))  /* snilevel < 2 : add default keypair */
  {
    int e ;
    char const *keyfile ;
    char const *certfile = getenv("CERTFILE") ;
    if (!certfile) strerr_dienotset(100, "CERTFILE") ;
    keyfile = getenv("KEYFILE") ;
    if (!keyfile) strerr_dienotset(100, "KEYFILE") ;
    e = sbearssl_sni_policy_add_keypair_file(&pol, "", certfile, keyfile) ;
    if (e < 0)
      strerr_diefu1sys(96, "add default keypair to policy context") ;
    else if (e)
      strerr_diefu3x(96, "add default keypair to policy context", ": ", sbearssl_error_str(e)) ;
  }

  if (preoptions & 4)  /* snilevel > 0 : add additional keypairs */
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
          int e ;
          char const *x ;
          char certvar[len - kequal + 10] ;
          memcpy(certvar, "CERTFILE:", 9) ;
          memcpy(certvar + 9, *envp + 8, kequal - 8) ;
          certvar[kequal + 1] = 0 ;
          x = getenv(certvar) ;
          if (!x)
            strerr_dief3x(96, "environment variable KEYFILE:", certvar + 9, " not paired with the corresponding CERTFILE") ;
          e = sbearssl_sni_policy_add_keypair_file(&pol, certvar + 9, x, *envp + kequal + 1) ;
          if (e < 0)
            strerr_diefu3sys(96, "add keypair for servername ", certvar + 9, " to policy context") ;
          else if (e)
            strerr_diefu5x(96, "add keypair for servername ", certvar + 9, " to policy context", ": ", sbearssl_error_str(e)) ;
        }
      }
    }
  }

  sbearssl_drop() ;

  if (!sbearssl_sni_policy_nkeypairs(&pol))
    strerr_dief1x(96, "no suitable keypairs found in the environment") ;

  {
    br_ssl_server_context sc ;
    sbearssl_x509_small_context xc ;
    stralloc tastorage = STRALLOC_ZERO ;
    genalloc tas = GENALLOC_ZERO ;  /* sbearssl_ta */
    size_t n = preoptions & 1 ? sbearssl_get_tas(&tas, &tastorage) : 0 ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;
    br_x509_trust_anchor btas[n ? n : 1] ;

    sbearssl_sctx_init_full_generic(&sc) ;
    sbearssl_sctx_set_policy_sni(&sc, &pol) ;
    random_buf((char *)buf, 32) ;
    br_ssl_engine_inject_entropy(&sc.eng, buf, 32) ;
    br_ssl_engine_set_buffer(&sc.eng, buf, sizeof(buf), 1) ;

    {
      uint32_t flags = BR_OPT_ENFORCE_SERVER_PREFERENCES | BR_OPT_NO_RENEGOTIATION ;
      if (!(preoptions & 2)) flags |= BR_OPT_TOLERATE_NO_CLIENT_AUTH ;
      br_ssl_engine_add_flags(&sc.eng, flags) ;
    }

    if (n)  /* Set up client cert verification */
    {
      for (size_t i = 0 ; i < n ; i++)
        sbearssl_ta_to(genalloc_s(sbearssl_ta, &tas) + i, btas + i, tastorage.s) ;
      genalloc_free(sbearssl_ta, &tas) ;
      sbearssl_x509_small_init_full(&xc, btas, n, &cbarg->eedn, &cbarg->eltstatus, cbarg->eehash) ;
      if (!sbearssl_x509_small_set_tain_g(&xc))
        strerr_diefu1sys(111, "initialize validation time") ;
      br_ssl_engine_set_default_rsavrfy(&sc.eng) ;
      br_ssl_engine_set_default_ecdsa(&sc.eng) ;
      br_ssl_engine_set_x509(&sc.eng, &xc.vtable) ;
      br_ssl_server_set_trust_anchor_names_alt(&sc, btas, n) ;
      cbarg->exportmask |= 3 ;
    }

    if (!br_ssl_server_reset(&sc))
      strerr_diefu2x(97, "reset server context: ", sbearssl_error_str(br_ssl_engine_last_error(&sc.eng))) ;
    sbearssl_run(&sc.eng, fds, tto, options, verbosity, cb, cbarg) ;
  }
}
