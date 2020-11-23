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

void sbearssl_client_init_and_run (int *fds, tain_t const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, sbearssl_handshake_cb_t_ref cb, unsigned int notif)
{
  stralloc storage = STRALLOC_ZERO ;
  genalloc tas = GENALLOC_ZERO ;
  size_t talen ;

  if (preoptions & 1)
    strerr_dief1x(100, "client certificates are not supported yet") ;

  {
    int r ;
    char const *x = getenv("CADIR") ;
    if (x)
      r = sbearssl_ta_readdir(x, &tas, &storage) ;
    else
    {
      x = getenv("CAFILE") ;
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

  sbearssl_drop() ;

  {
    sbearssl_handshake_cb_context_t cbarg = { .notif = notif } ;
    unsigned char buf[BR_SSL_BUFSIZE_BIDI] ;
    br_x509_minimal_context xc ;
    br_ssl_client_context cc ;
    br_x509_trust_anchor btas[talen] ;
    size_t i = talen ;

    stralloc_shrink(&storage) ;
    while (i--)
      sbearssl_ta_to(genalloc_s(sbearssl_ta, &tas) + i, btas + i, storage.s) ;
    genalloc_free(sbearssl_ta, &tas) ;
    br_ssl_client_init_full(&cc, &xc, btas, talen) ;
    br_ssl_engine_add_flags(&cc.eng, BR_OPT_NO_RENEGOTIATION) ;
    random_string((char *)buf, 32) ;
    random_finish() ;
    br_ssl_engine_inject_entropy(&cc.eng, buf, 32) ;
    br_ssl_engine_set_buffer(&cc.eng, buf, sizeof(buf), 1) ;
    if (!br_ssl_client_reset(&cc, servername, 0))
      strerr_diefu2x(97, "reset client context: ", sbearssl_error_str(br_ssl_engine_last_error(&cc.eng))) ;
    if (!sbearssl_x509_minimal_set_tain(&xc, &STAMP))
      strerr_diefu1sys(111, "initialize validation time") ;

    sbearssl_run(&cc.eng, fds, tto, options, verbosity, cb, &cbarg) ;
  }
}
