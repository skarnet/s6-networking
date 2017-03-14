/* ISC license. */

#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_cert_from (sbearssl_cert *sc, br_x509_certificate const *bc, stralloc *sa)
{
  if (!stralloc_catb(sa, (char const *)bc->data, bc->data_len)) return 0 ;
  sc->data = sa->len - bc->data_len ;
  sc->datalen = bc->data_len ;
  return 1 ;
}
