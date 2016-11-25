/* ISC license. */

#include <bearssl.h>
#include <s6-networking/sbearssl.h>

void sbearssl_cert_to (sbearssl_cert const *sc, br_x509_certificate *bc, char const *s)
{
  bc->data = s + sc->data ;
  bc->data_len = sc->datalen ;
}
