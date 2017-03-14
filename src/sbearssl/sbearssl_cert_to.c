/* ISC license. */

#include <s6-networking/sbearssl.h>

void sbearssl_cert_to (sbearssl_cert const *sc, br_x509_certificate *bc, char *s)
{
  bc->data = (unsigned char *)s + sc->data ;
  bc->data_len = sc->datalen ;
}
