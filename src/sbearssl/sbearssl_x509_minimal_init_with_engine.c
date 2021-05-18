/* ISC license. */

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

void sbearssl_x509_minimal_init_with_engine (br_x509_minimal_context *xc, br_ssl_engine_context *eng, br_x509_trust_anchor const *btas, size_t n)
{
  static const br_hash_class *hashes[] =
  {
    &br_md5_vtable,
    &br_sha1_vtable,
    &br_sha224_vtable,
    &br_sha256_vtable,
    &br_sha384_vtable,
    &br_sha512_vtable
  } ;

  br_x509_minimal_init(xc, &br_sha256_vtable, btas, n) ;
  br_x509_minimal_set_rsa(xc, br_ssl_engine_get_rsavrfy(eng)) ;
  br_x509_minimal_set_ecdsa(xc, br_ssl_engine_get_ec(eng), br_ssl_engine_get_ecdsa(eng)) ;
  for (unsigned int id = br_md5_ID ; id <= br_sha512_ID ; id++)
    br_x509_minimal_set_hash(xc, id, hashes[id-1]) ;
  br_ssl_engine_set_x509(eng, &xc->vtable) ;
}
