/* ISC license. */

#include <stdint.h>

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

static uint16_t const suites[] =
{
    BR_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,  /* ec cipher */
  BR_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,     /* rsa cipher */
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
  BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
  BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
  BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    BR_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
  BR_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
  BR_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
  BR_TLS_RSA_WITH_AES_128_GCM_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
  BR_TLS_RSA_WITH_AES_256_GCM_SHA384,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
  BR_TLS_RSA_WITH_AES_128_CCM,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
  BR_TLS_RSA_WITH_AES_256_CCM,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
  BR_TLS_RSA_WITH_AES_128_CCM_8,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
  BR_TLS_RSA_WITH_AES_256_CCM_8,
    BR_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
  BR_TLS_RSA_WITH_AES_128_CBC_SHA256,
    BR_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
  BR_TLS_RSA_WITH_AES_256_CBC_SHA256,
    BR_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
  BR_TLS_RSA_WITH_AES_128_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
  BR_TLS_RSA_WITH_AES_256_CBC_SHA,
    BR_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
  BR_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
  BR_TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    BR_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
} ;

static br_hash_class const *hashes[] =
{
  &br_md5_vtable,
  &br_sha1_vtable,
  &br_sha224_vtable,
  &br_sha256_vtable,
  &br_sha384_vtable,
  &br_sha512_vtable
} ;

void sbearssl_sctx_init_full_generic (br_ssl_server_context *sc)
{
  br_ssl_server_zero(sc) ;
  br_ssl_engine_set_versions(&sc->eng, BR_TLS10, BR_TLS12) ;
  br_ssl_engine_set_suites(&sc->eng, suites, sizeof(suites) / sizeof(suites[0])) ;
  br_ssl_engine_set_default_ec(&sc->eng) ;

  for (unsigned int i = br_md5_ID ; i <= br_sha512_ID ; i++)
    br_ssl_engine_set_hash(&sc->eng, i, hashes[i-1]) ;

  br_ssl_engine_set_prf10(&sc->eng, &br_tls10_prf) ;
  br_ssl_engine_set_prf_sha256(&sc->eng, &br_tls12_sha256_prf) ;
  br_ssl_engine_set_prf_sha384(&sc->eng, &br_tls12_sha384_prf) ;

  br_ssl_engine_set_default_aes_cbc(&sc->eng) ;
  br_ssl_engine_set_default_aes_ccm(&sc->eng) ;
  br_ssl_engine_set_default_aes_gcm(&sc->eng) ;
  br_ssl_engine_set_default_des_cbc(&sc->eng) ;
  br_ssl_engine_set_default_chapol(&sc->eng) ;
}
