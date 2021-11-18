/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <bearssl.h>

#include <skalibs/bytestr.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

#define INSTANCE(c) ((sbearssl_sni_policy_context *)(c))

#define COPY(x) do { k->data.rsa.x##len = l->data.rsa.x##len ; k->data.rsa.x = (unsigned char *)s + m ; memcpy(s + m, t + l->data.rsa.x, l->data.rsa.x##len) ; m += l->data.rsa.x##len ; } while (0)

static inline size_t skey_copy (br_skey *k, sbearssl_skey const *l, char *s, char const *t)
{
  size_t m = 0 ;
  k->type = l->type ;
  switch (l->type)
  {
    case BR_KEYTYPE_RSA :
      k->data.rsa.n_bitlen = l->data.rsa.n_bitlen ;
      COPY(p) ; COPY(q) ; COPY(dp) ; COPY(dq) ; COPY(iq) ;
      break ;
    case BR_KEYTYPE_EC :
      k->data.ec.curve = l->data.ec.curve ;
      k->data.ec.xlen = l->data.ec.xlen ; k->data.ec.x = (unsigned char *)s + m ; memcpy(s + m, t + l->data.ec.x, l->data.ec.xlen) ; m += l->data.ec.xlen ;
      break ;
  }
  return m ;
}

static inline size_t cert_copy (br_x509_certificate *newc, sbearssl_cert const *oldc, char *s, char const *t)
{
  memcpy(s, t + oldc->data, oldc->datalen) ;
  newc->data = (unsigned char *)s ;
  newc->data_len = oldc->datalen ;
  return oldc->datalen ;
}

static int choose (br_ssl_server_policy_class const **pctx, br_ssl_server_context const *sc, br_ssl_server_choices *choices)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  sbearssl_sni_policy_node *node ;
  char const *servername = br_ssl_engine_get_server_name(&sc->eng) ;

 /*
    Get the node corresponding to the ServerName sent by the client.
    If servername is foo.bar.baz, try:
    1. foo.bar.baz
    2. *.bar.baz (don't do this for TLDs, we don't want *.com)
    3. empty string (i.e. default certificate)
    If no SNI, only try the empty string.
 */
  {
    uint32_t n = avltree_totalsize(&pol->map) ;
    if (servername)
    {
      if (!avltree_search(&pol->map, servername, &n))
      {
        char const *sub1 = strchr(servername, '.') ;
        if (sub1 && sub1[1])
        {
          char const *sub2 = strchr(sub1 + 1, '.') ;
          if (sub2 && sub2[1])
          {
            size_t len = strlen(sub1) ;
            char tmp[len + 2] ;
            tmp[0] = '*' ;
            memcpy(tmp + 1, sub1, len + 1) ;
            avltree_search(&pol->map, tmp, &n) ;
          }
        }
      }
    }
    if (n == avltree_totalsize(&pol->map) && !avltree_search(&pol->map, "", &n)) return 0 ;
    avltree_free(&pol->map) ;
    node = genalloc_s(sbearssl_sni_policy_node, &pol->mapga) + n ;
  }

 /* Replace certga and storage with the chosen chain and its data, free all the rest */
  {
    stralloc storage = STRALLOC_ZERO ;
    genalloc certga = GENALLOC_ZERO ;
    size_t clen = 0 ;
    size_t m = 0 ;
    sbearssl_cert const *certstart = genalloc_s(sbearssl_cert, &pol->certga) + node->chainindex ;
    for (size_t i = 0 ; i < node->chainlen ; i++) clen += certstart[i].datalen ;
    if (!stralloc_ready_tuned(&storage, sbearssl_skey_storagelen(&node->skey) + clen, 0, 0, 1)) return 0 ;
    if (!genalloc_ready_tuned(br_x509_certificate, &certga, node->chainlen, 0, 0, 1))
    {
      stralloc_free(&storage) ;
      return 0 ;
    }
    m += skey_copy(&pol->skey, &node->skey, storage.s + m, pol->storage.s) ;
    for (size_t i = 0 ; i < node->chainlen ; i++)
      m += cert_copy(genalloc_s(br_x509_certificate, &certga) + i, certstart + i, storage.s + m, pol->storage.s) ;
    genalloc_setlen(br_x509_certificate, &certga, node->chainlen) ;
    genalloc_free(sbearssl_sni_policy_node, &pol->mapga) ;
    genalloc_free(sbearssl_cert, &pol->certga) ;
    byte_zzero(pol->storage.s, pol->storage.len) ;  /* contains skeys, so we wipe it */
    stralloc_free(&pol->storage) ;
    pol->certga = certga ;
    pol->storage = storage ;
  }

 /* We got our choice of cert chain */
  choices->chain = genalloc_s(br_x509_certificate, &pol->certga) ;
  choices->chain_len = genalloc_len(br_x509_certificate, &pol->certga) ;

 /* Now fill up the rest of the choices structure and gather info for later keyx/sign */
  switch (pol->skey.type)
  {
    case BR_KEYTYPE_RSA :
      if (!sbearssl_choose_algos_rsa(sc, choices, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN)) return 0 ;
      pol->keyx.rsa = br_rsa_private_get_default() ;
      pol->sign.rsa = br_rsa_pkcs1_sign_get_default() ;
      break ;
    case BR_KEYTYPE_EC :
    {
      int kt ;
      if (sbearssl_ec_issuer_keytype(&kt, &choices->chain[0])) return 0 ;
      if (!sbearssl_choose_algos_ec(sc, choices, BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, kt)) return 0 ;
      pol->keyx.ec = sc->eng.iec ;  /* the br_ssl_engine_get_ec() abstraction lacks a const */
      pol->sign.ec = br_ecdsa_sign_asn1_get_default() ;
      pol->mhash = &sc->eng.mhash ;  /* missing an abstraction function there */
      break ;
    }
    default : return 0 ;
  }
  return 1 ;
}

static uint32_t do_keyx (br_ssl_server_policy_class const **pctx, unsigned char *data, size_t *len)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  switch (pol->skey.type)
  {
    case BR_KEYTYPE_RSA :
      return br_rsa_ssl_decrypt(pol->keyx.rsa, &pol->skey.data.rsa, data, *len) ;
    case BR_KEYTYPE_EC :
    {
      size_t xlen ;
      uint32_t r = pol->keyx.ec->mul(data, *len, pol->skey.data.ec.x, pol->skey.data.ec.xlen, pol->skey.data.ec.curve) ;
      size_t xoff = pol->keyx.ec->xoff(pol->skey.data.ec.curve, &xlen) ;
      memmove(data, data + xoff, xlen) ;
      *len = xlen ;
      return r ;
    }
    default : return 0 ;
  }
}

static inline size_t sign_rsa (sbearssl_sni_policy_context *pol, unsigned int algo_id, unsigned char *data, size_t hv_len, size_t len)
{
  static unsigned char const HASH_OID_SHA1[] = { 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A } ;
  static unsigned char const HASH_OID_SHA224[] = { 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 } ;
  static unsigned char const HASH_OID_SHA256[] = { 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 } ;
  static unsigned char const HASH_OID_SHA384[] = { 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 } ;
  static unsigned char const HASH_OID_SHA512[] = { 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 } ;
  static unsigned char const *HASH_OID[] = { HASH_OID_SHA1, HASH_OID_SHA224, HASH_OID_SHA256, HASH_OID_SHA384, HASH_OID_SHA512 } ;
  unsigned char const *hash_oid = 0 ;
  size_t sig_len ;
  unsigned char hv[64] ;
  memcpy(hv, data, hv_len) ;
  if (algo_id >= 2 && algo_id <= 6) hash_oid = HASH_OID[algo_id - 2] ;
  else if (algo_id) return 0 ;
  sig_len = (pol->skey.data.rsa.n_bitlen + 7) >> 3 ;
  if (len < sig_len) return 0 ;
  return pol->sign.rsa(hash_oid, hv, hv_len, &pol->skey.data.rsa, data) ? sig_len : 0 ;
}

static inline size_t sign_ec (sbearssl_sni_policy_context *pol, unsigned int algo_id, unsigned char *data, size_t hv_len, size_t len)
{
  unsigned char hv[64] ;
  br_hash_class const *hc = br_multihash_getimpl(pol->mhash, algo_id) ;
  if (!hc) return 0 ;
  memcpy(hv, data, hv_len) ;
  if (len < 139) return 0 ;
  return pol->sign.ec(pol->keyx.ec, hc, hv, &pol->skey.data.ec, data) ;
}

static size_t do_sign (br_ssl_server_policy_class const **pctx, unsigned int algo_id, unsigned char *data, size_t hv_len, size_t len)
{
  sbearssl_sni_policy_context *pol = INSTANCE(pctx) ;
  algo_id &= 0xff ;  /* workaround for bearssl bug */
  switch (pol->skey.type)
  {
    case BR_KEYTYPE_RSA : return sign_rsa(pol, algo_id, data, hv_len, len) ;
    case BR_KEYTYPE_EC : return sign_ec(pol, algo_id, data, hv_len, len) ;
    default : return 0 ;
  }
}

br_ssl_server_policy_class const sbearssl_sni_policy_vtable =
{
  .context_size = sizeof(sbearssl_sni_policy_context),
  .choose = &choose,
  .do_keyx = &do_keyx,
  .do_sign = &do_sign
} ;
