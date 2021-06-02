/* ISC license. */

#include <string.h>

#include <bearssl.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/avltree.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

int sbearssl_sni_policy_add_keypair_file (sbearssl_sni_policy_context *pol, char const *servername, char const *certfile, char const *keyfile)
{
  size_t sabase = pol->storage.len ;
  size_t gabase = genalloc_len(sbearssl_cert, &pol->certga) ;
  size_t mbase = genalloc_len(sbearssl_sni_policy_node, &pol->mapga) ;
  sbearssl_sni_policy_node node = { .servername = sabase, .chainindex = gabase } ;
  int e ;

  if (!stralloc_catb(&pol->storage, servername, strlen(servername) + 1)) return -1 ;
  e = sbearssl_cert_readbigpem(certfile, &pol->certga, &pol->storage) ;
  if (e) goto err0 ;
  node.chainlen = genalloc_len(sbearssl_cert, &pol->certga) - node.chainindex ;
  e = sbearssl_skey_readfile(keyfile, &node.skey, &pol->storage) ;
  if (e) goto err1 ;
  e = genalloc_catb(sbearssl_sni_policy_node, &pol->mapga, &node, 1) ? 0 : -1 ;
  if (e) goto err2 ;
  e = avltree_insert(&pol->map, mbase) ? 0 : -1 ;
  if (e) goto err3 ;
  return 0 ;

 err3:
  if (mbase) genalloc_setlen(sbearssl_sni_policy_node, &pol->mapga, mbase) ;
  else genalloc_free(sbearssl_sni_policy_node, &pol->mapga) ;
 err2:
  sbearssl_skey_wipe(&node.skey, pol->storage.s) ;
 err1:
  if (gabase) genalloc_setlen(sbearssl_cert, &pol->certga, gabase) ;
  else genalloc_free(sbearssl_sni_policy_node, &pol->mapga) ;
 err0:
  if (sabase) pol->storage.len = sabase ;
  else stralloc_free(&pol->storage) ;
  return e ;
}
