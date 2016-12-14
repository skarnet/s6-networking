/* ISC license. */

#include <sys/types.h>
#include <bearssl.h>
#include <skalibs/stralloc.h>
#include <s6-networking/sbearssl.h>

int sbearssl_ta_from (sbearssl_ta *l, br_x509_trust_anchor const *k, stralloc *sa)
{
  size_t sabase = sa->len ;
  int sawasnull = !sa->s ;
  sbearssl_ta ta = { .dn = sa->len, .dnlen = k->dn.len, .flags = k->flags } ;
  if (!stralloc_catb(sa, (char const *)k->dn.data, k->dn.len)) return 0 ;
  if (!sbearssl_pkey_from(&ta.pkey, &k->pkey, sa)) goto fail ;
  *l = ta ;
  return 1 ;

 fail:
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  return 0 ;
}
