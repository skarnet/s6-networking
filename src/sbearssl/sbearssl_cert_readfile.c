/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <bearssl.h>
#include <skalibs/bytestr.h>
#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/djbunix.h>
#include <s6-networking/sbearssl.h>

int sbearssl_cert_readfile (char const *fn, genalloc *certs, stralloc *sa)
{
  char buf[SBEARSSL_MAXCERTFILESIZE] ;
  size_t certsbase = genalloc_len(sbearssl_cert, certs) ;
  size_t sabase = sa->len ;
  size_t n ;
  int certswasnull = !genalloc_s(sbearssl_cert, certs) ;
  int sawasnull = !sa->s ;
  {
    register ssize_t r = openreadnclose(fn, buf, SBEARSSL_MAXCERTFILESIZE) ;
    if (r < 0) return r ;
    n = r ;
  }
  if (sbearssl_isder((unsigned char *)buf, n))
  {
    sbearssl_cert cert = { .data = sa->len, .datalen = n } ;
    if (!stralloc_catb(sa, buf, n)) return -1 ;
    if (!genalloc_append(sbearssl_cert, certs, &cert)) goto fail ;
  }
  else
  {
    genalloc pems = GENALLOC_ZERO ;
    size_t i = 0 ;
    sbearssl_pemobject *p ;
    register int r = sbearssl_pem_decode_from_string(buf, n, &pems, sa) ;
    if (r) return r ;
    p = genalloc_s(sbearssl_pemobject, &pems) ;
    n = genalloc_len(sbearssl_pemobject, &pems) ;
    for (; i < n ; i++)
    {
      char const *name = sa->s + p[i].name ;
      if (!str_diff(name, "CERTIFICATE")
       || !str_diff(name, "X509 CERTIFICATE"))
      {
        sbearssl_cert cert = { .data = p[i].data, .datalen = p[i].datalen } ;
        if (!genalloc_append(sbearssl_cert, certs, &cert))
        {
          genalloc_free(sbearssl_pemobject, &pems) ;
          goto fail ;
        }
      }
      genalloc_free(sbearssl_pemobject, &pems) ;
    }
  }
  
  return 0 ;

 fail:
  if (certswasnull) genalloc_free(sbearssl_cert, certs) ;
  else genalloc_setlen(sbearssl_cert, certs, certsbase) ;
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  return -1 ;
}
