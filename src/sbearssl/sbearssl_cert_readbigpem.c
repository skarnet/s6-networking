/* ISC license. */

#include <string.h>

#include <bearssl.h>

#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/djbunix.h>

#include <s6-networking/sbearssl.h>

int sbearssl_cert_readbigpem (char const *fn, genalloc *certs, stralloc *sa)
{
  char buf[BUFFER_INSIZE] ;
  int fd = open_readb(fn) ;
  buffer b = BUFFER_INIT(&buffer_read, fd, buf, BUFFER_INSIZE) ;
  genalloc pems = GENALLOC_ZERO ;
  sbearssl_pemobject *p ;
  size_t certsbase = genalloc_len(sbearssl_cert, certs) ;
  size_t sabase = sa->len ;
  size_t n ;
  size_t i = 0 ;
  int certswasnull = !genalloc_s(sbearssl_cert, certs) ;
  int sawasnull = !sa->s ;
  if (fd < 0) return -1 ;
  {
    int r = sbearssl_pem_decode_from_buffer(&b, &pems, sa) ;
    fd_close(fd) ;
    if (r) return r ;
  }
  p = genalloc_s(sbearssl_pemobject, &pems) ;
  n = genalloc_len(sbearssl_pemobject, &pems) ;
  for (; i < n ; i++)
  {
    char const *name = sa->s + p[i].name ;
    if (!strcmp(name, "CERTIFICATE")
     || !strcmp(name, "X509 CERTIFICATE"))
    {
      sbearssl_cert sc = { .data = p[i].data, .datalen = p[i].datalen } ;
      if (!genalloc_append(sbearssl_cert, certs, &sc)) goto fail ;
    }
  }
  
  genalloc_free(sbearssl_pemobject, &pems) ;
  return 0 ;

 fail:
  if (certswasnull) genalloc_free(sbearssl_cert, certs) ;
  else genalloc_setlen(sbearssl_cert, certs, certsbase) ;
  if (sawasnull) stralloc_free(sa) ;
  else sa->len = sabase ;
  genalloc_free(sbearssl_pemobject, &pems) ;
  return -1 ;
}
