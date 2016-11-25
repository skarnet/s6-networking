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

int sbearssl_cert_readfile (char const *fn, genalloc *certs, stralloc *sa) ;
{
  char buf[BUFFER_INSIZE] ;
  int fd = open_readb(fn) ;
  buffer b = BUFFER_INIT(&buffer_read, fd, buf, BUFFER_INSIZE) ;
  genalloc pems = GENALLOC_ZERO ;
  sbearssl_pemobject *p ;
  size_t certsbase = genalloc_len(sbearssl_cert, certs) ;
  size_t n ;
  size_t i = 0 ;
  int certswasnull = !genalloc_s(sbearssl_cert, certs) ;
  int r ;
  if (fd < 0) return -1 ;
  r = sbearssl_pem_decode_from_buffer(buf, n, &pems, sa) ;
  if (r) { fd_close(fd) ; return r ; }
  fd_close(fd) ;
  p = genalloc_s(sbearssl_pemobject, &pems) ;
  n = genalloc_len(sbearssl_pemobject, &pems) ;
  for (; i < n ; i++)
  {
    char const *name = sa->s + p[i].name ;
    if (!str_diff(name, "CERTIFICATE")
     || !str_diff(name, "X509 CERTIFICATE"))
    {
      sbearssl_cert sc = { .data = p[i].data, .datalen = p[i].datalen } ;
      if (!genalloc_append(sbearssl_cert, certs, &sc)) goto fail ;
    }
  }
  
  genalloc_free(sbearssl_pemobject, &pems) ;
  fd_close(fd) ;
  return 0 ;

 fail:
  if (certswasnull) genalloc_free(sbearssl_cert, certs) ;
  else genalloc_setlen(sbearssl_cert, certs, certsbase) ;
  stralloc_free(&sa) ;
  genalloc_free(sbearssl_pemobject, pems) ;
  return r ;
}
