/* ISC license. */

#include <skalibs/bytestr.h>
#include <skalibs/buffer.h>

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

int sbearssl_send_environment (br_ssl_engine_context *ctx, int fd)
{
  char buf[4096] ;
  buffer b = BUFFER_INIT(&buffer_write, fd, buf, 4096) ;
  unsigned int v = br_ssl_engine_get_version(ctx) ;
  char const *name = br_ssl_engine_get_server_name(ctx) ;
  char const *suite ;
  br_ssl_session_parameters params ;

  br_ssl_engine_get_session_parameters(ctx, &params) ;
  suite = sbearssl_suite_name(&params) ;
  byte_zzero((char *)params.master_secret, 48) ;
  if (!suite) suite = "" ;

  if (buffer_puts(&b, "SSL_PROTOCOL=") < 0
   || buffer_puts(&b, v == BR_TLS12 ? "TLSv1.2" : v == BR_TLS11 ? "TLSv1.1" : v == BR_TLS10 ? "TLSv1" : "unknown") < 0
   || buffer_put(&b, "", 1) < 0
   || buffer_puts(&b, "SSL_CIPHER=") < 0
   || buffer_puts(&b, suite) < 0
   || buffer_put(&b, "", 1) < 0
   || buffer_puts(&b, "SSL_TLS_SNI_SERVERNAME") < 0)
    return 0 ;
  if (name[0])
  {
    if (buffer_put(&b, "=", 1) < 0
     || buffer_puts(&b, name) < 0)
      return 0 ;
  }
  if (buffer_putflush(&b, "\0", 2) < 0)
    return 0 ;
  return 1 ;
}
