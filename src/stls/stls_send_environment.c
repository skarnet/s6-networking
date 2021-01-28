/* ISC license. */

#include <unistd.h>
#include <stdlib.h>

#include <tls.h>

#include <skalibs/buffer.h>

#include <s6-networking/stls.h>

int stls_send_environment (struct tls *ctx, int fd)
{
  char const *servername = tls_conn_servername(ctx) ;
  char buf[4096] ;
  buffer b = BUFFER_INIT(&buffer_write, fd, buf, 4096) ;
  if (!servername) servername = "" ;
  if (buffer_puts(&b, "SSL_PROTOCOL=") < 0
   || buffer_puts(&b, tls_conn_version(ctx)) < 0
   || buffer_put(&b, "", 1) < 0
   || buffer_puts(&b, "SSL_CIPHER=") < 0
   || buffer_puts(&b, tls_conn_cipher(ctx)) < 0
   || buffer_put(&b, "", 1) < 0
   || buffer_puts(&b, "SSL_TLS_SNI_SERVERNAME=") < 0
   || buffer_puts(&b, servername) < 0
   || buffer_putflush(&b, "\0", 2) < 0) return 0 ;
  return 1 ;
}
