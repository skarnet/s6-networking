/* ISC license. */

#include <unistd.h>
#include <stdlib.h>

#include <tls.h>

#include <skalibs/buffer.h>

#include <s6-networking/stls.h>

static int add (buffer *b, int h, char const *key, char const *value)
{
  if (buffer_puts(b, key) < 0) return 0 ;
  if (h && value && value[0])
  {
    if (buffer_put(b, "=", 1) < 0
     || buffer_puts(b, value) < 0)
      return 0 ;
  }
  if (buffer_put(b, "", 1) < 0) return 0 ;
  return 1 ;
}


int stls_send_environment (struct tls *ctx, int fd)
{
  char buf[4096] ;
  buffer b = BUFFER_INIT(&buffer_write, fd, buf, 4096) ;
  if (buffer_puts(&b, "SSL_PROTOCOL=") < 0
   || buffer_puts(&b, tls_conn_version(ctx)) < 0
   || buffer_put(&b, "", 1) < 0
   || buffer_puts(&b, "SSL_CIPHER=") < 0
   || buffer_puts(&b, tls_conn_cipher(ctx)) < 0
   || buffer_put(&b, "", 1) < 0)
    return 0 ;

  if (!add(&b, 1, "SSL_TLS_SNI_SERVERNAME", tls_conn_servername(ctx))) return 0 ;
  if (!add(&b, tls_peer_cert_provided(ctx), "SSL_PEER_CERT_HASH", tls_peer_cert_hash(ctx))) return 0 ;
  if (!add(&b, tls_peer_cert_provided(ctx), "SSL_PEER_CERT_SUBJECT", tls_peer_cert_subject(ctx))) return 0 ;

  if (buffer_putflush(&b, "", 1) < 0) return 0 ;
  return 1 ;
}
