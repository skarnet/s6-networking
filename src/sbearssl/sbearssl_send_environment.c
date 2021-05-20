/* ISC license. */

#include <stddef.h>
#include <stdint.h>

#include <skalibs/bytestr.h>
#include <skalibs/buffer.h>
#include <skalibs/fmtscan.h>

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

static uint8_t class (char c)
{
  switch (c)
  {
    case '\0' : return 0 ;
    case ' ' : return 1 ;
    case ',' :
    case '=' :
    case '\n' :
    case '+' :
    case '<' :
    case '>' :
    case '#' :
    case '\\' : return 2 ;
    default : return 3 ;
  }
}

static int print_element (buffer *b, char const *s)
{
  static uint8_t const table[3][4] =
  {
    { 0x03, 0x00, 0x19, 0x09 },
    { 0x03, 0x62, 0x19, 0x09 },
    { 0x03, 0x42, 0x99, 0x89 }
  } ;
  size_t counter = 0 ;
  uint8_t state = 0 ;
  while (state < 3)
  {
    char ch = *s++ ;
    uint8_t c = table[state][class(ch)] ;
    state = c & 3 ;
    if (c & 0x10) if (buffer_put(b, "\\", 1) < 0) return 0 ;
    if (c & 0x20) counter = 0 ;
    if (c & 0x40) counter++ ;
    if (c & 0x80) while (counter--) if (buffer_put(b, " ", 1) < 0) return 0 ;
    if (c & 0x08) if (buffer_put(b, &ch, 1) < 0) return 0 ;
  }
  return 1 ;
}

struct eltinfo_s
{
  char const *keyword ;
  size_t offset ;
} ;


static int print_dn (buffer *b, sbearssl_dn const *dn, uint8_t eltstatus)
{
  static struct eltinfo_s const eltinfo[6] =
  {
    { .keyword = "C",  .offset = offsetof(sbearssl_dn, c)  },
    { .keyword = "ST", .offset = offsetof(sbearssl_dn, st) },
    { .keyword = "L",  .offset = offsetof(sbearssl_dn, l)  },
    { .keyword = "O",  .offset = offsetof(sbearssl_dn, o)  },
    { .keyword = "OU", .offset = offsetof(sbearssl_dn, ou) },
    { .keyword = "CN", .offset = offsetof(sbearssl_dn, cn) }
  } ;
  int got = 0 ;
  unsigned int mask = 1 ;
  for (unsigned int i = 0 ; i < 6 ; i++, mask <<= 1) if (eltstatus & mask)
  {
    if ((got && buffer_puts(b, ", ") < 0)
     || buffer_puts(b, eltinfo[i].keyword) < 0
     || buffer_put(b, "=", 1) < 0
     || !print_element(b, (char const *)dn + eltinfo[i].offset))
      return 0 ;
    got = 1 ;
  }
  return 1 ;
}

int sbearssl_send_environment (br_ssl_engine_context *ctx, sbearssl_handshake_cbarg *p)
{
  char buf[4096] ;
  buffer b = BUFFER_INIT(&buffer_write, p->notif, buf, 4096) ;
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
   || buffer_put(&b, "", 1) < 0) return 0 ;

  if (buffer_puts(&b, "SSL_TLS_SNI_SERVERNAME") < 0) return 0 ;
  if (name[0])
  {
    if (buffer_put(&b, "=", 1) < 0
     || buffer_puts(&b, name) < 0)
      return 0 ;
  }
  if (buffer_put(&b, "", 1) < 0) return 0 ;

  if (buffer_puts(&b, "SSL_PEER_CERT_HASH") < 0) return 0 ;
  if (p->exportmask & 1)
  {
    char eehash[64] ;
    ucharn_fmt(eehash, p->eehash, 32) ;
    if (buffer_puts(&b, "=SHA256:") < 0
     || buffer_put(&b, eehash, 64) < 0)
      return 0 ;
  }
  if (buffer_put(&b, "", 1) < 0) return 0 ;

  if (buffer_puts(&b, "SSL_PEER_CERT_SUBJECT") < 0) return 0 ;
  if (p->exportmask & 2 && p->eltstatus)
  {
    if (buffer_put(&b, "=", 1) < 0) return 0 ;
    if (p->eltstatus & 128)
    {
      if (buffer_puts(&b, "<invalid>") < 0) return 0 ;
    }
    else if (!print_dn(&b, &p->eedn, p->eltstatus)) return 0 ;
  }
  if (buffer_put(&b, "", 1) < 0) return 0 ;

  return buffer_putflush(&b, "\0", 2) >= 0 ;
}
