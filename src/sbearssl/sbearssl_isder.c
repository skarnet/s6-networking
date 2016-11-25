/* ISC license. */

#include <sys/types.h>
#include <s6-networking/sbearssl.h>

int sbearssl_isder (unsigned char const *s, size_t len)
{
  size_t dlen = 0 ;
  unsigned char c ;

  if (len < 2) return 0 ;
  if (*s++ != 0x30) return 0 ;
  c = *s++ ; len -= 2;
  if (c < 0x80) return (size_t)c == len ;
  else if (c == 0x80) return 0 ;
  c -= 0x80 ;
  if (len < (size_t)c + 2) return 0 ;
  len -= (size_t)c ;
  while (c--)
  {
    if (dlen > (len >> 8)) return 0 ;
    dlen = (dlen << 8) + (size_t)*s++ ;
  }
  return dlen == len ;
}
