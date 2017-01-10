/* ISC license. */

#include <stdint.h>
#include <netdb.h>
#include <skalibs/uint16.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr2.h>

#define USAGE "s6-getservbyname service proto"

int main (int argc, char const *const *argv)
{
  char fmt[UINT16_FMT] ;
  uint16_t port ;
  PROG = "s6-getservbyname" ;
  if (argc < 3) strerr_dieusage(100, USAGE) ;
  if (!uint160_scan(argv[1], &port))
  {
    struct servent *se = getservbyname(argv[1], argv[2]) ;
    uint16_t tmpport ;
    if (!se) return 1 ;
    tmpport = (uint16_t)se->s_port ;
    uint16_unpack_big((char const *)&tmpport, &port) ;
  }
  if ((buffer_put(buffer_1small, fmt, uint16_fmt(fmt, port)) < 0)
   || (buffer_putflush(buffer_1small, "\n", 1) < 1))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;
}
