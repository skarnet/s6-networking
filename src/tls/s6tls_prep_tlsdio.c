/* ISC license. */

#include <skalibs/types.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

void s6tls_prep_tlsdio (char const **argv, char *buf, int const *p, uint32_t options, unsigned int verbosity, unsigned int kimeout, unsigned int snilevel)
{
  size_t m = 0 ;
  size_t n = 0 ;

  argv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsd-io" ;
  if (verbosity != 1)
  {
    argv[m++] = "-v" ;
    argv[m++] = buf + n ;
    n += uint_fmt(buf + n, verbosity) ;
    buf[n++] = 0 ;
  }
  if (p[5])
  {
    argv[m++] = "-d" ;
    argv[m++] = buf + n ;
    n += uint_fmt(buf + n, p[5]) ;
    buf[n++] = 0 ;
  }
  argv[m++] = options & 4 ? "-S" : "-s" ;
  argv[m++] = options & 8 ? "-J" : "-j" ;
  if (options & 1)
    argv[m++] = options & 2 ? "-y" : "-Y" ;
  if (kimeout)
  {
    argv[m++] = "-K" ;
    argv[m++] = buf + n ;
    n += uint_fmt(buf + n, kimeout) ;
    buf[n++] = 0 ;
  }
  if (snilevel)
  {
    argv[m++] = "-k" ;
    argv[m++] = buf + n ;
    n += uint_fmt(buf + n, snilevel) ;
    buf[n++] = 0 ;
  }
  argv[m++] = "--" ;
  argv[m++] = buf + n ;
  n += uint_fmt(buf + n, p[0]) ;
  buf[n++] = 0 ;
  argv[m++] = buf + n ;
  n += uint_fmt(buf + n, p[3]) ;
  buf[n++] = 0 ;
  argv[m++] = 0 ;
}
