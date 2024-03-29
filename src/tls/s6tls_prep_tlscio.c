/* ISC license. */

#include <skalibs/types.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

void s6tls_prep_tlscio (char const **argv, char *buf, int const *p, uint32_t options, unsigned int verbosity, unsigned int kimeout, char const *servername)
{
  size_t m = 0 ;
  size_t n = 0 ;

  argv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsc-io" ;
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
  if (options & 4) argv[m++] = "-S" ;
  if (options & 2) argv[m++] = "-J" ;
  if (options & 1) argv[m++] = "-y" ;
  if (kimeout)
  {
    argv[m++] = "-K" ;
    argv[m++] = buf + n ;
    n += uint_fmt(buf + n, kimeout) ;
    buf[n++] = 0 ;
  }
  if (servername)
  {
    argv[m++] = "-k" ;
    argv[m++] = servername ;
  }
  argv[m++] = "--" ;
  argv[m++] = buf + n ;
  n += uint_fmt(buf + n, p[6]) ;
  buf[n++] = 0 ;
  argv[m++] = buf + n ;
  n += uint_fmt(buf + n, p[7]) ;
  buf[n++] = 0 ;
  argv[m++] = 0 ;
}
