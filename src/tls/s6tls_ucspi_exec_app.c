/* ISC license. */

#include <string.h>
#include <unistd.h>

#include <skalibs/types.h>

#include "s6tls-internal.h"

void s6tls_ucspi_exec_app (char const *const *argv, int const *p, uint32_t options)
{
  size_t m = 0 ;
  char modif[30 + 3 * UINT_FMT] ;
  close(p[5]) ;
  close(p[3]) ;
  close(p[0]) ;
  memcpy(modif + m, "SSLCTLFD=", 9) ; m += 9 ;
  m += uint_fmt(modif + m, p[4]) ;
  modif[m++] = 0 ;
  memcpy(modif + m, "SSLREADFD=", 10) ; m += 10 ;
  m += uint_fmt(modif + m, p[2]) ;
  modif[m++] = 0 ;
  memcpy(modif + m, "SSLWRITEFD=", 11) ; m += 11 ;
  m += uint_fmt(modif + m, p[1]) ;
  modif[m++] = 0 ;
  s6tls_clean_and_exec(argv, options, modif, m) ;
}
