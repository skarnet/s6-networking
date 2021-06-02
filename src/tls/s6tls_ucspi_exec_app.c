/* ISC license. */

#include <string.h>
#include <unistd.h>

#include <skalibs/types.h>

#include "s6tls-internal.h"

void s6tls_ucspi_exec_app (char const *const *argv, int const p[4][2], uint32_t options)
{
  size_t m = 0 ;
  char modif[33 + 3 * UINT_FMT] ;
  close(p[2][1]) ;
  close(p[1][1]) ;
  close(p[0][0]) ;
  memcpy(modif + m, "SSLCTLFD=", 9) ; m += 9 ;
  m += uint_fmt(modif + m, p[2][0]) ;
  modif[m++] = 0 ;
  memcpy(modif + m, "SSLREADFD=", 10) ; m += 10 ;
  m += uint_fmt(modif + m, p[1][0]) ;
  modif[m++] = 0 ;
  memcpy(modif + m, "SSLWRITEFD=", 11) ; m += 11 ;
  m += uint_fmt(modif + m, p[0][1]) ;
  modif[m++] = 0 ;
  s6tls_clean_and_exec(argv, options, modif, m) ;
}
