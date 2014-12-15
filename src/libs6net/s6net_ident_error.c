/* ISC license */

#include <errno.h>
#include <skalibs/error.h>
#include <s6-networking/ident.h>

#define N 5

static char const *s6net_ident_error_strings[N+1] =
{
  "invalid port",
  "no such user",
  "identification denied",
  "unknown error",
  "X-error-token",
  "(invalid error code)"
} ;

static int const s6net_ident_error_codes[N] =
{
  EINVAL,
  ESRCH,
  EPERM,
  EIO,
  EEXIST
} ;

char const *s6net_ident_error_str (int e)
{
  register unsigned int i = 0 ;
  for (; i < N ; i++) if (e == s6net_ident_error_codes[i]) break ;
  return s6net_ident_error_strings[i] ;
}
