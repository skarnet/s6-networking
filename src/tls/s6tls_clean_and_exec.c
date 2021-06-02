/* ISC license. */

#include <stddef.h>

#include <skalibs/posixplz.h>
#include <skalibs/bytestr.h>
#include <skalibs/env.h>
#include <skalibs/exec.h>

#include "s6tls-internal.h"

void s6tls_clean_and_exec (char const *const *argv, uint32_t options, char const *modif, size_t modiflen)
{
  if (options & 1)
  {
    static char const *const toclean[] =
    {
      "CADIR=",
      "CAFILE=",
      "KEYFILE=",
      "CERTFILE=",
      "TLS_UID=",
      "TLS_GID=",
      "KEYFILE:",
      "CERTFILE:",
      0
    } ;
    char const *const *envp = (char const *const *)environ ;
    size_t m = 0 ;
    size_t n = env_len(envp) ;
    char const *newenvp[n + 1] ;
    for (; *envp ; envp++)
    {
      char const *const *var = toclean ;
      for (; *var ; var++)
        if (str_start(*envp, *var)) break ;
      if (!*var) newenvp[m++] = *envp ;
    }
    newenvp[m] = 0 ;
    xmexec_fm(argv, newenvp, m, modif, modiflen) ;
  }
  else xmexec_m(argv, modif, modiflen) ;
}
