/* ISC license. */

#include <string.h>
#include <stdlib.h>

#include <skalibs/posixplz.h>
#include <skalibs/bytestr.h>
#include <skalibs/env.h>
#include <skalibs/exec.h>

#include "s6tls-internal.h"

static int startswith (void const *a, void const *b)
{
  char const *bb = *(char const *const *)b ;
  return strncmp(a, bb, strlen(bb)) ;
}

void s6tls_clean_and_exec (char const *const *argv, uint32_t options, char const *modif, size_t modiflen)
{
  if (options & 1)
  {
    static char const *const toclean[] =
    {
      "CADIR=",
      "CAFILE=",
      "CERTFILE:",
      "CERTFILE=",
      "KEYFILE:",
      "KEYFILE=",
      "TLS_GID=",
      "TLS_UID="
    } ;
    char const *const *envp = (char const *const *)environ ;
    size_t m = 0 ;
    size_t n = env_len(envp) ;
    char const *newenvp[n + 1] ;
    for (; *envp ; envp++)
      if (!bsearch(*envp, toclean, sizeof(toclean)/sizeof(char const *), sizeof(char const *), &startswith))
        newenvp[m++] = *envp ;
    newenvp[m] = 0 ;
    xmexec_fm(argv, newenvp, m, modif, modiflen) ;
  }
  else xmexec_m(argv, modif, modiflen) ;
}
