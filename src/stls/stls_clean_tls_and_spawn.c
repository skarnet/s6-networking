/* ISC license. */

#include <sys/types.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include "stls-internal.h"

pid_t stls_clean_tls_and_spawn (char const *const *argv, char const *const *envp, int *fds, uint32_t options)
{
  if (!(options & 1)) return child_spawn2(argv[0], argv, envp, fds) ;
  else
  {
    char const modifs[] = "CADIR\0CAFILE\0KEYFILE\0CERTFILE\0TLS_UID\0TLS_GID" ;
    size_t modiflen = sizeof(modifs) ;
    size_t n = env_len(envp) ;
    char const *newenv[n + 7] ;
    size_t newenvlen = env_merge(newenv, n+7, envp, n, modifs, modiflen) ;
    if (!newenvlen) return 0 ;
    return child_spawn2(argv[0], argv, newenv, fds) ;
  }
}
