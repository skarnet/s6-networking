/* ISC license. */

#include <unistd.h>
#include <signal.h>
#include <skalibs/env.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/selfpipe.h>
#include "sbearssl-internal.h"

pid_t sbearssl_prep_spawn_drop (char const *const *argv, char const *const *envp, int *fds, uid_t uid, gid_t gid, uint32_t options)
{
  pid_t pid ;

  fds[4] = selfpipe_init() ;
  if (fds[4] < 0) strerr_diefu1sys(111, "init selfpipe") ;
  if (selfpipe_trap(SIGCHLD) < 0) strerr_diefu1sys(111, "trap SIGCHLD") ;

  if (!(options & 1)) pid = child_spawn2(argv[0], argv, envp, fds) ;
  else
  {
    char const modifs[] = "CADIR\0CAFILE\0KEYFILE\0CERTFILE\0TLS_UID\0TLS_GID" ;
    size_t modiflen = sizeof(modifs) ;
    size_t n = env_len(envp) ;
    char const *newenv[n + 7] ;
    size_t newenvlen = env_merge(newenv, n+7, envp, n, modifs, modiflen) ;
    if (!newenvlen) return 0 ;
    pid = child_spawn2(argv[0], argv, newenv, fds) ;
  }

  if (!pid) strerr_diefu2sys(111, "spawn ", argv[0]) ;
  if (gid && setgid(gid) < 0) strerr_diefu1sys(111, "setgid") ;
  if (uid && setuid(uid) < 0) strerr_diefu1sys(111, "setuid") ;
  return pid ;
}
