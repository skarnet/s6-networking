/* ISC license. */

#include <skalibs/sysdeps.h>

#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#ifdef SKALIBS_HASPOSIXSPAWN

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <spawn.h>

#include <skalibs/config.h>
#include <skalibs/posixplz.h>

pid_t s6tls_io_spawn (char const *const *argv, int const p[4][2])
{
  pid_t pid ;
  posix_spawn_file_actions_t actions ;
  int e ;
  int nopath = !getenv("PATH") ;
#ifdef SKALIBS_HASPOSIXSPAWNEARLYRETURN
  int eep[2] ;
  if (pipecoe(eep) == -1) return 0 ;
#endif
  e = posix_spawn_file_actions_init(&actions) ;
  if (e) goto err ;
  e = posix_spawn_file_actions_addclose(&actions, p[0][1]) ;
  if (e) goto erractions ;
  e = posix_spawn_file_actions_addclose(&actions, p[1][0]) ;
  if (e) goto erractions ;
  e = posix_spawn_file_actions_addclose(&actions, p[2][0]) ;
  if (e) goto erractions ;
  if (p[3][0] >= 0)
  {
    e = posix_spawn_file_actions_adddup2(&actions, p[3][0], 0) ;
    if (e) goto erractions ;
    e = posix_spawn_file_actions_addclose(&actions, p[3][0]) ;
    if (e) goto erractions ;
  }
  if (p[3][1] >= 0)
  {
    e = posix_spawn_file_actions_adddup2(&actions, p[3][1], 1) ;
    if (e) goto erractions ;
    e = posix_spawn_file_actions_addclose(&actions, p[3][1]) ;
    if (e) goto erractions ;
  }

  if (nopath && (setenv("PATH", SKALIBS_DEFAULTPATH, 0) < 0)) { e = errno ; goto erractions ; }
  e = posix_spawnp(&pid, argv[0], &actions, 0, (char *const *)argv, environ) ;
  if (nopath) unsetenv("PATH") ;
  if (e) goto erractions ;

  posix_spawn_file_actions_destroy(&actions) ;
#ifdef SKALIBS_HASPOSIXSPAWNEARLYRETURN
  return child_spawn_workaround(pid, eep) ;
#else
  return pid ;
#endif

 erractions:
  posix_spawn_file_actions_destroy(&actions) ;
 err:
#ifdef SKALIBS_HASPOSIXSPAWNEARLYRETURN
  fd_close(eep[1]) ;
  fd_close(eep[0]) ;
#endif
  errno = e ;
  return 0 ;
}

#else

#include <string.h>

#include <skalibs/strerr.h>
#include <skalibs/exec.h>

pid_t s6tls_io_spawn (char const *const *argv, int const p[4][2])
{
  pid_t pid = fork() ;
  if (pid == -1) return 0 ;
  if (!pid)
  {
    size_t proglen = strlen(PROG) ;
    char newprog[proglen + 9] ;
    memcpy(newprog, PROG, proglen) ;
    memcpy(newprog, " (child)", 9) ;
    PROG = newprog ;
    fd_close(p[0][1]) ;
    fd_close(p[1][0]) ;
    fd_close(p[2][0]) ;
    if ((p[3][0] >= 0 && fd_move(0, p[3][0]) == -1)
     || (p[3][1] >= 0 && fd_move(1, p[3][1]) == -1))
      strerr_diefu1sys(111, "move network fds to stdin/stdout") ;
    xexec(argv) ;
  }
  return pid ;
}

#endif
