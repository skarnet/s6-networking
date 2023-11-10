/* ISC license. */

#include <unistd.h>

#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define MAXENVSIZE 4096

void s6tls_sync_and_exec_app (char const *const *argv, int const *p, pid_t pid, uint32_t options)
{
  char buf[MAXENVSIZE] ;
  ssize_t r ;
  close(p[5]) ;
  close(p[3]) ;
  close(p[0]) ;
  if (fd_move(p[6], p[2]) == -1 || fd_move(p[7], p[1]) == -1)
    strerr_diefu1sys(111, "move file descriptors") ;
  r = read(p[4], buf, MAXENVSIZE) ;
  if (r < 0) strerr_diefu1sys(111, "read from handshake notification pipe") ;
  if (!r)
  {
    int wstat ;
    if (wait_pid(pid, &wstat) < 0)
      strerr_diefu1sys(111, "waitpid") ;
    _exit(wait_estatus(wstat)) ;
  }
  if (r >= MAXENVSIZE) strerr_dief1x(101, "SSL data too large; recompile with a bigger MAXENVSIZE") ;
  close(p[4]) ;
  s6tls_clean_and_exec(argv, options, buf, r-1) ;
}
