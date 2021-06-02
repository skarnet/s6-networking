/* ISC license. */

#include <unistd.h>

#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define MAXENVSIZE 4096

void s6tls_sync_and_exec_app (char const *const *argv, int const p[4][2], pid_t pid, uint32_t options)
{
  char buf[MAXENVSIZE] ;
  ssize_t r ;
  close(p[2][1]) ;
  close(p[1][1]) ;
  close(p[0][0]) ;
  if (fd_move(p[3][0], p[1][0]) < 0 || fd_move(p[3][1], p[0][1]) < 0)
    strerr_diefu1sys(111, "move file descriptors") ;
  r = read(p[2][0], buf, MAXENVSIZE) ;
  if (r < 0) strerr_diefu1sys(111, "read from handshake notification pipe") ;
  if (!r)
  {
    int wstat ;
    if (wait_pid(pid, &wstat) < 0)
      strerr_diefu1sys(111, "waitpid") ;
    _exit(wait_estatus(wstat)) ;
  }
  if (r >= MAXENVSIZE) strerr_dief1x(101, "SSL data too large; recompile with a bigger MAXENVSIZE") ;
  s6tls_clean_and_exec(argv, options, buf, r-1) ;
}
