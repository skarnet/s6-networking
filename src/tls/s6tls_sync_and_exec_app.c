/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/exec.h>

#include "s6tls-internal.h"

#define MAXENVSIZE 2048

void s6tls_sync_and_exec_app (char const *const *argv, int const p[4][2], pid_t pid, uint32_t options)
{
  char buf[sizeof(s6tls_envvars) + MAXENVSIZE] ;
  size_t m = 0 ;
  ssize_t r ;
  close(p[2][1]) ;
  close(p[1][1]) ;
  close(p[0][0]) ;
  if (fd_move(p[3][0], p[1][0]) < 0 || fd_move(p[3][1], p[0][1]) < 0)
    strerr_diefu1sys(111, "move file descriptors") ;
  if (options & 1)
  {
    memcpy(buf + m, s6tls_envvars, sizeof(s6tls_envvars)) ;
    m += sizeof(s6tls_envvars) ;
  }
  r = read(p[2][0], buf + m, MAXENVSIZE) ;
  if (r < 0) strerr_diefu1sys(111, "read from handshake notification pipe") ;
  if (!r)
  {
    int wstat ;
    if (wait_pid(pid, &wstat) < 0)
      strerr_diefu1sys(111, "wait") ;
    _exit(wait_estatus(wstat)) ;
  }
  if (r >= MAXENVSIZE)
    strerr_dief1x(100, "SSL data too large") ;
  m += r - 1 ;
  xmexec_m(argv, buf, m) ;
}
