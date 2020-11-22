/* ISC license. */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsc [ -S | -s ]  [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -k servername ] [ -Z | -z ] [ -6 fdr ] [ -7 fdw ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static void child (int const [4][2], uint32_t, unsigned int, unsigned int, char const *) gccattr_noreturn ;
static void child (int const p[4][2], uint32_t options, unsigned int verbosity, unsigned int kimeout, char const *servername)
{
  int fds[3] = { p[0][0], p[1][1], p[2][1] } ;
  PROG = "s6-tlsc (child)" ;
  close(p[2][0]) ;
  close(p[0][1]) ;
  close(p[1][0]) ;
  if (fd_move(0, p[3][0]) < 0 || fd_move(1, p[3][1]) < 0)
    strerr_diefu1sys(111, "move network fds to stdin/stdout") ;
  s6tls_exec_tlscio(fds, options, verbosity, kimeout, servername) ;
}

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  int p[4][2] = { [3] = { 6, 7 } } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  pid_t pid ;
  char const *servername = 0 ;

  PROG = "s6-tlsc" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsYyv:K:k:Zz6:7:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : coptions &= ~4 ; break ;
        case 's' : coptions |= 4 ; break ;
        case 'Y' : coptions &= ~1 ; break ;
        case 'y' : coptions |= 1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'K' : if (!uint0_scan(l.arg, &kimeout)) dieusage() ; break ;
        case 'k' : servername = l.arg ; break ;
        case 'Z' : poptions &= ~1 ; break ;
        case 'z' : poptions |= 1 ; break ;
        case '6' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd)) dieusage() ;
          p[3][0] = fd ;
          break ;
        }
        case '7' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd)) dieusage() ;
          p[3][1] = fd ;
          break ;
        }
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc) dieusage() ;
  fd_sanitize() ;
  if (fcntl(p[3][0], F_GETFD) < 0 || fcntl(p[3][1], F_GETFD) < 0)
    strerr_diefu1sys(111, "check network fds") ;

  if (pipe(p[0]) < 0 || pipe(p[1]) < 0 || pipe(p[2]) < 0)
    strerr_diefu1sys(111, "pipe") ;
  pid = fork() ;
  switch (pid)
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, coptions, verbosity, kimeout, servername) ;
    default : break ;
  }
  s6tls_sync_and_exec_app(argv, p, pid, poptions) ;
}
