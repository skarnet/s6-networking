/* ISC license. */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsc [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -k servername ] [ -Z | -z ] [ -6 fdr ] [ -7 fdw ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  int p[8] = { [6] = 6, [7] = 7 } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  pid_t pid ;
  char const *servername = 0 ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  PROG = "s6-tlsc" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsJjyYv:K:k:Zz6:7:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : coptions |= 4 ; break ;
        case 's' : coptions &= ~4 ; break ;
        case 'J' : coptions |= 2 ; break ;
        case 'j' : coptions &= ~2 ; break ;
        case 'y' : coptions |= 1 ; break ;
        case 'Y' : coptions &= ~1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'K' : if (!uint0_scan(l.arg, &kimeout)) dieusage() ; break ;
        case 'k' : servername = l.arg ; break ;
        case 'Z' : poptions &= ~1 ; break ;
        case 'z' : poptions |= 1 ; break ;
        case '6' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd) || fd < 3) dieusage() ;
          p[6] = fd ;
          break ;
        }
        case '7' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd) || fd < 3) dieusage() ;
          p[7] = fd ;
          break ;
        }
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc || p[6] == p[7]) dieusage() ;
  fd_sanitize() ;
  if (fcntl(p[6], F_GETFD) == -1 || fcntl(p[7], F_GETFD) == -1)
    strerr_diefu1sys(111, "check network fds") ;
  if (pipe(p) == -1 || pipe(p+2) == -1 || pipe(p+4) == -1)
    strerr_diefu1sys(111, "pipe") ;
  s6tls_prep_tlscio(newargv, buf, p, coptions, verbosity, kimeout, servername) ;
  pid = s6tls_io_spawn(newargv, p, 1) ;
  if (!pid) strerr_diefu2sys(111, "spawn ", newargv[0]) ;
  s6tls_sync_and_exec_app(argv, p, pid, poptions) ;
}
