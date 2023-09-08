/* ISC license. */

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/exec.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

#define USAGE "s6-ucspitlsc [ -S | -s ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] [ -k servername ] [ -6 fdr ] [ -7 fdw ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static inline void child (int [4][2], uint32_t, unsigned int, unsigned int, char const *, pid_t) gccattr_noreturn ;
static inline void child (int p[4][2], uint32_t options, unsigned int verbosity, unsigned int kimeout, char const *servername, pid_t pid)
{
  ssize_t r ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  char c ;
  PROG = "s6-ucspitlsc" ;
  close(p[2][0]) ;
  close(p[1][0]) ;
  close(p[0][1]) ;
  if (fd_move(0, p[3][0]) == -1 || fd_move(1, p[3][1]) == -1)
    strerr_diefu1sys(111, "move network fds to stdin/stdout") ;
  r = read(p[2][1], &c, 1) ;
  if (r < 0) strerr_diefu1sys(111, "read from control socket") ;
  if (!r)
  {
    if (verbosity >= 2)
    {
      char fmt[PID_FMT] ;
      fmt[pid_fmt(fmt, pid)] = 0 ;
      strerr_warni4x("pid ", fmt, " declined", " opportunistic TLS") ;
    }
    _exit(0) ;
  }
  switch (c)
  {
    case 'y' :
      close(p[2][1]) ;
      p[2][1] = 0 ; /* we know 0 is open so it's a suitable invalid value */
      break ;
    case 'Y' :
      fd_shutdown(p[2][1], 0) ;
      break ;
    default :
      strerr_dief1x(100, "unrecognized command on control socket") ;
  }
  s6tls_prep_tlscio(newargv, buf, p, options, verbosity, kimeout, servername) ;
  if (verbosity >= 2)
  {
    char fmt[PID_FMT] ;
    fmt[pid_fmt(fmt, pid)] = 0 ;
    strerr_warni4x("pid ", fmt, " accepted", " opportunistic TLS") ;
  }
  xexec(newargv) ;
}

int main (int argc, char const *const *argv, char const *const *envp)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  int p[4][2] = { [3] = { [0] = 6, [1] = 7 } } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  char const *servername = 0 ;
  pid_t pid ;

  PROG = "s6-ucspitlsc (parent)" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsYyv:K:Zzk:6:7:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : coptions |= 4 ; break ;
        case 's' : coptions &= ~4 ; break ;
        case 'Y' : coptions |= 1 ; coptions &= ~2 ; break ;
        case 'y' : coptions |= 3 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'K' : if (!uint0_scan(l.arg, &kimeout)) dieusage() ; break ;
        case 'Z' : poptions &= ~1 ; break ;
        case 'z' : poptions |= 1 ; break ;
        case 'k' : servername = l.arg ; break ;
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
  if (fcntl(p[3][0], F_GETFD) == -1 || fcntl(p[3][1], F_GETFD) == -1)
    strerr_diefu1sys(111, "check network fds") ;

  if (ipc_pair_b(p[2]) == -1) strerr_diefu1sys(111, "ipc_pair") ;
  if (pipe(p[0]) == -1 || pipe(p[1]) == -1) strerr_diefu1sys(111, "pipe") ;
  pid = getpid() ;

  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, coptions, verbosity, kimeout, servername, pid) ;
    default : break ;
  }
  s6tls_ucspi_exec_app(argv, p, poptions) ;
}
