/* ISC license. */

#include <stdint.h>
#include <unistd.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

#define USAGE "s6-ucspitlsd [ -S | -s ] [ -Y | -y ] [ -k snilevel ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static inline void child (int [4][2], uint32_t, unsigned int, unsigned int, unsigned int, pid_t) gccattr_noreturn ;
static inline void child (int p[4][2], uint32_t options, unsigned int verbosity, unsigned int kimeout, unsigned int snilevel, pid_t pid)
{
  int fds[3] = { p[0][0], p[1][1], p[2][1] } ;
  ssize_t r ;
  char c ;
  PROG = "s6-ucspitlsd" ;
  close(p[2][0]) ;
  close(p[0][1]) ;
  close(p[1][0]) ;
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
      p[2][1] = 0 ; /* we know 0 is open so it's a correct invalid value */
      break ;
    case 'Y' :
      fd_shutdown(p[2][1], 0) ;
      break ;
    default :
      strerr_dief1x(100, "unrecognized command on control socket") ;
  }
  if (verbosity >= 2)
  {
    char fmt[PID_FMT] ;
    fmt[pid_fmt(fmt, pid)] = 0 ;
    strerr_warni4x("pid ", fmt, " accepted", " opportunistic TLS") ;
  }
  s6tls_exec_tlsdio(fds, options, verbosity, kimeout, snilevel) ;
}

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  unsigned int snilevel = 0 ;
  int p[4][2] = { [3] = { 0, 1 } } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  pid_t pid ;

  PROG = "s6-ucspitlsd (parent)" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsYyv:K:Zzk:", &l) ;
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
        case 'k' : if (!uint0_scan(l.arg, &snilevel)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc) dieusage() ;

  if (ipc_pair_b(p[2]) < 0) strerr_diefu1sys(111, "ipc_pair") ;
  if (pipe(p[0]) < 0 || pipe(p[1]) < 0) strerr_diefu1sys(111, "pipe") ;
  pid = getpid() ;

  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, coptions, verbosity, kimeout, snilevel, pid) ;
    default : break ;
  }
  s6tls_ucspi_exec_app(argv, p, poptions) ;
}
