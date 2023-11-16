/* ISC license. */

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

#define USAGE "s6-ucspitlsd [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -k snilevel ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static inline void child (int *, uint32_t, unsigned int, unsigned int, unsigned int, pid_t) gccattr_noreturn ;
static inline void child (int *p, uint32_t options, unsigned int verbosity, unsigned int kimeout, unsigned int snilevel, pid_t pid)
{
  ssize_t r ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  char c ;
  PROG = "s6-ucspitlsd" ;
  close(p[4]) ;
  close(p[1]) ;
  close(p[2]) ;
  r = read(p[5], &c, 1) ;
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
      close(p[5]) ;
      p[5] = 0 ; /* we know 0 is open so it's a suitable invalid value */
      break ;
    case 'Y' :
      fd_shutdown(p[5], 0) ;
      break ;
    default :
      strerr_dief1x(100, "unrecognized command on control socket") ;
  }
  s6tls_prep_tlsdio(newargv, buf, p, options, verbosity, kimeout, snilevel) ;
  if (verbosity >= 2)
  {
    char fmt[PID_FMT] ;
    fmt[pid_fmt(fmt, pid)] = 0 ;
    strerr_warni4x("pid ", fmt, " accepted", " opportunistic TLS") ;
  }
  xexec(newargv) ;
}

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  unsigned int snilevel = 0 ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  int p[6] ;
  pid_t pid ;

  PROG = "s6-ucspitlsd (parent)" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsJjyYv:K:Zzk:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : coptions |= 4 ; break ;
        case 's' : coptions &= ~4 ; break ;
        case 'J' : coptions |= 8 ; break ;
        case 'j' : coptions &= ~8 ; break ;
        case 'y' : coptions |= 3 ; break ;
        case 'Y' : coptions |= 1 ; coptions &= ~2 ; break ;
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

  if (pipe(p) == -1 || pipe(p+2) == -1) strerr_diefu1sys(111, "pipe") ;
  if (ipc_pair_b(p+4) == -1) strerr_diefu1sys(111, "ipc_pair") ;
  pid = getpid() ;

  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, coptions, verbosity, kimeout, snilevel, pid) ;
    default : break ;
  }
  s6tls_ucspi_exec_app(argv, p, poptions) ;
}
