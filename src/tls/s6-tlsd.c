/* ISC license. */

#include <stdint.h>
#include <unistd.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsd [ -S | -s ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static void child (int const [4][2], uint32_t, unsigned int, unsigned int) gccattr_noreturn ;
static void child (int const p[4][2], uint32_t options, unsigned int verbosity, unsigned int kimeout)
{
  int fds[3] = { p[0][0], p[1][1], p[2][1] } ;
  PROG = "s6-tlsd (child)" ;
  close(p[2][0]) ;
  close(p[0][1]) ;
  close(p[1][0]) ;
  s6tls_exec_tlsdio(fds, options, verbosity, kimeout) ;
}

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  int p[4][2] = { [3] = { 0, 1 } } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  pid_t pid ;

  PROG = "s6-tlsd (parent)" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsYyv:K:Zz", &l) ;
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
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc) dieusage() ;

  if (pipe(p[0]) < 0 || pipe(p[1]) < 0 || pipe(p[2]) < 0)
    strerr_diefu1sys(111, "pipe") ;
  pid = fork() ;
  switch (pid)
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, coptions, verbosity, kimeout) ;
    default : break ;
  }
  s6tls_sync_and_exec_app(argv, p, pid, poptions) ;
}
