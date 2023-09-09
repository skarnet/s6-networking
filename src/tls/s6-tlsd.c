/* ISC license. */

#include <stdint.h>
#include <unistd.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsd [ -S | -s ] [ -Y | -y ] [ -k snilevel ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  unsigned int snilevel = 0 ;
  int p[4][2] = { [3] = { [0] = 0, [1] = 1 } } ;
  uint32_t coptions = 0 ;
  uint32_t poptions = 1 ;
  pid_t pid ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  PROG = "s6-tlsd" ;
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

  if (pipe(p[0]) == -1 || pipe(p[1]) == -1 || pipe(p[2]) == -1)
    strerr_diefu1sys(111, "create pipe") ;
  s6tls_prep_tlsdio(newargv, buf, p, coptions, verbosity, kimeout, snilevel) ;
  pid = s6tls_io_spawn(newargv, p) ;
  if (!pid) strerr_diefu2sys(111, "spawn ", newargv[0]) ;
  s6tls_sync_and_exec_app(argv, p, pid, poptions) ;
}
