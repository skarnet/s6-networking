/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <skalibs/webipc.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

#define USAGE "s6-ucspitlsd [ -S | -s ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

static inline void child (int [3][2], uint32_t, unsigned int, unsigned int) gccattr_noreturn ;
static inline void child (int p[3][2], uint32_t options, unsigned int verbosity, unsigned int kimeout)
{
  int fds[3] = { p[0][0], p[1][1], p[2][1] } ;
  ssize_t r ;
  char c ;
  PROG = "s6-ucspitlsd" ;
  close(p[2][0]) ;
  close(p[0][1]) ;
  close(p[1][0]) ;
  s6tls_drop() ;
  r = read(p[2][1], &c, 1) ;
  if (r < 0) strerr_diefu1sys(111, "read from control socket") ;
  if (!r) _exit(0) ;
  switch (c)
  {
    case 'y' :
      close(p[2][1]) ;
      p[2][1] = 0 ; /* we know 0 is open so it's a correct invalid value */
    case 'Y' :
      fd_shutdown(p[2][1], 0) ;
      break ;
    default :
      strerr_dief1x(100, "unrecognized command on control socket") ;
  }
  s6tls_exec_tlsdio(fds, options, verbosity, kimeout) ;
}

int main (int argc, char const *const *argv, char const *const *envp)
{
  unsigned int kimeout = 0 ;
  unsigned int verbosity = 1 ;
  uint32_t options = 0 ;
  int cleanenv = 1 ;
  int p[3][2] ;

  PROG = "s6-ucspitlsd (parent)" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "SsYyv:K:Zz", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : options |= 4 ; break ;
        case 's' : options &= ~4 ; break ;
        case 'Y' : options |= 1 ; options &= ~2 ; break ;
        case 'y' : options |= 3 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'K' : if (!uint0_scan(l.arg, &kimeout)) dieusage() ; break ;
        case 'Z' : cleanenv = 0 ; break ;
        case 'z' : cleanenv = 1 ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (!argc) dieusage() ;

  if (ipc_pair_b(p[2]) < 0) strerr_diefu1sys(111, "ipc_pair") ;
  if (pipe(p[0]) < 0 || pipe(p[1]) < 0) strerr_diefu1sys(111, "pipe") ;

  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, options, verbosity, kimeout) ;
    default : break ;
  }

  {
    size_t m = 0 ;
    char modif[sizeof(s6tls_envvars) + 33 + 3 * UINT_FMT] ;
    close(p[2][1]) ;
    close(p[1][1]) ;
    close(p[0][0]) ;
    if (cleanenv)
    {
      memcpy(modif + m, s6tls_envvars, sizeof(s6tls_envvars)) ;
      m += sizeof(s6tls_envvars) ;
    }
    memcpy(modif + m, "SSLCTLFD=", 9) ; m += 9 ;
    m += uint_fmt(modif + m, p[2][0]) ;
    modif[m++] = 0 ;
    memcpy(modif + m, "SSLREADFD=", 10) ; m += 10 ;
    m += uint_fmt(modif + m, p[1][0]) ;
    modif[m++] = 0 ;
    memcpy(modif + m, "SSLWRITEFD=", 11) ; m += 11 ;
    m += uint_fmt(modif + m, p[0][1]) ;
    modif[m++] = 0 ;
    xpathexec_r(argv, envp, env_len(envp), modif, m) ;
  }
}
