/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/uint64.h>
#include <skalibs/uint.h>
#include <skalibs/gidstuff.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <s6-networking/config.h>

#ifdef S6_NETWORKING_USE_TLS

#include <s6-networking/stls.h>
#define s6tlsc stls_s6tlsc

#else
#ifdef S6_NETWORKING_USE_BEARSSL

#include <s6-networking/sbearssl.h>
#define s6tlsc sbearssl_s6tlsc

#else

#error No SSL backend configured.

#endif
#endif


#define USAGE "s6-tlsc [ -S | -s ]  [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -6 rfd ] [ -7 wfd ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv, char const *const *envp)
{
  tain_t tto ;
  unsigned int verbosity = 1 ;
  uid_t uid = 0 ;
  gid_t gid = 0 ;
  uint32_t preoptions = 0 ;
  uint32_t options = 1 ;
  int fds[2] = { 6, 7 } ;

  PROG = "s6-tlsc" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int t = 0 ;
    for (;;)
    {
      register int opt = subgetopt_r(argc, argv, "SsYyv:K:6:7:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'S' : options &= ~(uint32_t)1 ; break ;
        case 's' : options |= 1 ; break ;
        case 'Y' : preoptions &= ~(uint32_t)1 ; break ;
        case 'y' : preoptions |= 1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'K' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        case '6' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd)) dieusage() ;
          fds[0] = fd ;
          break ;
        }
        case '7' :
        {
          unsigned int fd ;
          if (!uint0_scan(l.arg, &fd)) dieusage() ;
          fds[1] = fd ;
          break ;
        }
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (t) tain_from_millisecs(&tto, t) ; else tto = tain_infinite_relative ;
  }
  if (!argc) dieusage() ;

  if (!getuid())
  {
    x = env_get2(envp, "TLS_UID") ;
    if (x)
    {
      uint64 u ;
      if (!uint640_scan(x, &u)) strerr_dieinvalid(100, "TLS_UID") ;
      uid = (uid_t)u ;
    }
    x = env_get2(envp, "TLS_GID") ;
    if (x)
    {
      if (!gid0_scan(x, &gid)) strerr_dieinvalid(100, "TLS_GID") ;
    }
  }

  return s6tlsc(argv, envp, &tto, preoptions, options, uid, gid, verbosity) ;
}
