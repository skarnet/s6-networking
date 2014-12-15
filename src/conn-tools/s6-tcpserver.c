/* ISC license. */

#include <skalibs/uint.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>
#include <s6-networking/config.h>

#define USAGE "s6-tcpserver [ -q | -Q | -v ] [ -1 ] [ -4 | -6 ] [ -c maxconn ] [ -C localmaxconn ] [ -b backlog ] [ -G gid,gid,... ] [ -g gid ] [ -u uid ] [ -U ] ip port prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv, char const *const *envp)
{
  char const *newargv[2 + (argc << 1)] ;
  char const *path ;
  unsigned int m = 3 ;
  int what = 0 ;
  unsigned int verbosity = 1 ;
  char fmtv[UINT_FMT] ;
  PROG = "s6-tcpserver" ;
  newargv[1] = "-v" ;
  newargv[2] = fmtv ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      register int opt = subgetopt_r(argc, argv, "qQv146Uc:C:b:u:g:G:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '4' : if (what) dieusage() ; what = 4 ; break ;
        case '6' : if (what) dieusage() ; what = 6 ; break ;
        case 'q' : verbosity = 0 ; break ;
        case 'Q' : verbosity = 1 ; break ;
        case 'v' : verbosity = 2 ; break ;
        case '1' : newargv[m++] = "-1" ; break ;
        case 'U' : newargv[m++] = "-U" ; break ;
        case 'c' : newargv[m++] = "-c" ; newargv[m++] = l.arg ; break ;
        case 'C' : newargv[m++] = "-C" ; newargv[m++] = l.arg ; break ;
        case 'b' : newargv[m++] = "-b" ; newargv[m++] = l.arg ; break ;
        case 'u' : newargv[m++] = "-u" ; newargv[m++] = l.arg ; break ;
        case 'g' : newargv[m++] = "-g" ; newargv[m++] = l.arg ; break ;
        case 'G' : newargv[m++] = "-G" ; newargv[m++] = l.arg ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (argc < 3) dieusage() ;
  fmtv[uint_fmt(fmtv, verbosity)] = 0 ;
  newargv[m++] = 0 ;
  if (!what)
  {
    ip46_t ip ;
    if (!ip46_scan(argv[0], &ip)) dieusage() ;
    what = ip46_is6(&ip) ? 6 : 4 ;
  }
  if (what == 6)
  {
    newargv[0] = "s6-tcpserver6" ;
    path = S6_NETWORKING_BINPREFIX "s6-tcpserver6" ;
  }
  else
  {
    newargv[0] = "s6-tcpserver4" ;
    path = S6_NETWORKING_BINPREFIX "s6-tcpserver4" ;
  }
  pathexec_run(path, newargv, envp) ;
  strerr_dieexec(111, path) ;
}
