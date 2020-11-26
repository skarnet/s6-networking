/* ISC license. */

#include <skalibs/types.h>
#include <skalibs/exec.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

void s6tls_exec_tlsdio (int const *fds, uint32_t options, unsigned int verbosity, unsigned int kimeout)
{
  char const *newargv[13] ;
  unsigned int m = 0 ;
  char fmtv[UINT_FMT] ;
  char fmtd[UINT_FMT] ;
  char fmtk[UINT_FMT] ;
  char fmtr[UINT_FMT] ;
  char fmtw[UINT_FMT] ;

  newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsd-io" ;
  if (verbosity != 1)
  {
    newargv[m++] = "-v" ;
    newargv[m++] = fmtv ;
    fmtv[uint_fmt(fmtv, verbosity)] = 0 ;
  }
  if (fds[2])
  {
    newargv[m++] = "-d" ;
    newargv[m++] = fmtd ;
    fmtd[uint_fmt(fmtd, fds[2])] = 0 ;
  }
  newargv[m++] = options & 4 ? "-S" : "-s" ;
  if (options & 1)
    newargv[m++] = options & 2 ? "-y" : "-Y" ;
  if (kimeout)
  {
    newargv[m++] = "-K" ;
    newargv[m++] = fmtk ;
    fmtk[uint_fmt(fmtk, kimeout)] = 0 ;
  }
  newargv[m++] = "--" ;
  newargv[m++] = fmtr ;
  fmtr[uint_fmt(fmtr, fds[0])] = 0 ;
  newargv[m++] = fmtw ;
  fmtw[uint_fmt(fmtw, fds[1])] = 0 ;
  newargv[m++] = 0 ;
  xexec(newargv) ;
}
