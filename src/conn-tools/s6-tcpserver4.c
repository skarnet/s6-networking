/* ISC license. */

#include <sys/types.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/exec.h>

#include <s6/config.h>

#include <s6-networking/config.h>

#define USAGE "s6-tcpserver4 [ -v verbosity ] [ -d | -D ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] [ -b backlog ] [ -G gid,gid,... ] [ -g gid ] [ -u uid ] [ -U ] ip port prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  unsigned int verbosity = 1 ;
  int flag1 = 0 ;
  int flagU = 0 ;
  int flagreuse = 1 ;
  uid_t uid = 0 ;
  gid_t gid = 0 ;
  gid_t gids[NGROUPS_MAX] ;
  size_t gidn = (size_t)-1 ;
  unsigned int maxconn = 0 ;
  unsigned int localmaxconn = 0 ;
  unsigned int backlog = (unsigned int)-1 ;
  PROG = "s6-tcpserver4" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "Dd1Uv:c:C:b:u:g:G:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'D' : flagreuse = 0 ; break ;
        case 'd' : flagreuse = 1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'c' : if (!uint0_scan(l.arg, &maxconn)) dieusage() ; if (!maxconn) maxconn = 1 ; break ;
        case 'C' : if (!uint0_scan(l.arg, &localmaxconn)) dieusage() ; if (!localmaxconn) localmaxconn = 1 ; break ;
        case 'b' : if (!uint0_scan(l.arg, &backlog)) dieusage() ; break ;
        case 'u' : if (!uid0_scan(l.arg, &uid)) dieusage() ; break ;
        case 'g' : if (!gid0_scan(l.arg, &gid)) dieusage() ; break ;
        case 'G' : if (!gid_scanlist(gids, NGROUPS_MAX, l.arg, &gidn) && *l.arg) dieusage() ; break ;
        case '1' : flag1 = 1 ; break ;
        case 'U' : flagU = 1 ; uid = 0 ; gid = 0 ; gidn = (size_t)-1 ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (argc < 3) dieusage() ;
  }

  {
    size_t pos = 0 ;
    unsigned int m = 0 ;
    char fmt[UINT_FMT * 4 + UID_FMT + GID_FMT * (NGROUPS_MAX + 1)] ;
    char const *newargv[24 + argc] ;
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpserver4-socketbinder" ;
    if (!flagreuse) newargv[m++] = "-D" ;
    if (backlog != (unsigned int)-1)
    {
      if (!backlog) backlog = 1 ;
      newargv[m++] = "-b" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, backlog) ;
      fmt[pos++] = 0 ;
    }
    newargv[m++] = "--" ;
    newargv[m++] = *argv++ ;
    newargv[m++] = *argv++ ;
    if (flagU || uid || gid || gidn != (size_t)-1)
    {
      newargv[m++] = S6_EXTBINPREFIX "s6-applyuidgid" ;
      if (flagU) newargv[m++] = "-Uz" ;
      if (uid)
      {
        newargv[m++] = "-u" ;
        newargv[m++] = fmt + pos ;
        pos += uid_fmt(fmt + pos, uid) ;
        fmt[pos++] = 0 ;
      }
      if (gid)
      {
        newargv[m++] = "-g" ;
        newargv[m++] = fmt + pos ;
        pos += gid_fmt(fmt + pos, gid) ;
        fmt[pos++] = 0 ;
      }
      if (gidn != (size_t)-1)
      {
        newargv[m++] = "-G" ;
        newargv[m++] = fmt + pos ;
        pos += gid_fmtlist(fmt + pos, gids, gidn) ;
        fmt[pos++] = 0 ;
      }
      newargv[m++] = "--" ;
    }
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpserver4d" ;
    if (verbosity != 1)
    {
      newargv[m++] = "-v" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, verbosity) ;
      fmt[pos++] = 0 ;
    }
    if (flag1) newargv[m++] = "-1" ;
    if (maxconn)
    {
      newargv[m++] = "-c" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, maxconn) ;
      fmt[pos++] = 0 ;
    }
    if (localmaxconn)
    {
      newargv[m++] = "-C" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, localmaxconn) ;
      fmt[pos++] = 0 ;
    }
    newargv[m++] = "--" ;
    while (*argv) newargv[m++] = *argv++ ;
    newargv[m++] = 0 ;
    xexec(newargv) ;
  }
}
