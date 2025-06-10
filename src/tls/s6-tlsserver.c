/* ISC license. */

#include <sys/types.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/exec.h>

#include <s6/config.h>

#include <s6-networking/config.h>

#define USAGE "s6-tlsserver [ options ] ip port prog...\n" \
"proxy-server options: [ -L ]" \
"s6-tcpserver options: [ -q | -Q | -v ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] [ -b backlog ] [ -G gidlist ] [ -g gid ] [ -u uid ] [ -U ]\n" \
"s6-tcpserver-access options: [ -W | -w ] [ -D | -d ] [ -H ] [ -h ] [ -R | -r ] [ -P | -p ] [ -l localname ] [ -B banner ] [ -t timeout ] [ -i rulesdir | -x rulesfile ]\n" \
"s6-tlsd options: [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -K timeout ] [ -Z | -z ] [ -k snilevel ]"

#define dieusage() strerr_dieusage(100, USAGE)

typedef struct options_s options_t, *options_t_ref ;
struct options_s
{
  char const *localname ;
  char const *banner ;
  char const *rules ;
  gid_t gids[NGROUPS_MAX] ;
  size_t gidn ;
  uid_t uid ;
  gid_t gid ;
  unsigned int maxconn ;
  unsigned int localmaxconn ;
  unsigned int backlog ;
  unsigned int timeout ;
  unsigned int kimeout ;
  unsigned int snilevel ;
  unsigned int verbosity : 2 ;
  unsigned int flagL : 1 ;
  unsigned int flag1 : 1 ;
  unsigned int flagU : 1 ;
  unsigned int flagw : 1 ;
  unsigned int flagD : 1 ;
  unsigned int flagH : 1 ;
  unsigned int flagh : 1 ;
  unsigned int flagr : 1 ;
  unsigned int flagp : 1 ;
  unsigned int rulesx : 1 ;
  unsigned int flagS : 1 ;
  unsigned int flagJ : 1 ;
  unsigned int flagy : 1 ;
  unsigned int flagY : 1 ;
  unsigned int flagZ : 1 ;
  unsigned int doapply : 1 ;
} ;

#define OPTIONS_ZERO \
{ \
  .localname = 0, \
  .banner = 0, \
  .rules = 0, \
  .backlog = (unsigned int)-1, \
  .gidn = (size_t)-1, \
  .uid = 0, \
  .gid = 0, \
  .maxconn = 0, \
  .localmaxconn = 0, \
  .timeout = 0, \
  .kimeout = 0, \
  .snilevel = 0, \
  .verbosity = 1, \
  .flagL = 0, \
  .flag1 = 0, \
  .flagU = 0, \
  .flagw = 0, \
  .flagD = 0, \
  .flagH = 0, \
  .flagh = 0, \
  .flagr = 0, \
  .flagp = 0, \
  .rulesx = 0, \
  .flagS = 0, \
  .flagJ = 0, \
  .flagy = 0, \
  .flagY = 0, \
  .flagZ = 0, \
  .doapply = 0 \
}

int main (int argc, char const *const *argv)
{
  options_t o = OPTIONS_ZERO ;
  PROG = "s6-tlsserver" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "qQv1c:C:b:G:g:u:LUWwDdHhRrPpl:B:t:i:x:SsJjYyK:Zzk:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'q' : o.verbosity = 0 ; break ;
        case 'Q' : o.verbosity = 1 ; break ;
        case 'v' : o.verbosity = 2 ; break ;
        case '1' : o.flag1 = 1 ; break ;
        case 'L' : o.flagL = 1 ; break ;
        case 'c' : if (!uint0_scan(l.arg, &o.maxconn)) dieusage() ; if (!o.maxconn) o.maxconn = 1 ; break ;
        case 'C' : if (!uint0_scan(l.arg, &o.localmaxconn)) dieusage() ; if (!o.localmaxconn) o.localmaxconn = 1 ; break ;
        case 'b' : if (!uint0_scan(l.arg, &o.backlog)) dieusage() ; break ;
        case 'G' : if (!gid_scanlist(o.gids, NGROUPS_MAX, l.arg, &o.gidn) && *l.arg) dieusage() ; o.doapply = 1 ; break ;
        case 'g' : if (!gid0_scan(l.arg, &o.gid)) dieusage() ; o.doapply = 1 ; break ;
        case 'u' : if (!uid0_scan(l.arg, &o.uid)) dieusage() ; o.doapply = 1 ; break ;
        case 'U' : o.flagU = 1 ; o.uid = 0 ; o.gid = 0 ; o.gidn = (size_t)-1 ; o.doapply = 1 ; break ;
        case 'W' : o.flagw = 0 ; break ;
        case 'w' : o.flagw = 1 ; break ;
        case 'D' : o.flagD = 1 ; break ;
        case 'd' : o.flagD = 0 ; break ;
        case 'H' : o.flagH = 1 ; break ;
        case 'h' : o.flagh = 1 ; break ;
        case 'R' : o.flagr = 0 ; break ;
        case 'r' : o.flagr = 1 ; break ;
        case 'P' : o.flagp = 0 ; break ;
        case 'p' : o.flagp = 1 ; break ;
        case 'l' : o.localname = l.arg ; break ;
        case 'B' : o.banner = l.arg ; break ;
        case 't' : if (!uint0_scan(l.arg, &o.timeout)) dieusage() ; break ;
        case 'i' : o.rules = l.arg ; o.rulesx = 0 ; break ;
        case 'x' : o.rules = l.arg ; o.rulesx = 1 ; break ;
        case 'S' : o.flagS = 1 ; break ;
        case 's' : o.flagS = 0 ; break ;
        case 'J' : o.flagJ = 1 ; break ;
        case 'j' : o.flagJ = 0 ; break ;
        case 'Y' : o.flagY = 1 ; o.flagy = 0 ; break ;
        case 'y' : o.flagy = 1 ; o.flagY = 0 ; break ;
        case 'K' : if (!uint0_scan(l.arg, &o.kimeout)) dieusage() ; break ;
        case 'Z' : o.flagZ = 1 ; break ;
        case 'z' : o.flagZ = 0 ; break ;
        case 'k' : if (!uint0_scan(l.arg, &o.snilevel)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (argc < 3) dieusage() ;
  }

  {
    size_t pos = 0 ;
    unsigned int m = 0 ;
    char fmt[UINT_FMT * 6 + UID_FMT + GID_FMT * (NGROUPS_MAX + 1)] ;
    char const *newargv[57 + argc] ;
    int doaccess = o.flagw || o.flagD || !o.flagH || o.flagr || o.flagp || o.localname || o.banner || o.timeout || o.rules ;
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpserver" ;
    if (o.verbosity != 1)
    {
      newargv[m++] = o.verbosity ? "-v" : "-q" ;
      pos = uint_fmt(fmt, o.verbosity) ;
      fmt[pos++] = 0 ;
    }
    if (o.flag1) newargv[m++] = "-1" ;
    if (o.maxconn)
    {
      newargv[m++] = "-c" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.maxconn) ;
      fmt[pos++] = 0 ;
    }
    if (o.localmaxconn)
    {
      newargv[m++] = "-C" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.localmaxconn) ;
      fmt[pos++] = 0 ;
    }
    if (o.backlog != (unsigned int)-1)
    {
      newargv[m++] = "-b" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.backlog) ;
      fmt[pos++] = 0 ;
    }
    newargv[m++] = "--" ;
    newargv[m++] = *argv++ ;
    newargv[m++] = *argv++ ;
    if (doaccess)
    {
      newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpserver-access" ;
      if (o.verbosity != 1)
      {
        newargv[m++] = "-v" ;
        newargv[m++] = fmt ;
      }
      if (o.flagw) newargv[m++] = "-w" ;
      if (o.flagD) newargv[m++] = "-D" ;
      if (o.flagH) newargv[m++] = "-H" ;
      if (o.flagh) newargv[m++] = "-h" ;
      if (o.flagr) newargv[m++] = "-r" ;
      if (o.flagp) newargv[m++] = "-p" ;
      if (o.localname)
      {
        newargv[m++] = "-l" ;
        newargv[m++] = o.localname ;
      }
      if (o.banner)
      {
        newargv[m++] = "-B" ;
        newargv[m++] = o.banner ;
      }
      if (o.timeout)
      {
        newargv[m++] = "-t" ;
        newargv[m++] = fmt + pos ;
        pos += uint_fmt(fmt + pos, o.timeout) ;
        fmt[pos++] = 0 ;
      }
      if (o.rules)
      {
        newargv[m++] = o.rulesx ? "-x" : "-i" ;
        newargv[m++] = o.rules ;
      }
      newargv[m++] = "--" ;
    }
    if (o.flagL)
    {
      newargv[m++] = S6_NETWORKING_BINPREFIX "proxy-server" ;
      newargv[m++] = "--before-tlsd" ;
      newargv[m++] = "--" ;
    }
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsd" ;
    if (o.verbosity != 1)
    {
      newargv[m++] = "-v" ;
      newargv[m++] = fmt ;
    }
    if (o.flagS) newargv[m++] = "-S" ;
    if (o.flagJ) newargv[m++] = "-J" ;
    if (o.flagy) newargv[m++] = "-y" ;
    else if (o.flagY) newargv[m++] = "-Y" ;
    if (o.kimeout)
    {
      newargv[m++] = "-K" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.kimeout) ;
      fmt[pos++] = 0 ;
    }
    if (o.flagZ) newargv[m++] = "-Z" ;
    if (o.snilevel >= 2) newargv[m++] = "-k2" ;
    else if (o.snilevel) newargv[m++] = "-k1" ;
    newargv[m++] = "--" ;
    if (o.doapply)
    {
      newargv[m++] = S6_EXTBINPREFIX "s6-applyuidgid" ;
      if (o.gidn != (size_t)-1)
      {
        newargv[m++] = "-G" ;
        newargv[m++] = fmt + pos ;
        pos += gid_fmtlist(fmt + pos, o.gids, o.gidn) ;
        fmt[pos++] = 0 ;
      }
      if (o.gid)
      {
        newargv[m++] = "-g" ;
        newargv[m++] = fmt + pos ;
        pos += gid_fmt(fmt + pos, o.gid) ;
        fmt[pos++] = 0 ;
      }
      if (o.uid)
      {
        newargv[m++] = "-u" ;
        newargv[m++] = fmt + pos ;
        pos += uid_fmt(fmt + pos, o.uid) ;
        fmt[pos++] = 0 ;
      }
      if (o.flagU) newargv[m++] = "-Uz" ;
      newargv[m++] = "--" ;
    }
    if (o.flagL)
    {
      newargv[m++] = S6_NETWORKING_BINPREFIX "proxy-server" ;
      newargv[m++] = "--after-tlsd" ;
      newargv[m++] = "--" ;
    }
    while (*argv) newargv[m++] = *argv++ ;
    newargv[m++] = 0 ;
    xexec(newargv) ;
  }
}
