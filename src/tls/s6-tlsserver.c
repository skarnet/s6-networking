/* ISC license. */

#include <sys/types.h>
#include <limits.h>

#include <skalibs/types.h>
#include <skalibs/envexec.h>

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
} ;

#define OPTIONS_ZERO \
{ \
  .gidn = (size_t)-1, \
  .uid = 0, \
  .gid = 0, \
  .maxconn = 0, \
  .localmaxconn = 0, \
  .backlog = (unsigned int)-1, \
  .timeout = 0, \
  .kimeout = 0, \
  .snilevel = 0, \
}

enum golb_e
{
  GOLB_QUIET = 0x1,
  GOLB_VERBOSE = 0x2,
  GOLB_NOTIF = 0x4,
  GOLB_PROXY = 0x8,
  GOLB_UIDGID = 0x10,
  GOLB_STRICTRES = 0x20,
  GOLB_NONAGLE = 0x40,
  GOLB_NOLOOKUPS = 0x80,
  GOLB_HOSTS = 0x100,
  GOLB_IDENT = 0x200,
  GOLB_PARANOID = 0x400,
  GOLB_CLOSENOTIFY = 0x800,
  GOLB_FATALEOF = 0x1000,
  GOLB_OPTCERT = 0x2000,
  GOLB_MANDCERT = 0x4000,
  GOLB_KEEPENV = 0x8000,
} ;

enum gola_e
{
  GOLA_MAXCONN,
  GOLA_LMAXCONN,
  GOLA_BACKLOG,
  GOLA_GIDLIST,
  GOLA_GID,
  GOLA_UID,
  GOLA_LOCALNAME,
  GOLA_BANNER,
  GOLA_TIMEOUT,
  GOLA_RULESDIR,
  GOLA_RULESFILE,
  GOLA_KIMEOUT,
  GOLA_SNILEVEL,
  GOLA_N
} ;

int main (int argc, char const *const *argv)
{
  static gol_bool const rgolb[] =
  {
    { .so = 'q', .lo = "quiet", .clear = GOLB_VERBOSE, .set = GOLB_QUIET },
    { .so = 'Q', .lo = "normally-verbose", .clear = GOLB_QUIET | GOLB_VERBOSE, .set = 0 },
    { .so = 'v', .lo = "verbose", .clear = GOLB_QUIET, .set = GOLB_VERBOSE },
    { .so = '1', .lo = "notify", .clear = 0, .set = GOLB_NOTIF },
    { .so = 'L', .lo = "proxy", .clear = 0, .set = GOLB_PROXY },
    { .so = 'U', .lo = "with-envuidgid", .clear = 0, .set = GOLB_UIDGID },
    { .so = 'W', .lo = "no-strict-resolution", .clear = GOLB_STRICTRES, .set = 0 },
    { .so = 'w', .lo = "strict-resolution", .clear = 0, .set = GOLB_STRICTRES },
    { .so = 'd', .lo = "enable-nagle", .clear = GOLB_NONAGLE, .set = 0 },
    { .so = 'D', .lo = "disable-nagle", .clear = 0, .set = GOLB_NONAGLE },
    { .so = 'H', .lo = "disable-dns-lookups", .clear = 0, .set = GOLB_NOLOOKUPS },
    { .so = 'h', .lo = "with-etchosts", .clear = 0, .set = GOLB_HOSTS },
    { .so = 'R', .lo = "disable-ident-lookups", .clear = GOLB_IDENT, .set = 0 },
    { .so = 'r', .lo = "enable-ident-lookups", .clear = 0, .set = GOLB_IDENT },
    { .so = 'P', .lo = "disable-paranoid-lookups", .clear = GOLB_PARANOID, .set = 0 },
    { .so = 'p', .lo = "enable-paranoid-lookups", .clear = 0, .set = GOLB_PARANOID },
    { .so = 's', .lo = "disable-closenotify", .clear = GOLB_CLOSENOTIFY, .set = 0 },
    { .so = 'S', .lo = "enable-closenotify", .clear = 0, .set = GOLB_CLOSENOTIFY },
    { .so = 'j', .lo = "allow-raw-eof", .clear = GOLB_FATALEOF, .set = 0 },
    { .so = 'J', .lo = "disallow-raw-eof", .clear = 0, .set = GOLB_FATALEOF },
    { .so = 'Y', .lo = "request-client-certificate", .clear = GOLB_MANDCERT, .set = GOLB_OPTCERT },
    { .so = 'y', .lo = "demand-client-certificate", .clear = GOLB_OPTCERT, .set = GOLB_MANDCERT },
    { .so = 'z', .lo = "no-keep-tlsd-environment", .clear = GOLB_KEEPENV, .set = 0 },
    { .so = 'Z', .lo = "keep-tlsd-environment", .clear = 0, .set = GOLB_KEEPENV },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'c', .lo = "global-max-connections", .i = GOLA_MAXCONN },
    { .so = 'C', .lo = "local-max-connections", .i = GOLA_LMAXCONN },
    { .so = 'b', .lo = "backlog", .i = GOLA_BACKLOG },
    { .so = 'G', .lo = "gidlist", .i = GOLA_GIDLIST },
    { .so = 'g', .lo = "gid", .i = GOLA_GID },
    { .so = 'u', .lo = "uid", .i = GOLA_UID },
    { .so = 'l', .lo = "local-name", .i = GOLA_LOCALNAME },
    { .so = 'B', .lo = "banner", .i = GOLA_BANNER },
    { .so = 't', .lo = "timeout", .i = GOLA_TIMEOUT },
    { .so = 'i', .lo = "rules-directory", .i = GOLA_RULESDIR },
    { .so = 'x', .lo = "rules-file", .i = GOLA_RULESFILE },
    { .so = 'K', .lo = "handshake-timeout", .i = GOLA_KIMEOUT },
    { .so = 'k', .lo = "sni-level", .i = GOLA_SNILEVEL },
  } ;

  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  options_t o = OPTIONS_ZERO ;
  unsigned int golc ;
  int doapply = 0 ;
  PROG = "s6-tlsserver" ;

  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (argc < 3) dieusage() ;

  if (wgola[GOLA_MAXCONN])
  {
    if (!uint0_scan(wgola[GOLA_MAXCONN], &o.maxconn)) dieusage() ;
    if (!o.maxconn) o.maxconn = 1 ;
  }
  if (wgola[GOLA_LMAXCONN])
  {
    if (!uint0_scan(wgola[GOLA_LMAXCONN], &o.localmaxconn)) dieusage() ;
    if (!o.localmaxconn) o.localmaxconn = 1 ;
  }
  if (wgola[GOLA_BACKLOG])
  {
    if (!uint0_scan(wgola[GOLA_BACKLOG], &o.backlog)) dieusage() ;
  }
  if (wgola[GOLA_GIDLIST])
  {
    if (!gid_scanlist(o.gids, NGROUPS_MAX, wgola[GOLA_GIDLIST], &o.gidn) && wgola[GOLA_GIDLIST]) dieusage() ;
    doapply = 1 ;
  }
  if (wgola[GOLA_GID])
  {
    if (!gid0_scan(wgola[GOLA_GID], &o.gid)) dieusage() ;
    doapply = 1 ;
  }
  if (wgola[GOLA_UID])
  {
    if (!uid0_scan(wgola[GOLA_UID], &o.uid)) dieusage() ;
    doapply = 1 ;
  }
  if (wgola[GOLA_TIMEOUT])
  {
    if (!uint0_scan(wgola[GOLA_TIMEOUT], &o.timeout)) dieusage() ;
  }
  if (wgola[GOLA_KIMEOUT])
  {
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &o.kimeout)) dieusage() ;
  }
  if (wgola[GOLA_SNILEVEL])
  {
    if (!uint0_scan(wgola[GOLA_SNILEVEL], &o.snilevel)) dieusage() ;
  }
  if (wgolb & GOLB_UIDGID)
  {
    o.uid = 0 ;
    o.gid = 0 ;
    o.gidn = (size_t)-1 ;
    doapply = 1 ;
  }

  {
    size_t pos = 0 ;
    unsigned int m = 0 ;
    int doaccess = !(wgolb & GOLB_NOLOOKUPS)
     || !!(wgolb & (GOLB_STRICTRES | GOLB_NONAGLE | GOLB_IDENT | GOLB_PARANOID))
     || !!wgola[GOLA_LOCALNAME] || !!wgola[GOLA_BANNER] || !!wgola[GOLA_RULESDIR] || !!wgola[GOLA_RULESFILE]
     || !!o.timeout ;
    char fmt[UINT_FMT * 5 + UID_FMT + GID_FMT * (NGROUPS_MAX + 1)] ;
    char const *newargv[54 + argc] ;

    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpserver" ;
    if (wgolb & GOLB_QUIET) newargv[m++] = "-q" ; else if (wgolb & GOLB_VERBOSE) newargv[m++] = "-v" ;
    if (wgolb & GOLB_NOTIF) newargv[m++] = "-1" ;
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
      if (wgolb & GOLB_QUIET) newargv[m++] = "-v0" ; else if (wgolb & GOLB_VERBOSE) newargv[m++] = "-v2" ;
      if (wgolb & GOLB_STRICTRES) newargv[m++] = "-w" ;
      if (wgolb & GOLB_NONAGLE) newargv[m++] = "-D" ;
      if (wgolb & GOLB_NOLOOKUPS) newargv[m++] = "-H" ;
      if (wgolb & GOLB_HOSTS) newargv[m++] = "-h" ;
      if (wgolb & GOLB_IDENT) newargv[m++] = "-r" ;
      if (wgolb & GOLB_PARANOID) newargv[m++] = "-p" ;
      if (wgola[GOLA_LOCALNAME])
      {
        newargv[m++] = "-l" ;
        newargv[m++] = wgola[GOLA_LOCALNAME] ;
      }
      if (wgola[GOLA_BANNER])
      {
        newargv[m++] = "-B" ;
        newargv[m++] = wgola[GOLA_BANNER] ;
      }
      if (o.timeout)
      {
        newargv[m++] = "-t" ;
        newargv[m++] = fmt + pos ;
        pos += uint_fmt(fmt + pos, o.timeout) ;
        fmt[pos++] = 0 ;
      }
      if (wgola[GOLA_RULESDIR])
      {
        newargv[m++] = "-i" ;
        newargv[m++] = wgola[GOLA_RULESDIR] ;
      }
      else if (wgola[GOLA_RULESFILE])
      {
        newargv[m++] = "-x" ;
        newargv[m++] = wgola[GOLA_RULESFILE] ;
      }
      newargv[m++] = "--" ;
    }
    if (wgolb & GOLB_PROXY)
    {
      newargv[m++] = S6_NETWORKING_BINPREFIX "proxy-server" ;
      newargv[m++] = "--before-tlsd" ;
      newargv[m++] = "--" ;
    }
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsd" ;
    if (wgolb & GOLB_QUIET) newargv[m++] = "-v0" ; else if (wgolb & GOLB_VERBOSE) newargv[m++] = "-v2" ;
    if (wgolb & GOLB_CLOSENOTIFY) newargv[m++] = "-S" ;
    if (wgolb & GOLB_FATALEOF) newargv[m++] = "-J" ;
    if (wgolb & GOLB_MANDCERT) newargv[m++] = "-y" ;
    else if (wgolb & GOLB_OPTCERT) newargv[m++] = "-Y" ;
    if (o.kimeout)
    {
      newargv[m++] = "-K" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.kimeout) ;
      fmt[pos++] = 0 ;
    }
    if (wgolb & GOLB_KEEPENV) newargv[m++] = "-Z" ;
    if (o.snilevel >= 2) newargv[m++] = "-k2" ;
    else if (o.snilevel) newargv[m++] = "-k1" ;
    newargv[m++] = "--" ;
    if (doapply)
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
      if (wgolb & GOLB_UIDGID) newargv[m++] = "-Uz" ;
      newargv[m++] = "--" ;
    }
    if (wgolb & GOLB_PROXY)
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
