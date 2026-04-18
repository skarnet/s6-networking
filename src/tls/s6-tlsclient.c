/* ISC license. */

#include <stdint.h>
#include <string.h>

#include <skalibs/uint64.h>
#include <skalibs/types.h>
#include <skalibs/ip46.h>
#include <skalibs/envexec.h>

#include <s6-networking/config.h>

#define USAGE "s6-tlsclient [ options ] host port prog...\n" \
"s6-tcpclient options: [ -q | -Q | -v ] [ -4 | -6 ] [ -d | -D ] [ -r | -R ] [ -h ] [ -H ] [ -n | -N ] [ -t timeout ] [ -l localname ] [ -T timeoutconn ] [ -i localip ] [ -p localport ]\n" \
"s6-tlsc options: [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -K timeout ] [ -k servername ] [ -Z | -z ]"

#define dieusage() strerr_dieusage(100, USAGE)

typedef struct options_s options_t, *options_t_ref ;
struct options_s
{
  unsigned int timeout ;
  unsigned int ximeout ;
  unsigned int yimeout ;
  unsigned int kimeout ;
  uint16_t localport ;
  ip46full localip ;
  uint8_t doxy : 1 ;
} ;

#define OPTIONS_ZERO \
{ \
  .timeout = 0, \
  .ximeout = 2, \
  .yimeout = 58, \
  .kimeout = 0, \
  .localport = 0, \
  .localip = IP46FULL_ZERO, \
  .doxy = 0 \
}

enum golb_e
{
  GOLB_QUIET = 0x0001,
  GOLB_VERBOSE = 0x0002,
  GOLB_V4 = 0x0004,
  GOLB_V6 = 0x0008,
  GOLB_NONAGLE = 0x0010,
  GOLB_NODNS = 0x0020,
  GOLB_HOSTS = 0x0040,
  GOLB_IDENT = 0x0080,
  GOLB_QUALIFY = 0x0100,
  GOLB_CLOSENOTIFY = 0x0200,
  GOLB_STRICTCN = 0x0400,
  GOLB_CLIENTCERT = 0x0800,
  GOLB_NOVERIFY = 0x1000,
  GOLB_KEEP = 0x2000,
} ;

enum gola_e
{
  GOLA_TIMEOUT,
  GOLA_LOCALNAME,
  GOLA_XYIMEOUT,
  GOLA_IP,
  GOLA_PORT,
  GOLA_KIMEOUT,
  GOLA_SERVERNAME,
  GOLA_N
} ;

int main (int argc, char const *const *argv)
{
  static gol_bool const rgolb[] =
  {
    { .so = 'q', .lo = "quiet", .clear = GOLB_VERBOSE, .set = GOLB_QUIET },
    { .so = 'Q', .lo = "normally-verbose", .clear = GOLB_QUIET | GOLB_VERBOSE, .set = 0 },
    { .so = 'v', .lo = "verbose", .clear = GOLB_QUIET, .set = GOLB_VERBOSE },
    { .so = '4', .lo = "ipv4", .clear = 0, .set = GOLB_V4 },
    { .so = '6', .lo = "ipv6", .clear = 0, .set = GOLB_V6 },
    { .so = 'd', .lo = "nagle", .clear = GOLB_NONAGLE, .set = 0 },
    { .so = 'D', .lo = "no-nagle", .clear = 0, .set = GOLB_NONAGLE },
    { .so = 0, .lo = "dns", .clear = GOLB_NODNS, .set = 0 },
    { .so = 'H', .lo = "no-dns", .clear = 0, .set = GOLB_NODNS },
    { .so = 0, .lo = "no-hosts", .clear = GOLB_HOSTS, .set = 0 },
    { .so = 'h', .lo = "hosts", .clear = 0, .set = GOLB_HOSTS },
    { .so = 'R', .lo = "no-ident", .clear = GOLB_IDENT, .set = 0 },
    { .so = 'r', .lo = "ident", .clear = 0, .set = GOLB_IDENT },
    { .so = 'N', .lo = "no-qualify", .clear = GOLB_QUALIFY, .set = 0 },
    { .so = 'n', .lo = "qualify", .clear = 0, .set = GOLB_QUALIFY },
    { .so = 's', .lo = "no-close-notify", .clear = GOLB_CLOSENOTIFY, .set = 0 },
    { .so = 'S', .lo = "close-notify", .clear = 0, .set = GOLB_CLOSENOTIFY },
    { .so = 'j', .lo = "no-enforce-close-notify", .clear = GOLB_STRICTCN, .set = 0 },
    { .so = 'J', .lo = "enforce-close-notify", .clear = 0, .set = GOLB_STRICTCN },
    { .so = 'Y', .lo = "no-client-cert", .clear = GOLB_CLIENTCERT, .set = 0 },
    { .so = 'y', .lo = "client-cert", .clear = 0, .set = GOLB_CLIENTCERT },
    { .so = 0, .lo = "verify-cert", .clear = GOLB_NOVERIFY, .set = 0 },
    { .so = 0, .lo = "no-verify-cert", .clear = 0, .set = GOLB_NOVERIFY },
    { .so = 'z', .lo = "no-keep", .clear = GOLB_KEEP, .set = 0 },
    { .so = 'Z', .lo = "keep", .clear = 0, .set = GOLB_KEEP },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 't', .lo = "timeout", .i = GOLA_TIMEOUT },
    { .so = 'l', .lo = "local-name", .i = GOLA_LOCALNAME },
    { .so = 'T', .lo = "connection-timeouts", .i = GOLA_XYIMEOUT },
    { .so = 'i', .lo = "local-ip", .i = GOLA_IP },
    { .so = 'p', .lo = "local-port", .i = GOLA_PORT },
    { .so = 'K', .lo = "handshake-timeout", .i = GOLA_KIMEOUT },
    { .so = 'k', .lo = "servername", .i = GOLA_SERVERNAME },
  } ;
  options_t o = OPTIONS_ZERO ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  unsigned int golc ;

  PROG = "s6-tlsclient" ;
  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (argc < 3) dieusage() ;

  if (wgola[GOLA_TIMEOUT])
    if (!uint0_scan(wgola[GOLA_TIMEOUT], &o.timeout))
      strerr_dief(100, "timeout", " needs to be a", "n unsigned integer") ;
  if (wgola[GOLA_KIMEOUT])
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &o.kimeout))
      strerr_dief(100, "handshake-timeout", " needs to be a", "n unsigned integer") ;
  if (wgola[GOLA_IP])
    if (!ip46full_scan(wgola[GOLA_IP], &o.localip))
      strerr_dief(100, "local-ip", " needs to be a", " valid IP address") ;
  if (wgola[GOLA_PORT])
    if (!uint160_scan(wgola[GOLA_PORT], &o.localport))
      strerr_dief(100, "handshake-timeout", " needs to be a", "valid port number") ;
  if (wgola[GOLA_XYIMEOUT])
  {
    size_t n = uint_scan(wgola[GOLA_XYIMEOUT], &o.ximeout) ;
    if (!n) strerr_dief(100, "connection-timeouts must be x+y") ;
    o.doxy = 1 ;
    if (!wgola[GOLA_XYIMEOUT][n]) o.yimeout = 0 ;
    else
    {
      if (wgola[GOLA_XYIMEOUT][n] != '+') strerr_dief(100, "connection-timeouts must be x+y") ;
      if (!uint0_scan(wgola[GOLA_XYIMEOUT] + n + 1, &o.yimeout)) strerr_dief(100, "connection-timeouts must be x+y") ;
    }
  }

  if (!wgola[GOLA_SERVERNAME] && !(wgolb & GOLB_NODNS))
  {
    ip46full ip ;
    if (!ip46full_scan(argv[0], &ip))
      wgola[GOLA_SERVERNAME] = argv[0] ;
  }

  {
    size_t pos = 0 ;
    unsigned int m = 0 ;
    char fmt[UINT_FMT * 4 + UINT16_FMT + IP46_FMT] ;
    char const *newargv[32 + argc] ;

    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tcpclient" ;
    if (wgolb & GOLB_QUIET) newargv[m++] = "-q" ;
    else if (wgolb & GOLB_VERBOSE) newargv[m++] = "-v" ;
    if (wgolb & GOLB_V4) newargv[m++] = "-4" ;
    if (wgolb & GOLB_V6) newargv[m++] = "-6" ;
    if (wgolb & GOLB_NONAGLE) newargv[m++] = "-D" ;
    if (wgolb & GOLB_NODNS) newargv[m++] = "-H" ;
    if (wgolb & GOLB_HOSTS) newargv[m++] = "-h" ;
    if (wgolb & GOLB_IDENT) newargv[m++] = "-r" ;
    if (wgolb & GOLB_QUALIFY) newargv[m++] = "-N" ;
    if (o.timeout)
    {
      newargv[m++] = "-t" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.timeout) ;
      fmt[pos++] = 0 ;
    }
    if (wgola[GOLA_LOCALNAME])
    {
      newargv[m++] = "-l" ;
      newargv[m++] = wgola[GOLA_LOCALNAME] ;
    }
    if (o.doxy)
    {
      newargv[m++] = "-T" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.ximeout) ;
      fmt[pos++] = '+' ;
      pos += uint_fmt(fmt + pos, o.yimeout) ;
      fmt[pos++] = 0 ;
    }
    if (memcmp(o.localip.ip, IP6_ANY, 16))
    {
      newargv[m++] = "-i" ;
      newargv[m++] = fmt + pos ;
      pos += ip46full_fmt(fmt + pos, &o.localip) ;
      fmt[pos++] = 0 ;
    }
    if (o.localport)
    {
      newargv[m++] = "-p" ;
      newargv[m++] = fmt + pos ;
      pos += uint16_fmt(fmt + pos, o.localport) ;
      fmt[pos++] = 0 ;
    }
    newargv[m++] = "--" ;
    newargv[m++] = *argv++ ;
    newargv[m++] = *argv++ ;
    newargv[m++] = S6_NETWORKING_BINPREFIX "s6-tlsc" ;
    if (wgolb & GOLB_CLOSENOTIFY) newargv[m++] = "-S" ;
    if (wgolb & GOLB_STRICTCN) newargv[m++] = "-J" ;
    if (wgolb & GOLB_CLIENTCERT) newargv[m++] = "-y" ;
    if (wgolb & GOLB_NOVERIFY) newargv[m++] = "--no-verify-cert" ;
    if (wgolb & GOLB_KEEP) newargv[m++] = "-Z" ;
    if (o.kimeout)
    {
      newargv[m++] = "-K" ;
      newargv[m++] = fmt + pos ;
      pos += uint_fmt(fmt + pos, o.kimeout) ;
      fmt[pos++] = 0 ;
    }
    if (wgola[GOLA_SERVERNAME])
    {
      newargv[m++] = "-k" ;
      newargv[m++] = wgola[GOLA_SERVERNAME] ;
    }
    newargv[m++] = "--" ;
    while (*argv) newargv[m++] = *argv++ ;
    newargv[m++] = 0 ;
    xexec(newargv) ;
  }
}
