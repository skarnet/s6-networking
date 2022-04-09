/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <skalibs/posixishard.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>
#include <skalibs/iopause.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/random.h>

#define USAGE "s6-taiclock [ -f ] [ -v verbosity ] [ -r roundtrips ] [ -t triptimeout ] [ -h throttle ] [ -T totaltimeout ] [ -e errmax ] [ -p port ] ipaddress"
#define dieusage() strerr_dieusage(100, USAGE)

static unsigned int verbosity = 1 ;

#define N 28

int tain_exchange (int s, ip46 const *ip, uint16_t port, tain *serversays, tain const *deadline)
{
  char query[N] = "ctai" ;
  char answer[N] ;
  ip46 dummyip ;
  ssize_t r ;
  uint16_t dummyport ;
  tain_pack(query+4, &STAMP) ;
  random_buf(query+20, N-20) ; /* cookie */
  r = socket_sendnb46_g(s, query, N, ip, port, deadline) ;
  if (r < 0) return 0 ;
  if (r < N) return (errno = EPIPE, 0) ;
  r = socket_recvnb46_g(s, answer, N, &dummyip, &dummyport, deadline) ;
  if (r < 0) return 0 ;
  if (r < N) return (errno = EPROTO, 0) ;
  if (memcmp(answer, "stai", 4)) return (errno = EPROTO, 0) ;
  if (memcmp(query+20, answer+20, N-20)) return (errno = EPROTO, 0) ;
  tain_unpack(answer+4, serversays) ;
  return 1 ;
}

int main (int argc, char const *const *argv)
{
  tain deltamin = TAIN_ZERO ;
  tain deltaoffset ;
  tain deltamax ;
  tain errmax ;
  tain timeouttto, throttletto, globaltto ;
  tain globaldeadline ;
  unsigned int roundtrips = 10 ;
  unsigned int i = 0 ;
  ip46 ipremote ;
  int sock ;
  int flagforce = 0 ;
  uint16_t portremote = 4014 ;
  PROG = "s6-taiclock" ;

  {
    unsigned int timeout = 2000 ;
    unsigned int throttle = 0 ;
    unsigned int bigtimeout = 10000 ;
    unsigned int emax = 100 ;
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "fv:r:t:h:T:e:p:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'f' : flagforce = 1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'r' : if (!uint0_scan(l.arg, &roundtrips)) dieusage() ; break ;
        case 't' : if (!uint0_scan(l.arg, &timeout)) dieusage() ; break ;
        case 'h' : if (!uint0_scan(l.arg, &throttle)) dieusage() ; break ;
        case 'T' : if (!uint0_scan(l.arg, &bigtimeout)) dieusage() ; break ;
        case 'e' : if (!uint0_scan(l.arg, &emax)) dieusage() ; break ;
        case 'p' : if (!uint160_scan(l.arg, &portremote)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (timeout) tain_from_millisecs(&timeouttto, timeout) ;
    else timeouttto = tain_infinite_relative ;
    tain_from_millisecs(&throttletto, throttle) ;
    if (bigtimeout) tain_from_millisecs(&globaltto, bigtimeout) ;
    else globaltto = tain_infinite_relative ;
    tain_from_millisecs(&errmax, emax) ;
  }
  if (!argc) dieusage() ;
  if (!ip46_scan(argv[0], &ipremote)) dieusage() ;

  sock = socket_udp46(ip46_is6(&ipremote)) ;
  if (sock < 0) strerr_diefu1sys(111, "socket_udp") ;

  tain_uint(&deltaoffset, 0xffffffffU) ;
  tain_add(&deltaoffset, &deltaoffset, &deltaoffset) ; /* about 136 years */
  tain_add(&deltamax, &deltaoffset, &deltaoffset) ;
  tain_now_g() ;
  tain_add_g(&globaldeadline, &globaltto) ;
  if (!socket_deadlineconnstamp46_g(sock, &ipremote, portremote, &globaldeadline))
    strerr_diefu1sys(111, "socket_deadlineconnstamp") ;

  for (; i < roundtrips ; i++)
  {
    tain deadline, before, serversays ;
    tain_add_g(&deadline, &timeouttto) ;
    if (tain_less(&globaldeadline, &deadline)) deadline = globaldeadline ;
    tain_copynow(&before) ;
    if (!tain_exchange(sock, &ipremote, portremote, &serversays, &deadline))
    {
      if (verbosity >= 2)
      {
        char fmt[UINT_FMT] ;
        char fmtr[UINT_FMT] ;
        fmt[uint_fmt(fmt, i+1)] = 0 ;
        fmtr[uint_fmt(fmtr, roundtrips)] = 0 ;
        strerr_warni5sys("TAIA round-trip ", fmt, "/", fmtr, " failed") ;
      }
    }
    else
    {
      tain cur, min, max ;
      tain_add(&cur, &serversays, &deltaoffset) ;
      tain_add(&min, &before, &deltamin) ;
      tain_add(&max, &before, &deltamax) ;
      if (tain_less(&cur, &max) && !tain_less(&cur, &min))
        tain_sub(&deltamax, &cur, &before) ;
      tain_add_g(&min, &deltamin) ;
      tain_add_g(&max, &deltamax) ;
      if (tain_less(&cur, &max) && !tain_less(&cur, &min))
        tain_sub(&deltamin, &cur, &STAMP) ;
    }

    tain_add_g(&deadline, &throttletto) ;
    if (tain_less(&globaldeadline, &deadline)) deadline = globaldeadline ;
    deepsleepuntil_g(&deadline) ;
    if (!tain_future(&globaldeadline))
    {
      if (verbosity)
      {
        errno = ETIMEDOUT ;
        strerr_diefu1sys(1, "complete series of TAIA exchanges") ;
      }
      else return 1 ;
    }
  }

  {
    char adj[TAIN_PACK] ;
    tain delta ;
    if (tain_less(&deltamax, &deltamin)) tain_sub(&delta, &deltamin, &deltamax) ;
    else tain_sub(&delta, &deltamax, &deltamin) ;
    if (tain_less(&errmax, &delta))
    {
      if (verbosity)
      {
        char fmtd[TAIN_FMT] ;
        char fmte[TAIN_FMT] ;
        fmtd[tain_fmt(fmtd, &delta)] = 0 ;
        fmte[tain_fmt(fmte, &errmax)] = 0 ;
        strerr_warnw2x("maximum acceptable uncertainty: ", fmte) ;
        strerr_warnw2x("current calculated uncertainty: ", fmtd) ;
      }
      if (!flagforce) strerr_dief1x(111, "time uncertainty too large") ;
    }

    tain_add(&delta, &deltamax, &deltamin) ;
    tain_half(&delta, &delta) ;
    tain_sub(&delta, &delta, &deltaoffset) ;
    tain_pack(adj, &delta) ;
    if (allwrite(1, adj, TAIN_PACK) < TAIN_PACK) strerr_diefu1sys(111, "write to stdout") ;
  }
  return 0 ;
}
