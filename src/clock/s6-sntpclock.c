/* ISC license. */

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <skalibs/error.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/uint.h>
#include <skalibs/sgetopt.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/bytestr.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>
#include <skalibs/iopause.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>

#define USAGE "s6-sntpclock [ -f ] [ -v verbosity ] [ -r roundtrips ] [ -t triptimeout ] [ -h throttle ] [ -T totaltimeout ] [ -e errmax ] [ -p port ] ipaddress"
#define dieusage() strerr_dieusage(100, USAGE)

static unsigned int verbosity = 1 ;

int ntp_exchange (int s, ip46_t const *ip, uint16 port, tain_t *stamps, tain_t const *deadline)
{
  char query[48] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ;
  char answer[48] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ;
  tain_t starttime ;
  uint64 ntpstamp ;
  ip46_t dummyip ;
  uint16 dummyport ;
  int r ;
  tain_copynow(&starttime) ;
  query[0] = 35 ; /* SNTPv4, client */
  if (!ntp_from_tain(&ntpstamp, &starttime)) return 0 ;
  uint64_pack_big(query+24, ntpstamp) ;
  uint64_pack_big(query+40, ntpstamp) ;
  if (verbosity >= 3)
  {
    char fmtntp[UINT64_XFMT] ;
    fmtntp[uint64_xfmt(fmtntp, ntpstamp)] = 0 ;
    strerr_warni2x("NTP stamp[0] sent: ", fmtntp) ;
  }
  r = socket_sendnb46_g(s, query, 48, ip, port, deadline) ;
  if (r < 0) return 0 ;
  if (r < 48) return (errno = EPIPE, 0) ;
  r = socket_recvnb46_g(s, answer, 48, &dummyip, &dummyport, deadline) ;
  if (r < 0) return 0 ;
  if (r < 48) return (errno = EPROTO, 0) ;
  if (((answer[0] & 7) != 2) && ((answer[0] & 7) != 4)) return (errno = EPROTO, 0) ;
  if (!(answer[0] & 56)) return (errno = EPROTO, 0) ;
  if (byte_diff(query+40, 8, answer+24)) return (errno = EPROTO, 0) ;
  stamps[0] = starttime ;
  uint64_unpack_big(answer+32, &ntpstamp) ;
  tain_from_ntp(stamps+1, ntpstamp) ;
  if (verbosity >= 3)
  {
    char fmtntp[UINT64_XFMT] ;
    fmtntp[uint64_xfmt(fmtntp, ntpstamp)] = 0 ;
    strerr_warni2x("NTP stamp[1] received: ", fmtntp) ;
  }
  uint64_unpack_big(answer+40, &ntpstamp) ;
  tain_from_ntp(stamps+2, ntpstamp) ;
  if (verbosity >= 3)
  {
    char fmtntp[UINT64_XFMT] ;
    fmtntp[uint64_xfmt(fmtntp, ntpstamp)] = 0 ;
    strerr_warni2x("NTP stamp[2] received: ", fmtntp) ;
  }
  tain_copynow(&stamps[3]) ;
  return 1 ;
}

int main (int argc, char const *const *argv)
{
  tain_t deltamin = TAIN_ZERO ;
  tain_t deltaoffset ;
  tain_t deltamax ;
  tain_t errmax ;
  tain_t timeouttto, throttletto, globaltto ;
  tain_t globaldeadline ;
  unsigned int roundtrips = 10 ;
  unsigned int i = 0 ;
  int sock ;
  int flagforce = 0 ;
  ip46_t ipremote ;
  uint16 portremote = 123 ;
  PROG = "s6-sntpclock" ;

  {
    unsigned int timeout = 2000 ;
    unsigned int throttle = 0 ;
    unsigned int bigtimeout = 10000 ;
    unsigned int emax = 100 ;
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      register int opt = subgetopt_r(argc, argv, "fv:r:t:h:T:e:p:", &l) ;
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

  tain_uint(&deltaoffset, 1072224000U) ; /* about 34 years, which is the best we can do with NTP */
  tain_add(&deltamax, &deltaoffset, &deltaoffset) ;
  tain_now_g() ;
  tain_add_g(&globaldeadline, &globaltto) ;
  if (!socket_deadlineconnstamp46_g(sock, &ipremote, portremote, &globaldeadline))
    strerr_diefu1sys(111, "socket_deadlineconnstamp") ;

  for (; i < roundtrips ; i++)
  {
    tain_t stamps[4] ;
    tain_t deadline ;
    tain_add_g(&deadline, &timeouttto) ;
    if (tain_less(&globaldeadline, &deadline)) deadline = globaldeadline ;
    if (verbosity >= 3)
    {
      char fmt[UINT_FMT] ;
      char fmtr[UINT_FMT] ;
      fmt[uint_fmt(fmt, i+1)] = 0 ;
      fmtr[uint_fmt(fmtr, roundtrips)] = 0 ;
      strerr_warni4x("NTP round-trip ", fmt, "/", fmtr) ;
    }
    if (!ntp_exchange(sock, &ipremote, portremote, stamps, &deadline))
    {
      if (verbosity >= 2)
      {
        char fmt[UINT_FMT] ;
        char fmtr[UINT_FMT] ;
        fmt[uint_fmt(fmt, i+1)] = 0 ;
        fmtr[uint_fmt(fmtr, roundtrips)] = 0 ;
        strerr_warni5sys("NTP round-trip ", fmt, "/", fmtr, " failed") ;
      }
    }
    else
    {
      tain_t cur, min, max ;
      if (verbosity >= 3)
      {
        unsigned int j = 0 ;
        for (; j < 4 ; j++)
        {
          uint64 ntp ;
          localtmn_t l ;
          char fmt[UINT_FMT] ;
          char fmtntp[UINT64_XFMT] ;
          char fmttaia[TAIN_FMT] ;
          char fmtlocal[LOCALTMN_FMT] ;
          ntp_from_tain(&ntp, &stamps[j]) ;
          localtmn_from_tain(&l, &stamps[j], 1) ;
          fmt[uint_fmt(fmt, j)] = 0 ;
          fmttaia[tain_fmt(fmttaia, &stamps[j])] = 0 ;
          fmtntp[uint64_xfmt(fmtntp, ntp)] = 0 ;
          fmtlocal[localtmn_fmt(fmtlocal, &l)] = 0 ;
          strerr_warni6x("stamp[", fmt, "] : taia: ", fmttaia, ", ntp: ", fmtntp) ;
          strerr_warni2x("localdate: ", fmtlocal) ;
        }
      }
      tain_add(&cur, &stamps[1], &deltaoffset) ;
      tain_add(&min, &stamps[0], &deltamin) ;
      tain_add(&max, &stamps[0], &deltamax) ;
      if (tain_less(&cur, &max) && !tain_less(&cur, &min))
        tain_sub(&deltamax, &cur, &stamps[0]) ;
      tain_add(&cur, &stamps[2], &deltaoffset) ;
      tain_add(&min, &stamps[3], &deltamin) ;
      tain_add(&max, &stamps[3], &deltamax) ;
      if (tain_less(&cur, &max) && !tain_less(&cur, &min))
        tain_sub(&deltamin, &cur, &stamps[3]) ;
    }

    tain_add_g(&deadline, &throttletto) ;
    if (tain_less(&globaldeadline, &deadline)) deadline = globaldeadline ;
    deepsleepuntil_g(&deadline) ;
    if (!tain_future(&globaldeadline))
    {
      if (verbosity)
      {
        errno = ETIMEDOUT ;
        strerr_diefu1sys(1, "complete series of SNTP exchanges") ;
      }
      else return 1 ;
    }
  }

  {
    char adj[TAIN_PACK] ;
    tain_t delta ;
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
