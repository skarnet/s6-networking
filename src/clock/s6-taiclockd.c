/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>

#define USAGE "s6-taiclockd [ -i ip ] [ -p port ]"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  int s ;
  ip46_t ip = IP46_ZERO ;
  uint16_t port = 4014 ;
  subgetopt_t l = SUBGETOPT_ZERO ;
  PROG = "s6-taiclockd" ;
  for (;;)
  {
    int opt = subgetopt_r(argc, argv, "i:p:", &l) ;
    if (opt == -1) break ;
    switch (opt)
    {
      case 'i' : if (!ip46_scan(l.arg, &ip)) dieusage() ; break ;
      case 'p' : if (!uint160_scan(l.arg, &port)) dieusage() ; break ;
      default : dieusage() ;
    }
  }
  argc -= l.ind ; argv += l.ind ;
  s = socket_udp46(ip46_is6(&ip)) ;
  if (s < 0) strerr_diefu1sys(111, "socket_udp") ;
  if (ndelay_off(s) < 0) strerr_diefu1sys(111, "ndelay_off") ;
  if (socket_bind46_reuse(s, &ip, port) < 0)
    strerr_diefu1sys(111, "socket_bind_reuse") ;

  for (;;)
  {
    char packet[256] ;
    ssize_t r = socket_recv46(s, packet, 256, &ip, &port) ;
    if ((r >= 20) && !memcmp(packet, "ctai", 4))
    {
      tain_t now ;
      packet[0] = 's' ;
      if (!tain_wallclock_read(&now)) strerr_diefu1sys(111, "tain_wallclock_read") ;
      tain_pack(packet + 4, &now) ;
      if (socket_send46(s, packet, r, &ip, port) < 0)
        strerr_warnwu1sys("socket_send") ;
    }
  }
}
