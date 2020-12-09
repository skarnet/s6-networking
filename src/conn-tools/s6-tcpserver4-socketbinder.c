/* ISC license. */

#include <skalibs/nonposix.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/fmtscan.h>
#include <skalibs/strerr2.h>
#include <skalibs/socket.h>
#include <skalibs/exec.h>

#define USAGE "s6-tcpserver4-socketbinder [ -d | -D ] [ -b backlog ] [ -M | -m ] [ -B ] ip4 port prog..."
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  unsigned int backlog = SOMAXCONN ;
  int flagreuse = 1 ;
  int flagudp = 0 ;
  unsigned int flags = O_NONBLOCK ;
  char ip[4] ;
  uint16_t port ;
  PROG = "s6-tcpserver4-socketbinder" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "DdMmBb:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'D' : flagreuse = 0 ; break ;
        case 'd' : flagreuse = 1 ; break ;
        case 'M' : flagudp = 0 ; break ;
        case 'm' : flagudp = 1 ; break ;
        case 'B' : flags = 0 ; break ;
        case 'b' : if (!uint0_scan(l.arg, &backlog)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (argc < 3) dieusage() ;
  if (!ip4_scan(argv[0], ip) || !uint160_scan(argv[1], &port)) dieusage() ;
  close(0) ;
  if (flagudp ? socket_udp4_internal(flags) : socket_tcp4_internal(flags))
    strerr_diefu1sys(111, "create socket") ;
  if ((flagreuse ? socket_bind4_reuse(0, ip, port) : socket_bind4(0, ip, port)) < 0)
    strerr_diefu5sys(111, "bind to ", argv[0], ":", argv[1], " ") ;
  if (backlog && socket_listen(0, backlog) < 0)
    strerr_diefu5sys(111, "listen to ", argv[0], ":", argv[1], " ") ;

  xexec(argv+2) ;
}
