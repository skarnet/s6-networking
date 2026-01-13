/* ISC license. */

#include <skalibs/nonposix.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <skalibs/types.h>
#include <skalibs/envexec.h>
#include <skalibs/fmtscan.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>

#define USAGE "s6-tcpserver-socketbinder [ -d | -D ] [ -b backlog ] [ -M | -m ] [ -B ] ip port prog..."
#define dieusage() strerr_dieusage(100, USAGE)

enum golb_e
{
  GOLB_NOREUSE = 0x01,
  GOLB_UDP = 0x02,
  GOLB_BLOCK = 0x04,
} ;

enum gola_e
{
  GOLA_BACKLOG,
  GOLA_N
} ;

int main (int argc, char const *const *argv)
{
  static gol_bool const rgolb[] =
  {
    { .so = 'd', .lo = "reuse-address", .clear = GOLB_NOREUSE, .set = 0 },
    { .so = 'D', .lo = "no-reuse-address", .clear = 0, .set = GOLB_NOREUSE },
    { .so = 'M', .lo = "tcp", .clear = GOLB_UDP, .set = 0 },
    { .so = 'm', .lo = "udp", .clear = 0, .set = GOLB_UDP },
    { .so = 'B', .lo = "block", .clear = 0, .set = GOLB_BLOCK },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'b', .lo = "backlog", .i = GOLA_BACKLOG },
  } ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  unsigned int backlog = SOMAXCONN ;
  unsigned int golc ;
  ip46 ip ;
  uint16_t port ;
  PROG = "s6-tcpserver-socketbinder" ;

  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (argc < 3) dieusage() ;
  if (wgola[GOLA_BACKLOG])
  {
    if (!uint0_scan(wgola[GOLA_BACKLOG], &backlog))
      strerr_dief1x(100, "backlog must be an unsigned integer") ;
  }
  if (!ip46_scan(argv[0], &ip) || !uint160_scan(argv[1], &port)) dieusage() ;
  close(0) ;
  if (wgolb & GOLB_UDP ?
      socket_udp46_internal(ip46_is6(&ip), wgolb & GOLB_BLOCK ? 0 : O_NONBLOCK) :
      socket_tcp46_internal(ip46_is6(&ip), wgolb & GOLB_BLOCK ? 0 : O_NONBLOCK))
    strerr_diefu1sys(111, "create socket") ;
  if ((wgolb & GOLB_NOREUSE ? socket_bind46(0, &ip, port) : socket_bind46_reuse(0, &ip, port)) == -1)
    strerr_diefu5sys(111, "bind to ", argv[0], " port ", argv[1], " ") ;
  if (backlog && socket_listen(0, backlog) == -1)
    strerr_diefu5sys(111, "listen to ", argv[0], " port ", argv[1], " ") ;

  xexec(argv+2) ;
}
