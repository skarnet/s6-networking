/* ISC license. */

#include <stdint.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/buffer.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>
#include <skalibs/unix-timed.h>
#include <s6-networking/ident.h>

#define USAGE "s6-ident-client [ -t timeout ] ra rp la lp"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  tain_t deadline ;
  ip46_t ra, la ;
  uint16_t rp, lp ;
  PROG = "s6-ident-client" ;
  {
    unsigned int t = 0 ;
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "t:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 't' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (t) tain_from_millisecs(&deadline, t) ; else deadline = tain_infinite_relative ;
  }
  if (argc < 4) dieusage() ;

 if (!ip46_scan(argv[0], &ra))
    strerr_dief2x(100, "invalid IP address: ", argv[0]) ;
  if (!uint160_scan(argv[1], &rp))
    strerr_dief2x(100, "invalid port number: ", argv[1]) ;
  if (!ip46_scan(argv[2], &la))
    strerr_dief2x(100, "invalid IP address: ", argv[2]) ;
  if (!uint160_scan(argv[3], &lp))
    strerr_dief2x(100, "invalid port number: ", argv[3]) ;
  if (ip46_is6(&ra) != ip46_is6(&la))
    strerr_dief1x(100, "address family mismatch") ;

  tain_now_set_stopwatch_g() ;
  tain_add_g(&deadline, &deadline) ;

  {
    char buf[BUFFER_OUTSIZE_SMALL] ;
    int r = s6net_ident_client_g(buf, BUFFER_OUTSIZE_SMALL, &ra, rp, &la, lp, &deadline) ;
    if (r < 0) strerr_diefu1sys(errno == ETIMEDOUT ? 99 : 111, "s6net_ident_client") ;
    else if (!r)
    {
      strerr_warnw2x("ident server replied: ", s6net_ident_error_str(errno)) ;
      return 1 ;
    }
    buffer_putnoflush(buffer_1small, buf, r-1) ;
  }
  buffer_putnoflush(buffer_1small, "\n", 1) ;
  if (!buffer_timed_flush_g(buffer_1small, &deadline))
    strerr_diefu1sys(111, "write to stdout") ;
  return 0 ;  
}
