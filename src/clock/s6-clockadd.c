/* ISC license. */

#include <skalibs/sgetopt.h>
#include <skalibs/types.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>

#define USAGE "s6-clockadd [ -f ] [ -e errmax ]"
#define dieusage() strerr_dieusage(100, USAGE)

int main (int argc, char const *const *argv)
{
  tain_t now, adj ;
  unsigned int emax = 2000 ;
  int flagforce = 0 ;
  PROG = "s6-clockadd" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "fe:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'f' : flagforce = 1 ; break ;
        case 'e' : if (!uint0_scan(l.arg, &emax)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  {
    char buf[TAIN_PACK] ;
    if (allread(0, buf, TAIN_PACK) < TAIN_PACK)
      strerr_diefu1sys(111, "read 16 bytes from stdin") ;
    tain_unpack(buf, &adj) ;
  }
  tain_from_millisecs(&now, emax) ;
  if (tain_less(&now, &adj))
  {
    tain_t tmp = TAIN_ZERO ;
    tain_sub(&tmp, &tmp, &adj) ;
    if (tain_less(&now, &tmp))
    {
      char fmt[UINT_FMT] ;
      fmt[uint_fmt(fmt, emax)] = 0 ;
      if (flagforce)
        strerr_warnw3x("time discrepancy bigger than ", fmt, " milliseconds") ;
      else
        strerr_dief3x(1, "time discrepancy bigger than ", fmt, " milliseconds") ;
    }
  }
  if (!sysclock_get(&now)) strerr_diefu1sys(111, "sysclock_get") ;
  tain_add(&now, &now, &adj) ;
  if (!sysclock_set(&now)) strerr_diefu1sys(111, "sysclock_set") ;
  return 0 ;
}
