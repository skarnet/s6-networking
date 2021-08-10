/* ISC license. */

#include <skalibs/allreadwrite.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/djbtime.h>

int main (void)
{
  char buf[TAIN_PACK] ;
  tain now, adj ;
  localtmn l ;
  char fmt[LOCALTMN_FMT] ;
  PROG = "s6-clockview" ;

  if (allread(0, buf, TAIN_PACK) < TAIN_PACK) strerr_diefu1sys(111, "read from stdin") ;
  tain_unpack(buf, &adj) ;
  if (!sysclock_get(&now)) strerr_diefu1sys(111, "sysclock_get") ;
  if (!localtmn_from_sysclock(&l, &now, 1)) strerr_diefu1sys(111, "localtmn_from_sysclock") ;
  if (buffer_puts(buffer_1, "before: ") < 0) goto fail ;
  if (buffer_put(buffer_1, fmt, localtmn_fmt(fmt, &l)) < 0) goto fail ;
  tain_add(&now, &now, &adj) ;
  if (!localtmn_from_sysclock(&l, &now, 1)) strerr_diefu1sys(111, "localtmn_from_sysclock") ;
  if (buffer_puts(buffer_1, "\nafter:  ") < 0) goto fail ;
  if (buffer_put(buffer_1, fmt, localtmn_fmt(fmt, &l)) < 0) goto fail ;
  if (buffer_putflush(buffer_1, "\n", 1) < 0) goto fail ;
  return 0 ;
 fail:
  strerr_diefu1sys(111, "write to stdout") ;
}
