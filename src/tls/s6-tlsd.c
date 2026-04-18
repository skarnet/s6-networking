/* ISC license. */

#include <stdint.h>
#include <unistd.h>

#include <skalibs/uint64.h>
#include <skalibs/types.h>
#include <skalibs/prog.h>
#include <skalibs/strerr.h>
#include <skalibs/gol.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsd [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -k snilevel ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

enum golb_e
{
  GOLB_CLOSENOTIFY = 0x0001,
  GOLB_STRICTCN = 0x0002,
  GOLB_CLIENTCERT = 0x0004,
  GOLB_CLIENTCERT_ONLY = 0x0008,
  GOLB_SNI = 0x0010,
  GOLB_SNI_ONLY = 0x0020,
  GOLB_KEEP = 0x100,
} ;

enum gola_e
{
  GOLA_VERBOSITY,
  GOLA_KIMEOUT,
  GOLA_SNILEVEL,
  GOLA_N
} ;

int main (int argc, char const *const *argv)
{
  static gol_bool const rgolb[] =
  {
    { .so = 's', .lo = "no-close-notify", .clear = GOLB_CLOSENOTIFY, .set = 0 },
    { .so = 'S', .lo = "close-notify", .clear = 0, .set = GOLB_CLOSENOTIFY },
    { .so = 'j', .lo = "no-enforce-close-notify", .clear = GOLB_STRICTCN, .set = 0 },
    { .so = 'J', .lo = "enforce-close-notify", .clear = 0, .set = GOLB_STRICTCN },
    { .so = 'Y', .lo = "client-cert", .clear = GOLB_CLIENTCERT_ONLY, .set = GOLB_CLIENTCERT },
    { .so = 'y', .lo = "mandatory-client-cert", .clear = 0, .set = GOLB_CLIENTCERT | GOLB_CLIENTCERT_ONLY },
    { .so = 'z', .lo = "no-keep", .clear = GOLB_KEEP, .set = 0 },
    { .so = 'Z', .lo = "keep", .clear = 0, .set = GOLB_KEEP },
    { .so = 0, .lo = "sni", .clear = GOLB_SNI_ONLY, .set = GOLB_SNI },
    { .so = 0, .lo = "mandatory-sni", .clear = 0, .set = GOLB_SNI | GOLB_SNI_ONLY },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'v', .lo = "verbosity", .i = GOLA_VERBOSITY },
    { .so = 'K', .lo = "handshake-timeout", .i = GOLA_KIMEOUT },
    { .so = 'k', .lo = "sni-level", .i = GOLA_SNILEVEL },
  } ;
  int p[8] = { [6] = 0, [7] = 1 } ;
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  pid_t pid ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  unsigned int golc ;
  PROG = "s6-tlsd" ;

  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (!argc) dieusage() ;

  if (wgola[GOLA_VERBOSITY])
    if (!uint0_scan(wgola[GOLA_VERBOSITY], &verbosity))
      strerr_dief2x(100, "verbosity", " must be an unsigned integer") ;
  if (wgola[GOLA_KIMEOUT])
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &kimeout))
      strerr_dief2x(100, "handshake-timeout", " must be an unsigned integer") ;
  if (wgola[GOLA_SNILEVEL])
  {
    unsigned int snilevel ;
    if (!uint0_scan(wgola[GOLA_SNILEVEL], &snilevel))
      strerr_dief2x(100, "sni-level", " must be an unsigned integer") ;
    wgolb &= ~(GOLB_SNI | GOLB_SNI_ONLY) ;
    wgolb |= (snilevel ? GOLB_SNI : 0) | (snilevel >= 2 ? GOLB_SNI_ONLY : 0) ;
  }

  if (pipe(p) == -1 || pipe(p+2) == -1 || pipe(p+4) == -1)
    strerr_diefu1sys(111, "create pipe") ;
  s6tls_prep_tlsdio(newargv, buf, p, wgolb & 0xff, verbosity, kimeout) ;
  pid = s6tls_io_spawn(newargv, p, 0) ;
  if (!pid) strerr_diefu2sys(111, "spawn ", newargv[0]) ;
  s6tls_sync_and_exec_app(argv, p, pid, wgolb >> 8) ;
}
