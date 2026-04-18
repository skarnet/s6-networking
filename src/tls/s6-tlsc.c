/* ISC license. */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include <skalibs/types.h>
#include <skalibs/envexec.h>
#include <skalibs/djbunix.h>

#include "s6tls-internal.h"

#define USAGE "s6-tlsc [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -k servername ] [ -Z | -z ] [ -6 fdr ] [ -7 fdw ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)

enum golb_e
{
  GOLB_CLOSENOTIFY = 0x01,
  GOLB_STRICTCN = 0x02,
  GOLB_CLIENTCERT = 0x04,
  GOLB_NOVERIFY = 0x08,
  GOLB_KEEP = 0x10,
} ;

enum gola_e
{
  GOLA_VERBOSITY,
  GOLA_KIMEOUT,
  GOLA_SERVERNAME,
  GOLA_RFD,
  GOLA_WFD,
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
    { .so = 'Y', .lo = "no-client-cert", .clear = GOLB_CLIENTCERT, .set = 0 },
    { .so = 'y', .lo = "client-cert", .clear = 0, .set = GOLB_CLIENTCERT },
    { .so = 'z', .lo = "no-keep", .clear = GOLB_KEEP, .set = 0 },
    { .so = 'Z', .lo = "keep", .clear = 0, .set = GOLB_KEEP },
    { .so = 0, .lo = "verify-cert", .clear = GOLB_NOVERIFY, .set = 0 },
    { .so = 0, .lo = "no-verify-cert", .clear = 0, .set = GOLB_NOVERIFY },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'v', .lo = "verbosity", .i = GOLA_VERBOSITY },
    { .so = 'K', .lo = "handshake-timeout", .i = GOLA_KIMEOUT },
    { .so = 'k', .lo = "servername", .i = GOLA_SERVERNAME },
    { .so = '6', .lo = "read-fd", .i = GOLA_RFD },
    { .so = '7', .lo = "write-fd", .i = GOLA_WFD },
  } ;
  unsigned int verbosity = 1 ;
  unsigned int kimeout = 0 ;
  int p[8] = { [6] = 6, [7] = 7 } ;
  pid_t pid ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  unsigned int golc ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;

  PROG = "s6-tlsc" ;
  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (!argc) dieusage() ;

  if (wgola[GOLA_VERBOSITY])
    if (!uint0_scan(wgola[GOLA_VERBOSITY], &verbosity))
      strerr_dief2x(100, "verbosity", " must be an unsigned integer") ;
  if (wgola[GOLA_KIMEOUT])
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &kimeout))
      strerr_dief2x(100, "handshake-timeout", " must be an unsigned integer") ;
  if (wgola[GOLA_RFD])
  {
    unsigned int fd ;
    if (!uint0_scan(wgola[GOLA_RFD], &fd) || fd < 3)
      strerr_dief3x(100, "read-fd", " must be an unsigned integer", " (3 or more)") ;
    p[6] = fd ;
  }
  if (wgola[GOLA_WFD])
  {
    unsigned int fd ;
    if (!uint0_scan(wgola[GOLA_WFD], &fd) || fd < 3)
      strerr_dief3x(100, "write-fd", " must be an unsigned integer", " (3 or more)") ;
    p[7] = fd ;
  }
  if (p[6] == p[7]) strerr_dief1x(100, "read-fd and write-fd must be different") ;

  fd_sanitize() ;
  if (fcntl(p[6], F_GETFD) == -1 || fcntl(p[7], F_GETFD) == -1)
    strerr_diefu1sys(111, "check network fds") ;
  if (pipe(p) == -1 || pipe(p+2) == -1 || pipe(p+4) == -1)
    strerr_diefu1sys(111, "pipe") ;
  s6tls_prep_tlscio(newargv, buf, p, wgolb & 0xf, verbosity, kimeout, wgola[GOLA_SERVERNAME]) ;
  pid = s6tls_io_spawn(newargv, p, 1) ;
  if (!pid) strerr_diefu2sys(111, "spawn ", newargv[0]) ;
  s6tls_sync_and_exec_app(argv, p, pid, wgolb >> 4) ;
}
