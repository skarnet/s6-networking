/* ISC license. */

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <skalibs/uint64.h>
#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/envexec.h>

#include <s6-networking/config.h>
#include "s6tls-internal.h"

#define USAGE "s6-ucspitlsc [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -v verbosity ] [ -K timeout ] [ -Z | -z ] [ -k servername ] [ -6 fdr ] [ -7 fdw ] prog..."
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

static inline void child (int *, uint32_t, unsigned int, unsigned int, char const *, pid_t) gccattr_noreturn ;
static inline void child (int *p, uint32_t options, unsigned int verbosity, unsigned int kimeout, char const *servername, pid_t pid)
{
  ssize_t r ;
  char const *newargv[S6TLS_PREP_IO_ARGC] ;
  char buf[S6TLS_PREP_IO_BUFLEN] ;
  char c ;
  PROG = "s6-ucspitlsc" ;
  close(p[4]) ;
  close(p[2]) ;
  close(p[1]) ;
  if (fd_move(0, p[0]) == -1 || fd_move(1, p[3]) == -1)
    strerr_diefu1sys(111, "move network fds to stdin/stdout") ;
  r = read(p[5], &c, 1) ;
  if (r < 0) strerr_diefu1sys(111, "read from control socket") ;
  if (!r)
  {
    if (verbosity >= 2)
    {
      char fmt[PID_FMT] ;
      fmt[pid_fmt(fmt, pid)] = 0 ;
      strerr_warni4x("pid ", fmt, " declined", " opportunistic TLS") ;
    }
    _exit(0) ;
  }
  switch (c)
  {
    case 'y' :
      close(p[5]) ;
      p[5] = 0 ; /* we know 0 is open so it's a suitable invalid value */
      break ;
    case 'Y' :
      fd_shutdown(p[5], 0) ;
      break ;
    default :
      strerr_dief1x(100, "unrecognized command on control socket") ;
  }
  s6tls_prep_tlscio(newargv, buf, p, options, verbosity, kimeout, servername) ;
  if (verbosity >= 2)
  {
    char fmt[PID_FMT] ;
    fmt[pid_fmt(fmt, pid)] = 0 ;
    strerr_warni4x("pid ", fmt, " accepted", " opportunistic TLS") ;
  }
  xexec(newargv) ;
}

int main (int argc, char const *const *argv, char const *const *envp)
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
    { .so = 'K', .lo = "kimeout", .i = GOLA_KIMEOUT },
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

  PROG = "s6-ucspitlsc (parent)" ;
  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (!argc) dieusage() ;

  if (wgola[GOLA_VERBOSITY])
    if (!uint0_scan(wgola[GOLA_VERBOSITY], &verbosity))
      strerr_dief2x(100, "verbosity", " must be an unsigned integer") ;
  if (wgola[GOLA_KIMEOUT])
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &kimeout))
      strerr_dief2x(100, "kimeout", " must be an unsigned integer") ;
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
  if (pipe(p) == -1 || pipe(p+2) == -1) strerr_diefu1sys(111, "pipe") ;
  if (ipc_pair_b(p+4) == -1) strerr_diefu1sys(111, "ipc_pair") ;
  pid = getpid() ;

  switch (fork())
  {
    case -1 : strerr_diefu1sys(111, "fork") ;
    case 0 : child(p, wgolb & 0xf, verbosity, kimeout, wgola[GOLA_SERVERNAME], pid) ;
    default : break ;
  }
  s6tls_ucspi_exec_app(argv, p, wgolb >> 4) ;
}
