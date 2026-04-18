/* ISC license. */

#include <stdint.h>
#include <signal.h>

#include <skalibs/uint64.h>
#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/envexec.h>
#include <skalibs/tai.h>
#include <skalibs/sig.h>
#include <skalibs/djbunix.h>

#include <s6-networking/config.h>

#define USAGE "s6-tlsc-io [ -v verbosity ] [ -d notif ] [ -S | -s ] [ -J | -j ] [ -Y | -y ] [ -K timeout ] [ -k servername ] fdr fdw"
#define dieusage() strerr_dieusage(100, USAGE)

enum golb_e
{
  GOLB_CLOSENOTIFY = 0x01,
  GOLB_STRICTCN = 0x02,
  GOLB_CLIENTCERT = 0x10,
  GOLB_NOVERIFY = 0x20,
} ;

enum gola_e
{
  GOLA_VERBOSITY,
  GOLA_KIMEOUT,
  GOLA_SERVERNAME,
  GOLA_NOTIF,
  GOLA_N
} ;

static inline void doit (int *, tain const *tto, uint32_t, uint32_t, unsigned int, char const *, unsigned int) gccattr_noreturn ;

#ifdef S6_NETWORKING_USE_TLS

#include <s6-networking/stls.h>

static inline void doit (int *fds, tain const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, unsigned int notif)
{
  struct tls *ctx = stls_client_init_and_handshake(fds + 2, tto, preoptions, servername) ;
  if (notif)
  {
    if (!stls_send_environment(ctx, notif))
      strerr_diefu1sys(111, "write post-handshake data") ;
    fd_close(notif) ;
  }
  stls_run(ctx, fds, options, verbosity) ;
}

#else
#ifdef S6_NETWORKING_USE_BEARSSL

#include <bearssl.h>

#include <s6-networking/sbearssl.h>

static int handshake_cb (br_ssl_engine_context *ctx, sbearssl_handshake_cbarg *cbarg)
{
  if (cbarg->notif)
  {
    if (!sbearssl_send_environment(ctx, cbarg)) return 0 ;
    fd_close(cbarg->notif) ;
  }
  return 1 ;
}

static inline void doit (int *fds, tain const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, unsigned int notif)
{
  sbearssl_handshake_cbarg cbarg = SBEARSSL_HANDSHAKE_CBARG_ZERO ;
  cbarg.notif = notif ;
  sbearssl_client_init_and_run(fds, tto, preoptions, options, verbosity, servername, &handshake_cb, &cbarg) ;
}

#else

#error No SSL backend configured.

#endif
#endif

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
    { .so = 0, .lo = "verify-cert", .clear = GOLB_NOVERIFY, .set = 0 },
    { .so = 0, .lo = "no-verify-cert", .clear = 0, .set = GOLB_NOVERIFY },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'v', .lo = "verbosity", .i = GOLA_VERBOSITY },
    { .so = 'K', .lo = "handshake-timeout", .i = GOLA_KIMEOUT },
    { .so = 'k', .lo = "servername", .i = GOLA_SERVERNAME },
    { .so = 'd', .lo = "notification-fd", .i = GOLA_NOTIF },
  } ;
  int fds[4] = { 0, 1 } ;
  tain tto = TAIN_INFINITE_RELATIVE ;
  unsigned int verbosity = 1 ;
  unsigned int notif = 0 ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  unsigned int golc ;
  PROG = "s6-tlsc-io" ;

  golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
  argc -= golc ; argv += golc ;
  if (argc < 2) dieusage() ;

  if (wgola[GOLA_VERBOSITY])
    if (!uint0_scan(wgola[GOLA_VERBOSITY], &verbosity))
      strerr_dief2x(100, "verbosity", " must be an unsigned integer") ;
  if (wgola[GOLA_KIMEOUT])
  {
    unsigned int kimeout ;
    if (!uint0_scan(wgola[GOLA_KIMEOUT], &kimeout))
      strerr_dief2x(100, "handshake-timeout", " must be an unsigned integer") ;
    if (kimeout) tain_from_millisecs(&tto, kimeout) ;
  }
  if (wgola[GOLA_NOTIF])
    if (!uint0_scan(wgola[GOLA_NOTIF], &notif))
      strerr_dief2x(100, "notification-fd", " must be an unsigned integer") ;

  {
    unsigned int u ;
    if (!uint0_scan(argv[0], &u)) dieusage() ;
    fds[2] = u ;
    if (!uint0_scan(argv[1], &u)) dieusage() ;
    fds[3] = u ;
  }

  if (!sig_ignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  tain_now_set_stopwatch_g() ;
  doit(fds, &tto, wgolb >> 4, wgolb & 0xf, verbosity, wgola[GOLA_SERVERNAME], notif) ;
}
