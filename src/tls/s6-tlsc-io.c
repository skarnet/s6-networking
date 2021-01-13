/* ISC license. */

#include <stdint.h>
#include <signal.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/sig.h>
#include <skalibs/djbunix.h>

#include <s6-networking/config.h>

#define USAGE "s6-tlsc-io [ -v verbosity ] [ -d notif ] [ -S | -s ] [ -Y | -y ] [ -K timeout ] [ -k servername ] fdr fdw"
#define dieusage() strerr_dieusage(100, USAGE)

static inline void doit (int *, tain_t const *tto, uint32_t, uint32_t, unsigned int, char const *, unsigned int) gccattr_noreturn ;

#ifdef S6_NETWORKING_USE_TLS

#include <s6-networking/stls.h>

static inline void doit (int *fds, tain_t const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, unsigned int notif)
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

#include <skalibs/random.h>

#include <s6-networking/sbearssl.h>

static int handshake_cb (br_ssl_engine_context *ctx, sbearssl_handshake_cb_context_t *cbarg)
{
  if (cbarg->notif)
  {
    if (!sbearssl_send_environment(ctx, cbarg->notif)) return 0 ;
    fd_close(cbarg->notif) ;
  }
  return 1 ;
}

static inline void doit (int *fds, tain_t const *tto, uint32_t preoptions, uint32_t options, unsigned int verbosity, char const *servername, unsigned int notif)
{
  if (!random_init()) strerr_diefu1sys(111, "initialize random device") ;
  sbearssl_client_init_and_run(fds, tto, preoptions, options, verbosity, servername, &handshake_cb, notif) ;
}

#else

#error No SSL backend configured.

#endif
#endif

int main (int argc, char const *const *argv, char const *const *envp)
{
  char const *servername = 0 ;
  tain_t tto ;
  int fds[4] = { 0, 1, 0, 1 } ;
  unsigned int verbosity = 1 ;
  unsigned int notif = 0 ;
  uint32_t preoptions = 0 ;
  uint32_t options = 1 ;

  PROG = "s6-tlsc-io" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int t = 0 ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "d:SsYyv:K:k:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'd' : if (!uint0_scan(l.arg, &notif)) dieusage() ; break ;
        case 'S' : options &= ~1 ; break ;
        case 's' : options |= 1 ; break ;
        case 'Y' : preoptions &= ~1 ; break ;
        case 'y' : preoptions |= 1 ; break ;
        case 'K' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        case 'k' : servername = l.arg ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (t) tain_from_millisecs(&tto, t) ; else tto = tain_infinite_relative ;
  }
  if (argc < 2) dieusage() ;
  {
    unsigned int u ;
    if (!uint0_scan(argv[0], &u)) dieusage() ;
    fds[0] = u ;
    if (!uint0_scan(argv[1], &u)) dieusage() ;
    fds[1] = u ;
  }

  if (sig_ignore(SIGPIPE) < 0) strerr_diefu1sys(111, "ignore SIGPIPE") ;
  tain_now_set_stopwatch_g() ;
  doit(fds, &tto, preoptions, options, verbosity, servername, notif) ;
}
