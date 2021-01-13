/* ISC license. */

#include <signal.h>
#include <unistd.h>

#include <tls.h>

#include <skalibs/alarm.h>
#include <skalibs/strerr2.h>

#include "stls-internal.h"

#define diectx(e, ctx, s) strerr_diefu3x(e, (s), ": ", tls_error(ctx))

static void alrm_handler (int sig)
{
  strerr_dief1x(98, "handshake timed out") ;
}

void stls_handshake (struct tls *ctx, tain_t const *tto)
{
  struct sigaction saold ;
  struct sigaction sanew = { .sa_handler = &alrm_handler, .sa_flags = SA_RESTART, .sa_sigaction = 0 } ;
  sigfillset(&sanew.sa_mask) ;
  if (sigaction(SIGALRM, &sanew, &saold) < 0) strerr_diefu1sys(111, "sigaction") ;
  if (!alarm_timeout(tto)) strerr_diefu1sys(111, "set an alarm") ;
  if (tls_handshake(ctx) < 0) diectx(97, ctx, "tls_handshake") ;
  alarm_disable() ;
  sigaction(SIGALRM, &saold, 0) ;
}
