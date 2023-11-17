/* ISC license. */

#include <unistd.h>
#include <errno.h>

#include <bearssl.h>

#include <skalibs/allreadwrite.h>
#include <skalibs/error.h>
#include <skalibs/strerr.h>
#include <skalibs/tai.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"


 /* declared in bearssl's src/inner.h */
extern void br_ssl_engine_fail (br_ssl_engine_context *, int) ;

 /* XXX: breaks encapsulation; see make_ready_in() in bearssl's src/ssl/ssl_engine.c */
static int br_ssl_engine_in_isempty (br_ssl_engine_context *ctx)
{
  return !ctx->iomode || (ctx->iomode == 3 && !ctx->ixa && !ctx->ixb) ;
}


void sbearssl_run (br_ssl_engine_context *ctx, int const *fds, tain const *tto, uint32_t options, unsigned int verbosity, sbearssl_handshake_cbfunc_ref cb, sbearssl_handshake_cbarg *cbarg)
{
  iopause_fd x[4] = { { .fd = fds[0], .revents = 0 }, { .fd = fds[1], .revents = 0 }, { .fd = fds[2] }, { .fd = fds[3] } } ;
  unsigned int state = br_ssl_engine_current_state(ctx) ;
  int handshake_done = 0 ;
  int closing = 0 ;
  tain deadline ;

  if (ndelay_on(x[0].fd) == -1
   || ndelay_on(x[1].fd) == -1
   || ndelay_on(x[2].fd) == -1
   || ndelay_on(x[3].fd) == -1)
    strerr_diefu1sys(111, "set fds non-blocking") ;
  tain_add_g(&deadline, tto) ;

  while ((x[0].fd >= 0 || x[1].fd >= 0 || x[3].fd >= 0) && !(state & BR_SSL_CLOSED))
  {

   /* Preparation */

    if (x[0].fd >= 0 && state & BR_SSL_SENDAPP)
    {
      x[0].events = IOPAUSE_READ ;
      if (!handshake_done)
      {
        if (!(*cb)(ctx, cbarg))
          strerr_dief1sys(111, "post-handshake callback failed") ;
        handshake_done = 1 ;
        deadline = tain_infinite ;
      }
    }
    else x[0].events = IOPAUSE_EXCEPT ;

    x[1].events = x[1].fd >= 0 ? IOPAUSE_EXCEPT | (state & BR_SSL_RECVAPP ? IOPAUSE_WRITE : 0) : 0 ;
    x[2].events = x[2].fd >= 0 && state & BR_SSL_RECVREC ? IOPAUSE_READ : 0 ;
    x[3].events = x[3].fd >= 0 ? IOPAUSE_EXCEPT | (state & BR_SSL_SENDREC ? IOPAUSE_WRITE : 0) : 0 ;


   /* Wait for events */

    switch (iopause_g(handshake_done ? x : x+2, handshake_done ? 4 : 2, &deadline))
    {
      case -1 : strerr_diefu1sys(111, "iopause") ;
      case 0 :
        if (verbosity) strerr_dief1x(98, "handshake timed out") ;
        else _exit(98) ;
    }


   /* Flush to local */

    if (x[1].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      for (;;)
      {
        ssize_t w ;
        unsigned char const *s = br_ssl_engine_recvapp_buf(ctx, &len) ;
        if (!len) break ;
        w = fd_write(x[1].fd, (char const *)s, len) ;
        if (w == -1)
        {
          if (error_isagain(errno)) break ;
          strerr_diefu1sys(111, "write to local") ;
        }
        br_ssl_engine_recvapp_ack(ctx, w) ;
      }
      if (x[2].fd == -1 && !len)
      {
        fd_close(x[1].fd) ;
        x[1].fd = -1 ;
      }
      state = br_ssl_engine_current_state(ctx) ;
    }
    else if (x[1].revents & IOPAUSE_EXCEPT)
    {
      fd_close(x[1].fd) ;
      x[1].fd = -1 ;
      if (x[2].fd >= 0)
      {
        fd_shutdown(x[2].fd, 0) ;
        fd_close(x[2].fd) ;
        x[2].fd = -1 ;
        if (!br_ssl_engine_in_isempty(ctx))
        {
          br_ssl_engine_fail(ctx, BR_ERR_IO) ;
          state = br_ssl_engine_current_state(ctx) ;
        }
      }
    }


   /* Flush to remote */

    if (x[3].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      for (;;)
      {
        ssize_t w ;
        unsigned char const *s = br_ssl_engine_sendrec_buf(ctx, &len) ;
        if (!len) break ;
        w = fd_write(x[3].fd, (char const *)s, len) ;
        if (w == -1)
        {
          if (error_isagain(errno)) break ;
          strerr_diefu1sys(111, "write to remote") ;
        }
        br_ssl_engine_sendrec_ack(ctx, w) ;
      }
      if (x[0].fd == -1 && !len)
      {
        if (options & 1 && !closing)
        {
          br_ssl_engine_close(ctx) ;
          closing = 1 ;
        }
        else
        {
          fd_shutdown(x[3].fd, 1) ;
          fd_close(x[3].fd) ;
          x[3].fd = -1 ;
        }
      }
      state = br_ssl_engine_current_state(ctx) ;
    }
    else if (x[3].revents & IOPAUSE_EXCEPT)
    {
      fd_shutdown(x[3].fd, 1) ;
      fd_close(x[3].fd) ;
      x[3].fd = -1 ;
      if (x[0].fd >= 0)
      {
        fd_close(x[0].fd) ;
        x[0].fd = -1 ;
      }
    }


   /* Fill from local */

    if (x[0].revents & IOPAUSE_READ && state & BR_SSL_SENDAPP)
    {
      for (;;)
      {
        size_t len ;
        ssize_t r ;
        unsigned char *s = br_ssl_engine_sendapp_buf(ctx, &len) ;
        if (!len) break ;
        r = fd_read(x[0].fd, (char *)s, len) ;
        if (r == -1 && !error_isagain(errno))
          strerr_diefu1sys(111, "read from local") ;
        else if (r <= 0)
        {
          br_ssl_engine_flush(ctx, 0) ;
          if (!r)
          {
            fd_close(x[0].fd) ;
            x[0].fd = -1 ;
            if (!br_ssl_engine_sendrec_buf(ctx, &len))
            {
              if (options & 1 && !closing)
              {
                br_ssl_engine_close(ctx) ;
                closing = 1 ;
              }
              else
              {
                fd_shutdown(x[3].fd, 1) ;
                fd_close(x[3].fd) ;
                x[3].fd = -1 ;
              }
            }
          }
          break ;
        }
        br_ssl_engine_sendapp_ack(ctx, r) ;
      }
      state = br_ssl_engine_current_state(ctx) ;
    }


   /* Fill from remote */

    if (x[2].revents & IOPAUSE_READ && state & BR_SSL_RECVREC)
    {
      for (;;)
      {
        size_t len ;
        ssize_t r ;
        unsigned char *s = br_ssl_engine_recvrec_buf(ctx, &len) ;
        if (!s) break ;
        r = fd_read(x[2].fd, (char *)s, len) ;
        if (r == -1)
        {
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "read from remote") ;
        }
        else if (!r)
        {
          if (handshake_done && options & 2)
            strerr_dief1x(98, "remote closed connection without a close_notify") ;
          fd_shutdown(x[2].fd, 0) ;
          fd_close(x[2].fd) ;
          x[2].fd = -1 ;
          if (!br_ssl_engine_recvapp_buf(ctx, &len))
          {
            fd_close(x[1].fd) ;
            x[1].fd = -1 ;
          }
          if (!handshake_done || !br_ssl_engine_in_isempty(ctx))
            br_ssl_engine_fail(ctx, BR_ERR_IO) ;
          break ;
        }
        br_ssl_engine_recvrec_ack(ctx, r) ;
      }
      state = br_ssl_engine_current_state(ctx) ;
    }

  }  /* end of main loop */

  if (state & BR_SSL_CLOSED)
  {
    int r = br_ssl_engine_last_error(ctx) ;
    if (r) strerr_dief4x(98, "the TLS engine closed the connection ", handshake_done ? "after" : "during", " the handshake: ", sbearssl_error_str(r)) ;
  }
  _exit(0) ;
}
