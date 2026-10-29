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


void sbearssl_run (br_ssl_engine_context *ctx, int *fd, tain const *tto, uint32_t options, unsigned int verbosity, sbearssl_handshake_cbfunc_ref cb, sbearssl_handshake_cbarg *cbarg)
{
  iopause_fd x[5] = { [4] = { .fd = -1, .events = 0, .revents = 0 } } ;
  unsigned int state = br_ssl_engine_current_state(ctx) ;
  int handshake_done = 0 ;
  int closing = 0 ;
  tain deadline ;
  tain_add_g(&deadline, tto) ;

  if (ndelay_on(fd[0]) == -1
   || ndelay_on(fd[1]) == -1
   || ndelay_on(fd[2]) == -1
   || ndelay_on(fd[3]) == -1)
    strerr_diefu1sys(111, "set fds non-blocking") ;

  while ((fd[0] >= 0 || fd[1] >= 0 || fd[3] >= 0) && !(state & BR_SSL_CLOSED))
  {
    uint8_t y[4] ;
    uint8_t j = 0 ;

   /* Preparation */

    if (fd[0] >= 0 && state & BR_SSL_SENDAPP)
    {
      x[j].fd = fd[0] ;
      x[j].events = IOPAUSE_READ ;
      y[0] = j++ ;
      if (!handshake_done)
      {
        if (!(*cb)(ctx, cbarg))
          strerr_dief1sys(111, "post-handshake callback failed") ;
        handshake_done = 1 ;
        deadline = tain_infinite ;
      }
    }
    else y[0] = 4 ;

    if (fd[1] >= 0)
    {
      x[j].fd = fd[1] ;
      x[j].events = state & BR_SSL_RECVAPP ? IOPAUSE_WRITE : 0 ;
      y[1] = j++ ;
    }
    else y[1] = 4 ;

    if (fd[2] >= 0 && state & BR_SSL_RECVREC)
    {
      x[j].fd = fd[2] ;
      x[j].events = IOPAUSE_READ ;
      y[2] = j++ ;
    }
    else y[2] = 4 ;

    if (fd[3] >= 0)
    {
      x[j].fd = fd[3] ;
      x[j].events = state & BR_SSL_SENDREC ? IOPAUSE_WRITE : 0 ;
      y[3] = j++ ;
    }
    else y[3] = 4 ;

    if (!j || (j == 1 && !x[0].events) || (j == 2 && !x[0].events && !x[1].events)) break ;

   /* Wait for events */

    switch (iopause_g(x, j, &deadline))
    {
      case -1 : strerr_diefu1sys(111, "iopause") ;
      case 0 :
        if (verbosity) strerr_dief1x(98, "handshake timed out") ;
        else _exit(98) ;
    }


   /* Flush to local */

    if (x[y[1]].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      for (;;)
      {
        ssize_t w ;
        unsigned char const *s = br_ssl_engine_recvapp_buf(ctx, &len) ;
        if (!len) break ;
        w = fd_write(fd[1], (char const *)s, len) ;
        if (w == -1)
        {
          if (error_isagain(errno)) break ;
          strerr_diefu1sys(111, "write to local") ;
        }
        br_ssl_engine_recvapp_ack(ctx, w) ;
      }
      if (fd[2] == -1 && !len)
      {
        fd_close(fd[1]) ;
        fd[1] = -1 ;
      }
      state = br_ssl_engine_current_state(ctx) ;
    }
    else if (x[y[1]].revents & IOPAUSE_EXCEPT)
    {
      fd_close(fd[1]) ;
      fd[1] = -1 ;
      if (fd[2] >= 0)
      {
        fd_shutdown(fd[2], 0) ;
        fd_close(fd[2]) ;
        fd[2] = -1 ;
        if (!br_ssl_engine_in_isempty(ctx))
        {
          br_ssl_engine_fail(ctx, BR_ERR_IO) ;
          state = br_ssl_engine_current_state(ctx) ;
        }
      }
    }


   /* Flush to remote */

    if (x[y[3]].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      for (;;)
      {
        ssize_t w ;
        unsigned char const *s = br_ssl_engine_sendrec_buf(ctx, &len) ;
        if (!len) break ;
        w = fd_write(fd[3], (char const *)s, len) ;
        if (w == -1)
        {
          if (error_isagain(errno)) break ;
          strerr_diefu1sys(111, "write to remote") ;
        }
        br_ssl_engine_sendrec_ack(ctx, w) ;
      }
      if (fd[0] == -1 && !len)
      {
        if (options & 1 && !closing)
        {
          br_ssl_engine_close(ctx) ;
          closing = 1 ;
        }
        else
        {
          fd_shutdown(fd[3], 1) ;
          fd_close(fd[3]) ;
          fd[3] = -1 ;
        }
      }
      state = br_ssl_engine_current_state(ctx) ;
    }
    else if (x[y[3]].revents & IOPAUSE_EXCEPT)
    {
      fd_shutdown(fd[3], 1) ;
      fd_close(fd[3]) ;
      fd[3] = -1 ;
      if (fd[0] >= 0)
      {
        fd_close(fd[0]) ;
        fd[0] = -1 ;
      }
    }


   /* Fill from local */

    if (x[y[0]].revents & IOPAUSE_READ)
    {
      for (;;)
      {
        size_t len ;
        ssize_t r ;
        unsigned char *s = br_ssl_engine_sendapp_buf(ctx, &len) ;
        if (!len) break ;
        r = fd_read(fd[0], (char *)s, len) ;
        if (r == -1 && !error_isagain(errno))
          strerr_diefu1sys(111, "read from local") ;
        else if (r <= 0)
        {
          br_ssl_engine_flush(ctx, 0) ;
          if (!r)
          {
            fd_close(fd[0]) ;
            fd[0] = -1 ;
            if (!br_ssl_engine_sendrec_buf(ctx, &len) || !len)
            {
              if (options & 1 && !closing)
              {
                br_ssl_engine_close(ctx) ;
                closing = 1 ;
              }
              else
              {
                fd_shutdown(fd[3], 1) ;
                fd_close(fd[3]) ;
                fd[3] = -1 ;
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

    if (x[y[2]].revents & IOPAUSE_READ)
    {
      for (;;)
      {
        size_t len ;
        ssize_t r ;
        unsigned char *s = br_ssl_engine_recvrec_buf(ctx, &len) ;
        if (!s) break ;
        r = fd_read(fd[2], (char *)s, len) ;
        if (r == -1)
        {
          if (error_isagain(errno)) break ;
          else strerr_diefu1sys(111, "read from remote") ;
        }
        else if (!r)
        {
          if (handshake_done && options & 2)
            strerr_dief1x(98, "remote closed connection without a close_notify") ;
          fd_shutdown(fd[2], 0) ;
          fd_close(fd[2]) ;
          fd[2] = -1 ;
          if (!br_ssl_engine_recvapp_buf(ctx, &len) || !len)
          {
            fd_close(fd[1]) ;
            fd[1] = -1 ;
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
