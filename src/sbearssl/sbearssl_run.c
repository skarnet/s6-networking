/* ISC license. */

#include <unistd.h>
#include <errno.h>

#include <bearssl.h>

#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/tai.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

void sbearssl_run (br_ssl_engine_context *ctx, int *fds, tain_t const *tto, uint32_t options, unsigned int verbosity, sbearssl_handshake_cb_t_ref cb, sbearssl_handshake_cb_context_t *cbarg)
{
  iopause_fd x[4] ;
  unsigned int xindex[4] ;
  int markedforflush = 0 ;
  int handshake_done = 0 ;

  if (ndelay_on(fds[0]) < 0
   || ndelay_on(fds[1]) < 0
   || ndelay_on(fds[2]) < 0
   || ndelay_on(fds[3]) < 0)
    strerr_diefu1sys(111, "set fds non-blocking") ;

  for (;;)
  {
    tain_t deadline = TAIN_INFINITE ;
    unsigned int j = 0 ;
    unsigned int state = br_ssl_engine_current_state(ctx) ;
    int r ;

    if (state & BR_SSL_CLOSED)
    {
      r = br_ssl_engine_last_error(ctx) ;
      if (r) strerr_diefu2x(98, "establish or maintain SSL connection to peer: ", sbearssl_error_str(r)) ;
      break ;
    }

    if (fds[0] >= 0 && state & BR_SSL_SENDAPP)
    {
      x[j].fd = fds[0] ;
      x[j].events = IOPAUSE_READ ;
      xindex[0] = j++ ;
      if (!handshake_done)
      {
        if (!(*cb)(ctx, cbarg))
          strerr_diefu1sys(111, "post-handshake callback failed") ;
        handshake_done = 1 ;
      }
    }
    else xindex[0] = 4 ;
    if (fds[1] >= 0 && state & BR_SSL_RECVAPP)
    {
      x[j].fd = fds[1] ;
      x[j].events = IOPAUSE_WRITE ;
      xindex[1] = j++ ;
    }
    else xindex[1] = 4 ;
    if (fds[2] >= 0 && state & BR_SSL_RECVREC)
    {
      x[j].fd = fds[2] ;
      x[j].events = IOPAUSE_READ ;
      xindex[2] = j++ ;
    }
    else xindex[2] = 4 ;
    if (fds[3] >= 0 && state & BR_SSL_SENDREC)
    {
      x[j].fd = fds[3] ;
      x[j].events = IOPAUSE_WRITE ;
      xindex[3] = j++ ;
    }
    else xindex[3] = 4 ;

    if (xindex[0] == 4 && xindex[1] == 4 && xindex[3] == 4)
    {
      if (!j || handshake_done) break ;
      tain_add_g(&deadline, tto) ;
    }

    r = iopause_g(x, j, &deadline) ;
    if (r < 0) strerr_diefu1sys(111, "iopause") ;
    else if (!r)
    {
      if (verbosity) strerr_dief1x(98, "handshake timed out") ;
      else _exit(98) ;
    }

    while (j--)
      if (x[j].revents & IOPAUSE_EXCEPT)
        x[j].revents |= IOPAUSE_READ | IOPAUSE_WRITE ;


   /* Flush to local */

    if (state & BR_SSL_RECVAPP && xindex[1] < 4 && x[xindex[1]].events & x[xindex[1]].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      unsigned char const *s = br_ssl_engine_recvapp_buf(ctx, &len) ;
      size_t w = allwrite(fds[1], (char const *)s, len) ;
      if (!w)
      {
        if (!error_isagain(errno))
          strerr_diefu1sys(111, "write to application") ;
      }
      else
      {
        br_ssl_engine_recvapp_ack(ctx, w) ;
        if (fds[2] < 0 && w == len)
        {
          fd_close(fds[1]) ; fds[1] = -1 ;
        }
        state = br_ssl_engine_current_state(ctx) ;
      }
    }


   /* Flush to remote */

    if (state & BR_SSL_SENDREC && xindex[3] < 4 && x[xindex[3]].events & x[xindex[3]].revents & IOPAUSE_WRITE)
    {
      size_t len ;
      unsigned char const *s = br_ssl_engine_sendrec_buf(ctx, &len) ;
      size_t w = allwrite(fds[3], (char const *)s, len) ;
      if (!w)
      {
        if (!error_isagain(errno))
          strerr_diefu1sys(111, "write to peer") ;
      }
      else
      {
        br_ssl_engine_sendrec_ack(ctx, w) ;
        if (fds[0] < 0 && w == len)
        {
          if (options & 1)
          {
            fd_shutdown(fds[3], 1) ;
            fd_close(fds[3]) ; fds[3] = -1 ;
          }
          else br_ssl_engine_close(ctx) ;
        }
        state = br_ssl_engine_current_state(ctx) ;
      }
    }


   /* Fill from local */

    if (state & BR_SSL_SENDAPP && xindex[0] < 4 && x[xindex[0]].events & IOPAUSE_READ && (markedforflush || x[xindex[0]].revents & IOPAUSE_READ))
    {
      size_t len ;
      unsigned char *s = br_ssl_engine_sendapp_buf(ctx, &len) ;
      size_t w = allread(fds[0], (char *)s, len) ;
      if (!w)
      {
        br_ssl_engine_flush(ctx, 0) ;
        markedforflush = 0 ;
        if (!error_isagain(errno))
        {
          fd_close(fds[0]) ; fds[0] = -1 ;
          if (!br_ssl_engine_sendrec_buf(ctx, &len))
          {
            if (options & 1)
            {
              fd_shutdown(fds[3], 1) ;
              fd_close(fds[3]) ; fds[3] = -1 ;
            }
            else br_ssl_engine_close(ctx) ;
          }
        }
      }
      else
      {
        br_ssl_engine_sendapp_ack(ctx, w) ;
        if (w == len) markedforflush = 1 ;
        else
        {
          br_ssl_engine_flush(ctx, 0) ;
          markedforflush = 0 ;
        }
      }
      state = br_ssl_engine_current_state(ctx) ;
    }


   /* Fill from remote */

    if (state & BR_SSL_RECVREC && xindex[2] < 4 && x[xindex[2]].events & x[xindex[2]].revents & IOPAUSE_READ)
    {
      size_t len ;
      unsigned char *s = br_ssl_engine_recvrec_buf(ctx, &len) ;
      size_t w = allread(fds[2], (char *)s, len) ;
      if (!w)
      {
        if (!error_isagain(errno))
        {
          if (options & 1) fd_shutdown(fds[2], 0) ;
          fd_close(fds[2]) ; fds[2] = -1 ;
          if (fds[1] >= 0 && !br_ssl_engine_recvapp_buf(ctx, &len))
          {
            fd_close(fds[1]) ; fds[1] = -1 ;
          }
        }
      }
      else br_ssl_engine_recvrec_ack(ctx, w) ;
    }
  }
  _exit(0) ;
}
