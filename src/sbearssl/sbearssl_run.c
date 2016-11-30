/* ISC license. */

#include <skalibs/nonposix.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <bearssl.h>
#include <skalibs/error.h>
#include <skalibs/strerr2.h>
#include <skalibs/sig.h>
#include <skalibs/tai.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>
#include <s6-networking/sbearssl.h>

#ifdef DEBUG
# include <skalibs/buffer.h>
# include <skalibs/strerr2.h>
# include <skalibs/lolstdio.h>
# define PLM(...) (bprintf(buffer_2, "%s: debug: ", PROG), bprintf(buffer_2, __VA_ARGS__), buffer_putflush(buffer_2, "\n", 1))
#else
# define PLM(...)
#endif


int sbearssl_run (br_ssl_engine_context *ctx, int *fds, unsigned int verbosity, uint32_t options, tain_t const *tto)
{
  iopause_fd x[4] ;
  unsigned int xindex[4] ;

  if (ndelay_on(fds[2]) < 0 || ndelay_on(fds[3]) < 0)
    strerr_diefu1sys(111, "set fds non-blocking") ;
  if (sig_ignore(SIGPIPE) < 0)
    strerr_diefu1sys(111, "ignore SIGPIPE") ;

  for (;;)
  {
    tain_t deadline ;
    unsigned int j = 0 ;
    unsigned int state = br_ssl_engine_current_state(ctx) ;
    int r ;

    tain_add_g(&deadline, fds[0] >= 0 && fds[2] >= 0 && state & (BR_SSL_SENDAPP | BR_SSL_RECVREC) ? tto : &tain_infinite_relative) ;

    if (fds[0] >= 0 && state & BR_SSL_SENDAPP)
    {
      x[j].fd = fds[0] ;
      x[j].events = IOPAUSE_READ ;
      xindex[0] = j++ ;
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

    if (!j) break ;
    r = iopause_g(x, j, &deadline) ;
    if (r < 0) strerr_diefu1sys(111, "iopause") ;
    else if (!r)
    {
      fd_close(fds[0]) ; fds[0] = -1 ;
      br_ssl_engine_close(ctx) ;
      continue ;
    }

    while (j--)
      if (x[j].revents & IOPAUSE_EXCEPT)
        x[j].revents |= IOPAUSE_READ | IOPAUSE_WRITE ;


   /* Flush to local */

    if (state & BR_SSL_RECVAPP && x[xindex[1]].events & x[xindex[1]].revents & IOPAUSE_WRITE)
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
        state = br_ssl_engine_current_state(ctx) ;
        if (fds[2] < 0 && w == len)
        {
          fd_close(fds[1]) ; fds[1] = -1 ;
        }
      }
    }


   /* Flush to remote */

    if (state & BR_SSL_SENDREC && x[xindex[3]].events & x[xindex[3]].revents & IOPAUSE_WRITE)
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
        state = br_ssl_engine_current_state(ctx) ;
        if (fds[0] < 0 && w == len)
        {
          if (options & 1) shutdown(fds[3], SHUT_WR) ;
          fd_close(fds[3]) ; fds[3] = -1 ;
        }
      }
    }


   /* Fill from local */

    if (state & BR_SSL_SENDAPP && x[xindex[0]].events & x[xindex[0]].revents & IOPAUSE_READ)
    {
      size_t len ;
      unsigned char *s = br_ssl_engine_sendapp_buf(ctx, &len) ;
      size_t w = allread(fds[0], (char *)s, len) ;
      if (!w)
      {
        if (!error_isagain(errno))
        {
          fd_close(fds[0]) ; fds[0] = -1 ;
          if (fds[2] >= 0) br_ssl_engine_close(ctx) ;
          if (!br_ssl_engine_sendrec_buf(ctx, &len))
          {
            if (options & 1) shutdown(fds[3], SHUT_WR) ;
            fd_close(fds[3]) ; fds[3] = -1 ;
          }
        }
      }
      else
      {
        br_ssl_engine_sendapp_ack(ctx, w) ;
        br_ssl_engine_flush(ctx, 0) ;
        state = br_ssl_engine_current_state(ctx) ;
      }
    }


   /* Fill from remote */

    if (state & BR_SSL_RECVREC && x[xindex[2]].events & x[xindex[2]].revents & IOPAUSE_READ)
    {
      size_t len ;
      unsigned char *s = br_ssl_engine_recvrec_buf(ctx, &len) ;
      size_t w = allread(fds[2], (char *)s, len) ;
      if (!w)
      {
        if (!error_isagain(errno))
        {
          if (options & 1) shutdown(fds[2], SHUT_RD) ;
          fd_close(fds[2]) ; fds[2] = -1 ;
          if (!br_ssl_engine_recvapp_buf(ctx, &len))
          {
            fd_close(fds[1]) ; fds[1] = -1 ;
          }
        }
      }
      else br_ssl_engine_recvrec_ack(ctx, w) ;
    }
  }

  if (fds[1] >= 0) fd_close(fds[1]) ;
  if (fds[0] >= 0) fd_close(fds[0]) ;
  if (fds[3] >= 0) fd_close(fds[3]) ;
  if (fds[2] >= 0) fd_close(fds[2]) ;
  return br_ssl_engine_last_error(ctx) ;
}
