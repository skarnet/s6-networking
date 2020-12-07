/* ISC license. */

#include <sys/uio.h>
#include <errno.h>
#include <unistd.h>

#include <tls.h>

#include <skalibs/error.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr2.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>

#include <s6-networking/stls.h>

typedef struct tlsbuf_s tlsbuf_t, *tlsbuf_t_ref ;
struct tlsbuf_s
{
  buffer b ;
  unsigned char blockedonother : 1 ;
  char buf[STLS_BUFSIZE] ;
} ;

static inline int buffer_tls_flush (struct tls *ctx, tlsbuf_t *b)
{
  struct iovec v[2] ;
  ssize_t r, w ;
  buffer_rpeek(&b[0].b, v) ;
  r = tls_write(ctx, v[0].iov_base, v[0].iov_len) ;
  switch (r)
  {
    case -1 : return -1 ;
    case TLS_WANT_POLLIN :
      if (b[1].blockedonother) strerr_dief1x(101, "TLS deadlock") ;
      b[0].blockedonother = 1 ;
    case TLS_WANT_POLLOUT : return 0 ;
    default : break ;
  }
  w = r ;
  if ((size_t)w == v[0].iov_len && v[1].iov_len)
  {
    r = tls_write(ctx, v[1].iov_base, v[1].iov_len) ;
    switch (r)
    {
      case TLS_WANT_POLLIN :
        if (b[1].blockedonother) strerr_dief1x(101, "TLS deadlock") ;
        b[0].blockedonother = 1 ;
      case -1 :
      case TLS_WANT_POLLOUT :
        buffer_rseek(&b[0].b, w) ;
        return 0 ;
      default : break ;
    }
    w += r ;
  }
  buffer_rseek(&b[0].b, w) ;
  return 1 ;
}

static inline int buffer_tls_fill (struct tls *ctx, tlsbuf_t *b)
{
  struct iovec v[2] ;
  ssize_t r, w ;
  int ok = 1 ;
  buffer_wpeek(&b[1].b, v) ;
  r = tls_read(ctx, v[0].iov_base, v[0].iov_len) ;
  switch (r)
  {
    case 0 : return -2 ;
    case -1 : return -1 ;
    case TLS_WANT_POLLOUT :
      if (b[0].blockedonother) strerr_dief1x(101, "TLS deadlock") ;
      b[1].blockedonother = 1 ;
    case TLS_WANT_POLLIN : return 0 ;
    default : break ;
  }
  w = r ;
  if ((size_t)w == v[0].iov_len && v[1].iov_len)
  {
    r = tls_read(ctx, v[1].iov_base, v[1].iov_len) ;
    switch (r)
    {
      case TLS_WANT_POLLOUT :
        if (b[0].blockedonother) strerr_dief1x(101, "TLS deadlock") ;
        b[1].blockedonother = 1 ;
      case -1 :
      case TLS_WANT_POLLIN :
        buffer_wseek(&b[1].b, w) ;
        return 0 ;
      case 0 : ok = -1 ; errno = EPIPE ;
      default : break ;
    }
    w += r ;
  }
  buffer_wseek(&b[1].b, w) ;
  return ok ;
}

static void send_closenotify (struct tls *ctx, int const *fds)
{
  iopause_fd x = { .fd = fds[3], .events = IOPAUSE_WRITE } ;
  while (tls_close(ctx) == TLS_WANT_POLLOUT)
    iopause_g(&x, 1, 0) ;
}

static void closeit (struct tls *ctx, int *fds, int brutal)
{
  if (brutal) fd_shutdown(fds[3], 1) ;
  else if (fds[2] >= 0) send_closenotify(ctx, fds) ;
  fd_close(fds[3]) ; fds[3] = -1 ;
}

void stls_run (struct tls *ctx, int *fds, uint32_t options, unsigned int verbosity)
{
  tlsbuf_t b[2] = { { .blockedonother = 0 }, { .blockedonother = 0 } } ;
  iopause_fd x[4] ;
  unsigned int xindex[4] ;

  if (ndelay_on(fds[0]) < 0
   || ndelay_on(fds[1]) < 0
   || ndelay_on(fds[2]) < 0
   || ndelay_on(fds[3]) < 0)
    strerr_diefu1sys(111, "set fds non-blocking") ;

  buffer_init(&b[0].b, &buffer_read, fds[0], b[0].buf, STLS_BUFSIZE) ;
  buffer_init(&b[1].b, &buffer_write, fds[1], b[1].buf, STLS_BUFSIZE) ;

  for (;;)
  {
    unsigned int j = 0 ;
    int r ;


   /* poll() preparation */

    if (fds[0] >= 0 && buffer_isreadable(&b[0].b))
    {
      x[j].fd = fds[0] ;
      x[j].events = IOPAUSE_READ ;
      xindex[0] = j++ ;
    }
    else xindex[0] = 4 ;

    if (fds[1] >= 0 && buffer_iswritable(&b[1].b))
    {
      x[j].fd = fds[1] ;
      x[j].events = IOPAUSE_WRITE ;
      xindex[1] = j++ ;
    }
    else xindex[1] = 4 ;

    if (fds[2] >= 0 && !b[1].blockedonother && buffer_isreadable(&b[1].b))
    {
      x[j].fd = fds[2] ;
      x[j].events = IOPAUSE_READ ;
      xindex[2] = j++ ;
    }
    else xindex[2] = 4 ;

    if (fds[3] >= 0 && !b[0].blockedonother && buffer_iswritable(&b[0].b))
    {
      x[j].fd = fds[3] ;
      x[j].events = IOPAUSE_WRITE ;
      xindex[3] = j++ ;
    }
    else xindex[3] = 4 ;

    if (xindex[0] == 4 && xindex[1] == 4 && xindex[3] == 4) break ;


   /* poll() */

    r = iopause_g(x, j, 0) ;
    if (r < 0) strerr_diefu1sys(111, "iopause") ;
    else if (!r) break ;

    while (j--)
      if (x[j].revents & IOPAUSE_EXCEPT)
        x[j].revents |= IOPAUSE_READ | IOPAUSE_WRITE ;



   /* Flush to local */

    if (xindex[1] < 4 && x[xindex[1]].revents & IOPAUSE_WRITE)
    {
      r = buffer_flush(&b[1].b) ;
      if (!r && !error_isagain(errno))
      {
        strerr_warnwu1sys("write to application") ;
        if (fds[2] >= 0)
        {
          if (options & 1) fd_shutdown(fds[2], 0) ;
          fd_close(fds[2]) ; fds[2] = -1 ;
          xindex[2] = 4 ;
        }
        r = 1 ;
      }
      if (r && fds[2] < 0)
      {
        fd_close(fds[1]) ; fds[1] = -1 ;
      }
    }


   /* Flush to remote */

    if (xindex[3] < 4 && x[xindex[3]].revents & IOPAUSE_WRITE)
    {
      r = buffer_tls_flush(ctx, b) ;
      if (r < 0)
      {
        strerr_warnwu2x("write to peer: ", tls_error(ctx)) ;
        fd_close(fds[0]) ; fds[0] = -1 ;
        xindex[0] = 4 ;
      }
      if (r && fds[0] < 0)
        closeit(ctx, fds, options & 1) ;
    }


   /* Fill from local */

    if (xindex[0] < 4 && x[xindex[0]].revents & IOPAUSE_READ)
    {
      r = sanitize_read(buffer_fill(&b[0].b)) ;
      if (r < 0)
      {
        if (errno != EPIPE) strerr_warnwu1sys("read from application") ;
        fd_close(fds[0]) ; fds[0] = -1 ;
        if (buffer_isempty(&b[0].b))
          closeit(ctx, fds, options & 1) ;
      }
    }


   /* Fill from remote */

    if (xindex[2] < 4 && x[xindex[2]].revents & IOPAUSE_READ)
    {
      r = buffer_tls_fill(ctx, b) ;
      if (r < 0)
      {
        if (r == -1) strerr_warnwu2x("read from peer: ", tls_error(ctx)) ;
        if (options & 1) fd_shutdown(fds[2], 0) ;
        /*
           XXX: We need a way to detect when we've received a close_notify,
           because then we need to trigger a write and then shut the engine
           down. This is orthogonal to options&1, it only means that the
           peer sent a close_notify.
           As for now, libtls doesn't offer an API to detect that, so we
           do nothing special - we just wait until our app sends EOF.
        */
        fd_close(fds[2]) ; fds[2] = -1 ;
        if (buffer_isempty(&b[1].b))
        {
          fd_close(fds[1]) ; fds[1] = -1 ;
        }
      }
    }
  }
  _exit(0) ;
}
