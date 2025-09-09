/* ISC license. */

#include <sys/uio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include <tls.h>

#include <skalibs/error.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr.h>
#include <skalibs/iopause.h>
#include <skalibs/djbunix.h>

#include <s6-networking/stls.h>


typedef struct stls_buffer_s stls_buffer, *stls_buffer_ref ;
struct stls_buffer_s
{
  buffer b ;
  char buf[STLS_BUFSIZE] ;
  uint8_t flags ;  /* 0x1: flush/fill wants opposite IO; 0x2: want close */
} ;


 /*
    We need access to the state field of struct tls, which is private.
    So we fake enough stuff that we get the correct field offset.
 */

#define TLS_EOF_NO_CLOSE_NOTIFY 1

struct fake_tls_error_s
{
  char *msg ;
  int num ;
  int tls ;
} ;

struct fake_tls_s
{
  void *config ;
  void *keypair ;
  struct fake_tls_error_s error ;
  uint32_t flags ;
  uint32_t state ;
} ;

 /* All because there's no accessor for this in the official libtls API: */

static inline int tls_eof_got_close_notify (struct tls *ctx)
{
  return !(((struct fake_tls_s *)ctx)->state & TLS_EOF_NO_CLOSE_NOTIFY) ;
}

 /* We want tls_read/write to behave l */

static int tls_allwrite (struct tls *ctx, char const *s, size_t len, size_t *w)
{
  while (*w < len)
  {
    ssize_t r = tls_write(ctx, s + *w, len - *w) ;
    switch (r)
    {
      case -1 : strerr_diefu2x(98, "tls_write: ", tls_error(ctx)) ;
      case TLS_WANT_POLLIN : return 1 ;
      case TLS_WANT_POLLOUT : return 0 ;
      default : break ;
    }
    *w += r ;
  }
  return 0 ;
}

static void tls_flush (struct tls *ctx, stls_buffer *b)
{
  struct iovec v[2] ;
  size_t w = 0 ;
  int r ;
  buffer_rpeek(&b[0].b, v) ;
  r = tls_allwrite(ctx, v[0].iov_base, v[0].iov_len, &w) ;
  buffer_rseek(&b[0].b, w) ;
  if (w < v[0].iov_len || !v[1].iov_len) goto out ;
  w = 0 ;
  r = tls_allwrite(ctx, v[1].iov_base, v[1].iov_len, &w) ;
  buffer_rseek(&b[0].b, w) ;
 out:
  if (r) b[1].flags |= 1 ; else b[1].flags &= ~1 ;
}

static int tls_allread (struct tls *ctx, char *s, size_t len, size_t *w)
{
  while (*w < len)
  {
    ssize_t r = tls_read(ctx, s + *w, len - *w) ;
    switch (r)
    {
      case -1 : strerr_diefu2x(98, "tls_read: ", tls_error(ctx)) ;
      case 0 : return -1 ;
      case TLS_WANT_POLLIN : return 0 ;
      case TLS_WANT_POLLOUT : return 1 ;
      default : break ;
    }
    *w += r ;
  }
  return 0 ;
}

static int tls_fill (struct tls *ctx, stls_buffer *b)
{
  struct iovec v[2] ;
  size_t w = 0 ;
  int r ;
  buffer_wpeek(&b[1].b, v) ;
  r = tls_allread(ctx, v[0].iov_base, v[0].iov_len, &w) ;
  buffer_wseek(&b[1].b, w) ;
  if (w < v[0].iov_len || !v[1].iov_len) goto out ;
  w = 0 ;
  r = tls_allread(ctx, v[1].iov_base, v[1].iov_len, &w) ;
  buffer_wseek(&b[1].b, w) ;
 out:
  if (r == 1) b[0].flags |= 1 ; else b[0].flags &= ~1 ;
  return r == -1 ;
}

static int tls_tryclose (struct tls *ctx, stls_buffer *b)
{
  switch (tls_close(ctx))
  {
    case 0 : b[0].flags &= ~2 ; return 1 ;
    case TLS_WANT_POLLIN : b[1].flags |= 1 ; break ;
    case TLS_WANT_POLLOUT : b[0].flags |= 2 ; break ;
    default : strerr_diefu2x(98, "tls_close: ", tls_error(ctx)) ;
  }
  return 0 ;
}

 /* The engine. */

void stls_run (struct tls *ctx, int const *fds, uint32_t options, unsigned int verbosity)
{
  stls_buffer b[2] =
  {
    { .b = BUFFER_INIT(&buffer_read, fds[0], b[0].buf, STLS_BUFSIZE), .flags = 0 },
    { .b = BUFFER_INIT(&buffer_write, fds[1], b[1].buf, STLS_BUFSIZE), .flags = 0 },
  } ;
  iopause_fd x[4] = { { .fd = fds[0] }, { .fd = fds[1] }, { .fd = fds[2] }, { .fd = fds[3] } } ;

  if (ndelay_on(x[0].fd) == -1
   || ndelay_on(x[1].fd) == -1
   || ndelay_on(x[2].fd) == -1
   || ndelay_on(x[3].fd) == -1)
    strerr_diefu1sys(111, "set fds non-blocking") ;

  while (x[0].fd >= 0 || x[1].fd >= 0 || x[3].fd >= 0)
  {

    x[0].events = x[0].fd >= 0 && buffer_isreadable(&b[0].b) ? IOPAUSE_READ : 0 ;
    x[1].events = x[1].fd >= 0 && buffer_iswritable(&b[1].b) ? IOPAUSE_WRITE : 0 ;
    x[2].events = x[2].fd >= 0 && (buffer_isreadable(&b[1].b) || (b[1].flags & 1 && buffer_iswritable(&b[0].b))) ? IOPAUSE_READ : 0 ;
    x[3].events = x[3].fd >= 0 && (buffer_iswritable(&b[0].b) || (b[0].flags & 1 && buffer_isreadable(&b[1].b)) || b[0].flags & 2) ? IOPAUSE_WRITE : 0 ;

    if (iopause_g(x, 4, 0) == -1) strerr_diefu1sys(111, "iopause") ;


   /* Flush to local */

    if (x[1].revents)
    {
      if (!buffer_flush(&b[1].b))
      {
        if (!error_isagain(errno)) strerr_diefu1sys(111, "write to local") ;
      }
      else if (x[2].fd == -1)
      {
        fd_close(x[1].fd) ;
        x[1].fd = -1 ;
      }
      else if (x[1].revents & IOPAUSE_EXCEPT)
      {
        errno = EIO ;
        strerr_diefu1sys(111, "iopause for writing on local") ;
      }
    }


   /* Flush to remote: do everything that had TLS_WANT_POLLOUT */

    if (x[3].revents)
    {
      if (buffer_len(&b[0].b)) tls_flush(ctx, b) ;  /* normal write */
      if (b[0].flags & 1 && tls_fill(ctx, b))
        strerr_dief1x(98, "tls_read returned 0 during a renegotiation?") ;
      if (x[0].fd == -1 && buffer_isempty(&b[0].b)
       && (!(options & 1) || tls_tryclose(ctx, b)))
      {
        fd_shutdown(x[3].fd, 1) ;
        fd_close(x[3].fd) ;
        x[3].fd = -1 ;
      }
    }


   /* Fill from local */

    if (x[0].revents)
    {
      ssize_t r = buffer_fill(&b[0].b) ;
      if (r == -1 && !error_isagain(errno))
        strerr_diefu1sys(111, "read from local") ;
      else if (!r)
      {
        fd_close(x[0].fd) ;
        x[0].fd = -1 ;
        if (buffer_isempty(&b[0].b))
        {
          if (!(options & 1) || tls_tryclose(ctx, b))
          {
            fd_shutdown(x[3].fd, 1) ;
            fd_close(x[3].fd) ;
            x[3].fd = -1 ;
          }
        }
      }
    }


   /* Fill from remote: do everything that had TLS_WANT_POLLIN */

    if (x[2].revents)
    {
      if (buffer_isreadable(&b[1].b) && tls_fill(ctx, b))
      {  /* connection closed */
        if (options & 2 && !tls_eof_got_close_notify(ctx))
          strerr_dief1x(98, "remote closed connection without a close_notify") ;
        fd_shutdown(x[2].fd, 0) ;
        fd_close(x[2].fd) ;
        x[2].fd = -1 ;
        if (buffer_isempty(&b[1].b))
        {
          fd_close(x[1].fd) ;
          x[1].fd = -1 ;
        }
        if (x[3].fd >= 0 && options & 1 && tls_tryclose(ctx, b))
        {
          fd_shutdown(x[3].fd, 1) ;
          fd_close(x[3].fd) ;
          x[3].fd = -1 ;
        }
      }
      else if (b[1].flags & 1) tls_flush(ctx, b) ;
    }
  }
  _exit(0) ;
}
