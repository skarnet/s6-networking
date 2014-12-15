/* ISC license. */

#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/buffer.h>
#include <skalibs/error.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/ip46.h>
#include <skalibs/unix-timed.h>
#include <s6-networking/ident.h>

int s6net_ident_reply_get (char *s, ip46_t const *remoteip, uint16 remoteport, ip46_t const *localip, uint16 localport, tain_t const *deadline, tain_t *stamp)
{
  unsigned int len ;
  int fd ;
  if (ip46_is6(remoteip) != ip46_is6(localip)) return (errno = EAFNOSUPPORT, -1) ;
  fd = socket_tcp46(ip46_is6(remoteip)) ;
  if (fd < 0) return -1 ;
  if (socket_bind46(fd, localip, 0) < 0) goto err ;
  if (socket_deadlineconnstamp46(fd, remoteip, 113, deadline, stamp) <= 0) goto err ;
  {
    char buf[S6NET_IDENT_REPLY_SIZE + 1] ;
    char fmt[UINT16_FMT] ;
    buffer b = BUFFER_INIT(&buffer_write, fd, buf, 256) ;
    unsigned int n = uint16_fmt(fmt, remoteport) ;
    buffer_putnoflush(&b, fmt, n) ;
    buffer_putnoflush(&b, " , ", 3) ;
    n = uint16_fmt(fmt, localport) ;
    buffer_putnoflush(&b, fmt, n) ;
    buffer_putnoflush(&b, "\r\n", 2) ;
    if (!buffer_timed_flush(&b, deadline, stamp)) goto err ;
    buffer_init(&b, &buffer_read, fd, buf, S6NET_IDENT_REPLY_SIZE + 1) ;
    if (sanitize_read(timed_getlnmax(&b, s, S6NET_IDENT_REPLY_SIZE, &len, '\n', deadline, stamp)) <= 0) goto err ;
  }
  fd_close(fd) ;
  if (len < 2) return (errno = EPROTO, -1) ;
  len -= 2 ;
  s[len] = 0 ;
  return (int)len ;

err:
  fd_close(fd) ;
  return -1 ;
}
