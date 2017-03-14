/* ISC license. */

#include <string.h>
#include <errno.h>
#include <s6-networking/ident.h>

ssize_t s6net_ident_client (char *s, size_t max, ip46_t const *remoteip, uint16_t remoteport, ip46_t const *localip, uint16_t localport, tain_t const *deadline, tain_t *stamp)
{
  char buf[S6NET_IDENT_REPLY_SIZE] ;
  size_t len ;
  ssize_t r = s6net_ident_reply_get(buf, remoteip, remoteport, localip, localport, deadline, stamp) ;
  if (r < 0) return errno == EPIPE ? (errno = EIO, 0) : -1 ; /* the RFC says so */
  len = r ;
  r = s6net_ident_reply_parse(buf, remoteport, localport) ;
  if (r <= 0) return r ;
  if (max + r < len + 1) return (errno = ENAMETOOLONG, -1) ;
  memcpy(s, buf + r, len - r + 1) ;
  return len - r + 1 ;
}
