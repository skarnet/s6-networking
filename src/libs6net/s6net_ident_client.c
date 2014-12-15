/* ISC license. */

#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/bytestr.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>
#include <s6-networking/ident.h>

int s6net_ident_client (char *s, unsigned int max, ip46_t const *remoteip, uint16 remoteport, ip46_t const *localip, uint16 localport, tain_t const *deadline, tain_t *stamp)
{
  char buf[S6NET_IDENT_REPLY_SIZE] ;
  unsigned int len ;
  register int r = s6net_ident_reply_get(buf, remoteip, remoteport, localip, localport, deadline, stamp) ;
  if (r < 0) return errno == EPIPE ? (errno = EIO, 0) : -1 ; /* the RFC says so */
  len = r ;
  r = s6net_ident_reply_parse(buf, remoteport, localport) ;
  if (r <= 0) return r ;
  if (max + r < len + 1) return (errno = ENAMETOOLONG, -1) ;
  byte_copy(s, len - r + 1, buf + r) ;
  return len - r + 1 ;
}
