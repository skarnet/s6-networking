/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/bytestr.h>
#include <skalibs/error.h>
#include <s6-networking/ident.h>

static size_t skipspace (char const *s)
{
  size_t n = 0 ;
  while ((s[n] == ' ') || (s[n] == '\t')) n++ ;
  return n ;
}

ssize_t s6net_ident_reply_parse (char const *s, uint16_t rp, uint16_t lp)
{
  size_t n = 0 ;
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  {
    size_t i ;
    uint16_t u ;
    i = uint16_scan(s+n, &u) ; if (!i) goto err ; n += i ;
    if (u != rp) goto err ;
    n += skipspace(s+n) ; if (!s[n]) goto err ;
    if (s[n++] != ',') goto err ;
    n += skipspace(s+n) ; if (!s[n]) goto err ;
    i = uint16_scan(s+n, &u) ; if (!i) goto err ; n += i ;
    if (u != lp) goto err ;
  }
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  if (s[n++] != ':') goto err ;
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  if (!strncmp(s+n, "ERROR", 5)) goto ERROR ;
  if (!strncmp(s+n, "USERID", 6)) goto USERID ;
 err:
  return (errno = EPROTO, -1) ;

 ERROR:
  n += 5 ;
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  if (s[n++] != ':') goto err ;
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  if (!strncmp(s+n, "INVALID-PORT", 12)) return (errno = EINVAL, 0) ;
  if (!strncmp(s+n, "NO-USER", 7)) return (errno = ESRCH, 0) ;
  if (!strncmp(s+n, "HIDDEN-USER", 11)) return (errno = EPERM, 0) ;
  if (!strncmp(s+n, "UNKNOWN-ERROR", 13)) return (errno = EIO, 0) ;
  if (s[n] == 'X') return (errno = EEXIST, 0) ;
  goto err ;

 USERID:
  n += 6 ;
  n += skipspace(s+n) ; if (!s[n]) goto err ;
  if (s[n++] != ':') goto err ;
  n += str_chr(s+n, ':') ; if (!s[n]) goto err ;
  n++ ; if ((s[n] == ' ') || (s[n] == '\t')) n++ ;
  return n ;
}
