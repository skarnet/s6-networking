/* ISC license. */

#ifndef IDENT1413_H
#define IDENT1413_H

#include <sys/types.h>
#include <stdint.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>

#define S6NET_IDENT_ID_SIZE 512
#define S6NET_IDENT_REPLY_SIZE 1024

 /* High-level */

extern ssize_t s6net_ident_client (char *, size_t, ip46_t const *, uint16_t, ip46_t const *, uint16_t, tain_t const *, tain_t *) ;
#define s6net_ident_client_g(s, max, ra, rp, la, lp, deadline) s6net_ident_client(s, max, ra, rp, la, lp, (deadline), &STAMP)
extern char const *s6net_ident_error_str (int) ;


 /* Low-level */

extern ssize_t s6net_ident_reply_get (char *, ip46_t const *, uint16_t, ip46_t const *, uint16_t, tain_t const *, tain_t *) ;
#define s6net_ident_reply_get_g(s, ra, rp, la, lp, deadline) s6net_ident_reply_get(s, ra, rp, la, lp, (deadline), &STAMP)
extern ssize_t s6net_ident_reply_parse (char const *, uint16_t, uint16_t) ;

#endif
