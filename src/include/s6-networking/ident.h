/* ISC license. */

#ifndef IDENT1413_H
#define IDENT1413_H

#include <skalibs/uint16.h>
#include <skalibs/tai.h>
#include <skalibs/ip46.h>

#define S6NET_IDENT_ID_SIZE 512
#define S6NET_IDENT_REPLY_SIZE 1024

 /* High-level */

extern int s6net_ident_client (char *, unsigned int, ip46_t const *, uint16, ip46_t const *, uint16, tain_t const *, tain_t *) ;
#define s6net_ident_client_g(s, max, ra, rp, la, lp, deadline) s6net_ident_client(s, max, ra, rp, la, lp, (deadline), &STAMP)
extern char const *s6net_ident_error_str (int) ;


 /* Low-level */

extern int s6net_ident_reply_get (char *, ip46_t const *, uint16, ip46_t const *, uint16, tain_t const *, tain_t *) ;
#define s6net_ident_reply_get_g(s, ra, rp, la, lp, deadline) s6net_ident_reply_get(s, ra, rp, la, lp, (deadline), &STAMP)
extern int s6net_ident_reply_parse (char const *, uint16, uint16) ;

#endif
