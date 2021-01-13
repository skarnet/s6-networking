/* ISC license. */

#ifndef STLS_INTERNAL_H
#define STLS_INTERNAL_H

#include <tls.h>

#include <skalibs/tai.h>

extern void stls_drop (void) ;
extern void stls_handshake (struct tls *, tain_t const *) ;

#endif
