/* ISC license. */

#ifndef SBEARSSL_INTERNAL_H
#define SBEARSSL_INTERNAL_H

#include <sys/types.h>
#include <stdint.h>

#include <bearssl.h>

#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>

#include <s6-networking/sbearssl.h>

typedef struct sbearssl_strallocerr_s sbearssl_strallocerr, *sbearssl_strallocerr_ref ;
struct sbearssl_strallocerr_s
{
  stralloc *sa ;
  int err ;
} ;

typedef enum sbearssl_suite_prop_e sbearssl_suite_prop ;
enum sbearssl_suite_prop_e
{
 /* key exchange */
  kRSA      = 1<<0,
  ECDHE     = 1<<1,

 /* authentication */
  aRSA      = 1<<2,
  ECDSA     = 1<<3,

 /* encryption */
  TRIPLEDES = 1<<4,
  AES128    = 1<<5,
  AES256    = 1<<6,
  AESGCM    = 1<<7,
  AESCCM    = 1<<8,
  AESCCM8   = 1<<9,
  CHACHA20  = 1<<10,

 /* MAC */
  AEAD      = 1<<11,
  SHA1      = 1<<12,
  SHA256    = 1<<13,
  SHA384    = 1<<14,

 /* minimum TLS version */
  TLS10     = 1<<15,
  TLS12     = 1<<16,

 /* strength */
  HIGH      = 1<<17,
  MEDIUM    = 1<<18,
  LOW       = 1<<19,
} ;

typedef struct sbearssl_suiteinfo_s sbearssl_suiteinfo, *sbearssl_suiteinfo_ref ;
struct sbearssl_suiteinfo_s
{
  char name[32] ;
  uint16_t id ;
  sbearssl_suite_prop prop ;
  uint16_t bits ;
} ;

extern void sbearssl_drop (void) ;
extern void sbearssl_append (void *, void const *, size_t) ;
extern int sbearssl_pem_push (br_pem_decoder_context *, char const *, size_t, sbearssl_pemobject *, genalloc *, sbearssl_strallocerr *, int *) ;

extern sbearssl_suiteinfo const *const sbearssl_suite_list ;
extern size_t const sbearssl_suite_list_len ;

#endif
