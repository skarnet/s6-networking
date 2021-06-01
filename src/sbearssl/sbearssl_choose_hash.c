/* ISC license. */

#include <bearssl.h>

#include "sbearssl-internal.h"

unsigned int sbearssl_choose_hash (unsigned int bf)
{
  static unsigned char const pref[5] =
  {
    br_sha256_ID,
    br_sha384_ID,
    br_sha512_ID,
    br_sha224_ID,
    br_sha1_ID
  } ;
  for (unsigned int i = 0 ; i < 5 ; i++)
    if ((bf >> pref[i]) & 1) return pref[i] ;
  return 0 ;
}
