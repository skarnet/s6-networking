/* ISC license. */

#include <bearssl.h>
#include <skalibs/bytestr.h>
#include <s6-networking/sbearssl.h>

void sbearssl_x500_from_ta (br_x500_name *names, sbearssl_ta const *sta, size_t n, char *storage, char const *tastorage)
{
  while (n--)
  {
    register size_t len = sta->dnlen ;
    byte_copy(storage, len, tastorage + sta->dn) ;
    sta++ ;
    names->data = (unsigned char *)storage ;
    names->len = len ;
    names++ ;
    storage += len ;
  }
}
