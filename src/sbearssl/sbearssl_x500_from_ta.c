/* ISC license. */

#include <string.h>
#include <s6-networking/sbearssl.h>

void sbearssl_x500_from_ta (br_x500_name *names, sbearssl_ta const *sta, size_t n, char *storage, char const *tastorage)
{
  while (n--)
  {
    size_t len = sta->dnlen ;
    memcpy(storage, tastorage + sta->dn, len) ;
    sta++ ;
    names->data = (unsigned char *)storage ;
    names->len = len ;
    names++ ;
    storage += len ;
  }
}
