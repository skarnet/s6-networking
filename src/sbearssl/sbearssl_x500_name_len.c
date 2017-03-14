/* ISC license. */

#include <s6-networking/sbearssl.h>

size_t sbearssl_x500_name_len (sbearssl_ta const *sta, size_t n)
{
  size_t total = 0 ;
  while (n--)
  {
    total += sta->dnlen ;
    sta++ ;
  }
  return total ;
}
