/* ISC license. */

#include <stdint.h>

#include <bearssl.h>

#include <s6-networking/sbearssl.h>
#include "sbearssl-internal.h"

uint16_t sbearssl_suite_bits (br_ssl_session_parameters const *params)
{
  for (size_t i = 0 ; i < sbearssl_suite_list_len ; i++)
    if (sbearssl_suite_list[i].id == params->cipher_suite)
      return sbearssl_suite_list[i].bits ;
  return 0 ;
}
