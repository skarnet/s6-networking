/* ISC license. */

#include <sys/types.h>
#include <errno.h>
#include <skalibs/stralloc.h>
#include "sbearssl-internal.h"

void sbearssl_append (void *stuff, void const *src, size_t len)
{
  sbearssl_strallocerr *blah = stuff ;
  blah->err = stralloc_catb(blah->sa, (char const *)src, len) ? 0 : errno ;
}
