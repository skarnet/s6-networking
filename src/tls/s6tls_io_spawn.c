/* ISC license. */

#include <skalibs/posixplz.h>
#include <skalibs/cspawn.h>

#include "s6tls-internal.h"

pid_t s6tls_io_spawn (char const *const *argv, int const *p, int isc)
{
  cspawn_fileaction fa[5] =
  {
    { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[1] } },
    { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[2] } },
    { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[4] } },
    { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { 0, p[0] } } },
    { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { 1, p[3] } } }
  } ;
  return cspawn(argv[0], argv, (char const *const *)environ, 0, fa, isc ? 5 : 3) ;
}
