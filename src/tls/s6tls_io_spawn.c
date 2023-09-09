/* ISC license. */

#include <skalibs/posixplz.h>
#include <skalibs/cspawn.h>

#include "s6tls-internal.h"

pid_t s6tls_io_spawn (char const *const *argv, int const p[4][2])
{
  cspawn_fileaction fa[5] =
  {
    [0] = { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[0][1] } },
    [1] = { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[1][0] } },
    [2] = { .type = CSPAWN_FA_CLOSE, .x = { .fd = p[2][1] } },
    [3] = { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { [0] = 0, [1] = p[3][0] } } },
    [4] = { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { [0] = 1, [1] = p[3][1] } } }
  } ;
  return cspawn(argv[0], argv, (char const *const *)environ, 0, fa, p[3][0] >= 0 ? 5 : 3) ;
}
