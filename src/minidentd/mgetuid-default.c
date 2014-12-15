/* ISC license. */

#include <errno.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include "mgetuid.h"

int mgetuid (ip46_t const *localaddr, uint16 localport, ip46_t const *remoteaddr, uint16 remoteport)
{
  (void)localaddr ;
  (void)localport ;
  (void)remoteaddr ;
  (void)remoteport ;
  return (errno = ENOSYS, -2) ;
}
