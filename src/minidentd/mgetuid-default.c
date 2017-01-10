/* ISC license. */

#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/ip46.h>
#include "mgetuid.h"

uid_t mgetuid (ip46_t const *localaddr, uint16_t localport, ip46_t const *remoteaddr, uint16_t remoteport)
{
  (void)localaddr ;
  (void)localport ;
  (void)remoteaddr ;
  (void)remoteport ;
  return (errno = ENOSYS, -2) ;
}
