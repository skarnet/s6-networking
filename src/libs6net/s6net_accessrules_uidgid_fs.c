/* ISC license. */

#include <skalibs/diuint.h>
#include <s6-networking/accessrules.h>

s6net_accessrules_result_t s6net_accessrules_uidgid_fs (unsigned int uid, unsigned int gid, char const *rulesdir, s6net_accessrules_params_t *params)
{
  diuint uidgid = { uid, gid } ;
  return s6net_accessrules_keycheck_uidgid(&uidgid, (void *)rulesdir, params, &s6net_accessrules_backend_fs) ;
}
