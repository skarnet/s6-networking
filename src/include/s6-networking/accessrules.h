/* ISC license. */

#ifndef S6NET_ACCESSRULES_H
#define S6NET_ACCESSRULES_H

#include <skalibs/cdb.h>
#include <skalibs/stralloc.h>
#include <skalibs/ip46.h>

typedef struct s6net_accessrules_params_s s6net_accessrules_params_t, *s6net_accessrules_params_t_ref ;
struct s6net_accessrules_params_s
{
  stralloc env ;
  stralloc exec ;
} ;
#define S6NET_ACCESSRULES_PARAMS_ZERO { STRALLOC_ZERO, STRALLOC_ZERO }

typedef enum s6net_accessrules_result_e s6net_accessrules_result_t, *s6net_accessrules_result_t_ref ;
enum s6net_accessrules_result_e
{
  S6NET_ACCESSRULES_ERROR = -1,
  S6NET_ACCESSRULES_DENY = 0,
  S6NET_ACCESSRULES_ALLOW = 1,
  S6NET_ACCESSRULES_NOTFOUND = 2
} ;

typedef s6net_accessrules_result_t s6net_accessrules_backend_func_t (char const *, unsigned int, void *, s6net_accessrules_params_t *) ;
typedef s6net_accessrules_backend_func_t *s6net_accessrules_backend_func_t_ref ;

extern s6net_accessrules_backend_func_t s6net_accessrules_backend_fs ;
extern s6net_accessrules_backend_func_t s6net_accessrules_backend_cdb ;

typedef s6net_accessrules_result_t s6net_accessrules_keycheck_func_t (void const *, void *, s6net_accessrules_params_t *, s6net_accessrules_backend_func_t_ref) ;
typedef s6net_accessrules_keycheck_func_t *s6net_accessrules_keycheck_func_t_ref ;

extern s6net_accessrules_keycheck_func_t s6net_accessrules_keycheck_uidgid ;
extern s6net_accessrules_keycheck_func_t s6net_accessrules_keycheck_ip4 ;
extern s6net_accessrules_keycheck_func_t s6net_accessrules_keycheck_ip6 ;
extern s6net_accessrules_keycheck_func_t s6net_accessrules_keycheck_reversedns ;
#define s6net_accessrules_keycheck_ip46(key, data, params, f) (ip46_is6((ip46_t const *)(key)) ? s6net_accessrules_keycheck_ip6(((ip46_t const *)(key))->ip, data, params, f) : s6net_accessrules_keycheck_ip4(((ip46_t const *)(key))->ip, data, params, f))

extern s6net_accessrules_result_t s6net_accessrules_uidgid_cdb (unsigned int, unsigned int, struct cdb *, s6net_accessrules_params_t *) ;
extern s6net_accessrules_result_t s6net_accessrules_uidgid_fs (unsigned int, unsigned int, char const *, s6net_accessrules_params_t *) ;
#define s6net_accessrules_ip4_cdb(ip4, c, params) s6net_accessrules_keycheck_ip4(ip4, c, (params), &s6net_accessrules_backend_cdb)
#define s6net_accessrules_ip4_fs(ip4, rulesdir, params) s6net_accessrules_keycheck_ip4(ip4, rulesdir, (params), &s6net_accessrules_backend_fs)
#define s6net_accessrules_ip6_cdb(ip6, c, params) s6net_accessrules_keycheck_ip6(ip6, c, (params), &s6net_accessrules_backend_cdb)
#define s6net_accessrules_ip6_fs(ip6, rulesdir, params) s6net_accessrules_keycheck_ip6(ip6, rulesdir, (params), &s6net_accessrules_backend_fs)
#define s6net_accessrules_ip46_cdb(ip, c, params) s6net_accessrules_keycheck_ip46(ip, c, (params), &s6net_accessrules_backend_cdb)
#define s6net_accessrules_ip46_fs(ip, rulesdir, params) s6net_accessrules_keycheck_ip46(ip, rulesdir, (params), &s6net_accessrules_backend_fs)
#define s6net_accessrules_reversedns_cdb(name, c, params) s6net_accessrules_keycheck_reversedns(name, c, (params), &s6net_accessrules_backend_cdb)
#define s6net_accessrules_reversedns_fs(name, c, params) s6net_accessrules_keycheck_reversedns(name, c, (params), &s6net_accessrules_backend_fs)

#endif
