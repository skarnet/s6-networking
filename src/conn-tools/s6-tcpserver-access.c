/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/strerr2.h>
#include <skalibs/sgetopt.h>
#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/unix-timed.h>
#include <execline/config.h>
#include <s6/accessrules.h>
#include <s6-dns/s6dns.h>
#include <s6-networking/ident.h>

#define USAGE "s6-tcpserver-access [ -v verbosity ] [ -W | -w ] [ -D | -d ] [ -H | -h ] [ -R | -r ] [ -P | -p ] [ -l localname ] [ -B banner ] [ -t timeout ] [ -i rulesdir | -x rulesfile ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "update environment")
#define X() strerr_dief1x(101, "internal inconsistency. Please submit a bug-report.")


static void logit (pid_t pid, ip46_t const *ip, int h)
{
  char fmtpid[PID_FMT] ;
  char fmtip[IP46_FMT] ;
  fmtip[ip46_fmt(fmtip, ip)] = 0 ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  if (h) strerr_warni5x("allow", " pid ", fmtpid, " ip ", fmtip) ;
  else strerr_warni5sys("deny", " pid ", fmtpid, " ip ", fmtip) ;
}

static inline void log_accept (pid_t pid, ip46_t const *ip)
{
  logit(pid, ip, 1) ;
}

static inline void log_deny (pid_t pid, ip46_t const *ip)
{
  logit(pid, ip, 0) ;
}


int main (int argc, char const *const *argv, char const *const *envp)
{
  s6_accessrules_params_t params = S6_ACCESSRULES_PARAMS_ZERO ;
  stralloc modifs = STRALLOC_ZERO ;
  tain_t deadline, tto ;
  char const *rulestypestr[3] = { "no", "fs", "cdb" } ;
  char const *rules = 0 ;
  char const *localname = 0 ;
  char const *proto ;
  struct cdb c = CDB_ZERO ;
  int cdbfd = -1 ;
  unsigned int rulestype = 0 ;
  unsigned int verbosity = 1 ;
  size_t protolen ;
  s6_accessrules_result_t accepted ;
  ip46_t remoteip, localip ;
  int flagfatal = 1, flagnodelay = 0, flagdnslookup = 1,
    flagident = 0, flagparanoid = 0, e = 0 ;
  uint16_t remoteport, localport ;
  PROG = "s6-tcpserver-access" ;
  {
    unsigned int timeout = 0 ;
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "WwDdHhRrPpv:l:B:t:i:x:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'W' : flagfatal = 0 ; break ;
        case 'w' : flagfatal = 1 ; break ;
        case 'D' : flagnodelay = 1 ; break ;
        case 'd' : flagnodelay = 0 ; break ;
        case 'H' : flagdnslookup = 0 ; break ;
        case 'h' : flagdnslookup = 1 ; break ;
        case 'R' : flagident = 0 ; break ;
        case 'r' : flagident = 1 ; break ;
        case 'P' : flagparanoid = 0 ; break ;
        case 'p' : flagparanoid = 1 ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'l' : localname = l.arg ; break ;
        case 'B' :
        {
          size_t n = strlen(l.arg) ;
          if (buffer_putnoflush(buffer_1small, l.arg, n) < (ssize_t)n)
            strerr_dief1x(100, "banner too long") ;
          break ;
        }
        case 't' : if (!uint0_scan(l.arg, &timeout)) dieusage() ; break ;
        case 'i' : rules = l.arg ; rulestype = 1 ; break ;
        case 'x' : rules = l.arg ; rulestype = 2 ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (timeout) tain_from_millisecs(&tto, timeout) ;
    else tto = tain_infinite_relative ;
  }
  if (!argc) dieusage() ;
  if (!*argv[0]) dieusage() ;

  proto = env_get2(envp, "PROTO") ;
  if (!proto) strerr_dienotset(100, "PROTO") ;
  protolen = strlen(proto) ;
  {
    char const *x ;
    char tmp[protolen + 11] ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "REMOTEIP", 9) ;
    x = env_get2(envp, tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!ip46_scan(x, &remoteip)) strerr_dieinvalid(100, tmp) ;
    memcpy(tmp + protolen + 6, "PORT", 5) ;
    x = env_get2(envp, tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!uint160_scan(x, &remoteport)) strerr_dieinvalid(100, tmp) ;
  }

  if (flagnodelay)
  {
    if (socket_tcpnodelay(1) < 0)
      if (verbosity) strerr_warnwu1sys("socket_tcpnodelay") ;
  }
  tain_now_set_stopwatch_g() ;
  tain_add_g(&deadline, &tto) ;
  if (!buffer_timed_flush_g(buffer_1small, &deadline))
    strerr_diefu1sys(111, "write banner") ;

  switch (rulestype)
  {
    case 0 :
      if (verbosity >= 2) strerr_warnw1x("invoked without a ruleset!") ;
      accepted = S6_ACCESSRULES_ALLOW ;
      break ;
    case 1 :
      accepted = s6_accessrules_ip46_fs(&remoteip, (void *)rules, &params) ;
      break ;
    case 2 :
      cdbfd = open_readb(rules) ;
      if (cdbfd < 0) strerr_diefu2sys(111, "open_readb ", rules) ;
      if (cdb_init(&c, cdbfd) < 0) strerr_diefu2sys(111, "cdb_init ", rules) ;
      accepted = s6_accessrules_ip46_cdb(&remoteip, &c, &params) ;
      if (accepted == S6_ACCESSRULES_ALLOW)
      {
        cdb_free(&c) ;
        fd_close(cdbfd) ;
      }
      break ;
    default : X() ;
  }
  switch (accepted)
  {
    case S6_ACCESSRULES_ERROR :
      strerr_diefu6sys(111, "check ", rulestypestr[rulestype], " ruleset for ", "IP", " in ", rules) ;
    case S6_ACCESSRULES_ALLOW : break ;
    case S6_ACCESSRULES_DENY :
      if (verbosity >= 2) { errno = EACCES ; log_deny(getpid(), &remoteip) ; }
      return 1 ;
    case S6_ACCESSRULES_NOTFOUND :
      if (flagdnslookup) break ;
      if (verbosity >= 2) { errno = ENOENT ; log_deny(getpid(), &remoteip) ; }
      return 1 ;
    default: X() ;
  }

  {
    char const *x = 0 ;
    char idbuf[S6NET_IDENT_ID_SIZE] ;
    char fmt[IP46_FMT] ;
    char tmp[protolen + 11] ;
    if (socket_local46(0, &localip, &localport) < 0)
      strerr_diefu1sys(111, "socket_local") ;
    fmt[ip46_fmt(fmt, &localip)] = 0 ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "LOCALIP", 8) ;
    if (!env_addmodif(&modifs, tmp, fmt)) dienomem() ;
    fmt[uint16_fmt(fmt, localport)] = 0 ;
    memcpy(tmp + protolen + 5, "PORT", 5) ;
    if (!env_addmodif(&modifs, tmp, fmt)) dienomem() ;
    memcpy(tmp + protolen, "REMOTEINFO", 11) ;
    if (flagident)
    {
      ssize_t r = s6net_ident_client_g(idbuf, S6NET_IDENT_ID_SIZE, &remoteip, remoteport, &localip, localport, &deadline) ;
      if (r < 0)
      {
        if (verbosity >= 3) strerr_warnwu1sys("s6net_ident_client") ;
        if (flagfatal)
        {
          e = errno == ETIMEDOUT ? 99 : 111 ;
          goto reject ;
        }
      }
      else if (!r)
      {
        if (verbosity >= 3) strerr_warnw2x("ident server replied: ", s6net_ident_error_str(errno)) ;
        if (flagfatal)
        {
          e = 2 ;
          goto reject ;
        }
      }
      else x = idbuf ;
    }

    if (!env_addmodif(&modifs, tmp, x)) dienomem() ;
  }

  if (!flagdnslookup)
  {
    char tmp[protolen + 11] ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "LOCALHOST", 10) ;
    if (!env_addmodif(&modifs, tmp, localname)) dienomem() ;
    memcpy(tmp + protolen, "REMOTEHOST", 11) ;
    if (!env_addmodif(&modifs, tmp, 0)) dienomem() ;
  }
  else
  {
    tain_t infinite ;
    s6dns_dpag_t data[2] = { S6DNS_DPAG_ZERO, S6DNS_DPAG_ZERO } ;
    s6dns_resolve_t blob[2] ;
    char remotebuf[256] ;
    unsigned int remotelen = 0 ;
    char tcplocalhost[(protolen << 1) + 21] ;
    char *tcpremotehost = tcplocalhost + protolen + 10 ;
    memcpy(tcplocalhost, proto, protolen) ;
    memcpy(tcplocalhost + protolen, "LOCALHOST", 10) ;
    memcpy(tcpremotehost, proto, protolen) ;
    memcpy(tcpremotehost + protolen, "REMOTEHOST", 11) ;
    tain_add_g(&infinite, &tain_infinite_relative) ;

    if (!s6dns_init())
    {
      if (verbosity >= 2) strerr_warnwu1sys("init DNS") ;
      if (flagfatal)
      {
        e = 111 ;
        goto reject ;
      }
    }
    if (localname)
    {
      if (!env_addmodif(&modifs, tcplocalhost, localname)) dienomem() ;
    }
    else
    {
      s6dns_domain_arpafromip46(&blob[0].q, &localip) ;
      s6dns_domain_encode(&blob[0].q) ;
      blob[0].qtype = S6DNS_T_PTR ;
      blob[0].deadline = deadline ;
      blob[0].parsefunc = &s6dns_message_parse_answer_domain ;
      blob[0].data = &data[0] ;
      blob[0].options = S6DNS_O_RECURSIVE ;
      data[0].rtype = S6DNS_T_PTR ;
    }
    s6dns_domain_arpafromip46(&blob[1].q, &remoteip) ;
    s6dns_domain_encode(&blob[1].q) ;
    blob[1].qtype = S6DNS_T_PTR ;
    blob[1].deadline = deadline ;
    blob[1].parsefunc = &s6dns_message_parse_answer_domain ;
    blob[1].data = &data[1] ;
    blob[1].options = S6DNS_O_RECURSIVE ;
    data[1].rtype = S6DNS_T_PTR ;
    if (!s6dns_resolven_parse_g(blob + !!localname, 1 + !localname, &infinite))
    {
      if (verbosity >= 3) strerr_warnwu2x("resolve IP addresses: ", s6dns_constants_error_str(errno)) ;
      if (flagfatal)
      {
        e = 111 ;
        goto reject ;
      }
    }
    else
    {
      if (!localname)
      {
        if (blob[0].status)
        {
          if (!env_addmodif(&modifs, tcplocalhost, 0)) dienomem() ;
        }
        else
        {
          char s[256] ;
          unsigned int len = 0 ;
          if (genalloc_len(s6dns_domain_t, &data[0].ds))
          {
            s6dns_domain_noqualify(genalloc_s(s6dns_domain_t, &data[0].ds)) ;
            len = s6dns_domain_tostring(s, 255, genalloc_s(s6dns_domain_t, &data[0].ds)) ;
          }
          genalloc_free(s6dns_domain_t, &data[0].ds) ;
          s[len] = 0 ;
          if (!env_addmodif(&modifs, tcplocalhost, s)) dienomem() ;
        }
      }
      if (!blob[1].status)
      {
        if (genalloc_len(s6dns_domain_t, &data[1].ds))
        {
          s6dns_domain_noqualify(genalloc_s(s6dns_domain_t, &data[1].ds)) ;
          remotelen = s6dns_domain_tostring(remotebuf, 255, genalloc_s(s6dns_domain_t, &data[1].ds)) ;
        }
        remotebuf[remotelen] = 0 ;
        if (flagparanoid)
        {
          int r ;
          data[1].ds.len = 0 ;
          r = ip46_is6(&remoteip) ? s6dns_resolve_aaaa_g(&data[1].ds, remotebuf, remotelen, 0, &deadline) : s6dns_resolve_a_g(&data[1].ds, remotebuf, remotelen, 0, &deadline) ;
          if (r <= 0)
          {
            if (verbosity >= 3) strerr_warnwu4x("(paranoidly) resolve ", remotebuf, ": ", s6dns_constants_error_str(errno)) ;
            if (flagfatal)
            {
              e = errno == ETIMEDOUT ? 99 : 111 ;
              goto reject ;
            }
            remotelen = 0 ;
          }
          else
          {
            size_t i = 0 ;
            for (; i < data[1].ds.len ; i += ip46_is6(&remoteip) ? 16 : 4)
              if (!memcmp(remoteip.ip, data[1].ds.s + i, ip46_is6(&remoteip) ? 16 : 4)) break ;
            if (i >= data[1].ds.len) remotelen = 0 ;
          }
        }
        stralloc_free(&data[1].ds) ;
      }
    }
    if (!env_addmodif(&modifs, tcpremotehost, remotelen ? remotebuf : 0)) dienomem() ;
    if (remotelen && (accepted == S6_ACCESSRULES_NOTFOUND))
    {
      switch (rulestype)
      {
        case 1 :
          accepted = s6_accessrules_reversedns_fs(remotebuf, (void *)rules, &params) ;
          break ;
        case 2 : 
          accepted = s6_accessrules_reversedns_cdb(remotebuf, &c, &params) ;
          break ;
        default : X() ;
      }
    }

    if ((rulestype == 2) && (accepted != S6_ACCESSRULES_ALLOW))
    {
      cdb_free(&c) ;
      fd_close(cdbfd) ;
    }

    switch (accepted)
    {
      case S6_ACCESSRULES_ERROR :
        strerr_diefu6sys(111, "check ", rulestypestr[rulestype], " ruleset for ", "reverse DNS", " in ", rules) ;
      case S6_ACCESSRULES_ALLOW : break ;
      case S6_ACCESSRULES_DENY :
        if (verbosity >= 2) { errno = EACCES ; log_deny(getpid(), &remoteip) ; }
        return 1 ;
      case S6_ACCESSRULES_NOTFOUND :
        if (verbosity >= 2) { errno = ENOENT ; log_deny(getpid(), &remoteip) ; }
        return 1 ;
      default : X() ;
    }
  }

  if (!stralloc_catb(&params.env, modifs.s, modifs.len)) dienomem() ;
  stralloc_free(&modifs) ;
  if (verbosity) log_accept(getpid(), &remoteip) ;
  if (params.exec.len)
  {
    char *specialargv[4] = { EXECLINE_EXTBINPREFIX "execlineb", "-c", params.exec.s, 0 } ;
    xpathexec_r((char const *const *)specialargv, envp, env_len(envp), params.env.s, params.env.len) ;
  }

  xpathexec_r(argv, envp, env_len(envp), params.env.s, params.env.len) ;

 reject:
  if (verbosity >= 2)
  {
    char fmtpid[PID_FMT] ;
    char fmtip[IP46_FMT] ;
    fmtip[ip46_fmt(fmtip, &remoteip)] = 0 ;
    fmtpid[pid_fmt(fmtpid, getpid())] = 0 ;
    strerr_dief5x(e, "reject", " pid ", fmtpid, " ip ", fmtip) ;
  }
  else return e ;
}
