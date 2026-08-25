/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <skalibs/gccattributes.h>
#include <skalibs/types.h>
#include <skalibs/envexec.h>
#include <skalibs/buffer.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/cdb.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <skalibs/unix-timed.h>

#include <s6/accessrules.h>

#include <s6-dns/s6dns.h>

#include <s6-networking/config.h>
#include <s6-networking/ident.h>

#ifdef S6_NETWORKING_USE_EXECLINE
#include <execline/config.h>
#endif

#define NAME "s6-tcpserver-access"
#define USAGE NAME " [ -v verbosity ] [ -W | -w ] [ -D | -d ] [ -H ] [ -h ] [ -R | -r ] [ -P | -p ] [ -l localname ] [ -B banner ] [ -t timeout ] [ -i rulesdir | -x rulesfile ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "update environment")
#define X() strerr_dief(101, "internal inconsistency. Please submit a bug-report.")

enum golb_e
{
  GOLB_FATAL = 0x01,
  GOLB_NODELAY = 0x02,
  GOLB_NODNS = 0x04,
  GOLB_HOSTS = 0x08,
  GOLB_IDENT = 0x10,
  GOLB_PARANOID = 0x20,
} ;

enum gola_e
{
  GOLA_VERBOSITY,
  GOLA_LOCALNAME,
  GOLA_BANNER,
  GOLA_TIMEOUT,
  GOLA_RULESDIR,
  GOLA_RULESFILE,
  GOLA_N
} ;

static inline void logit (ip46 const *ip, int h)
{
  char fmtip[IP46_FMT] ;
  fmtip[ip46_fmt(fmtip, ip)] = 0 ;
  if (h) strerr_warni("allow", " ip ", fmtip) ;
  else strerr_warni("deny", " ip ", fmtip) ;
}

static inline void log_accept (ip46 const *ip)
{
  logit(ip, 1) ;
}

static inline void log_deny (ip46 const *ip)
{
  logit(ip, 0) ;
}

int main (int argc, char const *const *argv)
{
  static gol_bool const rgolb[] =
  {
    { .so = 'W', .lo = "no-fatal", .clear = GOLB_FATAL, .set = 0 },
    { .so = 'w', .lo = "fatal", .clear = 0, .set = GOLB_FATAL },
    { .so = 'd', .lo = "delay", .clear = GOLB_NODELAY, .set = 0 },
    { .so = 'D', .lo = "no-delay", .clear = 0, .set = GOLB_NODELAY },
    { .so = 0, .lo = "dns", .clear = GOLB_NODNS, .set = 0 },
    { .so = 'H', .lo = "no-dns", .clear = GOLB_HOSTS | GOLB_PARANOID, .set = GOLB_NODNS },
    { .so = 0, .lo = "no-hosts", .clear = GOLB_HOSTS, .set = 0 },
    { .so = 'h', .lo = "hosts", .clear = 0, .set = GOLB_HOSTS },
    { .so = 'R', .lo = "no-ident", .clear = GOLB_IDENT, .set = 0 },
    { .so = 'r', .lo = "ident", .clear = 0, .set = GOLB_IDENT },
    { .so = 'p', .lo = "no-paranoid", .clear = GOLB_PARANOID, .set = 0 },
    { .so = 'P', .lo = "paranoid", .clear = GOLB_NODNS, .set = GOLB_PARANOID },
  } ;
  static gol_arg const rgola[] =
  {
    { .so = 'v', .lo = "verbosity", .i = GOLA_VERBOSITY },
    { .so = 'l', .lo = "localname", .i = GOLA_LOCALNAME },
    { .so = 'B', .lo = "banner", .i = GOLA_BANNER },
    { .so = 't', .lo = "timeout", .i = GOLA_TIMEOUT },
    { .so = 'i', .lo = "rulesdir", .i = GOLA_RULESDIR },
    { .so = 'x', .lo = "rulesfile", .i = GOLA_RULESFILE },
  } ;
  uint64_t wgolb = 0 ;
  char const *wgola[GOLA_N] = { 0 } ;
  stralloc modifs = STRALLOC_ZERO ;
  tain deadline = TAIN_INFINITE_RELATIVE ;
  char const *proto ;
  cdb c = CDB_ZERO ;
  unsigned int verbosity = 1 ;
  int e = 0 ;
  size_t protolen ;
  s6_accessrules_params_t params = S6_ACCESSRULES_PARAMS_ZERO ;
  s6_accessrules_result_t accepted = S6_ACCESSRULES_ALLOW ;
  uint16_t remoteport, localport ;
  ip46 remoteip, localip ;
  char prog_storage[PROG_pid_len(NAME)] ;
  PROG_pid_fill(prog_storage, NAME) ;
  PROG = prog_storage ;

  {
    unsigned int golc = GOL_main(argc, argv, rgolb, rgola, &wgolb, wgola) ;
    argc -= golc ; argv += golc ;
    if (!argc) dieusage() ;
  }

  if (wgola[GOLA_VERBOSITY])
  {
    if (!uint0_scan(wgola[GOLA_VERBOSITY], &verbosity)) dieusage() ;
  }

  if (wgola[GOLA_TIMEOUT])
  {
    unsigned int timeout = 0 ;
    if (!uint0_scan(wgola[GOLA_TIMEOUT], &timeout)) dieusage() ;
    if (timeout) tain_from_millisecs(&deadline, timeout) ;
  }

  if (!argc) dieusage() ;
  if (!*argv[0]) dieusage() ;

  proto = getenv("PROTO") ;
  if (!proto) strerr_dienotset(100, "PROTO") ;
  protolen = strlen(proto) ;

  {
    char const *x ;
    char tmp[protolen + 11] ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "LOCALIP", 8) ;
    x = getenv(tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!ip46_scan(x, &localip)) strerr_dieinvalid(100, tmp) ;
    memcpy(tmp + protolen + 5, "PORT", 5) ;
    x = getenv(tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!uint160_scan(x, &localport)) strerr_dieinvalid(100, tmp) ;
    memcpy(tmp + protolen, "REMOTEIP", 9) ;
    x = getenv(tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!ip46_scan(x, &remoteip)) strerr_dieinvalid(100, tmp) ;
    memcpy(tmp + protolen + 6, "PORT", 5) ;
    x = getenv(tmp) ;
    if (!x) strerr_dienotset(100, tmp) ;
    if (!uint160_scan(x, &remoteport)) strerr_dieinvalid(100, tmp) ;
  }

  tain_now_set_stopwatch_g() ;
  tain_add_g(&deadline, &deadline) ;

  if (wgolb & GOLB_NODELAY)
  {
    if (socket_tcpnodelay(1) < 0)
      if (verbosity) strerr_warnwu1sys("socket_tcpnodelay") ;
  }

  if (wgola[GOLA_BANNER])
  {
    size_t bannerlen = strlen(wgola[GOLA_BANNER]) ;
    if (buffer_timed_put_g(buffer_1small, wgola[GOLA_BANNER], bannerlen, &deadline) < bannerlen
     || !buffer_timed_flush_g(buffer_1small, &deadline))
      strerr_diefusys(111, "write banner") ;
  }

  if (wgola[GOLA_RULESDIR])
    accepted = s6_accessrules_ip46_fs(&remoteip, wgola[GOLA_RULESDIR], &params) ;
  else if (wgola[GOLA_RULESFILE])
  {
    if (!cdb_init(&c, wgola[GOLA_RULESFILE])) strerr_diefusys(111, "cdb_init ", wgola[GOLA_RULESFILE]) ;
    accepted = s6_accessrules_ip46_cdb(&remoteip, &c, &params) ;
    if (accepted == S6_ACCESSRULES_ALLOW) cdb_free(&c) ;
  }

  switch (accepted)
  {
    case S6_ACCESSRULES_ERROR :
      strerr_diefusys(111, "check ruleset for ", "IP", " in ", wgola[GOLA_RULESDIR] ? wgola[GOLA_RULESDIR] : wgola[GOLA_RULESFILE]) ;
    case S6_ACCESSRULES_ALLOW : break ;
    case S6_ACCESSRULES_NOTFOUND :
      if (!(wgolb & GOLB_NODNS)) break ;
    case S6_ACCESSRULES_DENY : e = 1 ; goto reject ;
    default: X() ;
  }

  {
    char const *x = 0 ;
    char idbuf[S6NET_IDENT_ID_SIZE] ;
    char tmp[protolen + 11] ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "REMOTEINFO", 11) ;
    if (wgolb & GOLB_IDENT)
    {
      ssize_t r = s6net_ident_client_g(idbuf, S6NET_IDENT_ID_SIZE, &remoteip, remoteport, &localip, localport, &deadline) ;
      if (r < 0)
      {
        if (verbosity >= 3) strerr_warnwusys("s6net_ident_client") ;
        if (wgolb & GOLB_FATAL)
        {
          e = errno == ETIMEDOUT ? 99 : 111 ;
          goto reject ;
        }
      }
      else if (!r)
      {
        if (verbosity >= 3) strerr_warnw("ident server replied: ", s6net_ident_error_str(errno)) ;
        if (wgolb & GOLB_FATAL)
        {
          e = 2 ;
          goto reject ;
        }
      }
      else x = idbuf ;
    }
    if (!env_addmodif(&modifs, tmp, x)) dienomem() ;
  }

  if (wgolb & GOLB_NODNS)
  {
    char tmp[protolen + 11] ;
    memcpy(tmp, proto, protolen) ;
    memcpy(tmp + protolen, "LOCALHOST", 10) ;
    if (!env_addmodif(&modifs, tmp, wgola[GOLA_LOCALNAME])) dienomem() ;
    memcpy(tmp + protolen, "REMOTEHOST", 11) ;
    if (!env_addmodif(&modifs, tmp, 0)) dienomem() ;
  }
  else
  {
    stralloc sa = STRALLOC_ZERO ;
    genalloc ga = GENALLOC_ZERO ;
    tain infinite ;
    s6dns_dpag_t data[2] = { S6DNS_DPAG_ZERO, S6DNS_DPAG_ZERO } ;
    s6dns_resolve_t blob[2] ;
    int gotname = 0 ;
    char tcplocalhost[(protolen << 1) + 21] ;
    char *tcpremotehost = tcplocalhost + protolen + 10 ;
    memcpy(tcplocalhost, proto, protolen) ;
    memcpy(tcplocalhost + protolen, "LOCALHOST", 10) ;
    memcpy(tcpremotehost, proto, protolen) ;
    memcpy(tcpremotehost + protolen, "REMOTEHOST", 11) ;
    tain_add_g(&infinite, &tain_infinite_relative) ;
    if (wgola[GOLA_LOCALNAME])
    {
      if (!env_addmodif(&modifs, tcplocalhost, wgola[GOLA_LOCALNAME])) dienomem() ;
      gotname |= 1 ;
    }

    if (!s6dns_init_options(!!(wgolb & GOLB_HOSTS)))
    {
      if (wgolb & GOLB_FATAL)
      {
        e = 111 ;
        if (verbosity >= 2) strerr_warnfusys("init DNS") ;
        goto reject ;
      }
      if (verbosity >= 2) strerr_warnwusys("init DNS") ;
      goto afterdns ;
    }
    if (wgolb & GOLB_HOSTS)
    {
      int r = s6dns_hosts_name(remoteip.ip, &sa, &ga, ip46_is6(&remoteip)) ;
      if (r == -1)
      {
        if (wgolb & GOLB_FATAL)
        {
          e = 111 ;
          if (verbosity >= 2) strerr_warnfusys("look up ", "remote", " ip in hosts database") ;
          goto reject ;
        }
        if (verbosity >= 2) strerr_warnwusys("look up ", "remote", " ip in hosts database") ;
      }
      else if (r)
      {
        if (!env_addmodif(&modifs, tcpremotehost, sa.s + genalloc_s(size_t, &ga)[0])) dienomem() ;
        genalloc_setlen(size_t, &ga, 0) ;
        sa.len = 0 ;  
        gotname |= 2 ;
      }
      if (!(gotname & 1))
      {
        r = s6dns_hosts_name(localip.ip, &sa, &ga, ip46_is6(&localip)) ;
        if (r == -1)
        {
          if (wgolb & GOLB_FATAL)
          {
            e = 111 ;
            if (verbosity >= 2) strerr_warnfusys("look up ", "local", " ip in hosts database") ;
            goto reject ;
          }
          if (verbosity >= 2) strerr_warnwusys("look up ", "local", " ip in hosts database") ;
        }
        else if (r)
        {
          if (!env_addmodif(&modifs, tcplocalhost, sa.s + genalloc_s(size_t, &ga)[0])) dienomem() ;
          genalloc_setlen(size_t, &ga, 0) ;
          sa.len = 0 ;  
          gotname |= 1 ;
        }
      }
    }
    if (!(gotname & 1))
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
    if (!(gotname & 2))
    {
      s6dns_domain_arpafromip46(&blob[1].q, &remoteip) ;
      s6dns_domain_encode(&blob[1].q) ;
      blob[1].qtype = S6DNS_T_PTR ;
      blob[1].deadline = deadline ;
      blob[1].parsefunc = &s6dns_message_parse_answer_domain ;
      blob[1].data = &data[1] ;
      blob[1].options = S6DNS_O_RECURSIVE ;
      data[1].rtype = S6DNS_T_PTR ;
    }

    if (gotname < 3)
    {
      if (!s6dns_resolven_parse_g(blob + (gotname & 1), !(gotname & 1) + !(gotname & 2), &infinite))
      {
        if (wgolb & GOLB_FATAL)
        {
          e = errno == ENOENT ? 1 : 111 ;
          if (verbosity >= 3) strerr_warnfu("resolve IP addresses: ", s6dns_constants_error_str(errno)) ;
          goto reject ;
        }
        if (verbosity >= 3) strerr_warnwu("resolve IP addresses: ", s6dns_constants_error_str(errno)) ;
      }
      else
      {
        if (!(gotname & 1) && !blob[0].status)
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
          gotname |= 1 ;
        }
        if (!(gotname & 2) && !blob[1].status)
        {
          char s[256] ;
          unsigned int len = 0 ;
          if (genalloc_len(s6dns_domain_t, &data[1].ds))
          {
            s6dns_domain_noqualify(genalloc_s(s6dns_domain_t, &data[1].ds)) ;
            len = s6dns_domain_tostring(s, 255, genalloc_s(s6dns_domain_t, &data[1].ds)) ;
          }
          s[len] = 0 ;

          if (wgolb & GOLB_PARANOID)
          {
            int r ;
            data[1].ds.len = 0 ;
            r = ip46_is6(&remoteip) ? s6dns_resolve_aaaa_g(&data[1].ds, s, len, 0, &deadline) : s6dns_resolve_a_g(&data[1].ds, s, len, 0, &deadline) ;
            if (r <= 0)
            {
              if (wgolb & GOLB_FATAL)
              {
                e = errno == ETIMEDOUT ? 99 : errno == ENOENT ? 1 : 111 ;
                if (verbosity >= 3) strerr_warnfu("(paranoidly) resolve ", s, ": ", s6dns_constants_error_str(errno)) ;
                goto reject ;
              }
              if (verbosity >= 3) strerr_warnwu("(paranoidly) resolve ", s, ": ", s6dns_constants_error_str(errno)) ;
            }
            else
            {
              size_t i = 0 ;
              for (; i < data[1].ds.len ; i += ip46_is6(&remoteip) ? 16 : 4)
                if (!memcmp(remoteip.ip, data[1].ds.s + i, ip46_is6(&remoteip) ? 16 : 4)) break ;
              if (i >= data[1].ds.len)
              {
                e = 1 ;
                if (verbosity >= 3) strerr_warnf("paranoid IP verification", " rejected available IPs") ;
                goto reject ;
              }
            }
          }

          if (!env_addmodif(&modifs, tcpremotehost, s)) dienomem() ;
          gotname |= 2 ;

          if (accepted == S6_ACCESSRULES_NOTFOUND)
          {
            if (wgola[GOLA_RULESDIR])
              accepted = s6_accessrules_reversedns_fs(s, wgola[GOLA_RULESDIR], &params) ;
            else if (wgola[GOLA_RULESFILE])
            {
              accepted = s6_accessrules_reversedns_cdb(s, &c, &params) ;
              cdb_free(&c) ;
            }
            switch (accepted)
            {
              case S6_ACCESSRULES_ERROR :
                strerr_diefusys(111, "check ruleset for ", "reverse DNS", " in ", wgola[GOLA_RULESDIR] ? wgola[GOLA_RULESDIR] : wgola[GOLA_RULESFILE]) ;
              case S6_ACCESSRULES_ALLOW : break ;
              case S6_ACCESSRULES_NOTFOUND :
              case S6_ACCESSRULES_DENY : e = 1 ; goto reject ;
              default : X() ;
            }
          }
        }
      }
    }

    if (!(gotname & 1))
    {
      if (!env_addmodif(&modifs, tcplocalhost, 0)) dienomem() ;
    }

    if (!(gotname & 2))
    {
      if (wgolb & GOLB_PARANOID)
      {
        if (verbosity >= 3) strerr_warnfu("get a valid remote host name for ", "paranoid IP verification") ;
        e = 1 ;
        goto reject ;
      }
      if (!env_addmodif(&modifs, tcpremotehost, 0)) dienomem() ;
    }
  }

 afterdns:

  if (accepted != S6_ACCESSRULES_ALLOW)
  {
    e = 1 ;
    if (verbosity >= 3) strerr_warnf("inconclusive access control result") ;
    goto reject ;
  }

  if (!stralloc_catb(&params.env, modifs.s, modifs.len)) dienomem() ;
  if (verbosity) log_accept(&remoteip) ;

  if (params.exec.len)
#ifdef S6_NETWORKING_USE_EXECLINE
  {
    char *specialargv[4] = { EXECLINE_EXTBINPREFIX "execlineb", "-c", params.exec.s, 0 } ;
    xmexec_m((char const *const *)specialargv, params.env.s, params.env.len) ;
  }
#else
  strerr_warnw("exec file found but ignored because s6-networking was compiled without execline support!") ;
#endif

  xmexec_m(argv, params.env.s, params.env.len) ;

 reject:
  if (verbosity >= 2) log_deny(&remoteip) ;
  _exit(e) ;
}
