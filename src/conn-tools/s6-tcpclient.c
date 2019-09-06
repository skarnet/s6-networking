/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/fmtscan.h>
#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/genalloc.h>
#include <skalibs/tai.h>
#include <skalibs/djbunix.h>
#include <skalibs/skamisc.h>
#include <skalibs/socket.h>
#include <skalibs/ip46.h>
#include <s6-dns/s6dns.h>
#include <s6-networking/ident.h>

#ifdef SKALIBS_IPV6_ENABLED
# define USAGE "s6-tcpclient [ -q | -Q | -v ] [ -4 | -6 ] [ -d | -D ] [ -r | -R ] [ -h | -H ] [ -n | -N ] [ -t timeoutinfo ] [ -l localname ] [ -T timeoutconn ] [ -i localip ] [ -p localport ] host port prog..."
# define TFLAGS_DEFAULT { 0, 0, { 2, 58 }, IP46_ZERO, 0, 1, 0, 0, 1, 0, 1, 1 }
# define OPTSTRING "qQv46dDrRhHnNt:l:T:i:p:"
#else
# define USAGE "s6-tcpclient [ -q | -Q | -v ] [ -d | -D ] [ -r | -R ] [ -h | -H ] [ -n | -N ] [ -t timeoutinfo ] [ -l localname ] [ -T timeoutconn ] [ -i localip ] [ -p localport ] host port prog..."
# define TFLAGS_DEFAULT { 0, 0, { 2, 58 }, IP46_ZERO, 0, 1, 1, 0, 1, 1 }
# define OPTSTRING "qQvdDrRhHnNt:l:T:i:p:"
#endif

#define usage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "allocate")

#define MAXIP 16

typedef struct tflags_s tflags, *tflags_ref ;
struct tflags_s
{
  char const *localname ;
  unsigned int timeout ;
  unsigned int timeoutconn[2] ;
  ip46_t localip ;
  uint16_t localport ;
  unsigned int verbosity : 2 ;
#ifdef SKALIBS_IPV6_ENABLED
  unsigned int ip4 : 1 ;
  unsigned int ip6 : 1 ;
#endif
  unsigned int delay : 1 ;
  unsigned int remoteinfo : 1 ;
  unsigned int remotehost : 1 ;
  unsigned int qualif : 1 ;
} ;

static tain_t deadline ;

int main (int argc, char const *const *argv)
{
  int s ;
  int localip = 0;
  tflags flags = TFLAGS_DEFAULT ;
  uint16_t remoteport ;
  PROG = "s6-tcpclient" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, OPTSTRING, &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'q' : if (flags.verbosity) flags.verbosity-- ; break ;
        case 'Q' : flags.verbosity = 1 ; break ;
        case 'v' : flags.verbosity++ ; break ;
#ifdef SKALIBS_IPV6_ENABLED
        case '4' : flags.ip4 = 1 ; break ;
        case '6' : flags.ip6 = 1 ; break ;
#endif
        case 'd' : flags.delay = 1 ; break ;
        case 'D' : flags.delay = 0 ; break ;
        case 'r' : flags.remoteinfo = 1 ; break ;
        case 'R' : flags.remoteinfo = 0 ; break ;
        case 'h' : flags.remotehost = 1 ; break ;
        case 'H' : flags.remotehost = 0 ; break ;
        case 'n' : flags.qualif = 1 ; break ;
        case 'N' : flags.qualif = 0 ; break ;
        case 't' : if (!uint0_scan(l.arg, &flags.timeout)) usage() ; break ;
        case 'l' : flags.localname = l.arg ; break ;
        case 'T' :
        {
          size_t n = uint_scan(l.arg, &flags.timeoutconn[0]) ;
          if (!n) usage() ;
          if (!l.arg[n])
          {
            flags.timeoutconn[1] = 0 ;
            break ;
          }
          if (l.arg[n] != '+') usage() ;
          if (!uint0_scan(l.arg + n + 1, &flags.timeoutconn[1])) usage() ;
          break ;
        }
        case 'i' : if (!ip46_scan(l.arg, &flags.localip)) usage() ; localip = 1 ; break ;
        case 'p' : if (!uint160_scan(l.arg, &flags.localport)) usage() ; break ;
        default : usage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
  }
  if (argc < 3) usage() ;
#ifdef SKALIBS_IPV6_ENABLED
  if (!flags.ip6) flags.ip4 = 1 ;
#endif
  if (!uint160_scan(argv[1], &remoteport))
    strerr_dief2x(100, "invalid port number: ", argv[1]) ;
  tain_now_set_stopwatch_g() ;
  if (flags.timeout) tain_addsec_g(&deadline, flags.timeout) ;
  else tain_add_g(&deadline, &tain_infinite_relative) ;
  if (!s6dns_init()) strerr_diefu1sys(111, "init DNS") ; 
  {
    ip46_t ip[2][MAXIP] ;
    unsigned int j = 0 ;
    size_t n[2] = { 0, 0 } ;
    if (!**argv || ((**argv == '0') && !argv[0][1]))
    {
#ifdef SKALIBS_IPV6_ENABLED
      ip46_from_ip6(&ip[0][n[0]++], IP6_LOCAL) ; 
#endif
      ip46_from_ip4(&ip[0][n[0]++], IP4_LOCAL) ; 
    }
    else
    {
      if (!flags.remotehost)
      {
#ifdef SKALIBS_IPV6_ENABLED
        if (flags.ip6 && !flags.ip4)
        {
          char ip6[MAXIP << 4] ;
          size_t i = 0 ;
          if (!ip6_scanlist(ip6, MAXIP, argv[0], &n[0])) usage() ;
          for (; i < n[0] ; i++) ip46_from_ip6(&ip[0][i], ip6 + (i << 4)) ;
        }
        else if (!flags.ip6)
        {
          char ip4[MAXIP << 2] ;
          size_t i = 0 ;
          if (!ip4_scanlist(ip4, MAXIP, argv[0], &n[0])) usage() ;
          for (; i < n[0] ; i++) ip46_from_ip4(&ip[0][i], ip4 + (i << 2)) ;
        }
        else
#endif
        if (!ip46_scanlist(ip[0], MAXIP, argv[0], &n[0])) usage() ;
      }
      else
      {
#ifdef SKALIBS_IPV6_ENABLED
        if (flags.ip6 && flags.ip4)
        {
          if (!ip46_scanlist(ip[0], MAXIP, argv[0], &n[0]))
          {
            genalloc ips = STRALLOC_ZERO ;
            size_t i = 0 ;
            if (s6dns_resolve_aaaaa_g(&ips, argv[0], strlen(argv[0]), flags.qualif, &deadline) <= 0)
              strerr_diefu4x(111, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
            n[0] = genalloc_len(ip46_t, &ips) ;
            if (n[0] >= MAXIP) n[0] = MAXIP ;
            for (; i < n[0] ; i++) ip[0][i] = genalloc_s(ip46_t, &ips)[i] ;
            genalloc_free(ip46_t, &ips) ;
          }
        }
        else if (flags.ip6)
        {
          char ip6[MAXIP << 4] ;
          if (ip6_scanlist(ip6, MAXIP, argv[0], &n[0]))
          {
            size_t i = 0 ;
            for (; i < n[0] ; i++) ip46_from_ip6(&ip[0][i], ip6 + (i << 4)) ;
          }
          else
          {
            stralloc ip6s = STRALLOC_ZERO ;
            size_t i = 0 ;
            if (s6dns_resolve_aaaa_g(&ip6s, argv[0], strlen(argv[0]), flags.qualif, &deadline) <= 0)
              strerr_diefu4x(111, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
            n[0] = ip6s.len >> 4 ;
            if (n[0] >= MAXIP) n[0] = MAXIP ;
            for (; i < n[0] ; i++) ip46_from_ip6(&ip[0][i], ip6s.s + (i << 4)) ;
            stralloc_free(&ip6s) ;
          }
        }
        else
#endif
        {
          char ip4[MAXIP << 2] ;
          if (ip4_scanlist(ip4, MAXIP, argv[0], &n[0]))
          {
            size_t i = 0 ;
            for (; i < n[0] ; i++) ip46_from_ip4(&ip[0][i], ip4 + (i << 2)) ;
          }
          else
          {
            stralloc ip4s = STRALLOC_ZERO ;
            size_t i = 0 ;
            if (s6dns_resolve_a_g(&ip4s, argv[0], strlen(argv[0]), flags.qualif, &deadline) <= 0)
              strerr_diefu4x(111, "resolve ", argv[0], ": ", s6dns_constants_error_str(errno)) ;
            n[0] = ip4s.len >> 2 ;
            if (n[0] >= MAXIP) n[0] = MAXIP ;
            for (; i < n[0] ; i++) ip46_from_ip4(&ip[0][i], ip4s.s + (i << 2)) ;
            stralloc_free(&ip4s) ;
          }
        } 
      }
      if (!n[0]) strerr_dief2x(100, "no IP address for ", argv[0]) ;
    }

    if (n[0] == 1)
    {
      flags.timeoutconn[0] += flags.timeoutconn[1] ;
      flags.timeoutconn[1] = 0 ;
    }

    for (; j < 2 ; j++)
    {
      size_t i = 0 ;
      for (; i < n[j] ; i++)
      {
        tain_t localdeadline ;
#ifdef SKALIBS_IPV6_ENABLED
        if(!localip) flags.localip.is6 = ip46_is6(&ip[j][i]);
#endif
        s = socket_tcp46(ip46_is6(&flags.localip));
        if (s < 0) strerr_diefu1sys(111, "create socket") ;
        if (socket_bind46(s, &flags.localip, flags.localport) < 0)
          strerr_diefu1sys(111, "bind socket") ;
        tain_addsec_g(&localdeadline, flags.timeoutconn[j]) ;
        if (tain_less(&deadline, &localdeadline)) localdeadline = deadline ;
        if (socket_deadlineconnstamp46_g(s, &ip[j][i], remoteport, &localdeadline)) goto connected ;
        fd_close(s) ;
        if (!j && flags.timeoutconn[1]) ip[1][n[1]++] = ip[0][i] ;
        else
        {
          char fmtip[IP46_FMT] ;
          char fmtport[UINT16_FMT] ;
          fmtip[ip46_fmt(fmtip, &ip[j][i])] = 0 ;
          fmtport[uint16_fmt(fmtport, remoteport)] = 0 ;
          strerr_warnwu4sys("connect to ", fmtip, " port ", fmtport) ;
        }
      }
    }
    strerr_diefu2x(111, "connect to ", "a suitable IP address") ;
  }

 connected:

  if (ndelay_off(s) == -1)
    strerr_diefu1sys(111, "ndelay_off") ;
  if (!flags.delay) socket_tcpnodelay(s) ;
  if (socket_local46(s, &flags.localip, &flags.localport) == -1)
    strerr_diefu2sys(111, "get local", " address and port") ;

  {
    ip46_t remoteip ;
    char fmtip[IP46_FMT] ;
    char fmtport[UINT16_FMT] ;

    if (socket_remote46(s, &remoteip, &remoteport) == -1)
      strerr_diefu2sys(111, "get remote", " address and port") ;
    fmtip[ip46_fmt(fmtip, &remoteip)] = 0 ;
    fmtport[uint16_fmt(fmtport, remoteport)] = 0 ;
    if (flags.verbosity >= 2)
      strerr_warni4x("connected to ", fmtip, " port ", fmtport) ;
    if (!pathexec_env("PROTO", "TCP")
     || !pathexec_env("TCPREMOTEIP", fmtip)
     || !pathexec_env("TCPREMOTEPORT", fmtport)) dienomem() ;

    fmtip[ip46_fmt(fmtip, &flags.localip)] = 0 ;
    fmtport[uint16_fmt(fmtport, flags.localport)] = 0 ;
    if (!pathexec_env("TCPLOCALIP", fmtip)
     || !pathexec_env("TCPLOCALPORT", fmtport)) dienomem() ;

    if (flags.localname)
    {
      if (!pathexec_env("TCPLOCALHOST", flags.localname)) dienomem() ;
    }

 /* DNS resolution for TCPLOCALHOST and TCPREMOTEHOST */

    if (!flags.localname || flags.remotehost)
    {
      s6dns_resolve_t blob[2] ;
      s6dns_dpag_t data[2] = { S6DNS_DPAG_ZERO, S6DNS_DPAG_ZERO } ;
      if (!flags.localname)
      {
        s6dns_domain_arpafromip46(&blob[0].q, &flags.localip) ;
        s6dns_domain_encode(&blob[0].q) ;
        blob[0].qtype = S6DNS_T_PTR ;
        blob[0].deadline = deadline ;
        blob[0].parsefunc = &s6dns_message_parse_answer_domain ;
        blob[0].data = &data[0] ;
        blob[0].options = S6DNS_O_RECURSIVE ;
        data[0].rtype = S6DNS_T_PTR ;
      }
      if (flags.remotehost)
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
      {
        tain_t infinite = TAIN_INFINITE ;
        if (!s6dns_resolven_parse_g(blob + !!flags.localname, !flags.localname + !!flags.remotehost, &infinite))
          strerr_diefu2x(111, "resolve IP addresses: ", s6dns_constants_error_str(errno)) ;
      }
      if (!flags.localname)
      {
        if (blob[0].status)
        {
          if (!pathexec_env("TCPLOCALHOST", 0)) dienomem() ;
        }
        else
        {
          char s[256] ;
          unsigned int len = 0 ;
          if (genalloc_len(s6dns_domain_t, &data[0].ds))
           len = s6dns_domain_tostring(s, 255, genalloc_s(s6dns_domain_t, &data[0].ds)) ;
          genalloc_free(s6dns_domain_t, &data[0].ds) ;
          s[len] = 0 ;
          if (!pathexec_env("TCPLOCALHOST", s)) dienomem() ;
        }
      }
      if (flags.remotehost)
      {
        if (blob[1].status)
        {
          if (!pathexec_env("TCPREMOTEHOST", 0)) dienomem() ;
        }
        else
        {
          char s[256] ;
          unsigned int len = 0 ;
          if (genalloc_len(s6dns_domain_t, &data[1].ds))
           len = s6dns_domain_tostring(s, 255, genalloc_s(s6dns_domain_t, &data[1].ds)) ;
          genalloc_free(s6dns_domain_t, &data[1].ds) ;
          s[len] = 0 ;
          if (!pathexec_env("TCPREMOTEHOST", s)) dienomem() ;
        }
      }
    }


 /* TCPREMOTEINFO */
 /*
    Yes, I should have made all the network queries in parallel,
    not only the DNS ones, but the IDENT one too. Well, that was
    too much work for an obsolete protocol. Sue me.
 */
    {
      char idbuf[S6NET_IDENT_ID_SIZE] ;
      if (flags.remoteinfo)
      {
        ssize_t r = s6net_ident_client_g(idbuf, S6NET_IDENT_ID_SIZE, &remoteip, remoteport, &flags.localip, flags.localport, &deadline) ;
        if (r <= 0)
        {
          if (flags.verbosity)
          {
            if (r < 0) strerr_warnwu1sys("s6net_ident_client") ;
            else strerr_warnw2x("ident server replied: ", s6net_ident_error_str(errno)) ;
          }
          if (!pathexec_env("TCPREMOTEINFO", "")) dienomem() ;
        }
        else if (!pathexec_env("TCPREMOTEINFO", idbuf)) dienomem() ;
      }
    }
  }

  if (fd_move(6, s) < 0) strerr_diefu2sys(111, "set up fd ", "6") ;
  if (fd_copy(7, 6) < 0) strerr_diefu2sys(111, "set up fd ", "7") ;
  xpathexec(argv+2) ;
}
