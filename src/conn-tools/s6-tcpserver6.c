/* ISC license. */

#include <skalibs/nonposix.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <signal.h>
#include <skalibs/gccattributes.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/uint16.h>
#include <skalibs/uint.h>
#include <skalibs/gidstuff.h>
#include <skalibs/setgroups.h>
#include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/fmtscan.h>
#include <skalibs/strerr2.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <skalibs/sig.h>
#include <skalibs/selfpipe.h>
#include <skalibs/iopause.h>
#include <skalibs/socket.h>

#define ABSOLUTE_MAXCONN 1000

#define USAGE "s6-tcpserver6 [ -v verbosity ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] [ -b backlog ] [ -G gid,gid,... ] [ -g gid ] [ -u uid ] [ -U ] ip6 port prog..."

typedef struct ipnum_s ipnum_t, *ipnum_t_ref ;
struct ipnum_s
{
  char ip[16] ;
  unsigned int num ;
} ;
#define IPNUM_ZERO { "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0 }

static unsigned int maxconn = 40 ;
static unsigned int localmaxconn = 40 ;
static unsigned int verbosity = 1 ;
static int cont = 1 ;
static ipnum_t_ref pidip = 0 ;
static unsigned int numconn = 0 ;
static ipnum_t_ref ipnum = 0 ;
static unsigned int iplen = 0 ;

static char fmtmaxconn[UINT_FMT+1] = "/" ;
static char fmtlocalmaxconn[UINT_FMT+1] = "/" ;


 /* Utility functions */

static inline void dieusage ()
{
  strerr_dieusage(100, USAGE) ;
}

static inline void X (void)
{
  strerr_dief1x(101, "internal inconsistency. Please submit a bug-report.") ;
}


 /* Lookup primitives */
 
static unsigned int lookup_pid (unsigned int pid)
{
  register unsigned int i = 0 ;
  for (; i < numconn ; i++) if (pid == pidip[i].num) break ;
  return i ;
}

static unsigned int lookup_ip (char const *ip)
{
  register unsigned int i = 0 ;
  for (; i < iplen ; i++) if (!byte_diff(ip, 16, ipnum[i].ip)) break ;
  return i ;
}


 /* Logging */

static void log_start (char const *ip, uint16 port)
{
  char fmtip[IP6_FMT] ;
  char fmtport[UINT16_FMT] ;
  fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  strerr_warni4x("starting - listening on ", fmtip, " port ", fmtport) ;
}

static inline void log_exit (void)
{
  strerr_warni1x("exiting") ;
}

static void log_status (void)
{
  char fmt[UINT_FMT] ;
  fmt[uint_fmt(fmt, numconn)] = 0 ;
  strerr_warni3x("status: ", fmt, fmtmaxconn) ;
}

static void log_deny (char const *ip, uint16 port, unsigned int num)
{
  char fmtip[IP6_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT_FMT] ;
  fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  strerr_warni7sys("deny ", fmtip, " port ", fmtport, " count ", fmtnum, fmtlocalmaxconn) ;
}

static void log_accept (unsigned int pid, char const *ip, uint16 port, unsigned int num)
{
  char fmtipport[IP6_FMT + UINT16_FMT + 6] ;
  char fmtpid[UINT_FMT] ;
  char fmtnum[UINT_FMT] ;
  register unsigned int n ;
  n = ip6_fmt(fmtipport, ip) ;
  byte_copy(fmtipport + n, 6, " port ") ; n += 6 ;
  n += uint16_fmt(fmtipport + n, port) ;
  fmtipport[n] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  fmtpid[uint_fmt(fmtpid, pid)] = 0 ;
  strerr_warni7x("allow ", fmtipport, " pid ", fmtpid, " count ", fmtnum, fmtlocalmaxconn) ;
}

static void log_close (unsigned int pid, char const *ip, int w)
{
  char fmtpid[UINT_FMT] ;
  char fmtip[IP6_FMT] = "?" ;
  char fmtw[UINT_FMT] ;
  fmtpid[uint_fmt(fmtpid, pid)] = 0 ;
  fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  fmtw[uint_fmt(fmtw, WIFSIGNALED(w) ? WTERMSIG(w) : WEXITSTATUS(w))] = 0 ;
  strerr_warni6x("end pid ", fmtpid, " ip ", fmtip, WIFSIGNALED(w) ? " signal " : " exitcode ", fmtw) ;
}


 /* Signal handling */

static void killthem (int sig)
{
  register unsigned int i = 0 ;
  for (; i < numconn ; i++) kill(pidip[i].num, sig) ;
}

static void wait_children (void)
{
  for (;;)
  {
    unsigned int i ;
    int w ;
    register int pid = wait_nohang(&w) ;
    if (pid < 0)
      if (errno != ECHILD) strerr_diefu1sys(111, "wait_nohang") ;
      else break ;
    else if (!pid) break ;
    i = lookup_pid(pid) ;
    if (i < numconn) /* it's one of ours ! */
    {
      register unsigned int j = lookup_ip(pidip[i].ip) ;
      if (j >= iplen) X() ;
      if (!--ipnum[j].num) ipnum[j] = ipnum[--iplen] ;
      --numconn ;
      if (verbosity >= 2)
      {
        log_close(pid, pidip[i].ip, w) ;
        log_status() ;
      }
      pidip[i] = pidip[numconn] ;
    }
  }
}

static void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "read selfpipe") ;
    case 0 : return ;
    case SIGCHLD : wait_children() ; break ;
    case SIGTERM :
    {
      if (verbosity >= 2)
        strerr_warni3x("received ", "SIGTERM,", " quitting") ;
      cont = 0 ;
      break ;
    }
    case SIGHUP :
    {
      if (verbosity >= 2)
        strerr_warni5x("received ", "SIGHUP,", " sending ", "SIGTERM+SIGCONT", " to all connections") ;
      killthem(SIGTERM) ;
      killthem(SIGCONT) ;
      break ;
    }
    case SIGQUIT :
    {
      if (verbosity >= 2)
        strerr_warni6x("received ", "SIGQUIT,", " sending ", "SIGTERM+SIGCONT", " to all connections", " and quitting") ;
      cont = 0 ;
      killthem(SIGTERM) ;
      killthem(SIGCONT) ;
      break ;
    }
    case SIGABRT :
    {
      if (verbosity >= 2)
        strerr_warni6x("received ", "SIGABRT,", " sending ", "SIGKILL", " to all connections", " and quitting") ;
      cont = 0 ;
      killthem(SIGKILL) ;
      break ;
    }
    default : X() ;
  }
}


 /* New connection handling */

static void run_child (int, char const *, uint16, unsigned int, char const *const *, char const *const *) gccattr_noreturn ;
static void run_child (int s, char const *ip, uint16 port, unsigned int num, char const *const *argv, char const *const *envp)
{
  char fmt[98] ;
  unsigned int n = 0 ;
  PROG = "s6-tcpserver6 (child)" ;
  if ((fd_move(0, s) < 0) || (fd_copy(1, 0) < 0))
    strerr_diefu1sys(111, "move fds") ;
  byte_copy(fmt+n, 24, "PROTO=TCP\0TCPREMOTEIP=") ; n += 22 ;
  n += ip6_fmt(fmt+n, ip) ; fmt[n++] = 0 ;
  byte_copy(fmt+n, 14, "TCPREMOTEPORT=") ; n += 14 ;
  n += uint16_fmt(fmt+n, port) ; fmt[n++] = 0 ;
  byte_copy(fmt+n, 11, "TCPCONNNUM=") ; n += 11 ;
  n += uint_fmt(fmt+n, num) ; fmt[n++] = 0 ;
  pathexec_r(argv, envp, env_len(envp), fmt, n) ;
  strerr_dieexec(111, argv[0]) ;
}

static void new_connection (int s, char const *ip, uint16 port, char const *const *argv, char const *const *envp)
{
  unsigned int i = lookup_ip(ip) ;
  unsigned int num = (i < iplen) ? ipnum[i].num : 0 ;
  register int pid ;
  if (num >= localmaxconn)
  {
    log_deny(ip, port, num) ;
    return ;
  }
  pid = fork() ;
  if (pid < 0)
  {
    if (verbosity) strerr_warnwu1sys("fork") ;
    return ;
  }
  else if (!pid)
  {
    selfpipe_finish() ;
    run_child(s, ip, port, num+1, argv, envp) ;
  }

  if (i < iplen) ipnum[i].num = num + 1 ;
  else
  {
    byte_copy(ipnum[iplen].ip, 16, ip) ;
    ipnum[iplen++].num = 1 ;
  }
  pidip[numconn].num = pid ;
  byte_copy(pidip[numconn++].ip, 16, ip) ;
  if (verbosity >= 2)
  {
    log_accept(pid, ip, port, ipnum[i].num) ;
    log_status() ;
  }
}


int main (int argc, char const *const *argv, char const *const *envp)
{
  iopause_fd x[2] = { { -1, IOPAUSE_READ, 0 }, { -1, IOPAUSE_READ | IOPAUSE_EXCEPT, 0 } } ;
  PROG = "s6-tcpserver6" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int uid = 0, gid = 0 ;
    gid_t gids[NGROUPS_MAX] ;
    unsigned int gidn = 0 ;
    unsigned int backlog = 20 ;
    char ip[16] ;
    int flag1 = 0 ;
    uint16 port ;
    for (;;)
    {
      register int opt = subgetopt_r(argc, argv, "1Uc:C:b:u:g:G:v:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '1' : flag1 = 1 ; break ;
        case 'c' : if (!uint0_scan(l.arg, &maxconn)) dieusage() ; break ;
        case 'C' : if (!uint0_scan(l.arg, &localmaxconn)) dieusage() ; break ;
        case 'b' : if (!uint0_scan(l.arg, &backlog)) dieusage() ; break ;
        case 'u' : if (!uint0_scan(l.arg, &uid)) dieusage() ; break ;
        case 'g' : if (!uint0_scan(l.arg, &gid)) dieusage() ; break ;
        case 'G' : if (!gid_scanlist(gids, NGROUPS_MAX, l.arg, &gidn)) dieusage() ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        case 'U' :
        {
          char const *x = env_get2(envp, "UID") ;
          if (!x) strerr_dienotset(100, "UID") ;
          if (!uint0_scan(x, &uid)) strerr_dieinvalid(100, "UID") ;
          x = env_get2(envp, "GID") ;
          if (!x) strerr_dienotset(100, "GID") ;
          if (!uint0_scan(x, &gid)) strerr_dieinvalid(100, "GID") ;
          x = env_get2(envp, "GIDLIST") ;
          if (!x) strerr_dienotset(100, "GIDLIST") ;
          if (!gid_scanlist(gids, NGROUPS_MAX, x, &gidn) && *x)
            strerr_dieinvalid(100, "GIDLIST") ;
          break ;
        }
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (argc < 3) dieusage() ;
    if (!ip6_scan(argv[0], ip) || !uint160_scan(argv[1], &port)) dieusage() ;
    fd_close(0) ;
    if (!flag1) fd_close(1) ;
    if (!maxconn) maxconn = 1 ;
    if (maxconn > ABSOLUTE_MAXCONN) maxconn = ABSOLUTE_MAXCONN ;
    if (localmaxconn > maxconn) localmaxconn = maxconn ;
    x[1].fd = socket_tcp6() ;
    if ((x[1].fd == -1) || (coe(x[1].fd) == -1))
      strerr_diefu1sys(111, "create socket") ;
    if (socket_bind6_reuse(x[1].fd, ip, port) < 0)
      strerr_diefu2sys(111, "bind to ", argv[0]) ;
    if (socket_listen(x[1].fd, backlog) == -1)
      strerr_diefu1sys(111, "listen") ;
    if (gidn && (setgroups(gidn, gids) < 0)) strerr_diefu1sys(111, "setgroups") ;
    if (gid && (setgid(gid) < 0)) strerr_diefu1sys(111, "drop gid") ;
    if (uid && (setuid(uid) < 0)) strerr_diefu1sys(111, "drop uid") ;

    x[0].fd = selfpipe_init() ;
    if (x[0].fd == -1) strerr_diefu1sys(111, "create selfpipe") ;
    if (sig_ignore(SIGPIPE) < 0) strerr_diefu1sys(111, "ignore SIGPIPE") ;
    {
      sigset_t set ;
      sigemptyset(&set) ;
      sigaddset(&set, SIGCHLD) ;
      sigaddset(&set, SIGTERM) ;
      sigaddset(&set, SIGHUP) ;
      sigaddset(&set, SIGQUIT) ;
      sigaddset(&set, SIGABRT) ;
      if (selfpipe_trapset(&set) < 0) strerr_diefu1sys(111, "trap signals") ;
    }
    if (flag1)
    {
      char fmt[UINT16_FMT] ;
      unsigned int n = uint16_fmt(fmt, port) ;
      fmt[n++] = '\n' ;
      allwrite(1, fmt, n) ;
      fd_close(1) ;
    }
    fmtlocalmaxconn[1+uint_fmt(fmtlocalmaxconn+1, localmaxconn)] = 0 ;
    if (verbosity >= 2)
    {
      fmtmaxconn[1+uint_fmt(fmtmaxconn+1, maxconn)] = 0 ;
      log_start(ip, port) ;
      log_status() ;
    }
  }

  {
    ipnum_t inyostack[maxconn<<1] ;
    pidip = inyostack ; ipnum = inyostack + maxconn ;
    while (cont)
    {
      if (iopause_g(x, 1 + (numconn < maxconn), 0) < 0)
        strerr_diefu1sys(111, "iopause") ;

      if (x[0].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with selfpipe") ;
      if (x[0].revents & IOPAUSE_READ) handle_signals() ;
      if (numconn < maxconn)
      {
        if (x[1].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with socket") ;
        if (x[1].revents & IOPAUSE_READ)
        {
          char ip[16] ;
          uint16 port ;
          register int fd = socket_accept6(x[1].fd, ip, &port) ;
          if (fd < 0)
          {
            if (verbosity) strerr_warnwu1sys("accept") ;
          }
          else
          {
            new_connection(fd, ip, port, argv+2, envp) ;
            fd_close(fd) ;
          }
        }
      }
    }
  }
  if (verbosity >= 2) log_exit() ;
  return 0 ;
}
