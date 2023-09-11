/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <skalibs/posixplz.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/types.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/fmtscan.h>
#include <skalibs/env.h>
#include <skalibs/cspawn.h>
#include <skalibs/djbunix.h>
#include <skalibs/sig.h>
#include <skalibs/selfpipe.h>
#include <skalibs/iopause.h>
#include <skalibs/socket.h>

#define ABSOLUTE_MAXCONN 16384

#define USAGE "s6-tcpserver6d [ -v verbosity ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] prog..."

typedef struct pidip_s pidip_t, *pidip_t_ref ;
struct pidip_s
{
  pid_t pid ;
  char ip[16] ;
} ;

typedef struct ipnum_s ipnum_t, *ipnum_t_ref ;
struct ipnum_s
{
  char ip[16] ;
  unsigned int num ;
} ;

static unsigned int maxconn = 40 ;
static unsigned int localmaxconn = 40 ;
static unsigned int verbosity = 1 ;
static int cont = 1 ;
static pidip_t *pidip = 0 ;
static unsigned int numconn = 0 ;
static ipnum_t *ipnum = 0 ;
static unsigned int iplen = 0 ;

static char fmtmaxconn[UINT_FMT+1] = "/" ;
static char fmtlocalmaxconn[UINT_FMT+1] = "/" ;

static inline void dieusage ()
{
  strerr_dieusage(100, USAGE) ;
}

static inline void X (void)
{
  strerr_dief1x(101, "internal inconsistency. Please submit a bug-report.") ;
}

static inline unsigned int lookup_pid (pid_t pid)
{
  unsigned int i = 0 ;
  for (; i < numconn ; i++) if (pid == pidip[i].pid) break ;
  return i ;
}

static inline unsigned int lookup_ip (char const *ip)
{
  unsigned int i = 0 ;
  for (; i < iplen ; i++) if (!memcmp(ip, ipnum[i].ip, 16)) break ;
  return i ;
}

static inline void log_start (void)
{
  strerr_warni1x("starting") ;
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

static inline void log_deny (char const *ip, uint16_t port, unsigned int num)
{
  char fmtip[IP6_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT_FMT] ;
  fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  strerr_warni7sys("deny ", fmtip, " port ", fmtport, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_accept (pid_t pid, char const *ip, uint16_t port, unsigned int num)
{
  char fmtipport[IP6_FMT + UINT16_FMT + 6] ;
  char fmtpid[PID_FMT] ;
  char fmtnum[UINT_FMT] ;
  size_t n ;
  n = ip6_fmt(fmtipport, ip) ;
  memcpy(fmtipport + n, " port ", 6) ; n += 6 ;
  n += uint16_fmt(fmtipport + n, port) ;
  fmtipport[n] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  strerr_warni7x("allow ", fmtipport, " pid ", fmtpid, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_close (pid_t pid, char const *ip, int w)
{
  char fmtpid[PID_FMT] ;
  char fmtip[IP6_FMT] = "?" ;
  char fmtw[UINT_FMT] ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  fmtip[ip6_fmt(fmtip, ip)] = 0 ;
  fmtw[uint_fmt(fmtw, WIFSIGNALED(w) ? WTERMSIG(w) : WEXITSTATUS(w))] = 0 ;
  strerr_warni6x("end pid ", fmtpid, " ip ", fmtip, WIFSIGNALED(w) ? " signal " : " exitcode ", fmtw) ;
}

static void killthem (int sig)
{
  unsigned int i = 0 ;
  for (; i < numconn ; i++) kill(pidip[i].pid, sig) ;
}

static inline void wait_children (void)
{
  for (;;)
  {
    unsigned int i ;
    int w ;
    pid_t pid = wait_nohang(&w) ;
    if (pid < 0)
      if (errno != ECHILD) strerr_diefu1sys(111, "wait_nohang") ;
      else break ;
    else if (!pid) break ;
    i = lookup_pid(pid) ;
    if (i < numconn) /* it's one of ours ! */
    {
      unsigned int j = lookup_ip(pidip[i].ip) ;
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

static inline void handle_signals (void)
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

static inline void new_connection (int s, char const *ip, uint16_t port, char const *const *argv, char const *const *envp, size_t envlen)
{
  pid_t pid ;
  unsigned int i = lookup_ip(ip) ;
  unsigned int num = (i < iplen) ? ipnum[i].num : 0 ;
  size_t m = 0 ;
  char fmt[47 + IP6_FMT + UINT16_FMT + UINT_FMT] ;

  if (num >= localmaxconn)
  {
    log_deny(ip, port, num) ;
    return ;
  }

  memcpy(fmt + m, "PROTO=TCP\0TCPREMOTEIP=", 22) ; m += 22 ;
  m += ip6_fmt(fmt + m, ip) ; fmt[m++] = 0 ;
  memcpy(fmt + m, "TCPREMOTEPORT=", 14) ; m += 14 ;
  m += uint16_fmt(fmt + m, port) ; fmt[m++] = 0 ;
  memcpy(fmt + m, "TCPCONNNUM=", 11) ; m += 11 ;
  m += uint_fmt(fmt + m, num) ; fmt[m++] = 0 ;

  {
    cspawn_fileaction fa[2] =
    {
      [0] = { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { [0] = 0, [1] = s } } },
      [1] = { .type = CSPAWN_FA_COPY, .x = { .fd2 = { [0] = 1, [1] = 0 } } }
    } ;
    char const *newenvp[envlen + 5] ;
    env_mergen(newenvp, envlen + 5, envp, envlen, fmt, m, 4) ;
    pid = cspawn(argv[0], argv, newenvp, CSPAWN_FLAGS_SELFPIPE_FINISH, fa, 2) ;
  }
  if (!pid)
  {
    if (verbosity) strerr_warnwu2sys("spawn ", argv[0]) ;
    return ;
  }

  if (i < iplen) ipnum[i].num = num + 1 ;
  else
  {
    memcpy(ipnum[iplen].ip, ip, 16) ;
    ipnum[iplen++].num = 1 ;
  }
  pidip[numconn].pid = pid ;
  memcpy(pidip[numconn++].ip, ip, 16) ;
  if (verbosity >= 2)
  {
    log_accept(pid, ip, port, ipnum[i].num) ;
    log_status() ;
  }
}

int main (int argc, char const *const *argv)
{
  iopause_fd x[2] = { { .events = IOPAUSE_READ }, { .fd = 0, .events = IOPAUSE_READ | IOPAUSE_EXCEPT } } ;
  PROG = "s6-tcpserver6d" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    int flag1 = 0 ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "1c:C:v:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '1' : flag1 = 1 ; break ;
        case 'c' : if (!uint0_scan(l.arg, &maxconn)) dieusage() ; break ;
        case 'C' : if (!uint0_scan(l.arg, &localmaxconn)) dieusage() ; break ;
        case 'v' : if (!uint0_scan(l.arg, &verbosity)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    argc -= l.ind ; argv += l.ind ;
    if (!argc || !*argv[0]) dieusage() ;
    {
      struct stat st ;
      if (fstat(0, &st) < 0) strerr_diefu1sys(111, "fstat stdin") ;
      if (!S_ISSOCK(st.st_mode)) strerr_dief1x(100, "stdin is not a socket") ;
    }
    if (coe(0) < 0) strerr_diefu1sys(111, "make socket close-on-exec") ;
    if (flag1)
    {
      if (fcntl(1, F_GETFD) < 0)
        strerr_dief1sys(100, "called with option -1 but stdout said") ;
    }
    else close(1) ;
    if (!maxconn) maxconn = 1 ;
    if (maxconn > ABSOLUTE_MAXCONN) maxconn = ABSOLUTE_MAXCONN ;
    if (localmaxconn > maxconn) localmaxconn = maxconn ;

    x[0].fd = selfpipe_init() ;
    if (x[0].fd == -1) strerr_diefu1sys(111, "create selfpipe") ;
    if (!sig_altignore(SIGPIPE)) strerr_diefu1sys(111, "ignore SIGPIPE") ;
    {
      sigset_t set ;
      sigemptyset(&set) ;
      sigaddset(&set, SIGCHLD) ;
      sigaddset(&set, SIGTERM) ;
      sigaddset(&set, SIGHUP) ;
      sigaddset(&set, SIGQUIT) ;
      sigaddset(&set, SIGABRT) ;
      if (!selfpipe_trapset(&set)) strerr_diefu1sys(111, "trap signals") ;
    }
    if (flag1)
    {
      uint16_t port ;
      uint16_t m = 0 ;
      char ip[16] ;
      char fmtport[UINT16_FMT] ;
      if (socket_local6(0, ip, &port) == -1)
      {
        if (verbosity) strerr_warnwu1sys("socket_local6") ;
      }
      else m = uint16_fmt(fmtport, port) ;
      fmtport[m++] = '\n' ;
      allwrite(1, fmtport, m) ;
      fd_close(1) ;
    }
    fmtlocalmaxconn[1+uint_fmt(fmtlocalmaxconn+1, localmaxconn)] = 0 ;
    if (verbosity >= 2)
    {
      fmtmaxconn[1+uint_fmt(fmtmaxconn+1, maxconn)] = 0 ;
      log_start() ;
      log_status() ;
    }
  }

  {
    pidip_t pidip_inyostack[maxconn] ;
    ipnum_t ipnum_inyostack[maxconn] ;
    size_t envlen = env_len((char const *const *)environ) ;
    pidip = pidip_inyostack ; ipnum = ipnum_inyostack ;

    while (cont)
    {
      if (iopause_g(x, 1 + (numconn < maxconn), 0) < 0)
        strerr_diefu1sys(111, "iopause") ;

      if (x[0].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with selfpipe") ;
      if (x[0].revents & IOPAUSE_READ) { handle_signals() ; continue ; }
      if (numconn < maxconn)
      {
        if (x[1].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with socket") ;
        if (x[1].revents & IOPAUSE_READ)
        {
          char ip[16] ;
          uint16_t port ;
          int fd = socket_accept6(x[1].fd, ip, &port) ;
          if (fd < 0)
          {
            if (verbosity) strerr_warnwu1sys("accept") ;
          }
          else
          {
            new_connection(fd, ip, port, argv, (char const *const *)environ, envlen) ;
            fd_close(fd) ;
          }
        }
      }
    }
  }
  if (verbosity >= 2) log_exit() ;
  return 0 ;
}
