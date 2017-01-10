/* ISC license. */

#include <sys/types.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <skalibs/gccattributes.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/uint.h>
#include <skalibs/bytestr.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr2.h>
#include <skalibs/fmtscan.h>
#include <skalibs/diuint32.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <skalibs/sig.h>
#include <skalibs/selfpipe.h>
#include <skalibs/iopause.h>
#include <skalibs/socket.h>

#define ABSOLUTE_MAXCONN 1000

#define USAGE "s6-tcpserver4d [ -v verbosity ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] prog..."

static unsigned int maxconn = 40 ;
static unsigned int localmaxconn = 40 ;
static unsigned int verbosity = 1 ;
static int cont = 1 ;
static diuint32 *pidip = 0 ;
static unsigned int numconn = 0 ;
static diuint32 *ipnum = 0 ;
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
 
static unsigned int lookup_diuint32 (diuint32 const *, unsigned int, unsigned int) gccattr_pure ;
static unsigned int lookup_diuint32 (diuint32 const *tab, unsigned int tablen, unsigned int key)
{
  register unsigned int i = 0 ;
  for (; i < tablen ; i++) if (key == tab[i].left) break ;
  return i ;
}

static inline unsigned int lookup_pid (uint32 pid)
{
  return lookup_diuint32(pidip, numconn, pid) ;
}

static inline unsigned int lookup_ip (uint32 ip)
{
  return lookup_diuint32(ipnum, iplen, ip) ;
}


 /* Logging */

static void log_start (void)
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

static void log_deny (uint32_t ip, uint16_t port, unsigned int num)
{
  char fmtip[UINT32_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT_FMT] ;
  fmtip[ip4_fmtu32(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  strerr_warni7sys("deny ", fmtip, ":", fmtport, " count ", fmtnum, fmtlocalmaxconn) ;
}

static void log_accept (uint32_t pid, uint32_t ip, uint16_t port, unsigned int num)
{
  char fmtipport[IP4_FMT + UINT16_FMT + 1] ;
  char fmtpid[UINT32_FMT] ;
  char fmtnum[UINT_FMT] ;
  register size_t n ;
  n = ip4_fmtu32(fmtipport, ip) ;
  fmtipport[n++] = ':' ;
  n += uint16_fmt(fmtipport + n, port) ;
  fmtipport[n] = 0 ;
  fmtnum[uint_fmt(fmtnum, num)] = 0 ;
  fmtpid[uint32_fmt(fmtpid, pid)] = 0 ;
  strerr_warni7x("allow ", fmtipport, " pid ", fmtpid, " count ", fmtnum, fmtlocalmaxconn) ;
}

static void log_close (uint32_t pid, uint32_t ip, int w)
{
  char fmtpid[UINT32_FMT] ;
  char fmtip[IP4_FMT] = "?" ;
  char fmtw[UINT_FMT] ;
  fmtpid[uint32_fmt(fmtpid, pid)] = 0 ;
  fmtip[ip4_fmtu32(fmtip, ip)] = 0 ;
  fmtw[uint_fmt(fmtw, WIFSIGNALED(w) ? WTERMSIG(w) : WEXITSTATUS(w))] = 0 ;
  strerr_warni6x("end pid ", fmtpid, " ip ", fmtip, WIFSIGNALED(w) ? " signal " : " exitcode ", fmtw) ;
}


 /* Signal handling */

static void killthem (int sig)
{
  register unsigned int i = 0 ;
  for (; i < numconn ; i++) kill(pidip[i].left, sig) ;
}

static void wait_children (void)
{
  for (;;)
  {
    unsigned int i ;
    int w ;
    register pid_t pid = wait_nohang(&w) ;
    if (pid < 0)
      if (errno != ECHILD) strerr_diefu1sys(111, "wait_nohang") ;
      else break ;
    else if (!pid) break ;
    i = lookup_pid(pid) ;
    if (i < numconn) /* it's one of ours ! */
    {
      uint32_t ip = pidip[i].right ;
      register unsigned int j = lookup_ip(ip) ;
      if (j >= iplen) X() ;
      if (!--ipnum[j].right) ipnum[j] = ipnum[--iplen] ;
      pidip[i] = pidip[--numconn] ;
      if (verbosity >= 2)
      {
        log_close(pid, ip, w) ;
        log_status() ;
      }
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

static void run_child (int, uint32_t, uint16_t, unsigned int, char const *const *, char const *const *) gccattr_noreturn ;
static void run_child (int s, uint32_t ip, uint16_t port, unsigned int num, char const *const *argv, char const *const *envp)
{
  char fmt[74] ;
  size_t n = 0 ;
  PROG = "s6-tcpserver (child)" ;
  if ((fd_move(0, s) < 0) || (fd_copy(1, 0) < 0))
    strerr_diefu1sys(111, "move fds") ;
  byte_copy(fmt+n, 22, "PROTO=TCP\0TCPREMOTEIP=") ; n += 22 ;
  n += ip4_fmtu32(fmt+n, ip) ; fmt[n++] = 0 ;
  byte_copy(fmt+n, 14, "TCPREMOTEPORT=") ; n += 14 ;
  n += uint16_fmt(fmt+n, port) ; fmt[n++] = 0 ;
  byte_copy(fmt+n, 11, "TCPCONNNUM=") ; n += 11 ;
  n += uint_fmt(fmt+n, num) ; fmt[n++] = 0 ;
  pathexec_r(argv, envp, env_len(envp), fmt, n) ;
  strerr_dieexec(111, argv[0]) ;
}

static void new_connection (int s, uint32_t ip, uint16_t port, char const *const *argv, char const *const *envp)
{
  unsigned int i = lookup_ip(ip) ;
  unsigned int num = (i < iplen) ? ipnum[i].right : 0 ;
  register pid_t pid ;
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

  if (i < iplen) ipnum[i].right = num + 1 ;
  else
  {
    ipnum[iplen].left = ip ;
    ipnum[iplen++].right = 1 ;
  }
  pidip[numconn].left = (uint32_t)pid ;
  pidip[numconn++].right = ip ;
  if (verbosity >= 2)
  {
    log_accept((uint32_t)pid, ip, port, ipnum[i].right) ;
    log_status() ;
  }
}


 /* And the main */

int main (int argc, char const *const *argv, char const *const *envp)
{
  iopause_fd x[2] = { { .events = IOPAUSE_READ }, { .fd = 0, .events = IOPAUSE_READ | IOPAUSE_EXCEPT } } ;
  PROG = "s6-tcpserver4d" ;
  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    int flag1 = 0 ;
    for (;;)
    {
      register int opt = subgetopt_r(argc, argv, "1c:C:v:", &l) ;
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
    fmtlocalmaxconn[1+uint_fmt(fmtlocalmaxconn+1, localmaxconn)] = 0 ;
    if (verbosity >= 2)
    {
      fmtmaxconn[1+uint_fmt(fmtmaxconn+1, maxconn)] = 0 ;
      log_start() ;
      log_status() ;
    }
    if (flag1)
    {
      fd_write(1, "\n", 1) ;
      fd_close(1) ;
    }
  }

  {
    diuint32 inyostack[maxconn<<1] ;
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
          char packedip[4] ;
          uint16_t port ;
          register int fd = socket_accept4(x[1].fd, packedip, &port) ;
          if (fd < 0)
          {
            if (verbosity) strerr_warnwu1sys("accept") ;
          }
          else
          {
            uint32_t ip ;
            uint32_unpack_big(packedip, &ip) ;
            new_connection(fd, ip, port, argv, envp) ;
            fd_close(fd) ;
          }
        }
      }
    }
  }
  if (verbosity >= 2) log_exit() ;
  return 0 ;
}
