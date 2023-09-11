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
#include <skalibs/uint16.h>
#include <skalibs/uint32.h>
#include <skalibs/types.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/sgetopt.h>
#include <skalibs/strerr.h>
#include <skalibs/fmtscan.h>
#include <skalibs/diuint32.h>
#include <skalibs/env.h>
#include <skalibs/cspawn.h>
#include <skalibs/djbunix.h>
#include <skalibs/sig.h>
#include <skalibs/selfpipe.h>
#include <skalibs/iopause.h>
#include <skalibs/socket.h>
#include <skalibs/genset.h>
#include <skalibs/avltreen.h>

#define ABSOLUTE_MAXCONN 16384

#define USAGE "s6-tcpserver4d [ -v verbosity ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] prog..."

typedef struct pidi_s pidi, *pidi_ref ;
struct pidi_s
{
  pid_t pid ;
  uint32_t i ;
} ;

static uint32_t maxconn = 40 ;
static uint32_t localmaxconn = 40 ;
static uint32_t verbosity = 1 ;
static int cont = 1 ;

static genset *pidis ;
#define PIDI(i) genset_p(pidi, pidis, (i))
#define numconn genset_n(pidis)
static genset *ipnums ;
#define IPNUM(i) genset_p(diuint32, ipnums, (i))
static avltreen *by_ip ;
static avltreen *by_pid ;

static char fmtmaxconn[UINT32_FMT+1] = "/" ;
static char fmtlocalmaxconn[UINT32_FMT+1] = "/" ;


static inline void dieusage ()
{
  strerr_dieusage(100, USAGE) ;
}

static inline void X (void)
{
  strerr_dief1x(101, "internal inconsistency. Please submit a bug-report.") ;
}

static void *bypid_dtok (uint32_t d, void *aux)
{
  genset *g = aux ;
  return &genset_p(pidi, g, d)->pid ;
}

static int bypid_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  pid_t aa = *(pid_t const *)a ;
  pid_t bb = *(pid_t const *)b ;
  return aa < bb ? -1 : aa > bb ;
}

static void *byip_dtok (uint32_t d, void *aux)
{
  genset *g = aux ;
  return &genset_p(diuint32, g, d)->left ;
}

static int byip_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  uint32_t aa = *(uint32_t const *)a ;
  uint32_t bb = *(uint32_t const *)b ;
  return aa < bb ? -1 : aa > bb ;
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

static inline void log_deny (uint32_t ip, uint16_t port, uint32_t num)
{
  char fmtip[UINT32_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT32_FMT] ;
  fmtip[ip4_fmtu32(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint32_fmt(fmtnum, num)] = 0 ;
  strerr_warni7sys("deny ", fmtip, ":", fmtport, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_accept (pid_t pid, uint32_t ip, uint16_t port, uint32_t num)
{
  char fmtipport[IP4_FMT + UINT16_FMT + 1] ;
  char fmtpid[PID_FMT] ;
  char fmtnum[UINT32_FMT] ;
  size_t n ;
  n = ip4_fmtu32(fmtipport, ip) ;
  fmtipport[n++] = ':' ;
  n += uint16_fmt(fmtipport + n, port) ;
  fmtipport[n] = 0 ;
  fmtnum[uint32_fmt(fmtnum, num)] = 0 ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  strerr_warni7x("allow ", fmtipport, " pid ", fmtpid, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_close (pid_t pid, uint32_t ip, int w)
{
  char fmtpid[PID_FMT] ;
  char fmtip[IP4_FMT] = "?" ;
  char fmtw[UINT_FMT] ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  fmtip[ip4_fmtu32(fmtip, ip)] = 0 ;
  fmtw[uint_fmt(fmtw, WIFSIGNALED(w) ? WTERMSIG(w) : WEXITSTATUS(w))] = 0 ;
  strerr_warni6x("end pid ", fmtpid, " ip ", fmtip, WIFSIGNALED(w) ? " signal " : " exitcode ", fmtw) ;
}

static int killthem_iter (void *data, void *aux)
{
  kill(((pidi *)data)->pid, *(int *)aux) ;
  return 1 ;
}

static void killthem (int sig)
{
  genset_iter(pidis, &killthem_iter, &sig) ;
}

static inline void wait_children (void)
{
  for (;;)
  {
    uint32_t d ;
    int wstat ;
    pid_t pid = wait_nohang(&wstat) ;
    if (pid < 0)
      if (errno != ECHILD) strerr_diefu1sys(111, "wait_nohang") ;
      else break ;
    else if (!pid) break ;
    if (avltreen_search(by_pid, &pid, &d))
    {
      uint32_t i = PIDI(d)->i ;
      uint32_t ip = IPNUM(i)->left ;
      avltreen_delete(by_pid, &pid) ;
      genset_delete(pidis, d) ;
      if (!--IPNUM(i)->right)
      {
        avltreen_delete(by_ip, &ip) ;
        genset_delete(ipnums, i) ;
      }
      if (verbosity >= 2)
      {
        log_close(pid, ip, wstat) ;
        log_status() ;
      }
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

static inline void new_connection (int s, uint32_t ip, uint16_t port, char const *const *argv, char const *const *envp, size_t envlen)
{
  size_t m = 0 ;
  pid_t pid ;
  uint32_t d ;
  uint32_t num = 0 ;
  char fmt[47 + IP4_FMT + UINT16_FMT + UINT_FMT] ;

  if (avltreen_search(by_ip, &ip, &d)) num = IPNUM(d)->right ;
  if (num >= localmaxconn)
  {
    log_deny(ip, port, num) ;
    return ;
  }

  memcpy(fmt + m, "PROTO=TCP\0TCPREMOTEIP=", 22) ; m += 22 ;
  m += ip4_fmtu32(fmt + m, ip) ;
  fmt[m++] = 0 ;
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

  if (num) IPNUM(d)->right++ ;
  else
  {
    d = genset_new(ipnums) ;
    IPNUM(d)->left = ip ;
    IPNUM(d)->right = 1 ;
    avltreen_insert(by_ip, d) ;
  }

  num = genset_new(pidis) ;
  PIDI(num)->pid = pid ;
  PIDI(num)->i = d ;
  avltreen_insert(by_pid, num) ;
  if (verbosity >= 2)
  {
    log_accept(pid, ip, port, IPNUM(d)->right) ;
    log_status() ;
  }
}

int main (int argc, char const *const *argv)
{
  iopause_fd x[2] = { { .events = IOPAUSE_READ }, { .fd = 0, .events = IOPAUSE_READ | IOPAUSE_EXCEPT } } ;
  int flag1 = 0 ;
  PROG = "s6-tcpserver4d" ;
  {
    subgetopt l = SUBGETOPT_ZERO ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "1c:C:v:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case '1' : flag1 = 1 ; break ;
        case 'c' : if (!uint320_scan(l.arg, &maxconn)) dieusage() ; break ;
        case 'C' : if (!uint320_scan(l.arg, &localmaxconn)) dieusage() ; break ;
        case 'v' : if (!uint320_scan(l.arg, &verbosity)) dieusage() ; break ;
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
    if (coe(0) == -1 || ndelay_on(0) == -1)
      strerr_diefu1sys(111, "set socket flags") ;
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
    fmtlocalmaxconn[1+uint32_fmt(fmtlocalmaxconn+1, localmaxconn)] = 0 ;
  }

  {
    diuint32 ipnum_storage[maxconn] ;
    uint32_t ipnum_freelist[maxconn] ;
    avlnode byip_storage[maxconn] ;
    uint32_t byip_freelist[maxconn] ;
    pidi pidi_storage[maxconn] ;
    uint32_t pidi_freelist[maxconn] ;
    avlnode bypid_storage[maxconn] ;
    uint32_t bypid_freelist[maxconn] ;
    genset ipnum_info ;
    genset pidi_info ;
    avltreen byip_info ;
    avltreen bypid_info ;
    size_t envlen = env_len((char const *const *)environ) ;

    GENSET_init(&ipnum_info, diuint32, ipnum_storage, ipnum_freelist, maxconn) ;
    GENSET_init(&pidi_info, pidi, pidi_storage, pidi_freelist, maxconn) ;
    avltreen_init(&byip_info, byip_storage, byip_freelist, maxconn, &byip_dtok, &byip_cmp, &ipnum_info) ;
    avltreen_init(&bypid_info, bypid_storage, bypid_freelist, maxconn, &bypid_dtok, &bypid_cmp, &pidi_info) ;
    ipnums = &ipnum_info ;
    pidis = &pidi_info ;
    by_ip = &byip_info ;
    by_pid = &bypid_info ;

    if (verbosity >= 2)
    {
      fmtmaxconn[1+uint32_fmt(fmtmaxconn+1, maxconn)] = 0 ;
      log_start() ;
      log_status() ;
    }

    if (flag1)
    {
      uint16_t port ;
      uint16_t m = 0 ;
      char ip[4] ;
      char fmtport[UINT16_FMT] ;
      if (socket_local4(0, ip, &port) == -1)
      {
        if (verbosity) strerr_warnwu1sys("socket_local4") ;
      }
      else m = uint16_fmt(fmtport, port) ;
      fmtport[m++] = '\n' ;
      allwrite(1, fmtport, m) ;
      close(1) ;
    }

    while (cont)
    {
      if (iopause_g(x, 1 + (numconn < maxconn), 0) < 0) strerr_diefu1sys(111, "iopause") ;
      if (x[0].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with selfpipe") ;
      if (x[0].revents & IOPAUSE_READ)  { handle_signals() ; continue ; }
      if (numconn < maxconn)
      {
        if (x[1].revents & IOPAUSE_EXCEPT) strerr_dief1x(111, "trouble with socket") ;
        if (x[1].revents & IOPAUSE_READ)
        {
          char packedip[4] ;
          uint16_t port ;
          int fd = socket_accept4(x[1].fd, packedip, &port) ;
          if (fd == -1)
          {
            if (verbosity) strerr_warnwu1sys("accept") ;
          }
          else
          {
            uint32_t ip ;
            uint32_unpack_big(packedip, &ip) ;
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
