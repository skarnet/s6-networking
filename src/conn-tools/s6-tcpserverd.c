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
#include <skalibs/ip46.h>
#include <skalibs/allreadwrite.h>
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
#include <skalibs/genset.h>
#include <skalibs/avltreen.h>

#define ABSOLUTE_MAXCONN 16384

#define USAGE "s6-tcpserverd [ -v verbosity ] [ -1 ] [ -c maxconn ] [ -C localmaxconn ] prog..."

static uint32_t maxconn = 40 ;
static uint32_t localmaxconn = 40 ;
static uint32_t verbosity = 1 ;
static int cont = 1 ;
static int is6 ;

typedef struct pidi_s pidi, *pidi_ref ;
struct pidi_s
{
  pid_t pid ;
  uint32_t i ;
} ;

static genset *pidis ;
#define PIDI(i) genset_p(pidi, pidis, (i))
#define numconn genset_n(pidis)
static avltreen *by_pid ;

static genset *ipnums ;
#define IP(i) (genset_p(char, ipnums, (i)) + 4)
#define NUMP(i) ((uint32_t *)genset_p(char, ipnums, (i)))
static avltreen *by_ip ;

static char fmtmaxconn[UINT32_FMT + 1] = "/" ;
static char fmtlocalmaxconn[UINT32_FMT + 1] = "/" ;


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
  return &genset_p(pidi, (genset *)aux, d)->pid ;
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
  return genset_p(char, (genset *)aux, d) + 4 ;
}

static int byip_cmp (void const *a, void const *b, void *aux)
{
  (void)aux ;
  return memcmp(a, b, is6 ? 16 : 4) ;
}

static inline void log_start (char const *fmtip, char const *fmtport)
{
  if (verbosity < 2) return ;
  strerr_warni4x("starting - bound to ip ", fmtip, " port ", fmtport) ;
}

static inline void log_exit (void)
{
  if (verbosity < 2) return ;
  strerr_warni1x("exiting") ;
}

static void log_status (void)
{
  char fmt[UINT_FMT] ;
  if (verbosity < 2) return ;
  fmt[uint_fmt(fmt, numconn)] = 0 ;
  strerr_warni3x("status: ", fmt, fmtmaxconn) ;
}

static inline void log_deny (char const *ip, uint16_t port, uint32_t num)
{
  char fmtip[IP46_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT32_FMT] ;
  if (!verbosity) return ;
  fmtip[is6 ? ip6_fmt(fmtip, ip) : ip4_fmt(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint32_fmt(fmtnum, num)] = 0 ;
  strerr_warni7sys("deny ", fmtip, ":", fmtport, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_accept (pid_t pid, char const *ip, uint16_t port, uint32_t num)
{
  char fmtip[IP46_FMT] ;
  char fmtport[UINT16_FMT] ;
  char fmtnum[UINT32_FMT] ;
  char fmtpid[PID_FMT] ;
  if (verbosity < 2) return ;
  fmtip[is6 ? ip6_fmt(fmtip, ip) : ip4_fmt(fmtip, ip)] = 0 ;
  fmtport[uint16_fmt(fmtport, port)] = 0 ;
  fmtnum[uint32_fmt(fmtnum, num)] = 0 ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  strerr_warni9x("allow ", fmtip, ":", fmtport, " pid ", fmtpid, " count ", fmtnum, fmtlocalmaxconn) ;
}

static inline void log_close (pid_t pid, char const *ip, int w, uint32_t num)
{
  char fmtpid[PID_FMT] ;
  char fmtw[UINT_FMT] ;
  char fmtnum[UINT32_FMT] ;
  if (verbosity < 2) return ;
  fmtpid[pid_fmt(fmtpid, pid)] = 0 ;
  fmtw[uint_fmt(fmtw, WIFSIGNALED(w) ? WTERMSIG(w) : WEXITSTATUS(w))] = 0 ;
  fmtnum[uint32_fmt(fmtnum, num)] = 0 ;
  strerr_warni7x("end pid ", fmtpid, WIFSIGNALED(w) ? " signal " : " exitcode ", fmtw, " count ", fmtnum, fmtlocalmaxconn) ;
}

static int send_termcont_iter (void *data, void *aux)
{
  (void)aux ;
  pid_t pid = ((pidi *)data)->pid ;
  kill(pid, SIGTERM) ;
  kill(pid, SIGCONT) ;
  return 1 ;
}

static int send_kill_iter (void *data, void *aux)
{
  (void)aux ;
  kill(((pidi *)data)->pid, SIGKILL) ;
  return 1 ;
}

static inline void send_termcont (void)
{
  genset_iter(pidis, &send_termcont_iter, 0) ;
}

static inline void send_kill (void)
{
  genset_iter(pidis, &send_kill_iter, 0) ;
}

static inline void end_connection (pid_t pid, int wstat)
{
  uint32_t d, i, num ;
  char ip[SKALIBS_IP_SIZE] ;
  if (!avltreen_search(by_pid, &pid, &d)) return ;
  i = PIDI(d)->i ;
  memcpy(ip, IP(i), is6 ? 16 : 4) ;
  avltreen_delete(by_pid, &pid) ;
  genset_delete(pidis, d) ;
  num = --*NUMP(i) ;
  if (!num)
  {
    avltreen_delete(by_ip, ip) ;
    genset_delete(ipnums, i) ;
  }
  log_close(pid, ip, wstat, num) ;
  log_status() ;
}

static inline void handle_signals (void)
{
  for (;;) switch (selfpipe_read())
  {
    case -1 : strerr_diefu1sys(111, "read selfpipe") ;
    case 0 : return ;
    case SIGCHLD :
      for (;;)
      {
        int wstat ;
        pid_t pid = wait_nohang(&wstat) ;
        if (pid == -1)
          if (errno != ECHILD) strerr_diefu1sys(111, "wait_nohang") ;
          else break ;
        else if (!pid) break ;
        end_connection(pid, wstat) ;
      }
      break ;
    case SIGTERM :
      if (verbosity >= 2)
        strerr_warni3x("received ", "SIGTERM,", " quitting") ;
      cont = 0 ;
      break ;
    case SIGHUP :
      if (verbosity >= 2)
        strerr_warni5x("received ", "SIGHUP,", " sending ", "SIGTERM and SIGCONT", " to all connections") ;
      send_termcont() ;
      break ;
    case SIGQUIT :
      if (verbosity >= 2)
        strerr_warni6x("received ", "SIGQUIT,", " sending ", "SIGTERM and SIGCONT", " to all connections", " and quitting") ;
      cont = 0 ;
      send_termcont() ;
      break ;
    case SIGABRT :
      if (verbosity >= 2)
        strerr_warni6x("received ", "SIGABRT,", " sending ", "SIGKILL", " to all connections", " and quitting") ;
      cont = 0 ;
      send_kill() ;
      break ;
    default : X() ;
  }
}

static inline void new_connection (int s, char const *ip, uint16_t port, char const *const *argv, char const *const *envp, char *modifs, size_t m, size_t envlen)
{
  pid_t pid ;
  uint32_t d ;
  uint32_t num = avltreen_search(by_ip, ip, &d) ? *NUMP(d) : 0 ;
  if (num >= localmaxconn)
  {
    log_deny(ip, port, num) ;
    return ;
  }

  m += is6 ? ip6_fmt(modifs + m, ip) : ip4_fmt(modifs + m, ip) ;
  modifs[m++] = 0 ;
  memcpy(modifs + m, "TCPREMOTEPORT=", 14) ; m += 14 ;
  m += uint16_fmt(modifs + m, port) ;
  modifs[m++] = 0 ;
  memcpy(modifs + m, "TCPCONNNUM=", 11) ; m += 11 ;
  m += uint32_fmt(modifs + m, num) ;
  modifs[m++] = 0 ;

  {
    cspawn_fileaction fa[2] =
    {
      [0] = { .type = CSPAWN_FA_MOVE, .x = { .fd2 = { [0] = 0, [1] = s } } },
      [1] = { .type = CSPAWN_FA_COPY, .x = { .fd2 = { [0] = 1, [1] = 0 } } }
    } ;
    char const *newenvp[envlen + 7] ;
    env_mergen(newenvp, envlen + 7, envp, envlen, modifs, m, 6) ;
    pid = cspawn(argv[0], argv, newenvp, CSPAWN_FLAGS_SELFPIPE_FINISH, fa, 2) ;
    if (!pid)
    {
      if (verbosity) strerr_warnwu2sys("spawn ", argv[0]) ;
      return ;
    }
  }

  if (num) (*NUMP(d))++ ;
  else
  {
    d = genset_new(ipnums) ;
    *NUMP(d) = 1 ;
    memcpy(IP(d), ip, is6 ? 16 : 4) ;
    avltreen_insert(by_ip, d) ;
  }

  num = genset_new(pidis) ;
  PIDI(num)->pid = pid ;
  PIDI(num)->i = d ;
  avltreen_insert(by_pid, num) ;
  log_accept(pid, ip, port, *NUMP(d)) ;
  log_status() ;
}

int main (int argc, char const *const *argv)
{
  iopause_fd x[2] = { { .events = IOPAUSE_READ }, { .fd = 0, .events = IOPAUSE_READ | IOPAUSE_EXCEPT } } ;
  int flag1 = 0 ;
  PROG = "s6-tcpserverd" ;
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
    fmtmaxconn[1 + uint32_fmt(fmtmaxconn + 1, maxconn)] = 0 ;
    fmtlocalmaxconn[1 + uint32_fmt(fmtlocalmaxconn + 1, localmaxconn)] = 0 ;
  }

  {
   /* Yo dawg, I herd u like stack allocations */
    char ipnum_storage[maxconn * (is6 ? 20 : 8)] ;
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
    size_t m = 21 ;
    char ip[SKALIBS_IP_SIZE] ;
    uint16_t port ;
    char modifs[sizeof("PROTO=TCP TCPLOCALIP= TCPLOCALPORT= TCPREMOTEIP= TCPREMOTEPORT= TCPCONNNUM=") + 2 * (IP46_FMT + UINT16_FMT) + UINT32_FMT] = "PROTO=TCP\0TCPLOCALIP=" ;

    genset_init(&ipnum_info, ipnum_storage, ipnum_freelist, is6 ? 20 : 8, maxconn) ;
    GENSET_init(&pidi_info, pidi, pidi_storage, pidi_freelist, maxconn) ;
    avltreen_init(&byip_info, byip_storage, byip_freelist, maxconn, &byip_dtok, &byip_cmp, &ipnum_info) ;
    avltreen_init(&bypid_info, bypid_storage, bypid_freelist, maxconn, &bypid_dtok, &bypid_cmp, &pidi_info) ;
    ipnums = &ipnum_info ;
    pidis = &pidi_info ;
    by_ip = &byip_info ;
    by_pid = &bypid_info ;

    {
      size_t iplen, portlen ;
      char fmtip[IP46_FMT] ;
      char fmtport[UINT16_FMT] ;
      ip46 loc ;
      if (socket_local46(0, &loc, &port) == -1)
        strerr_diefu1sys(111, "get local socket information") ;
      is6 = ip46_is6(&loc) ;
      memcpy(ip, loc.ip, is6 ? 16 : 4) ;
      iplen = is6 ? ip6_fmt(fmtip, ip) : ip4_fmt(fmtip, ip) ;
      portlen = uint16_fmt(fmtport, port) ; 
      memcpy(modifs + m, fmtip, iplen) ; m += iplen ;
      memcpy(modifs + m, "\0TCPLOCALPORT=", 14) ; m += 14 ;
      memcpy(modifs + m, fmtport, portlen) ; m += portlen ;
      memcpy(modifs + m, "\0TCPREMOTEIP=", 13) ; m += 13 ;

      log_start(fmtip, fmtport) ;
      log_status() ;

      if (flag1)
      {
        fmtport[portlen] = '\n' ;
        allwrite(1, fmtport, portlen + 1) ;
        close(1) ;
      }
    }

    while (cont)
    {
      if (iopause_g(x, 1 + (numconn < maxconn), 0) == -1)
        strerr_diefu1sys(111, "iopause") ;

      if (x[0].revents & (IOPAUSE_READ | IOPAUSE_EXCEPT)) { handle_signals() ; continue ; }
      if (numconn >= maxconn) continue ;
      if (x[1].revents & (IOPAUSE_READ | IOPAUSE_EXCEPT))
      {
        int fd = is6 ? socket_accept6(x[1].fd, ip, &port) : socket_accept4(x[1].fd, ip, &port) ;
        if (fd == -1)
        {
          if (verbosity) strerr_warnwu1sys("accept") ;
        }
        else
        {
          new_connection(fd, ip, port, argv, (char const *const *)environ, modifs, m, envlen) ;
          fd_close(fd) ;
        }
      }
    }
  }
  log_exit() ;
  return 0 ;
}
