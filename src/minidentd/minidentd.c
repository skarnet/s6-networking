/* ISC license. */

#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <skalibs/types.h>
#include <skalibs/allreadwrite.h>
#include <skalibs/bytestr.h>
#include <skalibs/fmtscan.h>
#include <skalibs/buffer.h>
#include <skalibs/strerr2.h>
#include <skalibs/stralloc.h>
#include <skalibs/env.h>
#include <skalibs/djbunix.h>
#include <skalibs/sgetopt.h>
#include <skalibs/tai.h>
#include <skalibs/random.h>
#include <skalibs/unix-timed.h>
#include "mgetuid.h"

#define USAGE "minidentd [ -v ] [ -n | -i | -r ] [ -y file ] [ -t timeout ]"
#define dieusage() strerr_dieusage(100, USAGE)


static int how = 0 ;
static int flagverbose = 0 ;
static char const *userfile = ".ident" ;

static tain_t deadline ;
static unsigned int nquery = 0 ;
static char logfmt[UINT_FMT] ;

#define godecimal(s) while (*(s) && !strchr("0123456789", *(s))) (s)++

static int parseline (char const *s, uint16_t *localport, uint16_t *remoteport)
{
  size_t pos ;
  godecimal(s) ;
  if (!*s) return 0 ;
  pos = uint16_scan(s, localport) ;
  if (!pos) return 0 ;
  s += pos ;
  if (!*s) return 0 ;
  s += str_chr(s, ',') ;
  if (*s) s++ ;
  godecimal(s) ;
  if (!*s) return 0 ;
  if (!uint16_scan(s, remoteport)) return 0 ;
  return 1 ;
}

static void formatlr (char *s, uint16_t lp, uint16_t rp)
{
  s += uint16_fmt(s, lp) ;
  *s++ = ',' ;
  *s++ = ' ' ;
  s += uint16_fmt(s, rp) ;
  *s = 0 ;
}

static void reply (char const *s, char const *r, char const *info)
{
  buffer_puts(buffer_1small, s) ;
  buffer_put(buffer_1small, " : ", 3) ;
  buffer_puts(buffer_1small, r) ;
  buffer_put(buffer_1small, " : ", 3) ;
  buffer_puts(buffer_1small, info) ;
  buffer_put(buffer_1small, "\r\n", 2) ;
  if (!buffer_timed_flush_g(buffer_1small, &deadline))
    strerr_diefu1sys(111, "write to stdout") ;
}

static void logquery (char const *s)
{
  if (!flagverbose) return ;
  buffer_puts(buffer_2, PROG) ;
  buffer_puts(buffer_2, ": info : query ") ;
  logfmt[uint_fmt(logfmt, ++nquery)] = 0 ;
  buffer_puts(buffer_2, logfmt) ;
  buffer_put(buffer_2, ": ", 2) ;
  buffer_puts(buffer_2, s) ;
  buffer_putflush(buffer_2, "\n", 1) ;
}

static void logreply (char const *type, char const *reply1, char const *reply2)
{
  if (!flagverbose) return ;
  buffer_puts(buffer_2, PROG) ;
  buffer_puts(buffer_2, ": info: reply type ") ;
  buffer_puts(buffer_2, type) ;
  buffer_put(buffer_2, ": ", 2) ;
  buffer_puts(buffer_2, logfmt) ;
  buffer_put(buffer_2, ": ", 2) ;
  buffer_puts(buffer_2, reply1) ;
  buffer_put(buffer_2, ": ", 2) ;
  buffer_puts(buffer_2, reply2) ;
  buffer_putflush(buffer_2, "\n", 1) ;
}

static int userident (char *s, char const *home)
{
  int fd ;
  size_t r = 1 ;
  {
    size_t homelen = strlen(home) ;
    size_t userlen = strlen(userfile) ;
    char tmp[homelen + userlen + 2] ;
    memcpy(tmp, home, homelen) ;
    tmp[homelen] = '/' ;
    memcpy(tmp + homelen + 1, userfile, userlen + 1) ;
    fd = open_readb(tmp) ;
  }  
  if (fd == -1) return (errno != ENOENT) ? -1 : 0 ;
  if (how == 1)
  {
    fd_close(fd) ;
    return 1 ;
  }
  r = allread(fd, s, 14) ;
  fd_close(fd) ;
  if (!r) return 1 ;
  s[r] = 0 ;
  s[byte_chr(s, r, '\n')] = 0 ;
  return 2 ;
}


static void doit (char const *s, ip46_t const *localaddr, ip46_t const *remoteaddr)
{
  char lr[15] ;
  uint16_t localport, remoteport ;
  struct passwd *pw ;
  uid_t uid ;
  if (!parseline(s, &localport, &remoteport))
  {
    reply("0, 0", "ERROR", "INVALID-PORT") ;
    return ;
  }
  formatlr(lr, localport, remoteport) ;
  logquery(lr) ;

  uid = mgetuid(localaddr, localport, remoteaddr, remoteport) ;
  if (uid == -2)
  {
    strerr_warnwu1sys("get uid") ;
    reply(lr, "ERROR", "UNKNOWN-ERROR") ;
    return ;
  }
  else if (uid == -1)
  {
    reply(lr, "ERROR", "NO-USER") ;
    logreply("error", "ERROR", "NO-USER") ;
    return ;
  }

  if (how == 3)
  {
    char name[9] ;
    char fmt[4 + UINT_FMT] = "uid " ;
    fmt[4 + uint_fmt(fmt+4, uid)] = 0 ;
    random_name(name, 8) ;
    reply(lr, "UNIX", name) ;
    logreply("random", fmt, name) ;
    return ;
  }

  pw = getpwuid(uid) ;
  if (!pw)
  {
    char fmt[UINT_FMT] ;
    fmt[uint_fmt(fmt, uid)] = 0 ;
    strerr_warnw2x("unknown uid ", fmt) ;
    reply(lr, "ERROR", "UNKNOWN-ERROR") ;
    return ;
  }

  if (how)
  {
    char s[15] ;
    int r = userident(s, pw->pw_dir) ;
    if ((how == 1) || (r == 1))
    {
      reply(lr, "ERROR", "HIDDEN-USER") ;
      logreply("user", "ERROR", "HIDDEN-USER") ;
      return ;
    }
    else if (r == 2)
    {
      reply(lr, "USERID : UNIX", s) ;
      logreply("user", "UNIX", s) ;
      return ;
    }
  }

  reply(lr, "USERID : UNIX", pw->pw_name) ;
  logreply("user", "UNIX", pw->pw_name) ;
}


int main (int argc, char const *const *argv, char const *const *envp)
{
  stralloc line = STRALLOC_ZERO ;
  tain_t tto ;
  ip46_t localaddr, remoteaddr ;
  PROG = "minidentd" ;

  {
    subgetopt_t l = SUBGETOPT_ZERO ;
    unsigned int t = 0 ;
    for (;;)
    {
      int opt = subgetopt_r(argc, argv, "vniry:t:", &l) ;
      if (opt == -1) break ;
      switch (opt)
      {
        case 'v' : flagverbose = 1 ; break ;
        case 'n' : how = 1 ; break ;
        case 'i' : how = 2 ; break ;
        case 'r' : how = 3 ; break ;
        case 'y' : userfile = l.arg ; break ;
        case 't' : if (!uint0_scan(l.arg, &t)) dieusage() ; break ;
        default : dieusage() ;
      }
    }
    if (t) tain_from_millisecs(&tto, t) ; else tto = tain_infinite_relative ;
    argc -= l.ind ; argv += l.ind ;
  }

  {
    char const *proto = env_get2(envp, "PROTO") ;
    if (!proto) strerr_dienotset(100, "PROTO") ;
    {
      char const *x ;
      size_t protolen = strlen(proto) ;
      char tmp[protolen + 9] ;
      memcpy(tmp, proto, protolen) ;
      memcpy(tmp + protolen, "LOCALIP", 8) ;
      x = env_get2(envp, tmp) ;
      if (!x) strerr_dienotset(100, tmp) ;
      if (!ip46_scan(x, &localaddr)) strerr_dieinvalid(100, tmp) ;
      memcpy(tmp + protolen, "REMOTEIP", 9) ;
      x = env_get2(envp, tmp) ;
      if (!x) strerr_dienotset(100, tmp) ;
      if (!ip46_scan(x, &remoteaddr)) strerr_dieinvalid(100, tmp) ;
    }
  }

  if (ip46_is6(&localaddr) != ip46_is6(&remoteaddr))
    strerr_dief1x(100, "local and remote address not of the same family") ;
  if (!random_init())
    strerr_diefu1sys(111, "init random generator") ;

  tain_now_set_stopwatch_g() ;
                                                                                    
  for (;;)
  {
    int r ;
    line.len = 0 ;
    tain_add_g(&deadline, &tto) ;
    r = timed_getln_g(buffer_0small, &line, '\n', &deadline) ;
    if (r == -1)
    {
      if (errno == ETIMEDOUT) return 1 ;
      else strerr_diefu1sys(111, "read from stdin") ;
    }
    if (!r) break ;
    line.s[line.len - 1] = 0 ;
    doit(line.s, &localaddr, &remoteaddr) ;
  }
  return 0 ;
}
