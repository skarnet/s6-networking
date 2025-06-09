/* ISC license. */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <skalibs/gccattributes.h>
#include <skalibs/uint16.h>
#include <skalibs/uint64.h>
#include <skalibs/bytestr.h>
#include <skalibs/types.h>
#include <skalibs/fmtscan.h>
#include <skalibs/prog.h>
#include <skalibs/strerr.h>
#include <skalibs/gol.h>
#include <skalibs/tai.h>
#include <skalibs/exec.h>
#include <skalibs/unix-timed.h>

#define NAME "proxy-server"
#define USAGE NAME "[ --disable-v1 | --disable-v2 ] [ -v verbosity ] [ -t timeout ] prog..."
#define dieusage() strerr_dieusage(100, USAGE)
#define dienomem() strerr_diefu1sys(111, "stralloc_catb")

static unsigned int verbosity = 1 ;
static tain deadline ;


 /* v2 */

struct v2hdr_s
{
  uint8_t version : 4 ;
  uint8_t command : 4 ;
  uint8_t family : 4 ;
  uint8_t proto : 4 ;
  uint16_t len ;
} ;

static inline void v2hdr_unpack (char const *s, struct v2hdr_s *h)
{
  h->version = s[0] >> 4 ;
  h->command = s[0] & 0xf ;
  h->family = s[1] >> 4 ;
  h->proto = s[1] & 0xf ;
  uint16_unpack_big(s+2, &h->len) ;
}

static inline void skip (uint16_t x)
{
  if (!x) return ;
  char buf[x] ;
  size_t r = timed_read_g(0, buf, x, &deadline) ;
  if (r < x)
  {
    char fmtr[UINT16_FMT] ;
    char fmtx[UINT16_FMT] ;
    fmtr[uint16_fmt(fmtr, r)] = 0 ;
    fmtx[uint16_fmt(fmtx, x)] = 0 ;
    strerr_diefu4sys(111, "skip ", fmtx, " bytes: only got ", fmtr) ;
  }
}

static void process_v2_extensions (char const *s, uint16_t len, int sub)
{
  while (len)
  {
    uint16_t n ;
    char c ;
    if (len < 3) strerr_dief3x(1, "invalid TLV encoding in ", sub ? "sub-" : "", "extension") ;
    c = *s++ ;
    uint16_unpack_big(s, &n) ; s += 2 ; len -= 3 ;
    if (n > len) strerr_dief3x(1, "invalid TLV encoding in ", sub ? "sub-" : "", "extension") ;
    switch (c)
    {
      case 0x02 :  /* PP2_TYPE_AUTHORITY */
      {
        char tmp[n+1] ;
        if (sub) strerr_dief1x(1, "invalid sub-extension type") ;
        memcpy(tmp, s, n) ; tmp[n] = 0 ;
        if (!env_mexec("SSL_TLS_SNI_SERVERNAME", tmp)) dienomem() ;
        break ;
      }
      case 0x20 :  /* PP2_TYPE_SSL */
        if (n < 5) strerr_dief1x(1, "invalid sub-TLV encoding in SSL extension") ;
        if (*s & 0x01) process_v2_extensions(s + 5, n - 5, 1) ;
        break ;

      case 0x21 :  /* PP2_SUBTYPE_SSL_VERSION */
      {
        char tmp[n+1] ;
        if (!sub) strerr_dief1x(1, "invalid main extension type") ;
        memcpy(tmp, s, n) ; tmp[n] = 0 ;
        if (!env_mexec("SSL_PROTOCOL", tmp)) dienomem() ;
        break ;
      }
      case 0x22 :  /* PP2_SUBTYPE_SSL_CN */
      {
        char tmp[n+1] ;
        if (!sub) strerr_dief1x(1, "invalid main extension type") ;
        memcpy(tmp, s, n) ; tmp[n] = 0 ;
        if (!env_mexec("SSL_PEER_CERT_CN", tmp)) dienomem() ;
        break ;
      }
      case 0x23 :  /* PP2_SUBTYPE_SSL_CIPHER */
      {
        char tmp[n+1] ;
        if (!sub) strerr_dief1x(1, "invalid main extension type") ;
        memcpy(tmp, s, n) ; tmp[n] = 0 ;
        if (!env_mexec("SSL_CIPHER", tmp)) dienomem() ;
        break ;
      }
      default : break ;
    }
    s += n ; len -= n ;
  }
}

static void do_v2 (struct v2hdr_s const *h)
{
  static uint16_t const famaddrlen[3] = { 12, 36, 216 } ;
  if (h->version != 2) strerr_dief1x(1, "invalid version") ;
  if (h->command == 0 && h->family && verbosity)
  {
    char fmt[UINT16_FMT] ;
    fmt[uint16_fmt(fmt, h->family)] = 0 ;
    strerr_warnw2x("received LOCAL command with family set to ", fmt) ;
  }
  else if (h->command > 1)
    strerr_dief1x(1, "invalid command") ;
  if (h->family > 3)
    strerr_dief1x(1, "invalid family") ;
  if (!h->family || !h->proto)
    skip(h->len) ;
  else if (h->proto > 2)
    strerr_dief1x(1, "invalid transport protocol") ;
  else if (h->proto == 2)
    strerr_dief1x(2, "unsupported transport protocol: datagram") ;
  else if (h->len < famaddrlen[h->family - 1])
    strerr_dief1x(1, "invalid address length") ;
  else
  {
    char buf[h->len] ;
    size_t r = timed_read_g(0, buf, h->len, &deadline) ;
    if (r < h->len) strerr_diefu1sys(111, "read address block") ;
    switch (h->family)
    {
      case 1 :
      case 2 :
      {
        uint16_t remoteport, localport ;
        char remoteip[IP6_FMT] ;
        char localip[IP6_FMT] ;
        char remoteportfmt[UINT16_FMT] ;
        char localportfmt[UINT16_FMT] ;
        remoteip[h->family == 2 ? ip6_fmt(remoteip, buf) : ip4_fmt(remoteip, buf)] = 0 ;
        localip[h->family == 2 ? ip6_fmt(localip, buf+16) : ip4_fmt(localip, buf+4)] = 0 ;
        uint16_unpack_big(buf + 24 * h->family - 16, &remoteport) ;
        uint16_unpack_big(buf + 24 * h->family - 14, &localport) ;
        remoteportfmt[uint16_fmt(remoteportfmt, remoteport)] = 0 ;
        localportfmt[uint16_fmt(localportfmt, localport)] = 0 ;

        if (!env_mexec("PROTO", "TCP")
         || !env_mexec("TCPREMOTEIP", remoteip)
         || !env_mexec("TCPLOCALIP", localip)
         || !env_mexec("TCPREMOTEPORT", remoteportfmt)
         || !env_mexec("TCPLOCALPORT", localportfmt)) dienomem() ;
        break ;
      }
      default :
      {
        char localpath[109] ;
        strncpy(localpath, buf + 108, 108) ;
        localpath[108] = 0 ;
        buf[108] = 0 ;
        if (!env_mexec("PROTO", "IPC")
         || !env_mexec("IPCREMOTEPATH", buf)
         || !env_mexec("IPCLOCALPATH", localpath)) dienomem() ;
        break ;
      }
    }
    if (h->len > famaddrlen[h->family-1])
      process_v2_extensions(buf + famaddrlen[h->family-1], h->len - famaddrlen[h->family-1], 0) ;
  }
}

static void maybe_v2 (char const *buf)
{
  struct v2hdr_s h ;
  if (memcmp(buf, "\r\n\r\n\0\r\nQUIT\n", 12)) strerr_dief1x(1, "invalid magic") ;
  v2hdr_unpack(buf + 12, &h) ;
  do_v2(&h) ;
}

static inline void v2 (void)
{
  char buf[16] ;
  size_t r = timed_read_g(0, buf, 16, &deadline) ;
  if (r < 16)
  {
    if (!errno) errno = EPIPE ;
    strerr_diefu1sys(111, "read from stdin") ;
  }
  maybe_v2(buf) ;
}


 /* v1 */

static void do_v1 (char const *prebuf)
{
  uint16_t len = byte_chr(prebuf, 9, '\n') ;
  if (len < 8) strerr_dief1x(1, "invalid PROXY line") ;
  if (len == 8 && !memcmp(prebuf, "UNKNOWN\r", 8)) return ;

  int is6 ;
  char buf[102] ;
  memcpy(buf, prebuf, 9) ; len = 9 ;
  for (; len < 101 ; len++)
  {
    if (!timed_read_g(0, buf + len, 1, &deadline))
      strerr_diefu1sys(111, "read from stdin") ;
    if (buf[len] == '\n') break ;
  }
  if (len >= 101) strerr_dief1x(1, "PROXY line too long") ;
  if (buf[len-1] != '\r') strerr_dief1x(1, "invalid PROXY line") ;
  if (!memcmp(buf, "UNKNOWN ", 8)) return ;
  if (memcmp(buf, "TCP", 3)) strerr_dief1x(1, "invalid protocol in PROXY line") ;
  if (buf[3] == '6') is6 = 1 ;
  else if (buf[3] == '4') is6 = 0 ;
  else strerr_dief1x(1, "invalid protocol in PROXY line") ;
  
  char remoteip[16] ;
  char localip[16] ;
  uint16_t remoteport, localport ;
  uint16_t pos = 5, m ;
  m = is6 ? ip6_scan(buf + pos, remoteip) : ip4_scan(buf + pos, remoteip) ;
  if (!m) strerr_dief1x(1, "invalid remote ip in PROXY line") ;
  pos += m ;
  if (buf[pos++] != ' ') strerr_dief1x(1, "invalid PROXY line") ;
  m = is6 ? ip6_scan(buf + pos, localip) : ip4_scan(buf + pos, localip) ;
  if (!m) strerr_dief1x(1, "invalid local ip in PROXY line") ;
  pos += m ;
  if (buf[pos++] != ' ') strerr_dief1x(1, "invalid PROXY line") ;
  m = uint16_scan(buf + pos, &remoteport) ;
  if (!m) strerr_dief1x(1, "invalid remote port in PROXY line") ;
  pos += m ;
  if (buf[pos++] != ' ') strerr_dief1x(1, "invalid PROXY line") ;
  m = uint16_scan(buf + pos, &localport) ;
  if (!m) strerr_dief1x(1, "invalid local port in PROXY line") ;
  pos += m ;
  if (pos != len - 1) strerr_dief1x(1, "invalid PROXY line") ;

  if (!env_mexec("PROTO", "TCP")) dienomem() ;
  pos = 0 ;
  m = is6 ? ip6_fmt(buf + pos, remoteip) : ip4_fmt(buf + pos, remoteip) ;
  buf[pos + m++] = 0 ;
  if (!env_mexec("TCPREMOTEIP", buf + pos)) dienomem() ;
  pos += m ;
  m = is6 ? ip6_fmt(buf + pos, localip) : ip4_fmt(buf + pos, localip) ;
  buf[pos + m++] = 0 ;
  if (!env_mexec("TCPLOCALIP", buf + pos)) dienomem() ;
  pos += m ;
  m = uint16_fmt(buf + pos, remoteport) ;
  buf[pos + m++] = 0 ;
  if (!env_mexec("TCPREMOTEPORT", buf + pos)) dienomem() ;
  pos += m ;
  m = uint16_fmt(buf + pos, localport) ;
  buf[pos + m++] = 0 ;
  if (!env_mexec("TCPLOCALPORT", buf + pos)) dienomem() ;
  pos += m ;
}

static inline void v1 (void)
{
  char buf[15] ;
  size_t r = timed_read_g(0, buf, 15, &deadline) ;
  if (r < 15)
  {
    if (!errno) errno = EPIPE ;
    strerr_diefu1sys(111, "read from stdin") ;
  }
  if (memcmp(buf, "PROXY ", 6)) strerr_dief1x(1, "invalid magic") ;
  do_v1(buf + 6) ;
}

static void both (void)
{
  char buf[16] ;
  size_t r = timed_read_g(0, buf, 15, &deadline) ;
  if (r < 15)
  {
    if (!errno) errno = EPIPE ;
    strerr_diefu1sys(111, "read from stdin") ;
  }
  if (!memcmp(buf, "PROXY ", 6)) do_v1(buf + 6) ;
  else if (!timed_read_g(0, buf + 15, 1, &deadline)) strerr_diefu1sys(111, "read from stdin") ;
  maybe_v2(buf) ;
}

enum main_golb_e
{
  MAIN_GOLB_V1,
  MAIN_GOLB_V2,
  MAIN_GOLB_N
} ;

enum main_gola_e
{
  MAIN_GOLA_TIMEOUT,
  MAIN_GOLA_VERBOSITY,
  MAIN_GOLA_N
} ;

int main (int argc, char const *const *argv)
{
  static gol_bool const main_golb[4] =
  {
    { .so = '1', .lo = "disable-v2", .set = 0, .mask = 1 << MAIN_GOLB_V2 },
    { .so = '2', .lo = "disable-v1", .set = 0, .mask = 1 << MAIN_GOLB_V1 },
  } ;
  static gol_arg const main_gola[MAIN_GOLA_N] =
  {
    { .so = 't', .lo = "timeout", .i = MAIN_GOLA_TIMEOUT },
    { .so = 'v', .lo = "verbosity", .i = MAIN_GOLA_VERBOSITY }
  } ;

  uint64_t golb = 1 << MAIN_GOLB_V1 | 1 << MAIN_GOLB_V2 ;
  PROG = NAME ;

  {
    char const *gola[MAIN_GOLA_N] = { 0 } ;
    tain tto = TAIN_INFINITE_RELATIVE ;
    unsigned int t = 0 ;
    unsigned int golc = gol_main(argc, argv, main_golb, 4, main_gola, MAIN_GOLA_N, &golb, gola) ;
    argc -= golc ; argv += golc ;
    if (!argc) dieusage() ;
    if (gola[MAIN_GOLA_TIMEOUT] && !uint0_scan(gola[MAIN_GOLA_TIMEOUT], &t))
      strerr_dief2x(100, "timeout", " must be an unsigned integer") ;
    if (gola[MAIN_GOLA_VERBOSITY] && !uint0_scan(gola[MAIN_GOLA_VERBOSITY], &verbosity))
      strerr_dief2x(100, "verbosity", " must be an unsigned integer") ;

    if (t) tain_from_millisecs(&tto, t) ;
    tain_now_set_stopwatch_g() ;
    tain_add_g(&deadline, &tto) ;
  }

  char prog_storage[PROG_pid_len(NAME)] ;
  PROG_pid_fill(prog_storage, NAME) ;
  PROG = prog_storage ;

  uint64_t ver = golb & (1 << MAIN_GOLB_V1 | 1 << MAIN_GOLB_V2) ;
  if (ver == (1 << MAIN_GOLB_V1 | 1 << MAIN_GOLB_V2)) both() ;
  else if (ver == 1 << MAIN_GOLB_V2) v2() ;
  else if (ver == 1 << MAIN_GOLB_V1) v1() ;
  else if (verbosity) strerr_warnw1x("both versions disabled, no proxy protocol expected") ;
  xmexec(argv) ;
}
