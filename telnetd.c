/* vi: set sw=4 ts=4: */
/*
 * Simple telnet server
 * Bjorn Wesen, Axis Communications AB (bjornw@axis.com)
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 *
 * ---------------------------------------------------------------------------
 * (C) Copyright 2000, Axis Communications AB, LUND, SWEDEN
 ****************************************************************************
 *
 * The telnetd manpage says it all:
 *
 * Telnetd operates by allocating a pseudo-terminal device (see pty(4)) for
 * a client, then creating a login process which has the slave side of the
 * pseudo-terminal as stdin, stdout, and stderr. Telnetd manipulates the
 * master side of the pseudo-terminal, implementing the telnet protocol and
 * passing characters between the remote client and the login process.
 *
 * Vladimir Oleynik <dzo@simtreas.ru> 2001
 * Set process group corrections, initial busybox port
 */

//usage:#define telnetd_trivial_usage
//usage:       "[OPTIONS]"
//usage:#define telnetd_full_usage "\n\n"
//usage:       "Handle incoming telnet connections"
//usage:	IF_NOT_FEATURE_TELNETD_STANDALONE(" via inetd") "\n"
//usage:     "\n	-l LOGIN	Exec LOGIN on connect"
//usage:     "\n	-f ISSUE_FILE	Display ISSUE_FILE instead of /etc/issue"
//usage:     "\n	-K		Close connection as soon as login exits"
//usage:     "\n			(normally wait until all programs close slave pty)"
//usage:	IF_FEATURE_TELNETD_STANDALONE(
//usage:     "\n	-p PORT		Port to listen on"
//usage:     "\n	-b ADDR[:PORT]	Address to bind to"
//usage:     "\n	-F		Run in foreground"
//usage:     "\n	-i		Inetd mode"
//usage:	IF_FEATURE_TELNETD_INETD_WAIT(
//usage:     "\n	-w SEC		Inetd 'wait' mode, linger time SEC"
//usage:     "\n	-S		Log to syslog (implied by -i or without -F and -w)"
//usage:	)
//usage:	)

#define DEBUG 0

#if 1
#define SO_TELNETD   1
#endif

#if SO_TELNETD
/* system header file */

#include <pthread.h>
#include <stdio.h>
#include <sys/types.h>
#include <pty.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <signal.h>
#include <resolv.h>
#include <stdlib.h>
#include <utmpx.h>
#include <stddef.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/un.h>
#include <stdarg.h>
#include <termios.h>
#include <unistd.h>
#include <sys/utsname.h>


#else

#include "libbb.h"

#endif

#include <syslog.h>

#if DEBUG
# define TELCMDS
# define TELOPTS
#endif
#include <arpa/telnet.h>

#if SO_TELNETD
/* marco */



#define IF_FEATURE_TELNETD_INETD_WAIT(...) __VA_ARGS__
#define IF_FEATURE_TELNETD_STANDALONE(...) __VA_ARGS__

#define IF_NOT_FEATURE_TELNETD_STANDALONE(...)
#define CONFIG_FEATURE_TELNETD_INETD_WAIT 1
#define ENABLE_FEATURE_TELNETD_INETD_WAIT 1

#define ENABLE_FEATURE_TELNETD_STANDALONE 1

#define xzalloc malloc
#define safe_read   read

#define ENABLE_FEATURE_DEVPTS   1
#define HAVE_PTSNAME_R 1
#define FAST_FUNC

#define ENABLE_FEATURE_IPV6 0
#define ENABLE_FEATURE_DEVPTS 1
#define ENABLE_FEATURE_UTMP 0

#define MAIN_EXTERNALLY_VISIBLE

#define bb_perror_msg_and_die       printf
#define bb_perror_msg               printf
#define bb_error_msg                printf

#define safe_write  write
#define safe_read   read

#define ENABLE_FEATURE_UNIX_LOCAL 0
#define IGNORE_PORT NI_NUMERICSERV
#define BB_EXECVP(prog,cmd)     execvp(prog,cmd)
#define bb_dev_null "/dev/null"
#define IF_FEATURE_IPV6(...) __VA_ARGS__
//#define BUFSIZ 4096

/* Providing hard guarantee on minimum size (think of BUFSIZ == 128) */
enum { COMMON_BUFSIZE = (BUFSIZ >= 256*sizeof(void*) ? BUFSIZ+1 : 256*sizeof(void*)) };
char bb_common_bufsiz1[COMMON_BUFSIZE];

enum { GETPTY_BUFSIZE = 16 }; /* more than enough for "/dev/ttyXXX" */


# define ALIGN1 __attribute__((aligned(1)))
# define ALIGN2 __attribute__((aligned(2)))
# define ALIGN4 __attribute__((aligned(4)))

#define UNUSED_PARAM __attribute__ ((__unused__))
#define xstrdup strdup
#define xopen   open
#define xdup2   dup2

#define fork_or_rexec(a)   fork()

#define ENABLE_FEATURE_CLEAN_UP 0
#define IF_NOT_FEATURE_IPV6(...)

#define xfunc_die()  exit(0)
#define xmalloc     malloc

#endif


#if SO_TELNETD
/* struct define */


typedef struct len_and_sockaddr {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
		struct sockaddr_in6 sin6;
#endif
	} u;
} len_and_sockaddr;

enum {
	LSA_LEN_SIZE = offsetof(len_and_sockaddr, u),
	LSA_SIZEOF_SA = sizeof(
		union {
			struct sockaddr sa;
			struct sockaddr_in sin;
#if ENABLE_FEATURE_IPV6
			struct sockaddr_in6 sin6;
#endif
		}
	)
};

const int const_int_1 = 1;
/* explicitly = 0, otherwise gcc may make it a common variable
 * and it will end up in bss */
const int const_int_0 = 0;


uint32_t option_mask32;

const char *opt_complementary;
const char *applet_name = "debug stuff usage";
int logmode = 1;
#define LOGMODE_STDIO   1
#define LOGMODE_SYSLOG  2
#define xatou16     atoi


#endif

struct tsession {
	struct tsession *next;
	pid_t shell_pid;
	int sockfd_read;
	int sockfd_write;
	int ptyfd;

	/* two circular buffers */
	/*char *buf1, *buf2;*/
/*#define TS_BUF1(ts) ts->buf1*/
/*#define TS_BUF2(ts) TS_BUF2(ts)*/
#define TS_BUF1(ts) ((unsigned char*)(ts + 1))
#define TS_BUF2(ts) (((unsigned char*)(ts + 1)) + BUFSIZE)
	int rdidx1, wridx1, size1;
	int rdidx2, wridx2, size2;
};

/* Two buffers are directly after tsession in malloced memory.
 * Make whole thing fit in 4k */
enum { BUFSIZE = (4 * 1024 - sizeof(struct tsession)) / 2 };


/* Globals */
struct globals {
	struct tsession *sessions;
	const char *loginpath;
	const char *issuefile;
	int maxfd;
} FIX_ALIASING;
#define G (*(struct globals*)&bb_common_bufsiz1)
#define INIT_G() do { \
	G.loginpath = "/bin/login"; \
	G.issuefile = "/etc/issue.net"; \
} while (0)


#if SO_TELNETD
/* function */
static unsigned long long ret_ERANGE(void)
{
	errno = ERANGE; /* this ain't as small as it looks (on glibc) */
	return ULLONG_MAX;
}

static unsigned long long handle_errors(unsigned long long v, char **endp)
{
	char next_ch = **endp;

	/* errno is already set to ERANGE by strtoXXX if value overflowed */
	if (next_ch) {
		/* "1234abcg" or out-of-range? */
		if (isalnum(next_ch) || errno)
			return ret_ERANGE();
		/* good number, just suspicious terminator */
		errno = EINVAL;
	}
	return v;
}

unsigned long FAST_FUNC bb_strtoul(const char *arg, char **endp, int base)
{
	unsigned long v;
	char *endptr;

	if (!endp) endp = &endptr;
	*endp = (char*) arg;

	if (!isalnum(arg[0])) return ret_ERANGE();
	errno = 0;
	v = strtoul(arg, endp, base);
	return handle_errors(v, endp);
}
unsigned bb_strtou(const char *arg, char **endp, int base)
{ return bb_strtoul(arg, endp, base); }


char* FAST_FUNC strncpy_IFNAMSIZ(char *dst, const char *src)
{
#ifndef IFNAMSIZ
	enum { IFNAMSIZ = 16 };
#endif
	return strncpy(dst, src, IFNAMSIZ);
}

FILE* FAST_FUNC fopen_for_read(const char *path)
{
	return fopen(path, "r");
}

void FAST_FUNC print_login_issue(const char *issue_file, const char *tty)
{
	FILE *fp;
	int c;
	char buf[256+1];
	const char *outbuf;
	time_t t;
	struct utsname uts;

	time(&t);
	uname(&uts);

	puts("\r");  /* start a new line */

	fp = fopen_for_read(issue_file);
	if (!fp)
		return;
	while ((c = fgetc(fp)) != EOF) {
		outbuf = buf;
		buf[0] = c;
		buf[1] = '\0';
		if (c == '\n') {
			buf[1] = '\r';
			buf[2] = '\0';
		}
		if (c == '\\' || c == '%') {
			c = fgetc(fp);
			switch (c) {
			case 's':
				outbuf = uts.sysname;
				break;
			case 'n':
			case 'h':
				outbuf = uts.nodename;
				break;
			case 'r':
				outbuf = uts.release;
				break;
			case 'v':
				outbuf = uts.version;
				break;
			case 'm':
				outbuf = uts.machine;
				break;
#if !SO_TELNETD
/* The field domainname of struct utsname is Linux specific. */
#if defined(__linux__)
			case 'D':
			case 'o':
				outbuf = uts.domainname;
				break;
#endif
			case 'd':
				strftime(buf, sizeof(buf), fmtstr_d, localtime(&t));
				break;
			case 't':
				strftime_HHMMSS(buf, sizeof(buf), &t);
				break;
#endif
			case 'l':
				outbuf = tty;
				break;
			default:
				buf[0] = c;
			}
		}
		fputs(outbuf, stdout);
	}
	fclose(fp);
	fflush_all();
}
/* Like strncpy but make sure the resulting string is always 0 terminated. */
char* FAST_FUNC safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size) return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

int xgetpty(char *line)
{
	int p;

#if ENABLE_FEATURE_DEVPTS
	p = open("/dev/ptmx", O_RDWR);
	if (p >= 0) {
		grantpt(p); /* chmod+chown corresponding slave pty */
		unlockpt(p); /* (what does this do?) */
#ifndef HAVE_PTSNAME_R
		{
			const char *name;
			name = ptsname(p); /* find out the name of slave pty */
			if (!name) {
				bb_perror_msg_and_die("ptsname error (is /dev/pts mounted?)");
			}
			safe_strncpy(line, name, GETPTY_BUFSIZE);
		}
#else
		/* find out the name of slave pty */
		if (ptsname_r(p, line, GETPTY_BUFSIZE-1) != 0) {
			bb_perror_msg_and_die("ptsname error (is /dev/pts mounted?)");
		}
		line[GETPTY_BUFSIZE-1] = '\0';
#endif
		return p;
	}
#else
	struct stat stb;
	int i;
	int j;

	strcpy(line, "/dev/ptyXX");

	for (i = 0; i < 16; i++) {
		line[8] = "pqrstuvwxyzabcde"[i];
		line[9] = '0';
		if (stat(line, &stb) < 0) {
			continue;
		}
		for (j = 0; j < 16; j++) {
			line[9] = j < 10 ? j + '0' : j - 10 + 'a';
			if (DEBUG)
				fprintf(stderr, "Trying to open device: %s\n", line);
			p = open(line, O_RDWR | O_NOCTTY);
			if (p >= 0) {
				line[5] = 't';
				return p;
			}
		}
	}
#endif /* FEATURE_DEVPTS */

}


int FAST_FUNC setsockopt_int(int fd, int level, int optname, int optval)
{
	return setsockopt(fd, level, optname, &optval, sizeof(int));
}


int FAST_FUNC setsockopt_SOL_SOCKET_int(int fd, int optname, int optval)
{
	return setsockopt_int(fd, SOL_SOCKET, optname, optval);
}


int FAST_FUNC setsockopt_SOL_SOCKET_1(int fd, int optname)
{
	return setsockopt_SOL_SOCKET_int(fd, optname, 1);
}

int FAST_FUNC setsockopt_keepalive(int fd)
{
	return setsockopt_SOL_SOCKET_1(fd, SO_KEEPALIVE);
}

static len_and_sockaddr* get_lsa(int fd, int (*get_name)(int fd, struct sockaddr *addr, socklen_t *addrlen))
{
	len_and_sockaddr lsa;
	len_and_sockaddr *lsa_ptr;

	lsa.len = LSA_SIZEOF_SA;
	if (get_name(fd, &lsa.u.sa, &lsa.len) != 0)
		return NULL;

	lsa_ptr = xzalloc(LSA_LEN_SIZE + lsa.len);
	if (lsa.len > LSA_SIZEOF_SA) { /* rarely (if ever) happens */
		lsa_ptr->len = lsa.len;
		get_name(fd, &lsa_ptr->u.sa, &lsa_ptr->len);
	} else {
		memcpy(lsa_ptr, &lsa, LSA_LEN_SIZE + lsa.len);
	}
	return lsa_ptr;
}



len_and_sockaddr* FAST_FUNC get_peer_lsa(int fd)
{
	return get_lsa(fd, getpeername);
}


/* Turn on nonblocking I/O on a fd */
int FAST_FUNC ndelay_on(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags & O_NONBLOCK)
		return flags;
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	return flags;
}

int FAST_FUNC ndelay_off(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (!(flags & O_NONBLOCK))
		return flags;
	fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	return flags;
}

void FAST_FUNC close_on_exec_on(int fd)
{
	fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int FAST_FUNC fflush_all(void)
{
	return fflush(NULL);
}

void FAST_FUNC bb_signals(int sigs, void (*f)(int))
{
	int sig_no = 0;
	int bit = 1;

	while (sigs) {
		if (sigs & bit) {
			sigs -= bit;
			signal(sig_no, f);
		}
		sig_no++;
		bit <<= 1;
	}
}
// Die with an error message if we can't malloc() enough space and do an
// sprintf() into that space.
char* FAST_FUNC xasprintf(const char *format, ...)
{
	va_list p;
	int r;
	char *string_ptr;

	va_start(p, format);
	r = vasprintf(&string_ptr, format, p);
	va_end(p);

	if (r < 0)
//		bb_error_msg_and_die(bb_msg_memory_exhausted);
	return string_ptr;
}

static char* FAST_FUNC sockaddr2str(const struct sockaddr *sa, int flags)
{
	char host[128];
	char serv[16];
	int rc;
	socklen_t salen;

	if (ENABLE_FEATURE_UNIX_LOCAL && sa->sa_family == AF_UNIX) {
		struct sockaddr_un *sun = (struct sockaddr_un *)sa;

		return xasprintf("local:%.*s",
				(int) sizeof(sun->sun_path),
				sun->sun_path);
	}
	

	salen = LSA_SIZEOF_SA;
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET)
		salen = sizeof(struct sockaddr_in);
	if (sa->sa_family == AF_INET6)
		salen = sizeof(struct sockaddr_in6);
#endif
	rc = getnameinfo(sa, salen,
			host, sizeof(host),
	/* can do ((flags & IGNORE_PORT) ? NULL : serv) but why bother? */
			serv, sizeof(serv),
			/* do not resolve port# into service _name_ */
			flags | NI_NUMERICSERV
	);
	if (rc)
		return NULL;
	if (flags & IGNORE_PORT)
		return xstrdup(host);
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET6) {
		if (strchr(host, ':')) /* heh, it's not a resolved hostname */
			return xasprintf("[%s]:%s", host, serv);
		/*return xasprintf("%s:%s", host, serv);*/
		/* - fall through instead */
	}
#endif
	/* For now we don't support anything else, so it has to be INET */
	/*if (sa->sa_family == AF_INET)*/
		return xasprintf("%s:%s", host, serv);
	/*return xstrdup(host);*/
}
char* FAST_FUNC xmalloc_sockaddr2dotted(const struct sockaddr *sa)
{
	return sockaddr2str(sa, NI_NUMERICHOST);
}

int FAST_FUNC tcsetattr_stdin_TCSANOW(const struct termios *tp)
{
	return tcsetattr(STDIN_FILENO, TCSANOW, tp);
}
pid_t FAST_FUNC safe_waitpid(pid_t pid, int *wstat, int options)
{
	pid_t r;

	do
		r = waitpid(pid, wstat, options);
	while ((r == -1) && (errno == EINTR));
	return r;
}

/* Due to a #define in libbb.h on MMU systems we actually have 1 argument -
 * char **argv "vanishes" */
void FAST_FUNC bb_daemonize_or_rexec(int flags, char **argv)
{
	int fd;

	fd = open(bb_dev_null, O_RDWR);
	if (fd < 0) {
		/* NB: we can be called as bb_sanitize_stdio() from init
		 * or mdev, and there /dev/null may legitimately not (yet) exist!
		 * Do not use xopen above, but obtain _ANY_ open descriptor,
		 * even bogus one as below. */
		fd = xopen("/", O_RDONLY); /* don't believe this can fail */
	}

	while ((unsigned)fd < 2)
		fd = dup(fd); /* have 0,1,2 open at least to /dev/null */

	if (1) {
		if (fork_or_rexec(argv))
			exit(EXIT_SUCCESS); /* parent */
		/* if daemonizing, detach from stdio & ctty */
		setsid();
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
	}
	while (fd > 2) {
		close(fd--);
		if (1)
			return;
		/* else close everything after fd#2 */
	}
}
pid_t FAST_FUNC wait_any_nohang(int *wstat)
{
	return safe_waitpid(-1, wstat, WNOHANG);
}

void FAST_FUNC setsockopt_reuseaddr(int fd)
{
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &const_int_1, sizeof(const_int_1));
}
int FAST_FUNC setsockopt_broadcast(int fd)
{
	return setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &const_int_1, sizeof(const_int_1));
}

#ifdef SO_BINDTODEVICE
int FAST_FUNC setsockopt_bindtodevice(int fd, const char *iface)
{
	int r;
	struct ifreq ifr;
	strncpy_IFNAMSIZ(ifr.ifr_name, iface);
	/* NB: passing (iface, strlen(iface) + 1) does not work!
	 * (maybe it works on _some_ kernels, but not on 2.6.26)
	 * Actually, ifr_name is at offset 0, and in practice
	 * just giving char[IFNAMSIZ] instead of struct ifreq works too.
	 * But just in case it's not true on some obscure arch... */
	r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
	if (r)
		bb_perror_msg("can't bind to interface %s", iface);
	return r;
}
#else
int FAST_FUNC setsockopt_bindtodevice(int fd UNUSED_PARAM,
		const char *iface UNUSED_PARAM)
{
	bb_error_msg("SO_BINDTODEVICE is not supported on this system");
	return -1;
}
#endif


len_and_sockaddr* FAST_FUNC get_sock_lsa(int fd)
{
	return get_lsa(fd, getsockname);
}


/* Return port number for a service.
 * If "port" is a number use it as the port.
 * If "port" is a name it is looked up in /etc/services,
 * if it isnt found return default_port
 */
unsigned FAST_FUNC bb_lookup_port(const char *port, const char *protocol, unsigned default_port)
{
	unsigned port_nr = default_port;
	if (port) {
		int old_errno;

		/* Since this is a lib function, we're not allowed to reset errno to 0.
		 * Doing so could break an app that is deferring checking of errno. */
		old_errno = errno;
		port_nr = bb_strtou(port, NULL, 10);
		if (errno || port_nr > 65535) {
			struct servent *tserv = getservbyname(port, protocol);
			port_nr = default_port;
			if (tserv)
				port_nr = ntohs(tserv->s_port);
		}
		errno = old_errno;
	}
	return (uint16_t)port_nr;
}


/* "New" networking API */


int FAST_FUNC get_nport(const struct sockaddr *sa)
{
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET6) {
		return ((struct sockaddr_in6*)sa)->sin6_port;
	}
#endif
	if (sa->sa_family == AF_INET) {
		return ((struct sockaddr_in*)sa)->sin_port;
	}
	/* What? UNIX socket? IPX?? :) */
	return -1;
}

void FAST_FUNC set_nport(struct sockaddr *sa, unsigned port)
{
#if ENABLE_FEATURE_IPV6
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (void*) sa;
		sin6->sin6_port = port;
		return;
	}
#endif
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void*) sa;
		sin->sin_port = port;
		return;
	}
	/* What? UNIX socket? IPX?? :) */
}

/* We hijack this constant to mean something else */
/* It doesn't hurt because we will remove this bit anyway */
#define DIE_ON_ERROR AI_CANONNAME

/* host: "1.2.3.4[:port]", "www.google.com[:port]"
 * port: if neither of above specifies port # */
static len_and_sockaddr* str2sockaddr(
		const char *host, int port,
IF_FEATURE_IPV6(sa_family_t af,)
		int ai_flags)
{
IF_NOT_FEATURE_IPV6(sa_family_t af = AF_INET;)
	int rc;
	len_and_sockaddr *r;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	const char *org_host = host; /* only for error msg */
	const char *cp;
	struct addrinfo hint;

	if (ENABLE_FEATURE_UNIX_LOCAL && strncmp(host, "local:", 6) == 0) {
		struct sockaddr_un *sun;

		r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_un));
		r->len = sizeof(struct sockaddr_un);
		r->u.sa.sa_family = AF_UNIX;
		sun = (struct sockaddr_un *)&r->u.sa;
		safe_strncpy(sun->sun_path, host + 6, sizeof(sun->sun_path));
		return r;
	}

	r = NULL;

	/* Ugly parsing of host:addr */
	if (ENABLE_FEATURE_IPV6 && host[0] == '[') {
		/* Even uglier parsing of [xx]:nn */
		host++;
		cp = strchr(host, ']');
		if (!cp || (cp[1] != ':' && cp[1] != '\0')) {
			/* Malformed: must be [xx]:nn or [xx] */
			bb_error_msg("bad address '%s'", org_host);
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
	} else {
		cp = strrchr(host, ':');
		if (ENABLE_FEATURE_IPV6 && cp && strchr(host, ':') != cp) {
			/* There is more than one ':' (e.g. "::1") */
			cp = NULL; /* it's not a port spec */
		}
	}
	if (cp) { /* points to ":" or "]:" */
		int sz = cp - host + 1;

		host = safe_strncpy(alloca(sz), host, sz);
		if (ENABLE_FEATURE_IPV6 && *cp != ':') {
			cp++; /* skip ']' */
			if (*cp == '\0') /* [xx] without port */
				goto skip;
		}
		cp++; /* skip ':' */
		port = bb_strtou(cp, NULL, 10);
		if (errno || (unsigned)port > 0xffff) {
			bb_error_msg("bad port spec '%s'", org_host);
			if (ai_flags & DIE_ON_ERROR)
				xfunc_die();
			return NULL;
		}
 skip: ;
	}

	/* Next two if blocks allow to skip getaddrinfo()
	 * in case host name is a numeric IP(v6) address.
	 * getaddrinfo() initializes DNS resolution machinery,
	 * scans network config and such - tens of syscalls.
	 */
	/* If we were not asked specifically for IPv6,
	 * check whether this is a numeric IPv4 */
	IF_FEATURE_IPV6(if(af != AF_INET6)) {
		struct in_addr in4;
		if (inet_aton(host, &in4) != 0) {
			r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in));
			r->len = sizeof(struct sockaddr_in);
			r->u.sa.sa_family = AF_INET;
			r->u.sin.sin_addr = in4;
			goto set_port;
		}
	}
#if ENABLE_FEATURE_IPV6
	/* If we were not asked specifically for IPv4,
	 * check whether this is a numeric IPv6 */
	if (af != AF_INET) {
		struct in6_addr in6;
		if (inet_pton(AF_INET6, host, &in6) > 0) {
			r = xzalloc(LSA_LEN_SIZE + sizeof(struct sockaddr_in6));
			r->len = sizeof(struct sockaddr_in6);
			r->u.sa.sa_family = AF_INET6;
			r->u.sin6.sin6_addr = in6;
			goto set_port;
		}
	}
#endif

	memset(&hint, 0 , sizeof(hint));
	hint.ai_family = af;
	/* Need SOCK_STREAM, or else we get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = ai_flags & ~DIE_ON_ERROR;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		bb_error_msg("bad address '%s'", org_host);
		if (ai_flags & DIE_ON_ERROR)
			xfunc_die();
		goto ret;
	}
	used_res = result;
#if ENABLE_FEATURE_PREFER_IPV4_ADDRESS
	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			break;
		}
	}
#endif
	r = xmalloc(LSA_LEN_SIZE + used_res->ai_addrlen);
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

 set_port:
	set_nport(&r->u.sa, htons(port));
 ret:
	if (result)
		freeaddrinfo(result);
	return r;
}

len_and_sockaddr* FAST_FUNC xdotted2sockaddr(const char *host, int port)
{
	return str2sockaddr(host, port, AF_UNSPEC, AI_NUMERICHOST);
}

// Die with an error message if we can't open a new socket.
int FAST_FUNC xsocket(int domain, int type, int protocol)
{
	int r = socket(domain, type, protocol);

	if (r < 0) {
		/* Hijack vaguely related config option */
#if ENABLE_VERBOSE_RESOLUTION_ERRORS
		const char *s = "INET";
# ifdef AF_PACKET
		if (domain == AF_PACKET) s = "PACKET";
# endif
# ifdef AF_NETLINK
		if (domain == AF_NETLINK) s = "NETLINK";
# endif
IF_FEATURE_IPV6(if (domain == AF_INET6) s = "INET6";)
		bb_perror_msg_and_die("socket(AF_%s,%d,%d)", s, type, protocol);
#else
		bb_perror_msg_and_die("socket");
#endif
	}

	return r;
}

// Die with an error message if we can't bind a socket to an address.
void FAST_FUNC xbind(int sockfd, struct sockaddr *my_addr, socklen_t addrlen)
{
	if (bind(sockfd, my_addr, addrlen)) bb_perror_msg_and_die("bind");
}

// Die with an error message if we can't listen for connections on a socket.
void FAST_FUNC xlisten(int s, int backlog)
{
	if (listen(s, backlog)) bb_perror_msg_and_die("listen");
}

int FAST_FUNC xsocket_type(len_and_sockaddr **lsap, int family, int sock_type)
{
	len_and_sockaddr *lsa;
	int fd;
	int len;

	if (family == AF_UNSPEC) {
#if ENABLE_FEATURE_IPV6
		fd = socket(AF_INET6, sock_type, 0);
		if (fd >= 0) {
			family = AF_INET6;
			goto done;
		}
#endif
		family = AF_INET;
	}

	fd = xsocket(family, sock_type, 0);

	len = sizeof(struct sockaddr_in);
	if (family == AF_UNIX)
		len = sizeof(struct sockaddr_un);
#if ENABLE_FEATURE_IPV6
	if (family == AF_INET6) {
 done:
		len = sizeof(struct sockaddr_in6);
	}
#endif
	lsa = xzalloc(LSA_LEN_SIZE + len);
	lsa->len = len;
	lsa->u.sa.sa_family = family;
	*lsap = lsa;
	return fd;
}
static int create_and_bind_or_die(const char *bindaddr, int port, int sock_type)
{
	int fd;
	len_and_sockaddr *lsa;

	if (bindaddr && bindaddr[0]) {
		lsa = xdotted2sockaddr(bindaddr, port);
		/* user specified bind addr dictates family */
		fd = xsocket(lsa->u.sa.sa_family, sock_type, 0);
	} else {
		fd = xsocket_type(&lsa, AF_UNSPEC, sock_type);
		set_nport(&lsa->u.sa, htons(port));
	}
	setsockopt_reuseaddr(fd);
	xbind(fd, &lsa->u.sa, lsa->len);
	free(lsa);
	return fd;
}

int FAST_FUNC create_and_bind_stream_or_die(const char *bindaddr, int port)
{
	return create_and_bind_or_die(bindaddr, port, SOCK_STREAM);
}

#endif

/*
   Remove all IAC's from buf1 (received IACs are ignored and must be removed
   so as to not be interpreted by the terminal).  Make an uninterrupted
   string of characters fit for the terminal.  Do this by packing
   all characters meant for the terminal sequentially towards the end of buf.

   Return a pointer to the beginning of the characters meant for the terminal
   and make *num_totty the number of characters that should be sent to
   the terminal.

   Note - if an IAC (3 byte quantity) starts before (bf + len) but extends
   past (bf + len) then that IAC will be left unprocessed and *processed
   will be less than len.

   CR-LF ->'s CR mapping is also done here, for convenience.

   NB: may fail to remove iacs which wrap around buffer!
 */
static unsigned char *
remove_iacs(struct tsession *ts, int *pnum_totty)
{
	unsigned char *ptr0 = TS_BUF1(ts) + ts->wridx1;
	unsigned char *ptr = ptr0;
	unsigned char *totty = ptr;
	unsigned char *end = ptr + MIN(BUFSIZE - ts->wridx1, ts->size1);
	int num_totty;

	while (ptr < end) {
		if (*ptr != IAC) {
			char c = *ptr;

			*totty++ = c;
			ptr++;
			/* We map \r\n ==> \r for pragmatic reasons.
			 * Many client implementations send \r\n when
			 * the user hits the CarriageReturn key.
			 * See RFC 1123 3.3.1 Telnet End-of-Line Convention.
			 */
			if (c == '\r' && ptr < end && (*ptr == '\n' || *ptr == '\0'))
				ptr++;
			continue;
		}

		if ((ptr+1) >= end)
			break;
		if (ptr[1] == NOP) { /* Ignore? (putty keepalive, etc.) */
			ptr += 2;
			continue;
		}
		if (ptr[1] == IAC) { /* Literal IAC? (emacs M-DEL) */
			*totty++ = ptr[1];
			ptr += 2;
			continue;
		}

		/*
		 * TELOPT_NAWS support!
		 */
		if ((ptr+2) >= end) {
			/* Only the beginning of the IAC is in the
			buffer we were asked to process, we can't
			process this char */
			break;
		}
		/*
		 * IAC -> SB -> TELOPT_NAWS -> 4-byte -> IAC -> SE
		 */
		if (ptr[1] == SB && ptr[2] == TELOPT_NAWS) {
			struct winsize ws;
			if ((ptr+8) >= end)
				break;  /* incomplete, can't process */
			ws.ws_col = (ptr[3] << 8) | ptr[4];
			ws.ws_row = (ptr[5] << 8) | ptr[6];
			ioctl(ts->ptyfd, TIOCSWINSZ, (char *)&ws);
			ptr += 9;
			continue;
		}
		/* skip 3-byte IAC non-SB cmd */
#if DEBUG
		fprintf(stderr, "Ignoring IAC %s,%s\n",
				TELCMD(ptr[1]), TELOPT(ptr[2]));
#endif
		ptr += 3;
	}

	num_totty = totty - ptr0;
	*pnum_totty = num_totty;
	/* The difference between ptr and totty is number of iacs
	   we removed from the stream. Adjust buf1 accordingly */
	if ((ptr - totty) == 0) /* 99.999% of cases */
		return ptr0;
	ts->wridx1 += ptr - totty;
	ts->size1 -= ptr - totty;
	/* Move chars meant for the terminal towards the end of the buffer */
	return memmove(ptr - num_totty, ptr0, num_totty);
}

/*
 * Converting single IAC into double on output
 */
static size_t iac_safe_write(int fd, const char *buf, size_t count)
{
	const char *IACptr;
	size_t wr, rc, total;

	total = 0;
	while (1) {
		if (count == 0)
			return total;
		if (*buf == (char)IAC) {
			static const char IACIAC[] ALIGN1 = { IAC, IAC };
			rc = safe_write(fd, IACIAC, 2);
			if (rc != 2)
				break;
			buf++;
			total++;
			count--;
			continue;
		}
		/* count != 0, *buf != IAC */
		IACptr = memchr(buf, IAC, count);
		wr = count;
		if (IACptr)
			wr = IACptr - buf;
		rc = safe_write(fd, buf, wr);
		if (rc != wr)
			break;
		buf += rc;
		total += rc;
		count -= rc;
	}
	/* here: rc - result of last short write */
	if ((ssize_t)rc < 0) { /* error? */
		if (total == 0)
			return rc;
		rc = 0;
	}
	return total + rc;
}

/* Must match getopt32 string */
enum {
	OPT_WATCHCHILD = (1 << 2), /* -K */
	OPT_INETD      = (1 << 3) * ENABLE_FEATURE_TELNETD_STANDALONE, /* -i */
	OPT_PORT       = (1 << 4) * ENABLE_FEATURE_TELNETD_STANDALONE, /* -p PORT */
	OPT_FOREGROUND = (1 << 6) * ENABLE_FEATURE_TELNETD_STANDALONE, /* -F */
	OPT_SYSLOG     = (1 << 7) * ENABLE_FEATURE_TELNETD_INETD_WAIT, /* -S */
	OPT_WAIT       = (1 << 8) * ENABLE_FEATURE_TELNETD_INETD_WAIT, /* -w SEC */
};

static struct tsession *
make_new_session(
		IF_FEATURE_TELNETD_STANDALONE(int sock)
		IF_NOT_FEATURE_TELNETD_STANDALONE(void)
) {
#if !ENABLE_FEATURE_TELNETD_STANDALONE
	enum { sock = 0 };
#endif
	const char *login_argv[2];
	struct termios termbuf;
	int fd, pid;
	char tty_name[GETPTY_BUFSIZE];
	struct tsession *ts = xzalloc(sizeof(struct tsession) + BUFSIZE * 2);

	/*ts->buf1 = (char *)(ts + 1);*/
	/*ts->buf2 = ts->buf1 + BUFSIZE;*/

	/* Got a new connection, set up a tty */
	fd = xgetpty(tty_name);
	if (fd > G.maxfd)
		G.maxfd = fd;
	ts->ptyfd = fd;
	ndelay_on(fd);
	close_on_exec_on(fd);

	/* SO_KEEPALIVE by popular demand */
	setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &const_int_1, sizeof(const_int_1));
#if ENABLE_FEATURE_TELNETD_STANDALONE
	ts->sockfd_read = sock;
	ndelay_on(sock);
	if (sock == 0) { /* We are called with fd 0 - we are in inetd mode */
		sock++; /* so use fd 1 for output */
		ndelay_on(sock);
	}
	ts->sockfd_write = sock;
	if (sock > G.maxfd)
		G.maxfd = sock;
#else
	/* ts->sockfd_read = 0; - done by xzalloc */
	ts->sockfd_write = 1;
	ndelay_on(0);
	ndelay_on(1);
#endif

	/* Make the telnet client understand we will echo characters so it
	 * should not do it locally. We don't tell the client to run linemode,
	 * because we want to handle line editing and tab completion and other
	 * stuff that requires char-by-char support. */
	{
		static const char iacs_to_send[] ALIGN1 = {
			IAC, DO, TELOPT_ECHO,
			IAC, DO, TELOPT_NAWS,
			/* This requires telnetd.ctrlSQ.patch (incomplete) */
			/*IAC, DO, TELOPT_LFLOW,*/
			IAC, WILL, TELOPT_ECHO,
			IAC, WILL, TELOPT_SGA
		};
		/* This confuses iac_safe_write(), it will try to duplicate
		 * each IAC... */
		//memcpy(TS_BUF2(ts), iacs_to_send, sizeof(iacs_to_send));
		//ts->rdidx2 = sizeof(iacs_to_send);
		//ts->size2 = sizeof(iacs_to_send);
		/* So just stuff it into TCP stream! (no error check...) */
#if ENABLE_FEATURE_TELNETD_STANDALONE
		safe_write(sock, iacs_to_send, sizeof(iacs_to_send));
#else
		safe_write(1, iacs_to_send, sizeof(iacs_to_send));
#endif
		/*ts->rdidx2 = 0; - xzalloc did it */
		/*ts->size2 = 0;*/
	}

	fflush_all();
	pid = vfork(); /* NOMMU-friendly */
	if (pid < 0) {
		free(ts);
		close(fd);
		/* sock will be closed by caller */
		bb_perror_msg("vfork");
		return NULL;
	}
	if (pid > 0) {
		/* Parent */
		ts->shell_pid = pid;
		return ts;
	}

	/* Child */
	/* Careful - we are after vfork! */

	/* Restore default signal handling ASAP */
	bb_signals((1 << SIGCHLD) + (1 << SIGPIPE), SIG_DFL);

	pid = getpid();

	if (ENABLE_FEATURE_UTMP) {
		len_and_sockaddr *lsa = get_peer_lsa(sock);
		char *hostname = NULL;
		if (lsa) {
			hostname = xmalloc_sockaddr2dotted(&lsa->u.sa);
			free(lsa);
		}
		write_new_utmp(pid, LOGIN_PROCESS, tty_name, /*username:*/ "LOGIN", hostname);
		free(hostname);
	}

	/* Make new session and process group */
	setsid();

	/* Open the child's side of the tty */
	/* NB: setsid() disconnects from any previous ctty's. Therefore
	 * we must open child's side of the tty AFTER setsid! */
	close(0);
	xopen(tty_name, O_RDWR); /* becomes our ctty */
	xdup2(0, 1);
	xdup2(0, 2);
	tcsetpgrp(0, pid); /* switch this tty's process group to us */

	/* The pseudo-terminal allocated to the client is configured to operate
	 * in cooked mode, and with XTABS CRMOD enabled (see tty(4)) */
	tcgetattr(0, &termbuf);
	termbuf.c_lflag |= ECHO; /* if we use readline we dont want this */
	termbuf.c_oflag |= ONLCR | XTABS;
	termbuf.c_iflag |= ICRNL;
	termbuf.c_iflag &= ~IXOFF;
	/*termbuf.c_lflag &= ~ICANON;*/
	tcsetattr_stdin_TCSANOW(&termbuf);

	/* Uses FILE-based I/O to stdout, but does fflush_all(),
	 * so should be safe with vfork.
	 * I fear, though, that some users will have ridiculously big
	 * issue files, and they may block writing to fd 1,
	 * (parent is supposed to read it, but parent waits
	 * for vforked child to exec!) */
	print_login_issue(G.issuefile, tty_name);

	/* Exec shell / login / whatever */
	login_argv[0] = G.loginpath;
	login_argv[1] = NULL;
	/* exec busybox applet (if PREFER_APPLETS=y), if that fails,
	 * exec external program.
	 * NB: sock is either 0 or has CLOEXEC set on it.
	 * fd has CLOEXEC set on it too. These two fds will be closed here.
	 */
	BB_EXECVP(G.loginpath, (char **)login_argv);
	/* _exit is safer with vfork, and we shouldn't send message
	 * to remote clients anyway */
	_exit(EXIT_FAILURE); /*bb_perror_msg_and_die("execv %s", G.loginpath);*/
}

#if ENABLE_FEATURE_TELNETD_STANDALONE

static void
free_session(struct tsession *ts)
{
	struct tsession *t;

	if (option_mask32 & OPT_INETD)
		exit(EXIT_SUCCESS);

	/* Unlink this telnet session from the session list */
	t = G.sessions;
	if (t == ts)
		G.sessions = ts->next;
	else {
		while (t->next != ts)
			t = t->next;
		t->next = ts->next;
	}

#if 0
	/* It was said that "normal" telnetd just closes ptyfd,
	 * doesn't send SIGKILL. When we close ptyfd,
	 * kernel sends SIGHUP to processes having slave side opened. */
	kill(ts->shell_pid, SIGKILL);
	waitpid(ts->shell_pid, NULL, 0);
#endif
	close(ts->ptyfd);
	close(ts->sockfd_read);
	/* We do not need to close(ts->sockfd_write), it's the same
	 * as sockfd_read unless we are in inetd mode. But in inetd mode
	 * we do not reach this */
	free(ts);

	/* Scan all sessions and find new maxfd */
	G.maxfd = 0;
	ts = G.sessions;
	while (ts) {
		if (G.maxfd < ts->ptyfd)
			G.maxfd = ts->ptyfd;
		if (G.maxfd < ts->sockfd_read)
			G.maxfd = ts->sockfd_read;
#if 0
		/* Again, sockfd_write == sockfd_read here */
		if (G.maxfd < ts->sockfd_write)
			G.maxfd = ts->sockfd_write;
#endif
		ts = ts->next;
	}
}

#else /* !FEATURE_TELNETD_STANDALONE */

/* Used in main() only, thus "return 0" actually is exit(EXIT_SUCCESS). */
#define free_session(ts) return 0

#endif

static void handle_sigchld(int sig UNUSED_PARAM)
{
	pid_t pid;
	struct tsession *ts;
	int save_errno = errno;

	/* Looping: more than one child may have exited */
	while (1) {
		pid = wait_any_nohang(NULL);
		if (pid <= 0)
			break;
		ts = G.sessions;
		while (ts) {
			if (ts->shell_pid == pid) {
				ts->shell_pid = -1;
// man utmp:
// When init(8) finds that a process has exited, it locates its utmp entry
// by ut_pid, sets ut_type to DEAD_PROCESS, and clears ut_user, ut_host
// and ut_time with null bytes.
// [same applies to other processes which maintain utmp entries, like telnetd]
//
// We do not bother actually clearing fields:
// it might be interesting to know who was logged in and from where
//				update_utmp(pid, DEAD_PROCESS, /*tty_name:*/ NULL, /*username:*/ NULL, /*hostname:*/ NULL);
				break;
			}
			ts = ts->next;
		}
	}

	errno = save_errno;
}

int telnetd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int telnetd_main(int argc UNUSED_PARAM, char **argv)
{
	fd_set rdfdset, wrfdset;
	unsigned opt = 0;
	int count;
	struct tsession *ts;
#if ENABLE_FEATURE_TELNETD_STANDALONE
#define IS_INETD (opt & OPT_INETD)
	int master_fd = master_fd; /* for compiler */
	int sec_linger = sec_linger;
	char *opt_bindaddr = NULL;
	char *opt_portnbr;
#else
	enum {
		IS_INETD = 1,
		master_fd = -1,
	};
#endif
	INIT_G();

	/* -w NUM, and implies -F. -w and -i don't mix */
	IF_FEATURE_TELNETD_INETD_WAIT(opt_complementary = "wF:w+:i--w:w--i";)

#if !SO_TELNETD
	/* Even if !STANDALONE, we accept (and ignore) -i, thus people
	 * don't need to guess whether it's ok to pass -i to us */
	opt = getopt32(argv, "f:l:Ki"
			IF_FEATURE_TELNETD_STANDALONE("p:b:F")
			IF_FEATURE_TELNETD_INETD_WAIT("Sw:"),
			&G.issuefile, &G.loginpath
			IF_FEATURE_TELNETD_STANDALONE(, &opt_portnbr, &opt_bindaddr)
			IF_FEATURE_TELNETD_INETD_WAIT(, &sec_linger)
	);
#endif
	if (!IS_INETD /*&& !re_execed*/) {
		/* inform that we start in standalone mode?
		 * May be useful when people forget to give -i */
		/*bb_error_msg("listening for connections");*/
//      if (!(opt & OPT_FOREGROUND)) {
        if (opt) {
			/* DAEMON_CHDIR_ROOT was giving inconsistent
			 * behavior with/without -F, -i */
			bb_daemonize_or_rexec(0 /*was DAEMON_CHDIR_ROOT*/, argv);
		}
	}
	/* Redirect log to syslog early, if needed */
	if (IS_INETD || (opt & OPT_SYSLOG) || !(opt & OPT_FOREGROUND)) {
		openlog(applet_name, LOG_PID, LOG_DAEMON);
		logmode = LOGMODE_SYSLOG;
	}
#if ENABLE_FEATURE_TELNETD_STANDALONE
	if (IS_INETD) {
		G.sessions = make_new_session(0);
		if (!G.sessions) /* pty opening or vfork problem, exit */
			return 1; /* make_new_session printed error message */
	} else {
		master_fd = 0;
//      if (!(opt & OPT_WAIT)) {
        if (opt) {
			unsigned portnbr = 23;
			if (opt & OPT_PORT)
				portnbr = xatou16(opt_portnbr);
//			master_fd = create_and_bind_stream_or_die(opt_bindaddr, portnbr);
			master_fd = create_and_bind_stream_or_die(opt_bindaddr, portnbr);
			xlisten(master_fd, 1);
		}
		close_on_exec_on(master_fd);
	}
#else
	G.sessions = make_new_session();
	if (!G.sessions) /* pty opening or vfork problem, exit */
		return 1; /* make_new_session printed error message */
#endif

	/* We don't want to die if just one session is broken */
	signal(SIGPIPE, SIG_IGN);

	if (opt & OPT_WATCHCHILD)
		signal(SIGCHLD, handle_sigchld);
	else /* prevent dead children from becoming zombies */
		signal(SIGCHLD, SIG_IGN);

/*
   This is how the buffers are used. The arrows indicate data flow.

   +-------+     wridx1++     +------+     rdidx1++     +----------+
   |       | <--------------  | buf1 | <--------------  |          |
   |       |     size1--      +------+     size1++      |          |
   |  pty  |                                            |  socket  |
   |       |     rdidx2++     +------+     wridx2++     |          |
   |       |  --------------> | buf2 |  --------------> |          |
   +-------+     size2++      +------+     size2--      +----------+

   size1: "how many bytes are buffered for pty between rdidx1 and wridx1?"
   size2: "how many bytes are buffered for socket between rdidx2 and wridx2?"

   Each session has got two buffers. Buffers are circular. If sizeN == 0,
   buffer is empty. If sizeN == BUFSIZE, buffer is full. In both these cases
   rdidxN == wridxN.
*/
 again:
	FD_ZERO(&rdfdset);
	FD_ZERO(&wrfdset);

	/* Select on the master socket, all telnet sockets and their
	 * ptys if there is room in their session buffers.
	 * NB: scalability problem: we recalculate entire bitmap
	 * before each select. Can be a problem with 500+ connections. */
	ts = G.sessions;
	while (ts) {
		struct tsession *next = ts->next; /* in case we free ts */
		if (ts->shell_pid == -1) {
			/* Child died and we detected that */
			free_session(ts);
		} else {
			if (ts->size1 > 0)       /* can write to pty */
				FD_SET(ts->ptyfd, &wrfdset);
			if (ts->size1 < BUFSIZE) /* can read from socket */
				FD_SET(ts->sockfd_read, &rdfdset);
			if (ts->size2 > 0)       /* can write to socket */
				FD_SET(ts->sockfd_write, &wrfdset);
			if (ts->size2 < BUFSIZE) /* can read from pty */
				FD_SET(ts->ptyfd, &rdfdset);
		}
		ts = next;
	}
	if (!IS_INETD) {
		FD_SET(master_fd, &rdfdset);
		/* This is needed because free_session() does not
		 * take master_fd into account when it finds new
		 * maxfd among remaining fd's */
		if (master_fd > G.maxfd)
			G.maxfd = master_fd;
	}

	{
		struct timeval *tv_ptr = NULL;
#if ENABLE_FEATURE_TELNETD_INETD_WAIT
		struct timeval tv;
		if ((opt & OPT_WAIT) && !G.sessions) {
			tv.tv_sec = sec_linger;
			tv.tv_usec = 0;
			tv_ptr = &tv;
		}
#endif
		count = select(G.maxfd + 1, &rdfdset, &wrfdset, NULL, tv_ptr);
	}
	if (count == 0) /* "telnetd -w SEC" timed out */
		return 0;
	if (count < 0)
		goto again; /* EINTR or ENOMEM */

#if ENABLE_FEATURE_TELNETD_STANDALONE
	/* Check for and accept new sessions */
	if (!IS_INETD && FD_ISSET(master_fd, &rdfdset)) {
		int fd;
		struct tsession *new_ts;

		fd = accept(master_fd, NULL, NULL);
		if (fd < 0)
			goto again;
		close_on_exec_on(fd);

		/* Create a new session and link it into active list */
		new_ts = make_new_session(fd);
		if (new_ts) {
			new_ts->next = G.sessions;
			G.sessions = new_ts;
		} else {
			close(fd);
		}
	}
#endif

	/* Then check for data tunneling */
	ts = G.sessions;
	while (ts) { /* For all sessions... */
		struct tsession *next = ts->next; /* in case we free ts */

		if (/*ts->size1 &&*/ FD_ISSET(ts->ptyfd, &wrfdset)) {
			int num_totty;
			unsigned char *ptr;
			/* Write to pty from buffer 1 */
			ptr = remove_iacs(ts, &num_totty);
			count = safe_write(ts->ptyfd, ptr, num_totty);
			if (count < 0) {
				if (errno == EAGAIN)
					goto skip1;
				goto kill_session;
			}
			ts->size1 -= count;
			ts->wridx1 += count;
			if (ts->wridx1 >= BUFSIZE) /* actually == BUFSIZE */
				ts->wridx1 = 0;
		}
 skip1:
		if (/*ts->size2 &&*/ FD_ISSET(ts->sockfd_write, &wrfdset)) {
			/* Write to socket from buffer 2 */
			count = MIN(BUFSIZE - ts->wridx2, ts->size2);
			count = iac_safe_write(ts->sockfd_write, (void*)(TS_BUF2(ts) + ts->wridx2), count);
			if (count < 0) {
				if (errno == EAGAIN)
					goto skip2;
				goto kill_session;
			}
			ts->size2 -= count;
			ts->wridx2 += count;
			if (ts->wridx2 >= BUFSIZE) /* actually == BUFSIZE */
				ts->wridx2 = 0;
		}
 skip2:
		/* Should not be needed, but... remove_iacs is actually buggy
		 * (it cannot process iacs which wrap around buffer's end)!
		 * Since properly fixing it requires writing bigger code,
		 * we rely instead on this code making it virtually impossible
		 * to have wrapped iac (people don't type at 2k/second).
		 * It also allows for bigger reads in common case. */
		if (ts->size1 == 0) {
			ts->rdidx1 = 0;
			ts->wridx1 = 0;
		}
		if (ts->size2 == 0) {
			ts->rdidx2 = 0;
			ts->wridx2 = 0;
		}

		if (/*ts->size1 < BUFSIZE &&*/ FD_ISSET(ts->sockfd_read, &rdfdset)) {
			/* Read from socket to buffer 1 */
			count = MIN(BUFSIZE - ts->rdidx1, BUFSIZE - ts->size1);
			count = safe_read(ts->sockfd_read, TS_BUF1(ts) + ts->rdidx1, count);
			if (count <= 0) {
				if (count < 0 && errno == EAGAIN)
					goto skip3;
				goto kill_session;
			}
			/* Ignore trailing NUL if it is there */
			if (!TS_BUF1(ts)[ts->rdidx1 + count - 1]) {
				--count;
			}
			ts->size1 += count;
			ts->rdidx1 += count;
			if (ts->rdidx1 >= BUFSIZE) /* actually == BUFSIZE */
				ts->rdidx1 = 0;
		}
 skip3:
		if (/*ts->size2 < BUFSIZE &&*/ FD_ISSET(ts->ptyfd, &rdfdset)) {
			/* Read from pty to buffer 2 */
			count = MIN(BUFSIZE - ts->rdidx2, BUFSIZE - ts->size2);
			count = safe_read(ts->ptyfd, TS_BUF2(ts) + ts->rdidx2, count);
			if (count <= 0) {
				if (count < 0 && errno == EAGAIN)
					goto skip4;
				goto kill_session;
			}
			ts->size2 += count;
			ts->rdidx2 += count;
			if (ts->rdidx2 >= BUFSIZE) /* actually == BUFSIZE */
				ts->rdidx2 = 0;
		}
 skip4:
		ts = next;
		continue;
 kill_session:
		if (ts->shell_pid > 0)
//			update_utmp(ts->shell_pid, DEAD_PROCESS, /*tty_name:*/ NULL, /*username:*/ NULL, /*hostname:*/ NULL);
		free_session(ts);
		ts = next;
	}

	goto again;
}

#if SO_TELNETD
void *so_telnetd_handle(void *param)
{
    telnetd_main(0, (char **)param);
}

int so_telnetd_init(int argc, char **argv)
{
    int rv = 0;
    pthread_t pid;

    rv = pthread_create(&pid, NULL, so_telnetd_handle, argv);
    if (rv == -1)
    {
        printf("telnetd thread create failed\n");
        return -1;
    }

    return 0;
}

#if 1

int main(int argc, char **argv)
{
    int rv = 0;

    rv = so_telnetd_init(argc, argv);

    while (1)
    {
        sleep(100);    
    }

    return rv;
}
#endif

#endif
