/* SPDX-License-Identifier: MIT */
/* LD_PRELOAD shim for libkrun TSI loopback networking (SIPB Hyades runner). Four workarounds, all measured 2026-10-14:
 *
 * 1. bind(port 0) is rewritten to a concrete random port in 20000-32000 (libkrun#818: a listener bound to port 0 lands
 *    on a different port in the VMM's netns and is unreachable). Never the same port twice in a row, and not any of
 *    the last 4096 handed out: a port reused right after its listener closed loses the new listener's connections
 *    (libkrun#929). Inherited by every child JVM through the environment.
 * 2. A thread blocked in recv()/read()/accept() blocks every other call on that socket from other threads, send()
 *    included (libkrun#819, #926). Blocking reads and accepts on TCP sockets therefore wait in poll() first (parked in
 *    poll() holds no lock), then read; signals still interrupt the wait, so the JDK's close wake-up keeps working.
 * 3. shutdown() on a listener is a no-op (it blocks or fails with ENOTCONN; getsockopt(SO_ACCEPTCONN) says 0), and
 *    on other sockets runs in a helper thread with a 300 ms wait. Java's ServerSocket.close()/Socket.close() call it.
 * 4. getsockopt() at any level but SOL_SOCKET on a UDP socket that has talked to a remote host crashes the guest
 *    kernel: tsi_stream_getsockopt calls vsock_dgram_ops.getsockopt, which is NULL (libkrunfw#140). Chromium's
 *    network thread does getsockopt(SOL_IP, IP_TOS) or (SOL_IPV6, IPV6_V6ONLY) on such sockets; the oops kills that thread and every
 *    later navigation hangs (Firecrawl's playwright-service on Hyades, 2026-10-14). On a datagram socket whose peer
 *    is not loopback these calls fail with EOPNOTSUPP, the upstream fix's return value, without entering the kernel.
 *
 *   gcc -shared -fPIC -O2 -pthread -o /tmp/portshim.so loopback-port-shim.c -ldl
 *   LD_PRELOAD=/tmp/portshim.so ./gradlew ...
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define RECENT 4096   /* ports not handed out again by this process until 4096 others were */
typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    static bind_fn real;
    if (!real) real = (bind_fn)dlsym(RTLD_NEXT, "bind");
    if (!addr) return real(fd, addr, len);

    int zero = 0;
    if (addr->sa_family == AF_INET && len >= sizeof(struct sockaddr_in))
        zero = ((const struct sockaddr_in *)addr)->sin_port == 0;
    else if (addr->sa_family == AF_INET6 && len >= sizeof(struct sockaddr_in6))
        zero = ((const struct sockaddr_in6 *)addr)->sin6_port == 0;
    if (!zero) return real(fd, addr, len);

    union { struct sockaddr_storage ss; struct sockaddr_in a4; struct sockaddr_in6 a6; } copy;
    if (len > sizeof copy) return real(fd, addr, len);
    __builtin_memcpy(&copy, addr, len);
    /* Never hand out the same port twice in a row: under TSI a listener that was just closed is still alive for a
     * moment on the host side, and a new listener on the same port number is accepted by bind() (no EADDRINUSE) but
     * its connections land on the dying one (EOF, "unexpected end of stream"; verified 2026-10-14, run 220: every
     * failure had port == previous port). So ports come from a high-resolution seed (the old pid^time(s)^fd seed
     * repeated within a second, i.e. the same port for every test of that second) and skip the last RECENT ports. */
    static pthread_mutex_t pm = PTHREAD_MUTEX_INITIALIZER;
    static unsigned short recent[RECENT]; static unsigned nrecent;
    static unsigned long long ctr;
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long z = (unsigned long long)ts.tv_nsec ^ ((unsigned long long)ts.tv_sec << 30) ^ ((unsigned long long)getpid() << 17) ^ (++ctr * 0x9E3779B97F4A7C15ull);
    z ^= z >> 30; z *= 0xBF58476D1CE4E5B9ull; z ^= z >> 27; z *= 0x94D049BB133111EBull; z ^= z >> 31;
    unsigned seed = (unsigned)z;
    /* 20000-32000: below the kernel ephemeral range, so no clash with auto-assigned ports */
    for (int i = 0; i < 400; i++) {
        unsigned short port = (unsigned short)(20000 + rand_r(&seed) % 12000);
        int seen = 0;
        pthread_mutex_lock(&pm);
        for (unsigned k = 0; k < RECENT && k < nrecent; k++) if (recent[k] == port) { seen = 1; break; }
        pthread_mutex_unlock(&pm);
        if (seen) continue;
        if (copy.ss.ss_family == AF_INET) copy.a4.sin_port = htons(port);
        else copy.a6.sin6_port = htons(port);
        int rc = real(fd, (struct sockaddr *)&copy, len);
        if (rc == 0) { pthread_mutex_lock(&pm); recent[nrecent++ % RECENT] = port; pthread_mutex_unlock(&pm); }
        if (rc == 0 || errno != EADDRINUSE) return rc;
    }
    return real(fd, addr, len);
}

/* shutdown() on a listener must not reach the kernel, and the shim cannot ask the socket whether it is a
 * listener: under TSI getsockopt(SO_ACCEPTCONN) answers 0 for a listener, and getpeername and shutdown block while
 * another thread sits in accept(). So listening fds are recorded in listen() and forgotten in close()/dup2(). */
#define MAXFD 65536
static volatile unsigned char listening[MAXFD];
static volatile unsigned char sockfd[MAXFD];   /* blocking-capable TCP sockets (socket()/accept() results) */

typedef int (*listen_fn)(int, int);
int listen(int fd, int backlog) {
    static listen_fn real;
    if (!real) real = (listen_fn)dlsym(RTLD_NEXT, "listen");
    int rc = real(fd, backlog);
    if (rc == 0 && fd >= 0 && fd < MAXFD) listening[fd] = 1;
    return rc;
}

typedef int (*close_fn)(int);
int close(int fd) {
    static close_fn real;
    if (!real) real = (close_fn)dlsym(RTLD_NEXT, "close");
    if (fd >= 0 && fd < MAXFD) { listening[fd] = 0; sockfd[fd] = 0; }
    return real(fd);
}

typedef int (*dup2_fn)(int, int);
int dup2(int oldfd, int newfd) {
    static dup2_fn real;
    if (!real) real = (dup2_fn)dlsym(RTLD_NEXT, "dup2");
    if (newfd >= 0 && newfd < MAXFD) { listening[newfd] = 0; sockfd[newfd] = 0; }
    return real(oldfd, newfd);
}

typedef int (*dup3_fn)(int, int, int);
int dup3(int oldfd, int newfd, int flags) {
    static dup3_fn real;
    if (!real) real = (dup3_fn)dlsym(RTLD_NEXT, "dup3");
    if (newfd >= 0 && newfd < MAXFD) { listening[newfd] = 0; sockfd[newfd] = 0; }
    return real(oldfd, newfd, flags);
}

/* Third TSI bug (found 2026-10-14, runs 224-227 duplex-probe.c): while one thread is blocked in recv()/read()/accept()
 * on a socket, send() and every other call on that socket from another thread blocks too (shutdown, getpeername: the
 * earlier hangs; a WebSocket client's writer thread behind its reader thread: the 3 OpenAiLiveSpeechClientTest
 * timeouts). A thread parked in poll() does not hold it. So a BLOCKING read or accept on a TCP socket first waits in
 * poll() and only then reads, which no longer blocks. Signals still interrupt the poll (EINTR), so the JDK's
 * close-wakes-blocked-thread trick keeps working. Non-blocking sockets and MSG_DONTWAIT calls pass straight through. */
typedef int (*socket_fn)(int, int, int);
int socket(int domain, int type, int proto) {
    static socket_fn real;
    if (!real) real = (socket_fn)dlsym(RTLD_NEXT, "socket");
    int fd = real(domain, type, proto);
    if (fd >= 0 && fd < MAXFD) sockfd[fd] = (domain == AF_INET || domain == AF_INET6) && (type & 0xff) == SOCK_STREAM;
    return fd;
}

/* 0: go ahead and call the real function; -1 (errno set, EINTR for a signal): the wait failed. */
static int wait_readable(int fd, int flags) {
    if (fd < 0 || fd >= MAXFD || !sockfd[fd] || (flags & MSG_DONTWAIT)) return 0;
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || (fl & O_NONBLOCK)) return 0;
    struct pollfd pf = {fd, POLLIN, 0};
    for (;;) { int r = poll(&pf, 1, -1); if (r > 0) return 0; if (r < 0) return -1; }
}

typedef ssize_t (*read_fn)(int, void *, size_t);
ssize_t read(int fd, void *buf, size_t n) {
    static read_fn real;
    if (!real) real = (read_fn)dlsym(RTLD_NEXT, "read");
    if (wait_readable(fd, 0) < 0) return -1;
    return real(fd, buf, n);
}
typedef ssize_t (*recv_fn)(int, void *, size_t, int);
ssize_t recv(int fd, void *buf, size_t n, int flags) {
    static recv_fn real;
    if (!real) real = (recv_fn)dlsym(RTLD_NEXT, "recv");
    if (wait_readable(fd, flags) < 0) return -1;
    return real(fd, buf, n, flags);
}
typedef ssize_t (*recvfrom_fn)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *a, socklen_t *l) {
    static recvfrom_fn real;
    if (!real) real = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    if (wait_readable(fd, flags) < 0) return -1;
    return real(fd, buf, n, flags, a, l);
}
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
ssize_t recvmsg(int fd, struct msghdr *m, int flags) {
    static recvmsg_fn real;
    if (!real) real = (recvmsg_fn)dlsym(RTLD_NEXT, "recvmsg");
    if (wait_readable(fd, flags) < 0) return -1;
    return real(fd, m, flags);
}
typedef int (*accept_fn)(int, struct sockaddr *, socklen_t *);
int accept(int fd, struct sockaddr *a, socklen_t *l) {
    static accept_fn real;
    if (!real) real = (accept_fn)dlsym(RTLD_NEXT, "accept");
    if (wait_readable(fd, 0) < 0) return -1;
    int c = real(fd, a, l);
    if (c >= 0 && c < MAXFD) sockfd[c] = 1;
    return c;
}
typedef int (*accept4_fn)(int, struct sockaddr *, socklen_t *, int);
int accept4(int fd, struct sockaddr *a, socklen_t *l, int flags) {
    static accept4_fn real;
    if (!real) real = (accept4_fn)dlsym(RTLD_NEXT, "accept4");
    if (wait_readable(fd, 0) < 0) return -1;
    int c = real(fd, a, l, flags);
    if (c >= 0 && c < MAXFD) sockfd[c] = 1;
    return c;
}

typedef int (*shutdown_fn)(int, int);
static shutdown_fn real_shutdown;

/* Any other socket: under TSI, shutdown() also blocks while another thread sits in a blocking read() or
 * connect() on it (okhttp's WebSocket reader; Socket.close() calls shutdown first). Run the real call in a
 * helper thread and give up waiting after 300 ms; the helper is then already inside the kernel, so the later
 * close() cannot race with fd reuse, and the JDK's dup2+signal wakes the blocked reader as usual. */
struct sd { int fd, how, rc, err, done, refs; pthread_mutex_t m; pthread_cond_t c; };

static void *sd_thread(void *p) {
    struct sd *a = p;
    int rc = real_shutdown(a->fd, a->how), e = errno;
    pthread_mutex_lock(&a->m);
    a->rc = rc; a->err = e; a->done = 1; pthread_cond_signal(&a->c);
    int last = --a->refs == 0;
    pthread_mutex_unlock(&a->m);
    if (last) free(a);
    return 0;
}

int shutdown(int fd, int how) {
    if (!real_shutdown) real_shutdown = (shutdown_fn)dlsym(RTLD_NEXT, "shutdown");
    if (fd >= 0 && fd < MAXFD && listening[fd]) return 0;
    static int mode = -1;   /* SHIM_SHUTDOWN: async (default) | passthrough | noop, for experiments */
    if (mode < 0) { const char *e = getenv("SHIM_SHUTDOWN"); mode = !e ? 0 : !strcmp(e, "passthrough") ? 1 : !strcmp(e, "noop") ? 2 : 0; }
    if (mode == 1) return real_shutdown(fd, how);
    if (mode == 2) return 0;
    struct sd *a = calloc(1, sizeof *a);
    pthread_t t;
    if (!a) return real_shutdown(fd, how);
    a->fd = fd; a->how = how; a->refs = 2;
    pthread_mutex_init(&a->m, 0); pthread_cond_init(&a->c, 0);
    if (pthread_create(&t, 0, sd_thread, a)) { free(a); return real_shutdown(fd, how); }
    pthread_detach(t);
    struct timespec dl; clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_nsec += 300 * 1000000L; if (dl.tv_nsec >= 1000000000L) { dl.tv_sec++; dl.tv_nsec -= 1000000000L; }
    int rc = 0, e = 0;
    pthread_mutex_lock(&a->m);
    while (!a->done && pthread_cond_timedwait(&a->c, &a->m, &dl) == 0) ;
    if (a->done) { rc = a->rc; e = a->err; }
    int last = --a->refs == 0;
    pthread_mutex_unlock(&a->m);
    if (last) free(a);
    if (rc) { errno = e; return rc; }
    return 0;
}

typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);

static int loopback_peer(int fd) {
    struct sockaddr_storage ss;
    socklen_t l = sizeof ss;
    if (getpeername(fd, (struct sockaddr *)&ss, &l) < 0) return 0;   /* unconnected: may have sent anywhere */
    if (ss.ss_family == AF_INET) return (ntohl(((struct sockaddr_in *)&ss)->sin_addr.s_addr) >> 24) == 127;
    if (ss.ss_family == AF_INET6) {
        const struct in6_addr *a = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        return IN6_IS_ADDR_LOOPBACK(a) || (IN6_IS_ADDR_V4MAPPED(a) && a->s6_addr[12] == 127);
    }
    return 1;
}

int getsockopt(int fd, int level, int name, void *val, socklen_t *len) {
    static getsockopt_fn real;
    if (!real) real = (getsockopt_fn)dlsym(RTLD_NEXT, "getsockopt");
    if (level != SOL_SOCKET) {
        int type;
        socklen_t tl = sizeof type;
        if (real(fd, SOL_SOCKET, SO_TYPE, &type, &tl) == 0 && type == SOCK_DGRAM && !loopback_peer(fd)) {
            errno = EOPNOTSUPP;
            return -1;
        }
    }
    return real(fd, level, name, val, len);
}
