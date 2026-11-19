#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>
#include <string.h>

typedef int (*bind_fn)(int, const struct sockaddr *, socklen_t);

int gethostname(char *name, size_t length) {
    static const char hostname[] = "localhost";
    if (length < sizeof(hostname)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(name, hostname, sizeof(hostname));
    return 0;
}

int bind(int socket, const struct sockaddr *address, socklen_t length) {
    bind_fn next_bind = (bind_fn)dlsym(RTLD_NEXT, "bind");
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;

    if (address->sa_family == AF_INET && length >= sizeof(ipv4)) {
        memcpy(&ipv4, address, sizeof(ipv4));
        if (ipv4.sin_addr.s_addr == htonl(INADDR_ANY)) {
            ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            address = (const struct sockaddr *)&ipv4;
        }
    } else if (address->sa_family == AF_INET6 && length >= sizeof(ipv6)) {
        memcpy(&ipv6, address, sizeof(ipv6));
        if (IN6_IS_ADDR_UNSPECIFIED(&ipv6.sin6_addr)) {
            ipv6.sin6_addr = in6addr_loopback;
            address = (const struct sockaddr *)&ipv6;
        }
    }

    if (next_bind == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return next_bind(socket, address, length);
}
