#include <dlfcn.h>
#include <netdb.h>
#include <string.h>

static int is_invalid_name(const char *name) {
    size_t length;
    if (name == NULL) {
        return 0;
    }
    length = strlen(name);
    return length >= 8 && strcmp(name + length - 8, ".invalid") == 0;
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **result) {
    typedef int (*lookup_fn)(const char *, const char *,
                             const struct addrinfo *, struct addrinfo **);
    static lookup_fn real_lookup;
    if (is_invalid_name(node)) {
        if (result != NULL) {
            *result = NULL;
        }
        return EAI_NONAME;
    }
    if (real_lookup == NULL) {
        real_lookup = (lookup_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    }
    return real_lookup(node, service, hints, result);
}

struct hostent *gethostbyname(const char *name) {
    typedef struct hostent *(*lookup_fn)(const char *);
    static lookup_fn real_lookup;
    if (is_invalid_name(name)) {
        h_errno = HOST_NOT_FOUND;
        return NULL;
    }
    if (real_lookup == NULL) {
        real_lookup = (lookup_fn)dlsym(RTLD_NEXT, "gethostbyname");
    }
    return real_lookup(name);
}
