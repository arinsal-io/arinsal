#define _GNU_SOURCE
#include <stdbool.h>
#include <erl_nif.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

typedef void ErlNifOnHaltCallback(void *);
struct enif_environment_t {
    bool loading;
    unsigned char option_flags;
    ErlNifOnHaltCallback *on_halt;
    ErlNifOnHaltCallback *on_unload_thread;
};

extern ERL_NIF_TERM arinsal_nif_tuple(ErlNifEnv *, const ERL_NIF_TERM *, unsigned);
extern ERL_NIF_TERM arinsal_nif_list(ErlNifEnv *, const ERL_NIF_TERM *, unsigned);
extern char *arinsal_nif_format_term(ERL_NIF_TERM);
extern void arinsal_nif_free_formatted(char *);

typedef struct {
    int (*erts_milli_sleep)(long);
    void (*ethr_atomic_dec)(void *);
    void (*ethr_atomic_inc)(void *);
    void (*ethr_atomic_init)(void *, intptr_t);
    intptr_t (*ethr_atomic_read)(void *);
    void (*ethr_atomic_set)(void *, intptr_t);
    int (*ethr_rwmutex_destroy)(void *);
    int (*ethr_rwmutex_init_opt)(void *, void *);
    void (*ethr_rwmutex_rlock)(void *);
    void (*ethr_rwmutex_runlock)(void *);
    void (*ethr_rwmutex_rwlock)(void *);
    void (*ethr_rwmutex_rwunlock)(void *);
    int (*ethr_rwmutex_tryrlock)(void *);
    int (*ethr_rwmutex_tryrwlock)(void *);
    int (*ethr_thr_create)(pthread_t *, void *(*)(void *), void *, void *);
    int (*ethr_thr_join)(pthread_t, void **);
} ArinsalInternalTest;

extern intptr_t arinsal_internal_test_dispatch(uint32_t, uintptr_t, uintptr_t);

static int internal_sleep(long ms) {
    struct timespec req = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    while (nanosleep(&req, &req) != 0) {
        if (errno != EINTR) return errno;
    }
    return 0;
}
static void internal_atomic_dec(void *a) { __atomic_sub_fetch((intptr_t *)a, 1, __ATOMIC_SEQ_CST); }
static void internal_atomic_inc(void *a) { __atomic_add_fetch((intptr_t *)a, 1, __ATOMIC_SEQ_CST); }
static void internal_atomic_init(void *a, intptr_t value) { __atomic_store_n((intptr_t *)a, value, __ATOMIC_SEQ_CST); }
static intptr_t internal_atomic_read(void *a) { return __atomic_load_n((intptr_t *)a, __ATOMIC_SEQ_CST); }
static void internal_atomic_set(void *a, intptr_t value) { __atomic_store_n((intptr_t *)a, value, __ATOMIC_SEQ_CST); }
static void *internal_rwmutex_handle(void *storage) { return *(void **)storage; }
static int internal_rwmutex_init(void *storage, void *opts) {
    intptr_t handle;
    uintptr_t type = opts ? (uintptr_t)*(int *)opts : 0;
    handle = arinsal_internal_test_dispatch(6, (uintptr_t)storage, type);
    if (handle < 0) return (int)-handle;
    *(void **)storage = (void *)handle;
    return 0;
}
static int internal_rwmutex_destroy(void *storage) {
    void *handle = internal_rwmutex_handle(storage);
    int result;
    if (!handle) return EINVAL;
    result = (int)arinsal_internal_test_dispatch(7, (uintptr_t)handle, 0);
    if (result == 0) *(void **)storage = NULL;
    return result;
}
#define INTERNAL_RW_LOCK(name, op) \
    static void name(void *storage) { (void)arinsal_internal_test_dispatch(op, (uintptr_t)internal_rwmutex_handle(storage), 0); }
#define INTERNAL_RW_TRY(name, op) \
    static int name(void *storage) { return (int)arinsal_internal_test_dispatch(op, (uintptr_t)internal_rwmutex_handle(storage), 0); }
INTERNAL_RW_LOCK(internal_rwmutex_rlock, 8)
INTERNAL_RW_LOCK(internal_rwmutex_runlock, 9)
INTERNAL_RW_LOCK(internal_rwmutex_rwlock, 10)
INTERNAL_RW_LOCK(internal_rwmutex_rwunlock, 11)
INTERNAL_RW_TRY(internal_rwmutex_tryrlock, 12)
INTERNAL_RW_TRY(internal_rwmutex_tryrwlock, 13)

static int internal_thr_create(pthread_t *tid, void *(*start)(void *), void *arg, void *opts) {
    (void)opts;
    return pthread_create(tid, NULL, start, arg);
}
static int internal_thr_join(pthread_t tid, void **result) { return pthread_join(tid, result); }

__attribute__((visibility("default")))
const ArinsalInternalTest erts_internal_test_instance = {
    internal_sleep, internal_atomic_dec, internal_atomic_inc, internal_atomic_init,
    internal_atomic_read, internal_atomic_set, internal_rwmutex_destroy, internal_rwmutex_init,
    internal_rwmutex_rlock, internal_rwmutex_runlock, internal_rwmutex_rwlock,
    internal_rwmutex_rwunlock, internal_rwmutex_tryrlock, internal_rwmutex_tryrwlock,
    internal_thr_create, internal_thr_join
};

void arinsal_nif_shim_anchor(void) {}
long long arinsal_nif_cpu_micros(void) {
#ifdef CLOCK_PROCESS_CPUTIME_ID
    struct timespec ts;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) == 0)
        return (long long)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
#endif
    return -1;
}

ERL_NIF_TERM enif_make_tuple(ErlNifEnv *env, unsigned cnt, ...) {
    ERL_NIF_TERM *items = malloc(cnt * sizeof(*items));
    if (!items && cnt) return enif_make_badarg(env);
    va_list args;
    va_start(args, cnt);
    for (unsigned i = 0; i < cnt; i++) items[i] = va_arg(args, ERL_NIF_TERM);
    va_end(args);
    ERL_NIF_TERM result = arinsal_nif_tuple(env, items, cnt);
    free(items);
    return result;
}
ERL_NIF_TERM enif_make_list(ErlNifEnv *env, unsigned cnt, ...) {
    ERL_NIF_TERM *items = malloc(cnt * sizeof(*items));
    if (!items && cnt) return enif_make_badarg(env);
    va_list args;
    va_start(args, cnt);
    for (unsigned i = 0; i < cnt; i++) items[i] = va_arg(args, ERL_NIF_TERM);
    va_end(args);
    ERL_NIF_TERM result = arinsal_nif_list(env, items, cnt);
    free(items);
    return result;
}
static int nif_append(char **data, size_t *len, size_t *cap, const char *part, size_t count) {
    if (count > SIZE_MAX - *len - 1) return 0;
    if (*len + count + 1 > *cap) {
        size_t next = (*len + count + 1) * 2;
        char *grown = realloc(*data, next);
        if (!grown) return 0;
        *data = grown;
        *cap = next;
    }
    memcpy(*data + *len, part, count);
    *len += count;
    (*data)[*len] = 0;
    return 1;
}
static int nif_format(char *buffer, size_t size, const char *format, va_list args) {
    size_t len = 0, cap = 128;
    char *result = calloc(cap, 1);
    if (!result) return -1;
    while (*format) {
        if (*format != '%') {
            if (!nif_append(&result, &len, &cap, format, 1)) goto error;
            format++;
            continue;
        }
        const char *start = format++;
        if (*format == '%') { if (!nif_append(&result, &len, &cap, "%", 1)) goto error; format++; continue; }
        while (*format && !strchr("diouxXfFeEgGaAcspT", *format)) format++;
        if (!*format || (size_t)(format - start) >= 120) goto error;
        char conversion = *format++;
        char spec[128], part[4096];
        size_t spec_len = (size_t)(format - start);
        memcpy(spec, start, spec_len); spec[spec_len] = 0;
        int n;
        if (conversion == 'T') {
            ERL_NIF_TERM value = va_arg(args, ERL_NIF_TERM);
            char *rendered = arinsal_nif_format_term(value);
            if (!rendered) goto error;
            n = (int)strlen(rendered);
            if (!nif_append(&result, &len, &cap, rendered, (size_t)n)) { arinsal_nif_free_formatted(rendered); goto error; }
            arinsal_nif_free_formatted(rendered);
            continue;
        } else if (strchr("di", conversion)) {
            if (strstr(spec, "ll")) n = snprintf(part, sizeof(part), spec, va_arg(args, long long));
            else if (strchr(spec, 'l')) n = snprintf(part, sizeof(part), spec, va_arg(args, long));
            else n = snprintf(part, sizeof(part), spec, va_arg(args, int));
        } else if (strchr("ouxX", conversion)) {
            if (strstr(spec, "ll")) n = snprintf(part, sizeof(part), spec, va_arg(args, unsigned long long));
            else if (strchr(spec, 'l')) n = snprintf(part, sizeof(part), spec, va_arg(args, unsigned long));
            else n = snprintf(part, sizeof(part), spec, va_arg(args, unsigned));
        } else if (strchr("fFeEgGaA", conversion)) n = snprintf(part, sizeof(part), spec, va_arg(args, double));
        else if (conversion == 'c') n = snprintf(part, sizeof(part), spec, va_arg(args, int));
        else if (conversion == 's') n = snprintf(part, sizeof(part), spec, va_arg(args, char *));
        else n = snprintf(part, sizeof(part), spec, va_arg(args, void *));
        if (n < 0 || (size_t)n >= sizeof(part) || !nif_append(&result, &len, &cap, part, (size_t)n)) goto error;
    }
    if (size && buffer) { size_t count = len < size - 1 ? len : size - 1; memcpy(buffer, result, count); buffer[count] = 0; }
    free(result);
    return (int)len;
error:
    free(result);
    return -1;
}
int enif_vsnprintf(char *buffer, size_t size, const char *format, va_list args) {
    if (!strstr(format, "%T")) return vsnprintf(buffer, size, format, args);
    return nif_format(buffer, size, format, args);
}
int enif_snprintf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = enif_vsnprintf(buffer, size, format, args);
    va_end(args);
    return n;
}
int enif_vfprintf(FILE *stream, const char *format, va_list args) {
    if (!strstr(format, "%T")) return vfprintf(stream, format, args);
    va_list copy;
    va_copy(copy, args);
    int n = enif_vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (n < 0) return n;
    char *buffer = malloc((size_t)n + 1);
    if (!buffer) return -1;
    va_copy(copy, args);
    enif_vsnprintf(buffer, (size_t)n + 1, format, copy);
    va_end(copy);
    int written = (int)fwrite(buffer, 1, (size_t)n, stream);
    free(buffer);
    return written;
}
int enif_fprintf(FILE *stream, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = enif_vfprintf(stream, format, args);
    va_end(args);
    return n;
}
int enif_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int n = enif_vfprintf(stdout, format, args);
    va_end(args);
    return n;
}
/* Port of erts/emulator/beam/erl_nif.c:5496-5560, OTP-29.1.1. */
int enif_set_option(ErlNifEnv *env, ErlNifOption option, ...) {
    if (!env || !env->loading) return EINVAL;
    va_list args;
    switch (option) {
    case ERL_NIF_OPT_DELAY_HALT:
        if (env->option_flags & 1) return EINVAL;
        env->option_flags |= 1;
        return 0;
    case ERL_NIF_OPT_ON_HALT: {
        va_start(args, option);
        ErlNifOnHaltCallback *callback = va_arg(args, ErlNifOnHaltCallback *);
        va_end(args);
        if (!callback || env->on_halt) return EINVAL;
        env->on_halt = callback;
        return 0;
    }
    case ERL_NIF_OPT_ON_UNLOAD_THREAD: {
        va_start(args, option);
        ErlNifOnHaltCallback *callback = va_arg(args, ErlNifOnHaltCallback *);
        va_end(args);
        if (!callback || env->on_unload_thread) return EINVAL;
        env->on_unload_thread = callback;
        return 0;
    }
    default:
        return EINVAL;
    }
}
void *enif_dlopen(const char *library, void (*error_handler)(void *, const char *), void *error_arg) {
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        size_t len = strlen(library);
        char *path = malloc(len + 4);
        if (path) {
            memcpy(path, library, len);
            memcpy(path + len, ".so", 4);
            handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
            free(path);
        }
    }
    if (!handle && error_handler) error_handler(error_arg, dlerror());
    if (handle) {
        ErlNifEntry *(*init)(void) = dlsym(handle, "nif_init");
        if (init) (void)init();
    }
    return handle;
}
void *enif_dlsym(void *handle, const char *symbol, void (*error_handler)(void *, const char *), void *error_arg) {
    void *address = dlsym(handle, symbol);
    if (!address && error_handler) error_handler(error_arg, dlerror());
    return address;
}

typedef struct { pthread_mutex_t value; char *name; } NifMutex;
ErlNifMutex *enif_mutex_create(char *name) {
    NifMutex *m = malloc(sizeof(*m));
    if (!m) return NULL;
    m->name = strdup(name ? name : "");
    if (pthread_mutex_init(&m->value, NULL)) { free(m->name); free(m); return NULL; }
    return (ErlNifMutex *)m;
}
void enif_mutex_destroy(ErlNifMutex *p) { NifMutex *m = (NifMutex *)p; pthread_mutex_destroy(&m->value); free(m->name); free(m); }
int enif_mutex_trylock(ErlNifMutex *p) { return pthread_mutex_trylock(&((NifMutex *)p)->value); }
void enif_mutex_lock(ErlNifMutex *p) { pthread_mutex_lock(&((NifMutex *)p)->value); }
void enif_mutex_unlock(ErlNifMutex *p) { pthread_mutex_unlock(&((NifMutex *)p)->value); }
char *enif_mutex_name(ErlNifMutex *p) { return ((NifMutex *)p)->name; }

typedef struct { pthread_cond_t value; char *name; } NifCond;
ErlNifCond *enif_cond_create(char *name) {
    NifCond *c = malloc(sizeof(*c));
    if (!c) return NULL;
    c->name = strdup(name ? name : "");
    if (pthread_cond_init(&c->value, NULL)) { free(c->name); free(c); return NULL; }
    return (ErlNifCond *)c;
}
void enif_cond_destroy(ErlNifCond *p) { NifCond *c = (NifCond *)p; pthread_cond_destroy(&c->value); free(c->name); free(c); }
void enif_cond_signal(ErlNifCond *p) { pthread_cond_signal(&((NifCond *)p)->value); }
void enif_cond_broadcast(ErlNifCond *p) { pthread_cond_broadcast(&((NifCond *)p)->value); }
void enif_cond_wait(ErlNifCond *p, ErlNifMutex *m) { pthread_cond_wait(&((NifCond *)p)->value, &((NifMutex *)m)->value); }
char *enif_cond_name(ErlNifCond *p) { return ((NifCond *)p)->name; }

typedef struct { pthread_rwlock_t value; char *name; } NifRWLock;
ErlNifRWLock *enif_rwlock_create(char *name) {
    NifRWLock *r = malloc(sizeof(*r));
    if (!r) return NULL;
    r->name = strdup(name ? name : "");
    if (pthread_rwlock_init(&r->value, NULL)) { free(r->name); free(r); return NULL; }
    return (ErlNifRWLock *)r;
}
void enif_rwlock_destroy(ErlNifRWLock *p) { NifRWLock *r = (NifRWLock *)p; pthread_rwlock_destroy(&r->value); free(r->name); free(r); }
int enif_rwlock_tryrlock(ErlNifRWLock *p) { return pthread_rwlock_tryrdlock(&((NifRWLock *)p)->value); }
void enif_rwlock_rlock(ErlNifRWLock *p) { pthread_rwlock_rdlock(&((NifRWLock *)p)->value); }
void enif_rwlock_runlock(ErlNifRWLock *p) { pthread_rwlock_unlock(&((NifRWLock *)p)->value); }
int enif_rwlock_tryrwlock(ErlNifRWLock *p) { return pthread_rwlock_trywrlock(&((NifRWLock *)p)->value); }
void enif_rwlock_rwlock(ErlNifRWLock *p) { pthread_rwlock_wrlock(&((NifRWLock *)p)->value); }
void enif_rwlock_rwunlock(ErlNifRWLock *p) { pthread_rwlock_unlock(&((NifRWLock *)p)->value); }
char *enif_rwlock_name(ErlNifRWLock *p) { return ((NifRWLock *)p)->name; }

/* Port of erl_nif.c:2423-2426: the TSD functions are erl_drv_tsd_*, whose keys are not
 * limited by pthread_key_create (the driver thread layer provides them in the full binary;
 * a binary without it falls back to pthread keys). */
static void *drv_tsd(const char *sym) { return dlsym(RTLD_DEFAULT, sym); }
int enif_tsd_key_create(char *name, ErlNifTSDKey *key) {
    int (*f)(char *, int *) = drv_tsd("erl_drv_tsd_key_create");
    if (f) { int k; int ret = f(name, &k); if (!ret) *key = (ErlNifTSDKey)(long)k; return ret; }
    pthread_key_t k; int ret = pthread_key_create(&k, NULL); if (!ret) *key = (ErlNifTSDKey)k; return ret;
}
void enif_tsd_key_destroy(ErlNifTSDKey key) {
    void (*f)(int) = drv_tsd("erl_drv_tsd_key_destroy");
    if (f) f((int)(long)key); else pthread_key_delete((pthread_key_t)key);
}
void enif_tsd_set(ErlNifTSDKey key, void *data) {
    void (*f)(int, void *) = drv_tsd("erl_drv_tsd_set");
    if (f) f((int)(long)key, data); else pthread_setspecific((pthread_key_t)key, data);
}
void *enif_tsd_get(ErlNifTSDKey key) {
    void *(*f)(int) = drv_tsd("erl_drv_tsd_get");
    return f ? f((int)(long)key) : pthread_getspecific((pthread_key_t)key);
}

ErlNifThreadOpts *enif_thread_opts_create(char *name) { (void)name; ErlDrvThreadOpts *p = calloc(1, sizeof(*p)); return (ErlNifThreadOpts *)p; }
void enif_thread_opts_destroy(ErlNifThreadOpts *p) { free(p); }
int enif_thread_create(char *name, ErlNifTid *tid, void *(*fn)(void *), void *arg, ErlNifThreadOpts *opts) {
    (void)name; (void)opts;
    pthread_t thread;
    int ret = pthread_create(&thread, NULL, fn, arg);
    if (!ret) *tid = (ErlNifTid)thread;
    return ret;
}
ErlNifTid enif_thread_self(void) { return (ErlNifTid)pthread_self(); }
int enif_equal_tids(ErlNifTid a, ErlNifTid b) { return pthread_equal((pthread_t)a, (pthread_t)b); }
void enif_thread_exit(void *result) { pthread_exit(result); }
int enif_thread_join(ErlNifTid tid, void **result) { return pthread_join((pthread_t)tid, result); }
char *enif_thread_name(ErlNifTid tid) {
    static _Thread_local char name[128];
    if (pthread_getname_np((pthread_t)tid, name, sizeof(name))) name[0] = 0;
    return name;
}
void enif_system_info(ErlNifSysInfo *info, size_t size) {
    ErlNifSysInfo full = {0};
    full.driver_major_version = 3;
    full.driver_minor_version = 4;
    full.erts_version = "17.1";
    full.otp_release = "29";
    full.thread_support = 1;
    full.smp_support = 1;
    full.async_threads = 1;
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    full.scheduler_threads = cpu_count > 0 ? (int)cpu_count : 1;
    full.nif_major_version = 2;
    full.nif_minor_version = 18;
    full.dirty_scheduler_support = 1;
    memcpy(info, &full, size < sizeof(full) ? size : sizeof(full));
}

