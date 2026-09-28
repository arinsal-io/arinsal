#include <erl_nif.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <dlfcn.h>

/* This API is variadic, which Rust cannot define on stable Rust. */
int enif_snprintf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    int result;
    va_start(args, format);
    result = vsnprintf(buffer, size, format, args);
    va_end(args);
    return result;
}

void nif_spike_shim_anchor(void) {}

ErlNifMutex *enif_mutex_create(char *name) {
    pthread_mutex_t *mutex = malloc(sizeof(*mutex));
    (void)name;
    if (!mutex) return NULL;
    if (pthread_mutex_init(mutex, NULL) != 0) { free(mutex); return NULL; }
    return (ErlNifMutex *)mutex;
}

void enif_mutex_destroy(ErlNifMutex *mutex) {
    pthread_mutex_destroy((pthread_mutex_t *)mutex);
    free(mutex);
}

void enif_mutex_lock(ErlNifMutex *mutex) {
    pthread_mutex_lock((pthread_mutex_t *)mutex);
}

void enif_mutex_unlock(ErlNifMutex *mutex) {
    pthread_mutex_unlock((pthread_mutex_t *)mutex);
}

int enif_set_option(ErlNifEnv *env, ErlNifOption option, ...) {
    (void)env;
    fprintf(stderr, "toy enif_set_option: %d\n", option);
    return 1;
}

void *enif_dlopen(const char *library, void (*error_handler)(void *, const char *), void *error_arg) {
    void *handle = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        char path[4096];
        if (snprintf(path, sizeof(path), "%s.so", library) < (int)sizeof(path))
            handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    }
    fprintf(stderr, "toy enif_dlopen: %s -> %s\n", library, handle ? "ok" : "failed");
    if (!handle && error_handler) error_handler(error_arg, dlerror());
    if (handle) {
        ErlNifEntry *(*init)(void) = (ErlNifEntry *(*)(void))dlsym(handle, "nif_init");
        if (init) (void)init();
    }
    return handle;
}

void *enif_dlsym(void *handle, const char *symbol, void (*error_handler)(void *, const char *), void *error_arg) {
    void *address = dlsym(handle, symbol);
    fprintf(stderr, "toy enif_dlsym: %s -> %s\n", symbol, address ? "ok" : "failed");
    if (!address && error_handler) error_handler(error_arg, dlerror());
    return address;
}
