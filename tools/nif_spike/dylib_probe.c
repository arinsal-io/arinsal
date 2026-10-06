#include <dlfcn.h>
#include <erl_nif.h>
#include <stdio.h>

static int probe(const char *path) {
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    ErlNifEntry *(*init)(void);
    ErlNifEntry *entry;
    if (!library) { fprintf(stderr, "dlopen %s: %s\n", path, dlerror()); return 1; }
    init = (ErlNifEntry *(*)(void))dlsym(library, "nif_init");
    if (!init) { fprintf(stderr, "nif_init %s: %s\n", path, dlerror()); return 1; }
    entry = init();
    printf("dylib host loaded %s: %s %d.%d, %d functions\n", path,
           entry->name, entry->major, entry->minor, entry->num_of_funcs);
    return 0;
}

int main(int argc, char **argv) {
    void *host;
    int result;
    if (argc != 4) { fprintf(stderr, "usage: dylib_probe host.dylib nb.so crypto.so\n"); return 2; }
    host = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!host) { fprintf(stderr, "host dlopen: %s\n", dlerror()); return 1; }
    result = probe(argv[2]);
    result |= probe(argv[3]);
    return result;
}
