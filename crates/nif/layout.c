#include <erl_nif.h>
#include <stddef.h>
#include <stdio.h>

#define SIZE(T) printf("SIZE_%s=%zu\n", #T, sizeof(T))
#define OFF(T, F) printf("OFF_%s_%s=%zu\n", #T, #F, offsetof(T, F))

int main(void) {
    SIZE(ErlNifEntry);
    OFF(ErlNifEntry, major);
    OFF(ErlNifEntry, minor);
    OFF(ErlNifEntry, name);
    OFF(ErlNifEntry, num_of_funcs);
    OFF(ErlNifEntry, funcs);
    OFF(ErlNifEntry, load);
    OFF(ErlNifEntry, reload);
    OFF(ErlNifEntry, upgrade);
    OFF(ErlNifEntry, unload);
    OFF(ErlNifEntry, vm_variant);
    OFF(ErlNifEntry, options);
    OFF(ErlNifEntry, sizeof_ErlNifResourceTypeInit);
    OFF(ErlNifEntry, min_erts);
    SIZE(ErlNifFunc);
    OFF(ErlNifFunc, name);
    OFF(ErlNifFunc, arity);
    OFF(ErlNifFunc, fptr);
    OFF(ErlNifFunc, flags);
    SIZE(ErlNifBinary);
    OFF(ErlNifBinary, size);
    OFF(ErlNifBinary, data);
    OFF(ErlNifBinary, ref_bin);
    OFF(ErlNifBinary, __spare__);
    SIZE(ErlNifResourceTypeInit);
    OFF(ErlNifResourceTypeInit, dtor);
    OFF(ErlNifResourceTypeInit, stop);
    OFF(ErlNifResourceTypeInit, down);
    OFF(ErlNifResourceTypeInit, members);
    OFF(ErlNifResourceTypeInit, dyncall);
    SIZE(ERL_NIF_TERM);
    return 0;
}
