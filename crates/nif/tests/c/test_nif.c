#include <erl_nif.h>
#include <string.h>

static ErlNifResourceType *counter_type;
static ErlNifResourceType *dynamic_type;
static unsigned destructors;
static void counter_dtor(ErlNifEnv *env, void *object) { (void)env; (void)object; destructors++; }
static void dynamic_call(ErlNifEnv *env, void *object, void *call_data) {
    (void)env;
    *(int *)call_data += *(int *)object;
}
static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)priv; (void)info;
    counter_type = enif_open_resource_type(env, NULL, "counter", counter_dtor, ERL_NIF_RT_CREATE, NULL);
    ErlNifResourceTypeInit init = {0};
    init.members = 4;
    init.dyncall = dynamic_call;
    dynamic_type = enif_init_resource_type(env, "dynamic", &init, ERL_NIF_RT_CREATE, NULL);
    return counter_type && dynamic_type ? 0 : 1;
}
static ERL_NIF_TERM basic(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    int n;
    if (argc != 1 || !enif_get_int(env, argv[0], &n)) return enif_make_badarg(env);
    ERL_NIF_TERM a = enif_make_atom(env, "ok");
    ERL_NIF_TERM list = enif_make_list(env, 2, enif_make_int(env, 1), enif_make_int(env, 2));
    return enif_make_tuple(env, 3, a, enif_make_int(env, n), list);
}
static ERL_NIF_TERM atom_string_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM atom;
    int existing = enif_make_new_atom(env, "ok", &atom, ERL_NIF_LATIN1);
    ERL_NIF_TERM string = enif_make_string(env, "abcd", ERL_NIF_LATIN1);
    unsigned length = 0;
    char buffer[3];
    int valid = enif_get_string_length(env, string, &length, ERL_NIF_LATIN1);
    int truncated = enif_get_string(env, string, buffer, sizeof(buffer), ERL_NIF_LATIN1);
    return enif_make_tuple(env, 4, enif_make_int(env, existing), atom,
                           enif_make_int(env, valid ? (int)length : -1),
                           enif_make_tuple(env, 2, enif_make_int(env, truncated),
                                           enif_make_string(env, buffer, ERL_NIF_LATIN1)));
}
static ERL_NIF_TERM compare_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM one = enif_make_int(env, 1);
    ERL_NIF_TERM two = enif_make_int(env, 2);
    return enif_make_tuple(env, 3, enif_make_int(env, enif_compare(one, two)),
                           enif_make_int(env, enif_compare(two, one)),
                           enif_make_int(env, enif_is_identical(one, enif_make_int(env, 1))));
}
static ERL_NIF_TERM system_info_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifSysInfo info;
    enif_system_info(&info, sizeof(info));
    return enif_make_tuple(env, 5, enif_make_int(env, info.nif_major_version),
                           enif_make_int(env, info.nif_minor_version),
                           enif_make_int(env, info.scheduler_threads),
                           enif_make_int(env, info.async_threads),
                           enif_make_int(env, info.dirty_scheduler_support));
}
static ERL_NIF_TERM scheduled_result(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) return enif_make_badarg(env);
    int value;
    if (!enif_get_int(env, argv[0], &value)) return enif_make_badarg(env);
    if (value < 42) {
        ERL_NIF_TERM next = enif_make_int(env, value + 1);
        return enif_schedule_nif(env, "scheduled_result", 0, scheduled_result, 1, &next);
    }
    return enif_make_int(env, value);
}
static ERL_NIF_TERM schedule_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM value = enif_make_int(env, 40);
    return enif_schedule_nif(env, "scheduled_result", 0, scheduled_result, 1, &value);
}
static ERL_NIF_TERM map_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM keys[2] = {enif_make_int(env, 1), enif_make_int(env, 2)};
    ERL_NIF_TERM values[2] = {enif_make_int(env, 10), enif_make_int(env, 20)};
    ERL_NIF_TERM map, key, value, entries[2];
    ErlNifMapIterator iter;
    if (!enif_make_map_from_arrays(env, keys, values, 2, &map)) return enif_make_badarg(env);
    if (!enif_map_iterator_create(env, map, &iter, ERL_NIF_MAP_ITERATOR_FIRST)) return enif_make_badarg(env);
    for (int i = 0; i < 2; i++) {
        if (!enif_map_iterator_get_pair(env, &iter, &key, &value)) return enif_make_badarg(env);
        entries[i] = enif_make_tuple(env, 2, key, value);
        if (i == 0 && !enif_map_iterator_next(env, &iter)) return enif_make_badarg(env);
    }
    enif_map_iterator_destroy(env, &iter);
    return enif_make_list_from_array(env, entries, 2);
}
static ERL_NIF_TERM iolist_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM binary;
    unsigned char *bytes = enif_make_new_binary(env, 2, &binary);
    if (!bytes) return enif_make_badarg(env);
    bytes[0] = 1; bytes[1] = 2;
    ERL_NIF_TERM list = enif_make_list(env, 2, binary, enif_make_int(env, 3));
    ErlNifBinary inspected;
    if (!enif_inspect_iolist_as_binary(env, list, &inspected)) return enif_make_badarg(env);
    return enif_make_int(env, (int)(inspected.data[0] + inspected.data[1] + inspected.data[2]));
}
static ERL_NIF_TERM env_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifEnv *other = enif_alloc_env();
    if (!other) return enif_make_badarg(env);
    ERL_NIF_TERM pair = enif_make_tuple(other, 2, enif_make_atom(other, "copied"), enif_make_long(other, 123));
    ERL_NIF_TERM copied = enif_make_copy(env, pair);
    enif_clear_env(other);
    enif_free_env(other);
    return copied;
}
static ERL_NIF_TERM binary_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifBinary binary;
    if (!enif_alloc_binary(3, &binary)) return enif_make_badarg(env);
    binary.data[0] = 1; binary.data[1] = 2; binary.data[2] = 3;
    ERL_NIF_TERM full = enif_make_binary(env, &binary);
    return enif_make_sub_binary(env, full, 1, 2);
}
static ERL_NIF_TERM resource_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    int *object = enif_alloc_resource(counter_type, sizeof(int));
    if (!object) return enif_make_badarg(env);
    *object = 42;
    ERL_NIF_TERM reference = enif_make_resource(env, object);
    int *read = NULL;
    int result = enif_get_resource(env, reference, counter_type, (void **)&read) && read == object ? *read : -1;
    enif_release_resource(object);
    enif_keep_resource(object);
    enif_release_resource(object);
    ERL_NIF_TERM second = enif_make_resource(env, object);
    void *second_read = NULL;
    if (!enif_get_resource(env, second, counter_type, &second_read) || second_read != object) result = -1;
    return enif_make_tuple(env, 2, enif_make_int(env, result),
                           enif_make_ulong(env, enif_sizeof_resource(object)));
}
static ERL_NIF_TERM resource_binary_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    char *object = enif_alloc_resource(counter_type, 4);
    if (!object) return enif_make_badarg(env);
    memcpy(object, "xyz", 4);
    ERL_NIF_TERM binary = enif_make_resource_binary(env, object, object, 3);
    enif_release_resource(object);
    return binary;
}
static ERL_NIF_TERM dtor_count(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_make_uint(env, destructors);
}
static ERL_NIF_TERM dynamic_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    int *object = enif_alloc_resource(dynamic_type, sizeof(int));
    if (!object) return enif_make_badarg(env);
    *object = 7;
    ERL_NIF_TERM reference = enif_make_resource(env, object);
    enif_release_resource(object);
    int value = 3;
    int ok = enif_dynamic_resource_call(env, enif_make_atom(env, "test_nif"),
                                        enif_make_atom(env, "dynamic"), reference, &value);
    return enif_make_tuple(env, 2, enif_make_int(env, ok), enif_make_int(env, value));
}
static ERL_NIF_TERM format_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    char buffer[64];
    if (enif_snprintf(buffer, sizeof(buffer), "v=%T", enif_make_int(env, 42)) != 4) return enif_make_badarg(env);
    return enif_make_string(env, buffer, ERL_NIF_LATIN1);
}
static ERL_NIF_TERM etf_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM original = enif_make_tuple(env, 2, enif_make_atom(env, "etf"), enif_make_int(env, 77));
    ErlNifBinary binary;
    if (!enif_term_to_binary(env, original, &binary)) return enif_make_badarg(env);
    ERL_NIF_TERM decoded;
    size_t consumed = enif_binary_to_term(env, binary.data, binary.size, &decoded, 0);
    enif_release_binary(&binary);
    return consumed ? decoded : enif_make_badarg(env);
}
static ERL_NIF_TERM time_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_make_long(env, enif_convert_time_unit(-1500, ERL_NIF_MSEC, ERL_NIF_SEC));
}
static ERL_NIF_TERM hash_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM t = enif_make_int(env, 42);
    return enif_make_uint(env, (unsigned)enif_hash(ERL_NIF_PHASH2, t, 0));
}
static ERL_NIF_TERM ioq_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifIOQueue *q = enif_ioq_create(ERL_NIF_IOQ_NORMAL);
    ErlNifBinary bin;
    if (!q || !enif_alloc_binary(3, &bin)) return enif_make_badarg(env);
    memcpy(bin.data, "abc", 3);
    if (!enif_ioq_enq_binary(q, &bin, 1)) return enif_make_badarg(env);
    int count;
    SysIOVec *iov = enif_ioq_peek(q, &count);
    int first = count && iov ? ((unsigned char *)iov[0].iov_base)[0] : 0;
    size_t remaining;
    if (!enif_ioq_deq(q, 1, &remaining)) return enif_make_badarg(env);
    enif_ioq_destroy(q);
    return enif_make_tuple(env, 2, enif_make_int(env, first), enif_make_ulong(env, remaining));
}
static ERL_NIF_TERM iovec_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ERL_NIF_TERM one, two, tail;
    unsigned char *a = enif_make_new_binary(env, 1, &one);
    unsigned char *b = enif_make_new_binary(env, 2, &two);
    a[0] = 1; b[0] = 2; b[1] = 3;
    ERL_NIF_TERM list = enif_make_list(env, 2, one, two);
    ErlNifIOVec *vec = NULL;
    if (!enif_inspect_iovec(NULL, 2, list, &tail, &vec)) return enif_make_badarg(env);
    size_t size = vec->size;
    enif_free_iovec(vec);
    return tail == enif_make_list(env, 0) ? enif_make_ulong(env, size) : enif_make_badarg(env);
}
static void *thread_fn(void *arg) { return arg; }
static ERL_NIF_TERM thread_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifMutex *mutex = enif_mutex_create("test");
    if (!mutex) return enif_make_badarg(env);
    enif_mutex_lock(mutex);
    int busy = enif_mutex_trylock(mutex);
    enif_mutex_unlock(mutex);
    enif_mutex_destroy(mutex);
    ErlNifCond *cond = enif_cond_create("condition");
    ErlNifRWLock *lock = enif_rwlock_create("rwlock");
    ErlNifTSDKey key;
    int key_ok = enif_tsd_key_create("tsd", &key) == 0;
    if (!cond || !lock || !key_ok) return enif_make_badarg(env);
    enif_cond_signal(cond);
    enif_cond_broadcast(cond);
    enif_rwlock_rlock(lock);
    enif_rwlock_runlock(lock);
    enif_rwlock_rwlock(lock);
    enif_rwlock_rwunlock(lock);
    enif_tsd_set(key, (void *)1);
    int tsd_ok = enif_tsd_get(key) == (void *)1;
    enif_tsd_key_destroy(key);
    enif_cond_destroy(cond);
    enif_rwlock_destroy(lock);
    ErlNifTid tid;
    void *result = NULL;
    int started = enif_thread_create("worker", &tid, thread_fn, (void *)2, NULL) == 0;
    int joined = started && enif_thread_join(tid, &result) == 0 && result == (void *)2;
    return enif_make_int(env, busy != 0 && tsd_ok && joined);
}
static ERL_NIF_TERM send_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    ErlNifPid pid;
    if (!enif_self(env, &pid)) return enif_make_badarg(env);
    return enif_make_int(env, enif_send(env, &pid, NULL, enif_make_atom(env, "delivered")));
}
static ERL_NIF_TERM exception_probe(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc; (void)argv;
    return enif_raise_exception(env, enif_make_atom(env, "test_exception"));
}
static ErlNifFunc funcs[] = {
    {"basic",1,basic,0}, {"atom_string_probe",0,atom_string_probe,0},
    {"compare_probe",0,compare_probe,0}, {"system_info_probe",0,system_info_probe,0},
    {"schedule_probe",0,schedule_probe,0}, {"map_probe",0,map_probe,0}, {"iolist_probe",0,iolist_probe,0},
    {"env_probe",0,env_probe,0}, {"binary_probe",0,binary_probe,0},
    {"resource_probe",0,resource_probe,0}, {"resource_binary_probe",0,resource_binary_probe,0},
    {"dynamic_probe",0,dynamic_probe,0}, {"dtor_count",0,dtor_count,0},
    {"format_probe",0,format_probe,0}, {"etf_probe",0,etf_probe,0},
    {"time_probe",0,time_probe,0}, {"hash_probe",0,hash_probe,0},
    {"ioq_probe",0,ioq_probe,0}, {"iovec_probe",0,iovec_probe,0},
    {"thread_probe",0,thread_probe,0}, {"send_probe",0,send_probe,0},
    {"exception_probe",0,exception_probe,0}
};
ERL_NIF_INIT(test_nif, funcs, load, NULL, NULL, NULL)
