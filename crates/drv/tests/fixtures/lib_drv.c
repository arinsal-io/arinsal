/* Library API driver for the arinsal-drv differential test: exercises driver_alloc,
 * driver binaries, the port queue, outputv/output_binary, erl_drv_output_term /
 * send_term, process monitors, threads and locks, port data locks, system info,
 * time, environment, dynamic library calls, add/remove_driver_entry, lock_driver
 * and driver_create_port. Every control operation answers with one text report. */
#include <erl_driver.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef DRV_NAME
#define DRV_NAME "lib_drv"
#endif

typedef struct {
    ErlDrvPort port;
    ErlDrvTermData stash;
    ErlDrvMonitor monitor;
    int exits;
} State;

#define N(a) ((int)(sizeof(a) / sizeof((a)[0])))

static char rep[8192];
static int replen;

static void rep_reset(void) {
    replen = 0;
    rep[0] = 0;
}

static void say(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(rep + replen, sizeof(rep) - replen, fmt, ap);
    va_end(ap);
    if (n > 0 && replen + n < (int)sizeof(rep))
        replen += n;
}

static ErlDrvSSizeT reply(char **rbuf) {
    char *out = driver_alloc(replen > 0 ? replen : 1);
    memcpy(out, rep, replen);
    *rbuf = out;
    return replen;
}

static int init(void) { return 0; }

#ifdef ACK_DRV
#include <unistd.h>
typedef struct { ErlDrvPort port; int fail; ErlDrvData data; } AckArg;
static void *ack_thread(void *arg) {
    AckArg *a = arg;
    usleep(100000);
    if (a->fail) {
        errno = EACCES;
        erl_drv_init_ack(a->port, ERL_DRV_ERROR_ERRNO);
    } else {
        erl_drv_init_ack(a->port, a->data);
    }
    driver_free(a);
    return NULL;
}
#endif

static ErlDrvData start(ErlDrvPort port, char *command) {
    State *st = driver_alloc(sizeof(State));
    memset(st, 0, sizeof(State));
    st->port = port;
    st->stash = driver_mk_term_nil();
#ifdef ACK_DRV
    AckArg *a = driver_alloc(sizeof(AckArg));
    a->port = port;
    a->fail = strstr(command, "fail") != NULL;
    a->data = (ErlDrvData)st;
    ErlDrvTid tid;
    erl_drv_thread_create("ack", &tid, ack_thread, a, NULL);
#endif
    return (ErlDrvData)st;
}

static void stop(ErlDrvData data) { driver_free(data); }

static void output(ErlDrvData data, char *buf, ErlDrvSizeT len) {
    State *st = (State *)data;
    driver_output(st->port, buf, len);
}

static void process_exit(ErlDrvData data, ErlDrvMonitor *monitor) {
    State *st = (State *)data;
    st->exits++;
    ErlDrvTermData spec[] = {ERL_DRV_ATOM, driver_mk_atom("process_exit"),
                             ERL_DRV_INT,  st->exits,
                             ERL_DRV_TUPLE, 2};
    erl_drv_output_term(driver_mk_port(st->port), spec, sizeof(spec) / sizeof(spec[0]));
}

static void fill(ErlDrvBinary *bin, const char *text) {
    memcpy(bin->orig_bytes, text, strlen(text));
}

static void op_alloc(void) {
    char *a = driver_alloc(8);
    memcpy(a, "abcdefg", 8);
    a = driver_realloc(a, 32);
    say("realloc=%s;", a);
    driver_free(a);
    ErlDrvBinary *b = driver_alloc_binary(10);
    fill(b, "0123456789");
    say("size=%ld;refc=%ld;", (long)b->orig_size, (long)driver_binary_get_refc(b));
    say("inc=%ld;", (long)driver_binary_inc_refc(b));
    say("dec=%ld;", (long)driver_binary_dec_refc(b));
    b = driver_realloc_binary(b, 20);
    say("size2=%ld;kept=%.10s;refc=%ld;", (long)b->orig_size, b->orig_bytes,
        (long)driver_binary_get_refc(b));
    driver_free_binary(b);
}

static void dump_queue(ErlDrvPort port, const char *label) {
    int vlen = 0;
    SysIOVec *iov = driver_peekq(port, &vlen);
    ErlIOVec ev;
    ErlDrvSizeT size = driver_peekqv(port, &ev);
    char buf[256];
    ErlDrvSizeT got = ev.size > 0 ? driver_vec_to_buf(&ev, buf, sizeof(buf) - 1) : 0;
    buf[got] = 0;
    say("%s[vlen=%d,%s,vsize=%d,size=%ld,sizeq=%ld,text=%s];", label, vlen,
        iov ? "iov" : "null", ev.vsize, (long)size, (long)driver_sizeq(port), buf);
}

static void op_queue(ErlDrvPort port) {
    say("empty=%ld;", (long)driver_sizeq(port));
    say("enq=%d;", driver_enq(port, "abc", 3));
    say("enq=%d;", driver_enq(port, "defg", 4));
    say("pushq=%d;", driver_pushq(port, "XY", 2));
    say("enq0=%d;", driver_enq(port, "", 0));
    dump_queue(port, "q1");
    say("deq3=%ld;", (long)driver_deq(port, 3));
    dump_queue(port, "q2");
    say("deqbig=%ld;", (long)driver_deq(port, 100));
    ErlDrvBinary *b = driver_alloc_binary(11);
    fill(b, "hello world");
    say("enq_bin=%d;", driver_enq_bin(port, b, 6, 5));
    say("pushq_bin=%d;", driver_pushq_bin(port, b, 0, 5));
    say("refc=%ld;", (long)driver_binary_get_refc(b));
    dump_queue(port, "q3");
    SysIOVec iov[4];
    ErlDrvBinary *binv[4];
    ErlIOVec ev = {4, 15, iov, binv};
#define FRESH_EV() do { \
    iov[0].iov_base = NULL; iov[0].iov_len = 0; binv[0] = NULL; \
    iov[1].iov_base = b->orig_bytes; iov[1].iov_len = 5; binv[1] = b; \
    iov[2].iov_base = "-mid-"; iov[2].iov_len = 5; binv[2] = NULL; \
    iov[3].iov_base = b->orig_bytes + 6; iov[3].iov_len = 5; binv[3] = b; \
    ev.vsize = 4; ev.size = 15; } while (0)
    FRESH_EV();
    say("enqv=%d;", driver_enqv(port, &ev, 2));
    say("edited=%ld,%ld;", (long)iov[1].iov_len, (long)ev.size);
    /* erts keeps no copy for a missing binary when pushing to the front (it
       writes the copy's address to the wrong slot), so push binaries only. */
    FRESH_EV();
    iov[0].iov_base = b->orig_bytes; iov[0].iov_len = 2; binv[0] = b;
    iov[2].iov_base = b->orig_bytes + 2; iov[2].iov_len = 5; binv[2] = b;
    say("pushqv=%d;", driver_pushqv(port, &ev, 7));
    FRESH_EV();
    say("enqv_all=%d;", driver_enqv(port, &ev, 15));
    FRESH_EV();
    say("enqv0=%d;", driver_enqv(port, &ev, 0));
    say("refc2=%ld;", (long)driver_binary_get_refc(b));
    dump_queue(port, "q4");
    driver_free_binary(b);
    ErlDrvSizeT rest = driver_sizeq(port);
    say("deqall=%ld;", (long)driver_deq(port, rest));
    dump_queue(port, "q5");
}

static void op_outputv(ErlDrvPort port) {
    ErlDrvBinary *b = driver_alloc_binary(100);
    for (int i = 0; i < 100; i++)
        b->orig_bytes[i] = 'a' + i % 26;
    SysIOVec iov[4];
    ErlDrvBinary *binv[4];
    iov[0].iov_base = NULL; iov[0].iov_len = 0; binv[0] = NULL;
    iov[1].iov_base = b->orig_bytes; iov[1].iov_len = 3; binv[1] = b;
    iov[2].iov_base = "-mid-"; iov[2].iov_len = 5; binv[2] = NULL;
    iov[3].iov_base = b->orig_bytes + 10; iov[3].iov_len = 80; binv[3] = b;
    ErlIOVec ev = {4, 88, iov, binv};
    say("outputv0=%d;", driver_outputv(port, "hd", 2, &ev, 0));
    say("edited0=%ld;", (long)iov[1].iov_len);
    iov[1].iov_base = b->orig_bytes; iov[1].iov_len = 3; binv[1] = b;
    ev.size = 88;
    say("outputv_skip=%d;", driver_outputv(port, "", 0, &ev, 4));
    say("edited1=%ld,%ld;", (long)iov[1].iov_len, (long)iov[2].iov_len);
    iov[2].iov_base = "-mid-"; iov[2].iov_len = 5; binv[2] = NULL;
    say("outputv_all=%d;", driver_outputv(port, "zz", 2, &ev, 88));
    say("output_binary=%d;", driver_output_binary(port, "HB", 2, b, 5, 20));
    say("output_binary_big=%d;", driver_output_binary(port, NULL, 0, b, 0, 100));
    driver_free_binary(b);
}

static void op_terms(ErlDrvPort port, State *st) {
    ErlDrvTermData me = driver_mk_port(port);
    ErlDrvTermData caller = driver_caller(port);
    long long i64 = -9223372036854775807LL - 1;
    unsigned long long u64 = 18446744073709551615ULL;
    double d = 1.5;
    ErlDrvBinary *b = driver_alloc_binary(100);
    for (int i = 0; i < 100; i++)
        b->orig_bytes[i] = 'A' + i % 26;
    char ext[] = {131, 104, 2, 100, 0, 2, 111, 107, 107, 0, 3, 1, 2, 3};
    ErlDrvTermData all[] = {
        ERL_DRV_ATOM, driver_mk_atom("all"),
        ERL_DRV_NIL,
        ERL_DRV_INT, (ErlDrvTermData)-5,
        ERL_DRV_INT, (ErlDrvTermData)-4611686018427387905LL,
        ERL_DRV_UINT, (ErlDrvTermData)7,
        ERL_DRV_UINT, (ErlDrvTermData)18446744073709551615ULL,
        ERL_DRV_INT64, (ErlDrvTermData)&i64,
        ERL_DRV_UINT64, (ErlDrvTermData)&u64,
        ERL_DRV_PORT, me,
        ERL_DRV_PID, caller,
        ERL_DRV_BINARY, (ErlDrvTermData)b, 10, 3,
        ERL_DRV_BINARY, (ErlDrvTermData)b, 100, 0,
        ERL_DRV_BUF2BINARY, (ErlDrvTermData)"buf", 3,
        ERL_DRV_BUF2BINARY, (ErlDrvTermData)"", 0,
        ERL_DRV_STRING, (ErlDrvTermData)"str", 3,
        ERL_DRV_FLOAT, (ErlDrvTermData)&d,
        ERL_DRV_EXT2TERM, (ErlDrvTermData)ext, sizeof(ext),
        ERL_DRV_TUPLE, 17,
    };
    say("all=%d;", erl_drv_output_term(me, all, N(all)));

    ErlDrvTermData lists[] = {
        ERL_DRV_ATOM, driver_mk_atom("lists"),
        ERL_DRV_INT, 1, ERL_DRV_INT, 2, ERL_DRV_NIL, ERL_DRV_LIST, 3,
        ERL_DRV_INT, 1, ERL_DRV_INT, 2, ERL_DRV_ATOM, driver_mk_atom("tail"), ERL_DRV_LIST, 3,
        ERL_DRV_NIL, ERL_DRV_LIST, 1,
        ERL_DRV_STRING, (ErlDrvTermData)"ab", 2, ERL_DRV_STRING_CONS, (ErlDrvTermData)"xy", 2,
        ERL_DRV_STRING, (ErlDrvTermData)"", 0,
        ERL_DRV_NIL, ERL_DRV_STRING_CONS, (ErlDrvTermData)"cd", 2,
        ERL_DRV_TUPLE, 0,
        ERL_DRV_TUPLE, 8,
    };
    say("lists=%d;", erl_drv_output_term(me, lists, N(lists)));

    ErlDrvTermData map[] = {
        ERL_DRV_ATOM, driver_mk_atom("k1"), ERL_DRV_INT, 1,
        ERL_DRV_ATOM, driver_mk_atom("k0"), ERL_DRV_INT, 0,
        ERL_DRV_MAP, 2,
    };
    say("map=%d;", erl_drv_output_term(me, map, N(map)));
    ErlDrvTermData emap[] = {ERL_DRV_MAP, 0};
    say("emap=%d;", erl_drv_output_term(me, emap, N(emap)));
    ErlDrvTermData dupmap[] = {
        ERL_DRV_ATOM, driver_mk_atom("k"), ERL_DRV_INT, 1,
        ERL_DRV_ATOM, driver_mk_atom("k"), ERL_DRV_INT, 2,
        ERL_DRV_MAP, 2,
    };
    say("dupmap=%d;", erl_drv_output_term(me, dupmap, N(dupmap)));

    /* send_term to the caller and to the stashed (possibly dead) process */
    ErlDrvTermData tosend[] = {ERL_DRV_ATOM, driver_mk_atom("sent"), ERL_DRV_INT, 42,
                               ERL_DRV_TUPLE, 2};
    say("send_caller=%d;", erl_drv_send_term(me, caller, tosend, N(tosend)));
    say("send_stash=%d;", erl_drv_send_term(me, st->stash, tosend, N(tosend)));
    say("send_old=%d;", driver_send_term(port, caller, tosend, N(tosend)));
    say("output_old=%d;", driver_output_term(port, tosend, N(tosend)));
    say("send_nonpid=%d;", erl_drv_send_term(me, me, tosend, N(tosend)));

    /* malformed specifications are rejected as a whole */
    ErlDrvTermData empty[] = {ERL_DRV_NIL};
    say("noargs=%d;", erl_drv_output_term(me, empty, 0));
    ErlDrvTermData two[] = {ERL_DRV_NIL, ERL_DRV_NIL};
    say("two=%d;", erl_drv_output_term(me, two, N(two)));
    ErlDrvTermData listzero[] = {ERL_DRV_NIL, ERL_DRV_LIST, 0};
    say("listzero=%d;", erl_drv_output_term(me, listzero, N(listzero)));
    ErlDrvTermData tupbig[] = {ERL_DRV_NIL, ERL_DRV_TUPLE, 2};
    say("tupbig=%d;", erl_drv_output_term(me, tupbig, N(tupbig)));
    ErlDrvTermData badtag[] = {ERL_DRV_NIL, 99};
    say("badtag=%d;", erl_drv_output_term(me, badtag, N(badtag)));
    ErlDrvTermData badatom[] = {ERL_DRV_ATOM, 12345};
    say("badatom=%d;", erl_drv_output_term(me, badatom, N(badatom)));
    ErlDrvTermData badpid[] = {ERL_DRV_PID, me};
    say("badpid=%d;", erl_drv_output_term(me, badpid, N(badpid)));
    ErlDrvTermData badport[] = {ERL_DRV_PORT, caller};
    say("badport=%d;", erl_drv_output_term(me, badport, N(badport)));
    ErlDrvTermData short1[] = {ERL_DRV_INT};
    say("short=%d;", erl_drv_output_term(me, short1, N(short1)));
    ErlDrvTermData badbin[] = {ERL_DRV_BINARY, (ErlDrvTermData)b, 99, 2};
    say("badbin=%d;", erl_drv_output_term(me, badbin, N(badbin)));
    ErlDrvTermData nullbuf[] = {ERL_DRV_BUF2BINARY, 0, 4};
    say("nullbuf=%d;", erl_drv_output_term(me, nullbuf, N(nullbuf)));
    ErlDrvTermData nullstr[] = {ERL_DRV_STRING, 0, 0};
    say("nullstr=%d;", erl_drv_output_term(me, nullstr, N(nullstr)));
    ErlDrvTermData consfirst[] = {ERL_DRV_STRING_CONS, (ErlDrvTermData)"ab", 2};
    say("consfirst=%d;", erl_drv_output_term(me, consfirst, N(consfirst)));
    double inf = 1.0 / 0.0;
    ErlDrvTermData badfloat[] = {ERL_DRV_FLOAT, (ErlDrvTermData)&inf};
    say("badfloat=%d;", erl_drv_output_term(me, badfloat, N(badfloat)));
    char badext[] = {130, 1, 2};
    ErlDrvTermData ext2[] = {ERL_DRV_EXT2TERM, (ErlDrvTermData)badext, sizeof(badext)};
    say("badext=%d;", erl_drv_output_term(me, ext2, N(ext2)));
    ErlDrvTermData deadport[] = {ERL_DRV_NIL};
    say("noport=%d;", erl_drv_output_term(ERL_DRV_PORT, deadport, N(deadport)));
    driver_free_binary(b);
}

static void op_monitor(ErlDrvPort port, State *st, int mode) {
    ErlDrvTermData caller = driver_caller(port);
    if (mode == 1) {
        ErlDrvMonitor m, m2;
        int rc = driver_monitor_process(port, caller, &m);
        int rc2 = driver_monitor_process(port, caller, &m2);
        say("monitor=%d,%d;same_process=%d;", rc, rc2,
            driver_get_monitored_process(port, &m) == caller);
        say("cmp_self=%d;cmp_other=%d;", driver_compare_monitors(&m, &m),
            driver_compare_monitors(&m, &m2) != 0);
        say("nil_unknown=%d;",
            driver_get_monitored_process(port, &(ErlDrvMonitor){{0}}) == driver_mk_term_nil());
        st->monitor = m2;
        say("demonitor_second=%d;", driver_demonitor_process(port, &m2));
        say("demonitor_again=%d;", driver_demonitor_process(port, &m2));
    } else if (mode == 2) {
        ErlDrvMonitor m;
        say("monitor=%d;", driver_monitor_process(port, caller, &m));
        say("demonitor=%d;", driver_demonitor_process(port, &m));
        say("demonitor_again=%d;", driver_demonitor_process(port, &m));
    } else if (mode == 3) {
        st->stash = caller;
        say("stashed;");
    } else {
        ErlDrvMonitor m;
        say("monitor_stash=%d;", driver_monitor_process(port, st->stash, &m));
        say("monitor_nonpid=%d;", driver_monitor_process(port, driver_mk_atom("nope"), &m));
    }
}

static void op_info(ErlDrvPort port) {
    ErlDrvSysInfo info;
    memset(&info, 0, sizeof(info));
    driver_system_info(&info, sizeof(info));
    say("major=%d;minor=%d;erts=%s;otp=%s;threads=%d;smp=%d;dirty=%d;nif=%d.%d;", info.driver_major_version,
        info.driver_minor_version, info.erts_version, info.otp_release, info.thread_support,
        info.smp_support, info.dirty_scheduler_support, info.nif_major_version,
        info.nif_minor_version);
    say("schedulers=%d;async=%d;", info.scheduler_threads, info.async_threads);
    say("nil=%d;", driver_mk_term_nil() == driver_term_nil);
    say("atom_same=%d;", driver_mk_atom("foo") == driver_mk_atom("foo"));
    say("atom_diff=%d;", driver_mk_atom("foo") != driver_mk_atom("bar"));
    say("flags=%d;", get_port_flags(port));
    say("null=%d;", null_func());
    ErlDrvSizeT low = 0, high = 0;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("limits=%ld,%ld;", (long)low, (long)high);
    low = 100; high = 50;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("set=%ld,%ld;", (long)low, (long)high);
    low = 0; high = 7;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("high7=%ld,%ld;", (long)low, (long)high);
    low = 3; high = 0;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("low3=%ld,%ld;", (long)low, (long)high);
    low = ERL_DRV_BUSY_MSGQ_DISABLED; high = 0;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("disabled=%d,%d;", low == ERL_DRV_BUSY_MSGQ_DISABLED, high == ERL_DRV_BUSY_MSGQ_DISABLED);
    low = 0; high = 0;
    erl_drv_busy_msgq_limits(port, &low, &high);
    say("after=%d,%d;", low == ERL_DRV_BUSY_MSGQ_DISABLED, high == ERL_DRV_BUSY_MSGQ_DISABLED);
}

typedef struct {
    ErlDrvMutex *mutex;
    ErlDrvCond *cond;
    ErlDrvRWLock *rw;
    ErlDrvTSDKey key;
    int started;
    int tsd_ok;
    int self_matches;
    ErlDrvTermData port_term;
} Shared;

static void *worker(void *arg) {
    Shared *sh = arg;
    erl_drv_tsd_set(sh->key, (void *)0x1234);
    int tsd = erl_drv_tsd_get(sh->key) == (void *)0x1234;
    /* erl_drv_output_term may be called from any thread */
    ErlDrvTermData spec[] = {ERL_DRV_ATOM, driver_mk_atom("thread_msg"), ERL_DRV_INT, 7,
                             ERL_DRV_TUPLE, 2};
    erl_drv_output_term(sh->port_term, spec, N(spec));
    erl_drv_rwlock_rlock(sh->rw);
    erl_drv_rwlock_runlock(sh->rw);
    erl_drv_mutex_lock(sh->mutex);
    sh->tsd_ok = tsd;
    sh->started = 1;
    erl_drv_cond_signal(sh->cond);
    erl_drv_mutex_unlock(sh->mutex);
    return (void *)0x77;
}

static void *exiter(void *arg) {
    erl_drv_thread_exit((void *)0x99);
    return NULL;
}

static void op_threads(ErlDrvPort port) {
    Shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.port_term = driver_mk_port(port);
    sh.mutex = erl_drv_mutex_create("test_mutex");
    sh.cond = erl_drv_cond_create("test_cond");
    sh.rw = erl_drv_rwlock_create(NULL);
    say("names=%s,%s,%s;", erl_drv_mutex_name(sh.mutex), erl_drv_cond_name(sh.cond),
        erl_drv_rwlock_name(sh.rw));
    say("tsd_create=%d;", erl_drv_tsd_key_create("k", &sh.key));
    ErlDrvTSDKey second;
    erl_drv_tsd_key_create(NULL, &second);
    say("keys=%d;", second - sh.key);
    erl_drv_tsd_key_destroy(second);
    erl_drv_tsd_key_create(NULL, &second);
    say("reuse=%d;", second - sh.key);
    erl_drv_tsd_key_destroy(second);
    say("tsd_empty=%d;", erl_drv_tsd_get(sh.key) == NULL);
    say("trylock=%d,%d;", erl_drv_mutex_trylock(sh.mutex) == 0, erl_drv_mutex_trylock(sh.mutex) != 0);
    erl_drv_mutex_unlock(sh.mutex);
    say("rw=%d,%d,%d,", erl_drv_rwlock_tryrlock(sh.rw) == 0, erl_drv_rwlock_tryrlock(sh.rw) == 0,
        erl_drv_rwlock_tryrwlock(sh.rw) != 0);
    erl_drv_rwlock_runlock(sh.rw);
    erl_drv_rwlock_runlock(sh.rw);
    say("%d,%d;", erl_drv_rwlock_tryrwlock(sh.rw) == 0, erl_drv_rwlock_tryrlock(sh.rw) != 0);
    erl_drv_rwlock_rwunlock(sh.rw);

    ErlDrvThreadOpts *opts = erl_drv_thread_opts_create("opts");
    opts->suggested_stack_size = 64;
    ErlDrvTid tid;
    erl_drv_mutex_lock(sh.mutex);
    int rc = erl_drv_thread_create("worker", &tid, worker, &sh, opts);
    say("create=%d;name=%s;", rc, erl_drv_thread_name(tid));
    while (!sh.started)
        erl_drv_cond_wait(sh.cond, sh.mutex);
    erl_drv_mutex_unlock(sh.mutex);
    void *res = NULL;
    say("join=%d;res=%p;tsd_ok=%d;", erl_drv_thread_join(tid, &res), res, sh.tsd_ok);
    ErlDrvTid exit_tid;
    erl_drv_thread_create("exiter", &exit_tid, exiter, NULL, NULL);
    erl_drv_thread_join(exit_tid, &res);
    say("exit_res=%p;", res);
    ErlDrvTid self = erl_drv_thread_self();
    say("self_equal=%d;", erl_drv_equal_tids(self, erl_drv_thread_self()));
    erl_drv_thread_opts_destroy(opts);
    erl_drv_tsd_key_destroy(sh.key);
    erl_drv_mutex_destroy(sh.mutex);
    erl_drv_cond_destroy(sh.cond);
    erl_drv_rwlock_destroy(sh.rw);
}

static void op_pdl(ErlDrvPort port) {
    ErlDrvPDL pdl = driver_pdl_create(port);
    say("pdl=%d;second=%d;", pdl != NULL, driver_pdl_create(port) == NULL);
    say("refc=%ld;", (long)driver_pdl_get_refc(pdl));
    driver_pdl_lock(pdl);
    say("locked=%ld;", (long)driver_pdl_get_refc(pdl));
    driver_pdl_unlock(pdl);
    say("unlocked=%ld;", (long)driver_pdl_get_refc(pdl));
    say("inc=%ld;", (long)driver_pdl_inc_refc(pdl));
    say("dec=%ld;", (long)driver_pdl_dec_refc(pdl));
    say("enq=%d;", driver_enq(port, "pdl", 3));
    driver_deq(port, 3);
}

static void op_env_time(void) {
    char buf[64];
    size_t size = sizeof(buf);
    say("put=%d;", erl_drv_putenv("DRV_LIB_TEST", "from_driver"));
    say("get=%d;", erl_drv_getenv("DRV_LIB_TEST", buf, &size));
    say("value=%s;len=%ld;", buf, (long)size);
    size = 5;
    int rc = erl_drv_getenv("DRV_LIB_TEST", buf, &size);
    say("small=%d,%ld;", rc, (long)size);
    size = sizeof(buf);
    rc = erl_drv_getenv("DRV_LIB_NOT_SET", buf, &size);
    say("unset=%d,%ld;", rc, (long)size);
    size = sizeof(buf);
    rc = erl_drv_getenv("DRV_LIB_FROM_ERL", buf, &size);
    say("from_erl=%d,%s;", rc, buf);
    say("conv=%ld,%ld,%ld,%ld;", (long)erl_drv_convert_time_unit(5, ERL_DRV_SEC, ERL_DRV_MSEC),
        (long)erl_drv_convert_time_unit(-1, ERL_DRV_MSEC, ERL_DRV_SEC),
        (long)erl_drv_convert_time_unit(1999, ERL_DRV_MSEC, ERL_DRV_SEC),
        (long)erl_drv_convert_time_unit(-1001, ERL_DRV_USEC, ERL_DRV_MSEC));
    say("bad_unit=%d;", erl_drv_convert_time_unit(1, 77, ERL_DRV_SEC) == ERL_DRV_TIME_ERROR);
    ErlDrvTime ns = erl_drv_monotonic_time(ERL_DRV_NSEC);
    ErlDrvTime ms = erl_drv_monotonic_time(ERL_DRV_MSEC);
    say("mono_units=%d;", erl_drv_convert_time_unit(ns, ERL_DRV_NSEC, ERL_DRV_MSEC) - ms <= 1);
    say("bad_mono=%d;", erl_drv_monotonic_time(77) == ERL_DRV_TIME_ERROR);
    ErlDrvNowData a, b;
    driver_get_now(&a);
    driver_get_now(&b);
    say("now_incr=%d;", (b.megasecs > a.megasecs) ||
        (b.megasecs == a.megasecs && (b.secs > a.secs || (b.secs == a.secs && b.microsecs > a.microsecs))));
    say("now_null=%d;", driver_get_now(NULL));
    char text[64];
    snprintf(text, sizeof(text), "%lld", (long long)ns);
    say("mono_ns=%s;", text);
    snprintf(text, sizeof(text), "%lld", (long long)erl_drv_time_offset(ERL_DRV_NSEC));
    say("offset_ns=%s;", text);
}

static void op_dl(char *path, ErlDrvSizeT len) {
    char file[512];
    snprintf(file, sizeof(file), "%.*s", (int)len, path);
    void *h = driver_dl_open(file);
    say("open=%d;", h != NULL);
    say("sym=%d;", driver_dl_sym(h, "driver_init") != NULL);
    say("nosym=%d;", driver_dl_sym(h, "no_such_symbol_here") == NULL);
    say("error_sym=%d;", strstr(driver_dl_error(), "no_such_symbol_here") != NULL);
    say("close=%d;", driver_dl_close(h));
    void *bad = driver_dl_open("/nonexistent/lib_nothing");
    say("open_bad=%d;error_has_name=%d;", bad == NULL,
        strstr(driver_dl_error(), "no_such_symbol_here") != NULL);
}

static ErlDrvData extra_start(ErlDrvPort port, char *command) { return (ErlDrvData)port; }
static void extra_stop(ErlDrvData data) {}
static void extra_output(ErlDrvData data, char *buf, ErlDrvSizeT len) {
    ErlDrvPort port = (ErlDrvPort)data;
    char out[64];
    int n = snprintf(out, sizeof(out), "extra:%.*s", (int)len, buf);
    driver_output(port, out, n);
}

static ErlDrvEntry extra_entry = {
    NULL, extra_start, extra_stop, extra_output, NULL, NULL, "lib_extra_drv", NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, ERL_DRV_EXTENDED_MARKER, ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION, 0, NULL, NULL, NULL, NULL};

static ErlDrvEntry entry;

static void op_entries(ErlDrvPort port, State *st, int mode) {
    if (mode == 1) {
        add_driver_entry(&extra_entry);
        say("added;");
    } else if (mode == 2) {
        say("remove=%d;", remove_driver_entry(&extra_entry));
        say("remove_again=%d;", remove_driver_entry(&extra_entry));
        say("remove_dynamic=%d;", remove_driver_entry(&entry));
    } else if (mode == 3) {
        say("lock=%d;", driver_lock_driver(port));
    } else {
        State *cs = driver_alloc(sizeof(State));
        memset(cs, 0, sizeof(State));
        cs->stash = driver_mk_term_nil();
        ErlDrvPort child = driver_create_port(port, driver_caller(port), "lib_child", (ErlDrvData)cs);
        say("created=%d;", child != (ErlDrvPort)-1);
        if (child == (ErlDrvPort)-1)
            return;
        cs->port = child;
        ErlDrvTermData spec[] = {ERL_DRV_ATOM, driver_mk_atom("child"), ERL_DRV_PORT,
                                 driver_mk_port(child), ERL_DRV_TUPLE, 2};
        say("sent=%d;", erl_drv_output_term(driver_mk_port(port), spec, N(spec)));
    }
}

static void op_busy(ErlDrvPort port) {
    set_busy_port(port, 1);
    say("busy;");
}

static ErlDrvSSizeT control(ErlDrvData data, unsigned int cmd, char *buf, ErlDrvSizeT len,
                            char **rbuf, ErlDrvSizeT rlen) {
    State *st = (State *)data;
    ErlDrvPort port = st->port;
    rep_reset();
    switch (cmd) {
    case 1: op_alloc(); break;
    case 2: op_queue(port); break;
    case 3: op_outputv(port); break;
    case 4: op_terms(port, st); break;
    case 5: op_monitor(port, st, 1); break;
    case 6: op_monitor(port, st, 2); break;
    case 7: op_monitor(port, st, 3); break;
    case 8: op_monitor(port, st, 4); break;
    case 9: op_info(port); break;
    case 10: op_threads(port); break;
    case 11: op_pdl(port); break;
    case 12: op_env_time(); break;
    case 13: op_dl(buf, len); break;
    case 14: op_busy(port); break;
    case 15: set_busy_port(port, 0); say("unbusy;"); break;
    case 16: op_entries(port, st, 1); break;
    case 17: op_entries(port, st, 2); break;
    case 18: op_entries(port, st, 3); break;
    case 19: op_entries(port, st, 4); break;
    case 20: say("exits=%d;", st->exits); break;
    default: return -1;
    }
    return reply(rbuf);
}

#ifdef NO_PROCESS_EXIT
#define PROCESS_EXIT NULL
#else
#define PROCESS_EXIT process_exit
#endif
#ifdef ACK_DRV
#define DRV_FLAGS (ERL_DRV_FLAG_USE_PORT_LOCKING | ERL_DRV_FLAG_USE_INIT_ACK)
#else
#define DRV_FLAGS ERL_DRV_FLAG_USE_PORT_LOCKING
#endif

static ErlDrvEntry entry = {
    init, start, stop, output, NULL, NULL, DRV_NAME, NULL, NULL, control, NULL, NULL, NULL,
    NULL, NULL, NULL, ERL_DRV_EXTENDED_MARKER, ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION, DRV_FLAGS, NULL, PROCESS_EXIT, NULL, NULL};

DRIVER_INIT(lib_drv) { return &entry; }
