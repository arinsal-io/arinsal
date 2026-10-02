/* I/O test driver for the arinsal-drv differential test: driver_select (read/write,
 * USE, USE_NO_CALLBACK, stealing, stale owners), port timers, driver_async and
 * erl_drv_consume_timeslice. Commands arrive through port_control/3; `output` writes
 * to the driver's pipe. Replies are decimal strings in the preallocated buffer. */
#include <erl_driver.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    ErlDrvPort port;
    int rfd, wfd;
    int rclosed, wclosed;
    int once;
    int out_fires;
    int leak;
    int slice;
    long timer_ms;
} State;

static int stop_selects = 0, frees = 0, ready_in = 0, ready_out = 0, asyncs = 0;

typedef struct {
    State *st;
    int value;
    int sleep_ms;
} Job;

static ErlDrvData io_start(ErlDrvPort port, char *command) {
    int fds[2];
    State *st = driver_alloc(sizeof(State));
    memset(st, 0, sizeof(State));
    st->port = port;
    if (pipe(fds) != 0) {
        driver_free(st);
        return ERL_DRV_ERROR_ERRNO;
    }
    st->rfd = fds[0];
    st->wfd = fds[1];
    fcntl(st->rfd, F_SETFL, O_NONBLOCK);
    fcntl(st->wfd, F_SETFL, O_NONBLOCK);
    (void)command;
    return (ErlDrvData)st;
}

static void io_stop_select(ErlDrvEvent ev, void *reserved) {
    (void)reserved;
    close((int)(long)ev);
    __atomic_add_fetch(&stop_selects, 1, __ATOMIC_SEQ_CST);
}

static void io_stop(ErlDrvData data) {
    State *st = (State *)data;
    if (st->leak) {
        /* leave the read end selected: the port dies without deselecting */
        if (!st->wclosed)
            close(st->wfd);
        driver_free(st);
        return;
    }
    if (!st->rclosed)
        driver_select(st->port, (ErlDrvEvent)(long)st->rfd,
                      ERL_DRV_READ | ERL_DRV_WRITE | ERL_DRV_USE, 0);
    if (!st->wclosed)
        driver_select(st->port, (ErlDrvEvent)(long)st->wfd,
                      ERL_DRV_READ | ERL_DRV_WRITE | ERL_DRV_USE, 0);
    driver_free(st);
}

static void io_output(ErlDrvData data, char *buf, ErlDrvSizeT len) {
    State *st = (State *)data;
    if (write(st->wfd, buf, len) < 0)
        driver_output(st->port, "writefail", 9);
}

static void say(State *st, const char *text) {
    driver_output(st->port, (char *)text, strlen(text));
}

static void io_ready_input(ErlDrvData data, ErlDrvEvent ev) {
    State *st = (State *)data;
    int fd = (int)(long)ev;
    char buf[64], out[96];
    ssize_t n = read(fd, buf, sizeof(buf));
    __atomic_add_fetch(&ready_in, 1, __ATOMIC_SEQ_CST);
    if (n > 0) {
        int len = snprintf(out, sizeof(out), "in:%.*s", (int)n, buf);
        driver_output(st->port, out, len);
        if (st->once)
            driver_select(st->port, ev, ERL_DRV_READ, 0);
    } else if (n == 0) {
        say(st, "eof");
        driver_select(st->port, ev, ERL_DRV_READ, 0);
    } else if (errno == EAGAIN) {
        say(st, "again");
    } else {
        say(st, errno == EBADF ? "badfd" : "readerr");
        driver_select(st->port, ev, ERL_DRV_READ, 0);
    }
}

static void io_ready_output(ErlDrvData data, ErlDrvEvent ev) {
    State *st = (State *)data;
    __atomic_add_fetch(&ready_out, 1, __ATOMIC_SEQ_CST);
    say(st, "out");
    if (++st->out_fires >= 3)
        driver_select(st->port, ev, ERL_DRV_WRITE, 0);
}

static void io_timeout(ErlDrvData data) {
    State *st = (State *)data;
    if (st->slice) {
        int n = 0;
        char out[32];
        st->slice = 0;
        do {
            n++;
        } while (erl_drv_consume_timeslice(st->port, 10) == 0);
        snprintf(out, sizeof(out), "slice:%d", n);
        say(st, out);
        return;
    }
    say(st, "timeout");
}

static void job_run(void *p) {
    Job *job = p;
    if (job->sleep_ms)
        usleep(job->sleep_ms * 1000);
    job->value *= 2;
}

static void job_free(void *p) {
    __atomic_add_fetch(&frees, 1, __ATOMIC_SEQ_CST);
    free(p);
}

static void io_ready_async(ErlDrvData data, ErlDrvThreadData td) {
    State *st = (State *)data;
    Job *job = (Job *)td;
    char out[32];
    snprintf(out, sizeof(out), "async:%d", job->value);
    say(st, out);
    free(job);
    __atomic_add_fetch(&asyncs, 1, __ATOMIC_SEQ_CST);
}

static long arg_num(char *buf, ErlDrvSizeT len) {
    char tmp[24];
    size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
    memcpy(tmp, buf, n);
    tmp[n] = 0;
    return atol(tmp);
}

static ErlDrvSSizeT reply(char **rbuf, ErlDrvSizeT rlen, const char *fmt, long a, long b) {
    return snprintf(*rbuf, rlen, fmt, a, b);
}

static ErlDrvSSizeT io_control(ErlDrvData data, unsigned int cmd, char *buf, ErlDrvSizeT len,
                               char **rbuf, ErlDrvSizeT rlen) {
    State *st = (State *)data;
    ErlDrvEvent r = (ErlDrvEvent)(long)st->rfd, w = (ErlDrvEvent)(long)st->wfd;
    switch (cmd) {
    case 1: /* select read; arg "1": deselect after the first event */
        st->once = len > 0 && buf[0] == '1';
        return reply(rbuf, rlen, "%ld", driver_select(st->port, r, ERL_DRV_READ | ERL_DRV_USE, 1), 0);
    case 2:
        return reply(rbuf, rlen, "%ld", driver_select(st->port, w, ERL_DRV_WRITE, 1), 0);
    case 3:
        return reply(rbuf, rlen, "%ld", driver_select(st->port, r, ERL_DRV_READ, 0), 0);
    case 4: { /* deselect with ERL_DRV_USE: stop_select runs inside the call */
        long ret = driver_select(st->port, r, ERL_DRV_READ | ERL_DRV_USE, 0);
        st->rclosed = 1;
        return reply(rbuf, rlen, "%ld,%ld", ret, stop_selects);
    }
    case 5:
        return reply(rbuf, rlen, "%ld,%ld", stop_selects, frees);
    case 6:
        return snprintf(*rbuf, rlen, "%d,%d,%d,%d", ready_in, ready_out, asyncs, frees);
    case 7: { /* USE_NO_CALLBACK: the events go away, stop_select is not called */
        long ret = driver_select(st->port, r, ERL_DRV_READ | ERL_DRV_USE_NO_CALLBACK, 0);
        return reply(rbuf, rlen, "%ld,%ld", ret, stop_selects);
    }
    case 8: { /* selecting twice is one event */
        long a = driver_select(st->port, r, ERL_DRV_READ, 1);
        long b = driver_select(st->port, r, ERL_DRV_READ, 1);
        return reply(rbuf, rlen, "%ld,%ld", a, b);
    }
    case 9:
        close(st->wfd);
        st->wclosed = 1;
        return 0;
    case 10:
        st->timer_ms = arg_num(buf, len);
        return reply(rbuf, rlen, "%ld", driver_set_timer(st->port, st->timer_ms), 0);
    case 11:
        return reply(rbuf, rlen, "%ld", driver_cancel_timer(st->port), 0);
    case 12: {
        unsigned long left = 12345;
        driver_read_timer(st->port, &left);
        if (left == 0)
            return snprintf(*rbuf, rlen, "none");
        return snprintf(*rbuf, rlen, "%s", left <= (unsigned long)st->timer_ms ? "inrange" : "toolarge");
    }
    case 20:
    case 21:
    case 22: { /* async job: 20 round robin, 21 keyed, 22 slow */
        Job *job = malloc(sizeof(Job));
        unsigned int key = 7;
        long id;
        job->st = st;
        job->value = (int)arg_num(buf, len);
        job->sleep_ms = cmd == 22 ? 200 : 0;
        id = driver_async(st->port, cmd == 21 ? &key : NULL, job_run, job, job_free);
        return reply(rbuf, rlen, "%ld,%ld", id > 0 ? 1 : id, cmd == 21 ? (long)key : -1L);
    }
    case 30:
        st->slice = 1;
        return reply(rbuf, rlen, "%ld", driver_set_timer(st->port, 1), 0);
    case 40: /* select a descriptor that is not open */
        return reply(rbuf, rlen, "%ld", driver_select(st->port, (ErlDrvEvent)(long)9999, ERL_DRV_READ, 1), 0);
    case 50:
        return reply(rbuf, rlen, "%ld", (long)st->rfd, 0);
    case 51: /* select a descriptor owned by another port: stealing */
        st->once = 0;
        return reply(rbuf, rlen, "%ld",
                     driver_select(st->port, (ErlDrvEvent)arg_num(buf, len), ERL_DRV_READ, 1), 0);
    case 60:
        st->leak = 1;
        return 0;
    case 70: /* a never selected descriptor with ERL_DRV_USE_NO_CALLBACK/USE */
        return reply(rbuf, rlen, "%ld,%ld",
                     driver_select(st->port, (ErlDrvEvent)(long)dup(st->rfd), ERL_DRV_USE, 0),
                     stop_selects);
    default:
        return -1;
    }
}

static ErlDrvEntry io_entry = {
    NULL,
    io_start,
    io_stop,
    io_output,
    io_ready_input,
    io_ready_output,
    "io_drv",
    NULL,
    NULL,
    io_control,
    io_timeout,
    NULL,
    io_ready_async,
    NULL,
    NULL,
    NULL,
    ERL_DRV_EXTENDED_MARKER,
    ERL_DRV_EXTENDED_MAJOR_VERSION,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING,
    NULL,
    NULL,
    io_stop_select,
    NULL,
};

DRIVER_INIT(io_drv) { return &io_entry; }
