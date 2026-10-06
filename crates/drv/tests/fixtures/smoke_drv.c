/* Smoke driver for the arinsal-drv differential test. Built as `smoke_drv`
 * (output), with -DSMOKE_OUTPUTV as `smoke_v_drv` (outputv), and with
 * -DDRV_NAME / -DDRV_MAJOR overrides for load error cases. */
#include <erl_driver.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef DRV_NAME
#ifdef SMOKE_OUTPUTV
#define DRV_NAME "smoke_v_drv"
#else
#define DRV_NAME "smoke_drv"
#endif
#endif
#ifndef DRV_MAJOR
#define DRV_MAJOR ERL_DRV_EXTENDED_MAJOR_VERSION
#endif

typedef struct {
    ErlDrvPort port;
} State;

static int stops = 0;

static int smoke_init(void) { return 0; }

static ErlDrvData smoke_start(ErlDrvPort port, char *command) {
    if (strstr(command, "fail_start") != NULL) {
        errno = EACCES;
        return ERL_DRV_ERROR_ERRNO;
    }
    if (strstr(command, "badarg_start") != NULL)
        return ERL_DRV_ERROR_BADARG;
    if (strstr(command, "general_start") != NULL)
        return ERL_DRV_ERROR_GENERAL;
    State *st = driver_alloc(sizeof(State));
    st->port = port;
    return (ErlDrvData)st;
}

static void smoke_stop(ErlDrvData data) {
    stops++;
    driver_free(data);
}

/* Commands start with '!'; anything else is echoed. */
static int command(State *st, char *buf, ErlDrvSizeT len) {
    if (len == 0 || buf[0] != '!')
        return 0;
    if (len == 4 && memcmp(buf, "!eof", 4) == 0)
        driver_failure_eof(st->port);
    else if (len == 5 && memcmp(buf, "!fail", 5) == 0)
        driver_failure_atom(st->port, "smoke_failed");
    else if (len == 9 && memcmp(buf, "!failcode", 9) == 0)
        driver_failure(st->port, 7);
    else if (len == 6 && memcmp(buf, "!posix", 6) == 0)
        driver_failure_posix(st->port, EACCES);
    else if (len == 5 && memcmp(buf, "!exit", 5) == 0)
        driver_exit(st->port, 0);
    else if (len == 8 && memcmp(buf, "!exiterr", 8) == 0)
        driver_exit(st->port, ENOENT);
    else if (len >= 4 && memcmp(buf, "!hdr", 4) == 0)
        driver_output2(st->port, "hd", 2, buf + 4, len - 4);
    else if (len == 7 && memcmp(buf, "!nodata", 7) == 0)
        driver_output2(st->port, "hd", 2, NULL, 0);
    return 1;
}

#ifndef SMOKE_OUTPUTV
static void smoke_output(ErlDrvData data, char *buf, ErlDrvSizeT len) {
    State *st = (State *)data;
    if (!command(st, buf, len))
        driver_output(st->port, buf, len);
}
#else
static void smoke_outputv(ErlDrvData data, ErlIOVec *ev) {
    State *st = (State *)data;
    char text[512];
    int n = snprintf(text, sizeof(text), "vsize=%d size=%lu", ev->vsize,
                     (unsigned long)ev->size);
    for (int i = 0; i < ev->vsize && n < 400; i++) {
        int shared = i > 0 && ev->binv[i] != NULL && ev->binv[i] == ev->binv[i - 1];
        n += snprintf(text + n, sizeof(text) - n, " %lu%s%s",
                      (unsigned long)ev->iov[i].iov_len,
                      ev->binv[i] ? "b" : "-", shared ? "s" : "");
    }
    driver_output(st->port, text, n);
    for (int i = 0; i < ev->vsize; i++)
        if (ev->iov[i].iov_len)
            driver_output(st->port, ev->iov[i].iov_base, ev->iov[i].iov_len);
}
#endif

static ErlDrvSSizeT smoke_control(ErlDrvData data, unsigned int cmd, char *buf,
                                  ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen) {
    State *st = (State *)data;
    switch (cmd) {
    case 1: /* reverse into the preallocated buffer */
        if (len > rlen)
            return -1;
        for (ErlDrvSizeT i = 0; i < len; i++)
            (*rbuf)[i] = buf[len - 1 - i];
        return len;
    case 2: { /* binary reply in a driver binary */
        set_port_control_flags(st->port, PORT_CONTROL_FLAG_BINARY);
        ErlDrvBinary *bin = driver_alloc_binary(100);
        for (int i = 0; i < 100; i++)
            bin->orig_bytes[i] = len ? buf[i % len] : 'z';
        *rbuf = (char *)bin;
        return 100;
    }
    case 3: { /* list reply in a driver_alloc buffer */
        set_port_control_flags(st->port, 0);
        char *out = driver_alloc(70);
        for (int i = 0; i < 70; i++)
            out[i] = 'a' + i % 26;
        *rbuf = out;
        return 70;
    }
    case 4:
        return -1;
    case 5:
        *rbuf = NULL;
        return 0;
    case 6:
        return snprintf(*rbuf, rlen, "%d", stops);
    case 7: /* small binary reply in the preallocated buffer */
        set_port_control_flags(st->port, PORT_CONTROL_FLAG_BINARY);
        memcpy(*rbuf, "pre", 3);
        return 3;
    case 8:
        set_port_control_flags(st->port, 0);
        return 0;
    default:
        return -1;
    }
}

/* Reply {Cmd, Arg} in external term format. */
static ErlDrvSSizeT smoke_call(ErlDrvData data, unsigned int cmd, char *buf,
                               ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen,
                               unsigned int *flags) {
    (void)data;
    (void)flags;
    if (cmd == 0 || len < 1 || (unsigned char)buf[0] != 131)
        return -1;
    if (cmd == 1) { /* no version magic: badarg */
        (*rbuf)[0] = 100;
        return 1;
    }
    ErlDrvSizeT need = 1 + 2 + 2 + (len - 1);
    char *out = need <= rlen ? *rbuf : driver_alloc(need);
    out[0] = (char)131;
    out[1] = 104; /* SMALL_TUPLE_EXT */
    out[2] = 2;
    out[3] = 97; /* SMALL_INTEGER_EXT */
    out[4] = (char)cmd;
    memcpy(out + 5, buf + 1, len - 1);
    *rbuf = out;
    return need;
}

static ErlDrvEntry smoke_entry = {
    smoke_init,
    smoke_start,
    smoke_stop,
#ifndef SMOKE_OUTPUTV
    smoke_output,
#else
    NULL,
#endif
    NULL,
    NULL,
    DRV_NAME,
    NULL,
    NULL,
    smoke_control,
    NULL,
#ifdef SMOKE_OUTPUTV
    smoke_outputv,
#else
    NULL,
#endif
    NULL,
    NULL,
    smoke_call,
    NULL,
    ERL_DRV_EXTENDED_MARKER,
    DRV_MAJOR,
    ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING,
    NULL,
    NULL,
    NULL,
    NULL,
};

DRIVER_INIT(smoke_drv) { return &smoke_entry; }
