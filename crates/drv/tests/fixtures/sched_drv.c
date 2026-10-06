/*
 * Port task scheduling fixture: a driver whose busy state and callback duration are
 * controlled from Erlang. Output commands:
 *   'B' V  set busy, record V        'L' V T  sleep T*10 ms, set busy, record V
 *   'C' V  record V                  'D' V T  sleep T*10 ms, record V
 *   'N'    clear busy
 * Controls 'B'/'N' set and clear busy. `stop` outputs the recorded values.
 */
#include <string.h>
#include <unistd.h>
#include "erl_driver.h"

typedef struct {
    ErlDrvPort port;
    char data[255];
    int len;
} SchedDrv;

static ErlDrvData sched_start(ErlDrvPort port, char *command)
{
    SchedDrv *d = driver_alloc(sizeof(SchedDrv));
    (void)command;
    d->port = port;
    d->len = 0;
    return (ErlDrvData)d;
}

static void sched_stop(ErlDrvData drv_data)
{
    SchedDrv *d = (SchedDrv *)drv_data;
    driver_output(d->port, d->data, d->len);
    driver_free(d);
}

static void record(SchedDrv *d, char *buf, ErlDrvSizeT len)
{
    if (len > 1 && d->len < (int)sizeof(d->data))
        d->data[d->len++] = buf[1];
}

static void sched_output(ErlDrvData drv_data, char *buf, ErlDrvSizeT len)
{
    SchedDrv *d = (SchedDrv *)drv_data;
    if (len < 1)
        return;
    switch (buf[0]) {
    case 'L':
        if (len > 2)
            usleep((unsigned char)buf[2] * 10000);
        set_busy_port(d->port, 1);
        break;
    case 'B':
        set_busy_port(d->port, 1);
        break;
    case 'D':
        if (len > 2)
            usleep((unsigned char)buf[2] * 10000);
        break;
    case 'N':
        set_busy_port(d->port, 0);
        return;
    default:
        break;
    }
    record(d, buf, len);
}

static ErlDrvSSizeT sched_control(ErlDrvData drv_data, unsigned int command, char *buf,
                                  ErlDrvSizeT len, char **rbuf, ErlDrvSizeT rlen)
{
    SchedDrv *d = (SchedDrv *)drv_data;
    (void)buf;
    (void)len;
    (void)rbuf;
    (void)rlen;
    set_busy_port(d->port, command == 'B');
    return 0;
}

static ErlDrvEntry sched_drv_entry = {
    NULL, sched_start, sched_stop, sched_output, NULL, NULL, "sched_drv", NULL, NULL,
    sched_control, NULL, NULL, NULL, NULL, NULL, NULL,
    ERL_DRV_EXTENDED_MARKER, ERL_DRV_EXTENDED_MAJOR_VERSION, ERL_DRV_EXTENDED_MINOR_VERSION,
    ERL_DRV_FLAG_USE_PORT_LOCKING | ERL_DRV_FLAG_SOFT_BUSY, NULL, NULL, NULL, NULL
};

DRIVER_INIT(sched_drv)
{
    return &sched_drv_entry;
}
