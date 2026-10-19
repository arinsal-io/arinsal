#include "erl_driver.h"

typedef struct {
    ErlDrvPort port;
} PortExitRaceData;

static ErlDrvData port_exit_race_start(ErlDrvPort port, char *command) {
    PortExitRaceData *data = driver_alloc(sizeof(*data));
    (void)command;
    if (data == NULL) {
        return ERL_DRV_ERROR_GENERAL;
    }
    data->port = port;
    return (ErlDrvData)data;
}

static void port_exit_race_stop(ErlDrvData drv_data) {
    driver_free((char *)drv_data);
}

static void port_exit_race_output(ErlDrvData drv_data, char *buf, ErlDrvSizeT len) {
    PortExitRaceData *data = (PortExitRaceData *)drv_data;
    driver_output(data->port, buf, len);
}

static ErlDrvEntry port_exit_race_entry = {
    .start = port_exit_race_start,
    .stop = port_exit_race_stop,
    .output = port_exit_race_output,
    .driver_name = "port_exit_race_drv",
    .extended_marker = ERL_DRV_EXTENDED_MARKER,
    .major_version = ERL_DRV_EXTENDED_MAJOR_VERSION,
    .minor_version = ERL_DRV_EXTENDED_MINOR_VERSION,
};

DRIVER_INIT(port_exit_race_drv) {
    return &port_exit_race_entry;
}
