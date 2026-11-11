#include <erl_driver.h>
#include <pthread.h>
#include <stdint.h>

static void *on_main_thread(void *arg) {
    (void)arg;
    return (void *)(uintptr_t)pthread_main_np();
}

static ErlDrvData start(ErlDrvPort port, char *command) {
    (void)command;
    return (ErlDrvData)port;
}

static void output(ErlDrvData data, char *buffer, ErlDrvSizeT length) {
    (void)data;
    (void)buffer;
    (void)length;
    ErlDrvTid tid = NULL;
    void *result = NULL;
    int status = erl_drv_steal_main_thread("main_thread_test", &tid,
                                           on_main_thread, NULL, NULL);
    if (status == 0)
        status = erl_drv_stolen_main_thread_join(tid, &result);
    char passed = status == 0 && (uintptr_t)result == 1 ? '1' : '0';
    driver_output((ErlDrvPort)data, &passed, 1);
}

static void stop(ErlDrvData data) { (void)data; }

static ErlDrvEntry entry = {
    .start = start,
    .output = output,
    .stop = stop,
    .driver_name = "main_thread_drv",
    .extended_marker = ERL_DRV_EXTENDED_MARKER,
    .major_version = ERL_DRV_EXTENDED_MAJOR_VERSION,
    .minor_version = ERL_DRV_EXTENDED_MINOR_VERSION,
    .driver_flags = ERL_DRV_FLAG_USE_PORT_LOCKING,
};

DRIVER_INIT(main_thread_drv) { return &entry; }
