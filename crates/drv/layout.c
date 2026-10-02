#include <erl_driver.h>
#include <erl_nif.h>
#include <stddef.h>
#include <stdio.h>

#define SIZE(T) printf("SIZE_%s=%zu\n", #T, sizeof(T))
#define OFF(T, F) printf("OFF_%s_%s=%zu\n", #T, #F, offsetof(T, F))
#define VAL(N) printf("%s=%lld\n", #N, (long long)(N))

int main(void) {
    SIZE(ErlDrvEntry);
    OFF(ErlDrvEntry, init);
    OFF(ErlDrvEntry, start);
    OFF(ErlDrvEntry, stop);
    OFF(ErlDrvEntry, output);
    OFF(ErlDrvEntry, ready_input);
    OFF(ErlDrvEntry, ready_output);
    OFF(ErlDrvEntry, driver_name);
    OFF(ErlDrvEntry, finish);
    OFF(ErlDrvEntry, handle);
    OFF(ErlDrvEntry, control);
    OFF(ErlDrvEntry, timeout);
    OFF(ErlDrvEntry, outputv);
    OFF(ErlDrvEntry, ready_async);
    OFF(ErlDrvEntry, flush);
    OFF(ErlDrvEntry, call);
    OFF(ErlDrvEntry, unused_event_callback);
    OFF(ErlDrvEntry, extended_marker);
    OFF(ErlDrvEntry, major_version);
    OFF(ErlDrvEntry, minor_version);
    OFF(ErlDrvEntry, driver_flags);
    OFF(ErlDrvEntry, handle2);
    OFF(ErlDrvEntry, process_exit);
    OFF(ErlDrvEntry, stop_select);
    OFF(ErlDrvEntry, emergency_close);
    SIZE(ErlIOVec);
    OFF(ErlIOVec, vsize);
    OFF(ErlIOVec, size);
    OFF(ErlIOVec, iov);
    OFF(ErlIOVec, binv);
    SIZE(SysIOVec);
    SIZE(ErlDrvBinary);
    OFF(ErlDrvBinary, orig_size);
    OFF(ErlDrvBinary, orig_bytes);
    VAL(ERL_DRV_EXTENDED_MARKER);
    VAL(ERL_DRV_EXTENDED_MAJOR_VERSION);
    VAL(ERL_DRV_EXTENDED_MINOR_VERSION);
    VAL(ERL_DRV_MIN_REQUIRED_MAJOR_VERSION_ON_LOAD);
    VAL(ERL_DRV_FLAG_USE_PORT_LOCKING);
    VAL(PORT_CONTROL_FLAG_BINARY);
    VAL(DRIVER_CALL_KEEP_BUFFER);
    VAL(ERL_DRV_READ);
    VAL(ERL_DRV_WRITE);
    VAL(ERL_DRV_USE);
    VAL(ERL_DRV_USE_NO_CALLBACK);
    VAL(ERL_DRV_NIL);
    VAL(ERL_DRV_ATOM);
    VAL(ERL_DRV_INT);
    VAL(ERL_DRV_PORT);
    VAL(ERL_DRV_BINARY);
    VAL(ERL_DRV_STRING);
    VAL(ERL_DRV_TUPLE);
    VAL(ERL_DRV_LIST);
    VAL(ERL_DRV_STRING_CONS);
    VAL(ERL_DRV_PID);
    VAL(ERL_DRV_FLOAT);
    VAL(ERL_DRV_EXT2TERM);
    VAL(ERL_DRV_UINT);
    VAL(ERL_DRV_BUF2BINARY);
    VAL(ERL_DRV_INT64);
    VAL(ERL_DRV_UINT64);
    VAL(ERL_DRV_MAP);
    VAL(PORT_FLAG_BINARY);
    VAL(PORT_FLAG_LINE);
    VAL(ERL_NIF_MAJOR_VERSION);
    VAL(ERL_NIF_MINOR_VERSION);
    SIZE(ErlDrvMonitor);
    SIZE(ErlDrvSysInfo);
    OFF(ErlDrvSysInfo, driver_major_version);
    OFF(ErlDrvSysInfo, driver_minor_version);
    OFF(ErlDrvSysInfo, erts_version);
    OFF(ErlDrvSysInfo, otp_release);
    OFF(ErlDrvSysInfo, thread_support);
    OFF(ErlDrvSysInfo, smp_support);
    OFF(ErlDrvSysInfo, async_threads);
    OFF(ErlDrvSysInfo, scheduler_threads);
    OFF(ErlDrvSysInfo, nif_major_version);
    OFF(ErlDrvSysInfo, nif_minor_version);
    OFF(ErlDrvSysInfo, dirty_scheduler_support);
    SIZE(ErlDrvNowData);
    OFF(ErlDrvNowData, megasecs);
    OFF(ErlDrvNowData, secs);
    OFF(ErlDrvNowData, microsecs);
    SIZE(ErlDrvThreadOpts);
    return 0;
}
