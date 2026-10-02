#include <erl_driver.h>
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
    return 0;
}
