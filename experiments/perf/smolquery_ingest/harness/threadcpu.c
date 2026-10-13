// threadcpu: per-thread CPU snapshot of one process on macOS (no root needed
// for a process of the same user).
//
//   threadcpu <pid>            one JSON line: process totals + every thread
//
// Uses proc_pidinfo(PROC_PIDLISTTHREADS / PROC_PIDTHREADINFO) for per-thread
// user/system time and pthread name, PROC_PIDTASKINFO for process totals and
// resident size, and proc_pid_rusage(RUSAGE_INFO_V4) for the lifetime peak
// physical footprint. Times are nanoseconds.
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <sys/resource.h>
#include <mach/mach_time.h>
#include <time.h>

static void json_str(const char *s) {
  putchar('"');
  for (; *s; s++) {
    if (*s == '"' || *s == '\\') putchar('\\');
    if ((unsigned char)*s < 0x20) continue;
    putchar(*s);
  }
  putchar('"');
}

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: threadcpu <pid>\n"); return 2; }
  int pid = atoi(argv[1]);
  mach_timebase_info_data_t tb; mach_timebase_info(&tb);

  struct proc_taskinfo ti;
  if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof ti) != sizeof ti) {
    fprintf(stderr, "PROC_PIDTASKINFO failed for %d\n", pid); return 1;
  }
  struct rusage_info_v4 ru;
  int have_ru = proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&ru) == 0;

  uint64_t ids[8192];
  int n = proc_pidinfo(pid, PROC_PIDLISTTHREADS, 0, ids, sizeof ids);
  if (n <= 0) { fprintf(stderr, "PROC_PIDLISTTHREADS failed\n"); return 1; }
  n /= sizeof(uint64_t);

  struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
  printf("{\"t_ms\":%lld,\"pid\":%d,", (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000, pid);
  // pti_total_user/system are in mach absolute time units.
  printf("\"user_ns\":%llu,\"sys_ns\":%llu,\"rss\":%llu,",
         (unsigned long long)(ti.pti_total_user * tb.numer / tb.denom),
         (unsigned long long)(ti.pti_total_system * tb.numer / tb.denom),
         (unsigned long long)ti.pti_resident_size);
  if (have_ru)
    printf("\"phys_footprint\":%llu,\"lifetime_max_phys_footprint\":%llu,\"ru_user_ns\":%llu,\"ru_sys_ns\":%llu,",
           (unsigned long long)ru.ri_phys_footprint,
           (unsigned long long)ru.ri_lifetime_max_phys_footprint,
           (unsigned long long)(ru.ri_user_time * tb.numer / tb.denom),
           (unsigned long long)(ru.ri_system_time * tb.numer / tb.denom));
  printf("\"nthreads\":%d,\"threads\":[", n);
  int first = 1;
  for (int i = 0; i < n; i++) {
    struct proc_threadinfo th;
    if (proc_pidinfo(pid, PROC_PIDTHREADINFO, ids[i], &th, sizeof th) != sizeof th) continue;
    if (!first) putchar(',');
    first = 0;
    printf("{\"id\":%llu,\"user_ns\":%llu,\"sys_ns\":%llu,\"name\":",
           (unsigned long long)ids[i], (unsigned long long)th.pth_user_time,
           (unsigned long long)th.pth_system_time);
    json_str(th.pth_name);
    putchar('}');
  }
  printf("]}\n");
  return 0;
}
