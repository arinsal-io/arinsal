use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub(super) fn set_parent_death_signal(command: &mut Command) {
    let parent_pid = std::process::id() as libc::pid_t;

    let hook = move || {
        // SAFETY: prctl is async-signal-safe in the pre-exec child.
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: getppid is async-signal-safe in the pre-exec child.
        if unsafe { libc::getppid() } != parent_pid {
            // SAFETY: getpid is async-signal-safe in the pre-exec child.
            let child_pid = unsafe { libc::getpid() };
            // SAFETY: kill is async-signal-safe; SIGKILL terminates this child.
            if unsafe { libc::kill(child_pid, libc::SIGKILL) } == -1 {
                return Err(io::Error::last_os_error());
            }
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }

        Ok(())
    };

    // SAFETY: the hook uses only async-signal-safe operations after fork and before exec.
    unsafe {
        command.pre_exec(hook);
    }
}
