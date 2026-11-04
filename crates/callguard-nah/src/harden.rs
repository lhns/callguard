//! Process settings for the nah child. The only `unsafe` in callguard.

/// Stops Windows from showing a crash dialog for the child, which would hold
/// it until the parent's kill: `SetErrorMode` for fault boxes and
/// `_set_error_mode(1)` (stderr, not a message box; mode 2 hung) for CRT
/// asserts. Nothing on Unix.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn harden_process() {
    unsafe extern "system" {
        fn SetErrorMode(mode: u32) -> u32;
    }
    unsafe extern "C" {
        fn _set_error_mode(mode: i32) -> i32;
    }
    // SAFETY: both take plain integers and only change process-wide flags.
    unsafe {
        SetErrorMode(0x0001 | 0x0002); // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
        _set_error_mode(1); // _OUT_TO_STDERR
    }
}

#[cfg(not(windows))]
pub fn harden_process() {}

/// Makes this process's own stdin, stdout and stderr non-inheritable, so no
/// process it starts can hold the harness's pipes (a hanging `git` kept them
/// open for 20 s after exit, Phase 0): `CreateProcess` inherits every
/// inheritable handle of the parent, not only those passed as the child's
/// standard handles. Children get their own pipes or null explicitly. Nothing
/// on Unix, where only the standard descriptors are inherited and the child's
/// are always set explicitly.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn isolate_std_handles() {
    unsafe extern "system" {
        fn GetStdHandle(id: u32) -> isize;
        fn SetHandleInformation(handle: isize, mask: u32, flags: u32) -> i32;
    }
    // STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE.
    for id in [0xFFFF_FFF6_u32, 0xFFFF_FFF5, 0xFFFF_FFF4] {
        // SAFETY: plain calls on this process's own standard handles; an
        // invalid or missing handle makes the call fail, which is ignored.
        unsafe {
            let h = GetStdHandle(id);
            if h != 0 && h != -1 {
                SetHandleInformation(h, 1, 0); // HANDLE_FLAG_INHERIT off
            }
        }
    }
}

#[cfg(not(windows))]
pub fn isolate_std_handles() {}

/// Why the memory limit could not be set, if it could not (`limit_memory`).
static LIMIT_FAILURE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The warning for a memory limit that was not set, for the child's answer.
pub fn memory_limit_warning() -> Option<String> {
    LIMIT_FAILURE.get().cloned()
}

/// Caps this process's memory at `bytes` before nah runs, so an input that
/// makes nah grow without bound ends as a crash (the parent then takes the
/// fail-safe verdict) instead of exhausting the machine. The cap covers the
/// processes this one starts, such as git. If it cannot be set the child
/// carries on without it and `memory_limit_warning` says why.
///
/// Unix: `RLIMIT_AS`, the address space. macOS may not enforce it. Windows: a
/// job object with a per-process memory limit, which this process joins.
pub fn limit_memory(bytes: usize) {
    if let Err(e) = set_memory_limit(bytes) {
        let _ = LIMIT_FAILURE.set(format!("nah child runs without a memory limit: {e}"));
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn set_memory_limit(bytes: usize) -> Result<(), String> {
    #[repr(C)]
    struct Rlimit {
        cur: usize, // rlim_t is unsigned long on Linux and macOS
        max: usize,
    }
    unsafe extern "C" {
        fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
    }
    #[cfg(target_os = "linux")]
    const RLIMIT_AS: i32 = 9;
    #[cfg(not(target_os = "linux"))]
    const RLIMIT_AS: i32 = 5; // macOS and the BSDs
    let limit = Rlimit {
        cur: bytes,
        max: bytes,
    };
    // SAFETY: `limit` is a valid struct that lives through the call.
    if unsafe { setrlimit(RLIMIT_AS, &limit) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "setrlimit failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn set_memory_limit(bytes: usize) -> Result<(), String> {
    #[repr(C)]
    struct Basic {
        per_process_user_time: i64,
        per_job_user_time: i64,
        limit_flags: u32,
        min_working_set: usize,
        max_working_set: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }
    #[repr(C)]
    struct Extended {
        basic: Basic,
        io: [u64; 6],
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory: usize,
        peak_job_memory: usize,
    }
    unsafe extern "system" {
        fn CreateJobObjectW(attrs: *const u8, name: *const u16) -> isize;
        fn SetInformationJobObject(job: isize, class: i32, info: *const Extended, len: u32) -> i32;
        fn AssignProcessToJobObject(job: isize, process: isize) -> i32;
        fn GetCurrentProcess() -> isize;
    }
    const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x100;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    // SAFETY: all-zero is a valid value of these plain structs.
    let mut info: Extended = unsafe { std::mem::zeroed() };
    info.basic.limit_flags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    info.process_memory_limit = bytes;
    // SAFETY: plain Win32 calls; `info` is valid for the call and the job
    // handle stays open for the life of the process, which it limits.
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job == 0 {
            return Err(format!(
                "CreateJobObject: {}",
                std::io::Error::last_os_error()
            ));
        }
        let len = std::mem::size_of::<Extended>() as u32;
        if SetInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, &info, len) == 0 {
            return Err(format!(
                "SetInformationJobObject: {}",
                std::io::Error::last_os_error()
            ));
        }
        if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
            return Err(format!(
                "AssignProcessToJobObject: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}
