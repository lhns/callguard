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
