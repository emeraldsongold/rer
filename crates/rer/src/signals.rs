use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Returns whether a shutdown has been requested (e.g. via SIGINT, SIGTERM, or programmatically).
#[must_use]
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

/// Requests shutdown of running relays programmatically.
pub fn request_shutdown() {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Resets the shutdown flag (primarily useful in tests).
pub fn reset_shutdown() {
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
}

/// Registers signal handlers for graceful shutdown on SIGINT and SIGTERM.
///
/// # Errors
/// Returns an error if signal handler registration fails.
pub fn register_signal_handlers() -> std::io::Result<()> {
    extern "C" fn handle_signal(_sig: libc::c_int) {
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }

    unsafe {
        if libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return Err(std::io::Error::last_os_error());
        }
    }

    Ok(())
}
