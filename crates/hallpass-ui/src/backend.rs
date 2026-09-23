//! Which display protocol a window speaks.
//!
//! Native Wayland whenever the session offers it, even with `DISPLAY` set
//! alongside. Under XWayland any X client - a Flatpak holding only the x11
//! socket, which cannot reach `/run/hallpass` - can focus a hallpass window
//! and type into it with XTEST, and answer a prompt or turn enforcement off
//! (probe-confirmed 2026-09-22). A Wayland client cannot reach another
//! client's surfaces at all.
//!
//! Forced rather than left to winit's default, so the choice is stated and
//! tested here and cannot drift with a library upgrade. A Wayland session
//! whose connection fails is an error, never a quiet move to XWayland.
//!
//! A session with X11 alone runs on X11, with a warning: there every client
//! can already inject into every window, a terminal running sudo included,
//! and nothing a single application does changes that.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Wayland,
    X11,
}

/// The backend for a session with a Wayland socket (`wayland`) and/or an X
/// display (`x11`), or why there is none.
pub fn choose(wayland: bool, x11: bool) -> Result<Backend, &'static str> {
    match (wayland, x11) {
        (true, _) => Ok(Backend::Wayland),
        (false, true) => Ok(Backend::X11),
        (false, false) => Err("no display: neither WAYLAND_DISPLAY nor DISPLAY is set"),
    }
}

/// Whether `name` is set to something. Empty counts as unset, as winit
/// counts it: `WAYLAND_DISPLAY= cmd` is the usual way to send a program to
/// X11, and forcing Wayland on it would only fail to connect.
fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

/// [`choose`] for this process's environment, warning when it lands on X11.
pub fn from_env() -> Result<Backend, &'static str> {
    let backend = choose(env_set("WAYLAND_DISPLAY"), env_set("DISPLAY"))?;
    if backend == Backend::X11 {
        tracing::warn!(
            "X11 session: any X client can send input to hallpass windows, \
             as it can to every other window here"
        );
    }
    Ok(backend)
}

/// Pin `options` to `backend`.
pub fn apply(options: &mut eframe::NativeOptions, backend: Backend) {
    options.event_loop_builder = Some(Box::new(move |builder| match backend {
        Backend::Wayland => {
            use winit::platform::wayland::EventLoopBuilderExtWayland;
            builder.with_wayland();
        }
        Backend::X11 => {
            use winit::platform::x11::EventLoopBuilderExtX11;
            builder.with_x11();
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_wins_even_with_an_x_display_beside_it() {
        assert_eq!(choose(true, true), Ok(Backend::Wayland));
        assert_eq!(choose(true, false), Ok(Backend::Wayland));
    }

    #[test]
    fn x11_only_when_there_is_nothing_else() {
        assert_eq!(choose(false, true), Ok(Backend::X11));
        assert!(choose(false, false).is_err());
    }
}
