// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.

//! A small native window shown while a scan runs, before the `WebView` exists (ADR 0001).
//! Windows draws it itself, with no `WebView` or `Edge`, and it reads nothing from the PC.

/// A small window that stays open while the scan runs. Closing is [`Splash::close`] or dropping it.
#[cfg(windows)]
pub struct Splash {
    hwnd: Option<isize>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// Anything but Windows: a splash that never appears, so a splash never stops a scan.
#[cfg(not(windows))]
pub struct Splash;

impl Splash {
    /// Opens the window on its own thread and returns once it is on screen. `lines` are drawn centred.
    /// Keep each line short — about 50 characters — so it ends in an ellipsis instead of being
    /// clipped, and keep to five lines: at most five fit above the strip.
    /// Off Windows, or if the window cannot be created, the splash does nothing and never stops a scan.
    pub fn show(title: &str, lines: &[&str]) -> Splash {
        #[cfg(windows)]
        {
            live::show(title, lines)
        }
        #[cfg(not(windows))]
        {
            let _ = (title, lines);
            Splash
        }
    }

    /// Closes the window and waits for its thread. Safe to call once; [`Drop`] does the same.
    pub fn close(self) {
        #[cfg(windows)]
        {
            let mut splash = self;
            splash.shut();
        }
        #[cfg(not(windows))]
        let _ = self;
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Splash {
    /// Posts `WM_SPLASH_CLOSE` and joins the window's thread; both handles are taken first, so a repeat is a no-op.
    fn shut(&mut self) {
        use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
        use windows::Win32::UI::WindowsAndMessaging::PostMessageW;

        if let Some(hwnd) = self.hwnd.take() {
            // SAFETY: `hwnd` belongs to this splash's window thread; `PostMessageW` only enqueues
            // `WM_SPLASH_CLOSE`, which the proc answers by destroying the window.
            let _ = unsafe {
                PostMessageW(
                    Some(HWND(hwnd as *mut core::ffi::c_void)),
                    WM_SPLASH_CLOSE,
                    WPARAM(0),
                    LPARAM(0),
                )
            };
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(windows)]
impl Drop for Splash {
    fn drop(&mut self) {
        self.shut();
    }
}

/// The app-defined message that makes the window proc destroy its window. The splash cannot be
/// closed by its user, so the handle `shut` posts to is still the splash's own, not one Windows
/// may have reused after the user closed it.
#[cfg(windows)]
const WM_SPLASH_CLOSE: u32 = windows::Win32::UI::WindowsAndMessaging::WM_APP + 1;

/// The segment advances by this many pixels per timer tick.
#[cfg(any(windows, test))]
const STRIP_STEP: i64 = 4;

/// Where the ~30 % segment sits at `tick`: it moves four pixels per tick and wraps at the right edge.
/// `left` and `right` stay in `0..=track_width`; a track of no width has no segment.
#[cfg(any(windows, test))]
fn strip_segment(tick: u32, track_width: i32) -> (i32, i32) {
    if track_width <= 0 {
        return (0, 0);
    }
    let track = i64::from(track_width);
    let segment = ((track * 3) / 10).clamp(1, track);
    let travel = track - segment;
    // A cycle of whole four-pixel steps, so the segment wraps to exactly the left edge.
    let cycle = ((travel / STRIP_STEP) + 1) * STRIP_STEP;
    let offset = (i64::from(tick) * STRIP_STEP) % cycle;
    (
        i32::try_from(offset).unwrap_or(0),
        i32::try_from(offset + segment).unwrap_or(track_width),
    )
}

/// The Windows window and its message loop; the helper above stays testable on every platform.
#[cfg(windows)]
#[allow(unsafe_code)]
mod live {
    use std::sync::mpsc;

    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, DEFAULT_GUI_FONT, DT_CENTER, DT_END_ELLIPSIS, DT_NOPREFIX,
        DT_SINGLELINE, DeleteObject, DrawTextW, EndPaint, FillRect, GetStockObject, HDC, HGDIOBJ,
        InvalidateRect, PAINTSTRUCT, SelectObject, SetBkMode, SetTextColor, TRANSPARENT,
        UpdateWindow,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GWLP_USERDATA,
        GetClientRect, GetMessageW, GetSystemMetrics, GetWindowLongPtrW, IDC_ARROW, KillTimer,
        LoadCursorW, MSG, PostQuitMessage, RegisterClassW, SM_CXSCREEN, SM_CYSCREEN, SW_SHOWNORMAL,
        SetForegroundWindow, SetTimer, SetWindowLongPtrW, ShowWindow, TranslateMessage, WM_CLOSE,
        WM_DESTROY, WM_ERASEBKGND, WM_PAINT, WM_TIMER, WNDCLASSW, WS_CAPTION, WS_EX_TOPMOST,
        WS_VISIBLE,
    };
    use windows::core::{PCWSTR, w};

    use super::Splash;
    use super::WM_SPLASH_CLOSE;

    const WIDTH: i32 = 460;
    const HEIGHT: i32 = 240;
    const TIMER_ID: usize = 1;
    const TIMER_MILLISECONDS: u32 = 40;
    /// `#F3F9FF` (white-ish blue) as `0x00BBGGRR`; text is `#1D2A44` (dark navy).
    const BACKGROUND: COLORREF = COLORREF(0x00FF_F9F3);
    const TEXT: COLORREF = COLORREF(0x0044_2A1D);
    const TRACK: COLORREF = COLORREF(0x00FA_E9D9);
    const SEGMENT: COLORREF = COLORREF(0x00C5_9D6D);
    const LINE_HEIGHT: i32 = 26;
    const PADDING: i32 = 24;
    const STRIP_HEIGHT: i32 = 6;
    const STRIP_MARGIN: i32 = 40;

    /// What a window proc needs between messages, reached through `GWLP_USERDATA` and freed after the loop.
    struct WindowState {
        lines: Vec<Vec<u16>>,
        tick: u32,
    }

    pub(super) fn show(title: &str, lines: &[&str]) -> Splash {
        let title: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        let lines: Vec<Vec<u16>> = lines
            .iter()
            .map(|line| line.encode_utf16().collect())
            .collect();
        let (ready, waiting) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("splash".to_owned())
            .spawn(move || run(title, lines, ready))
            .ok();
        // Either the window is on screen, or its thread has already said it could not create one.
        Splash {
            hwnd: thread.as_ref().and_then(|_| waiting.recv().ok().flatten()),
            thread,
        }
    }

    // The thread owns what it draws and the sender through which it reports readiness.
    #[allow(clippy::needless_pass_by_value)]
    fn run(title: Vec<u16>, lines: Vec<Vec<u16>>, ready: mpsc::Sender<Option<isize>>) {
        // SAFETY: `GetModuleHandleW` returns this process's own module handle and reads no memory of ours.
        let Ok(instance) = (unsafe { GetModuleHandleW(None) }) else {
            let _ = ready.send(None);
            return;
        };
        let class_name = w!("AeternaRongroiSplash");
        let window_class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance.into(),
            // SAFETY: `IDC_ARROW` is Windows' own cursor resource and `None` its own module.
            hCursor: unsafe { LoadCursorW(None, IDC_ARROW) }.unwrap_or_default(),
            lpszClassName: class_name,
            ..Default::default()
        };
        // SAFETY: the class is initialised, its strings outlive the call, and a duplicate is harmless.
        let _ = unsafe { RegisterClassW(&raw const window_class) };
        // SAFETY: `GetSystemMetrics` only reads the primary monitor's size and takes no arguments.
        let (screen_width, screen_height) =
            unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };

        let state = Box::into_raw(Box::new(WindowState { lines, tick: 0 }));
        // SAFETY: both strings are NUL-terminated and outlive the call; parent, menu, and `lpParam` are
        // null. `WS_CAPTION` without `WS_SYSMENU` gives no system buttons, and there is no resize style;
        // `WS_EX_TOPMOST` keeps the splash above other windows while the scan runs.
        let Ok(hwnd) = (unsafe {
            CreateWindowExW(
                WS_EX_TOPMOST,
                class_name,
                PCWSTR(title.as_ptr()),
                WS_CAPTION | WS_VISIBLE,
                (screen_width - WIDTH) / 2,
                (screen_height - HEIGHT) / 2,
                WIDTH,
                HEIGHT,
                None,
                None,
                Some(instance.into()),
                None,
            )
        }) else {
            // SAFETY: the window was not created, so nothing else has this `Box`.
            unsafe { drop(Box::from_raw(state)) };
            let _ = ready.send(None);
            return;
        };
        // SAFETY: `hwnd` owns the state until `WM_DESTROY`, so no message handler can read it before now.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as isize) };
        // SAFETY: these act on the window this thread just created; destruction releases its handles.
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
            // The old `MessageBoxW` used `MB_SETFOREGROUND`; this is what brings the splash to front now.
            let _ = SetForegroundWindow(hwnd);
            let _ = UpdateWindow(hwnd);
            let _ = SetTimer(Some(hwnd), TIMER_ID, TIMER_MILLISECONDS, None);
        }
        let _ = ready.send(Some(hwnd.0 as isize));

        let mut message = MSG::default();
        // SAFETY: `message` is writable and owned here; `None` reads this thread's queue.
        while unsafe { GetMessageW(&raw mut message, None, 0, 0) }.0 > 0 {
            // SAFETY: `GetMessageW` filled `message`; dispatching it runs this window's proc.
            unsafe {
                let _ = TranslateMessage(&raw const message);
                DispatchMessageW(&raw const message);
            }
        }
        // The loop can also end when `GetMessageW` fails with -1, while the window still exists and
        // `GWLP_USERDATA` still points at the state: detach the state before touching the window,
        // and destroy the window here on the thread that owns it.
        // SAFETY: `hwnd` is the window this thread created; clearing its `GWLP_USERDATA` touches
        // only that window's own state.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        // SAFETY: on the normal path the window is already gone and the call fails harmlessly; on
        // the failure path the thread owns the window, so destruction runs its proc on this thread.
        let _ = unsafe { DestroyWindow(hwnd) };
        // SAFETY: the window can no longer reach the state; this is the pointer `Box::into_raw` returned.
        unsafe { drop(Box::from_raw(state)) };
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            WM_PAINT => {
                // SAFETY: `hwnd` is this proc's window; `paint` balances `BeginPaint` with `EndPaint`.
                unsafe { paint(hwnd) };
                LRESULT(0)
            }
            WM_TIMER => {
                // SAFETY: the state is stored before the loop starts; messages run one at a time here.
                unsafe {
                    let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut WindowState;
                    if !pointer.is_null() {
                        let state = &mut *pointer;
                        state.tick = state.tick.wrapping_add(1);
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            // `WM_PAINT` fills every pixel, so the default erase would only flicker.
            WM_ERASEBKGND => LRESULT(1),
            // The splash cannot be closed by its user, and doing nothing keeps `shut` free of the
            // stale-handle hazard: had the user closed the window, Windows could have reused the
            // handle this proc posts back to.
            WM_CLOSE => LRESULT(0),
            // `shut` posts this when the scan ends; destroying here keeps the closing deliberate.
            WM_SPLASH_CLOSE => {
                // SAFETY: `hwnd` is this proc's window; `DestroyWindow` sends `WM_DESTROY` on this thread.
                unsafe {
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                // SAFETY: the timer belongs to this window; `run` frees the state after the loop ends.
                unsafe {
                    let _ = KillTimer(Some(hwnd), TIMER_ID);
                    PostQuitMessage(0);
                }
                LRESULT(0)
            }
            // SAFETY: `DefWindowProcW` is the default handling for every other message.
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    /// Builds a rectangle from its edges.
    const fn rect(left: i32, top: i32, right: i32, bottom: i32) -> RECT {
        RECT {
            left,
            top,
            right,
            bottom,
        }
    }

    /// Fills `rect` with a fresh brush and frees it straight away; `hdc` must be this thread's.
    unsafe fn fill(hdc: HDC, rect: RECT, colour: COLORREF) {
        // SAFETY: the brush is created, used and deleted here; `rect` is a copy of the caller's rectangle.
        unsafe {
            let brush = CreateSolidBrush(colour);
            if !brush.0.is_null() {
                FillRect(hdc, &raw const rect, brush);
                let _ = DeleteObject(HGDIOBJ(brush.0));
            }
        }
    }

    /// Fills the client area, draws `lines` centred with the default GUI font, and paints the strip.
    unsafe fn paint(hwnd: HWND) {
        let mut paint = PAINTSTRUCT::default();
        let mut client = RECT::default();
        // SAFETY: `hwnd` is this proc's window and both structs are writable and owned here.
        let hdc = unsafe { BeginPaint(hwnd, &raw mut paint) };
        // A null `hdc` would make every draw call below meaningless, but `EndPaint` still has to
        // balance the `BeginPaint` above.
        if !hdc.0.is_null() {
            // SAFETY: `client` is writable and `hwnd` is live for this message.
            let _ = unsafe { GetClientRect(hwnd, &raw mut client) };
            // SAFETY: `hdc` and `client` are what those calls returned, and `fill` owns its brush.
            unsafe { fill(hdc, client, BACKGROUND) };
            // SAFETY: the state is live between window creation and `WM_DESTROY`, on this thread.
            let pointer = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut WindowState;
            if !pointer.is_null() {
                // SAFETY: this message has exclusive use of the state; the font is a stock object and the old
                // one is selected back before `EndPaint` releases the context.
                unsafe {
                    let state = &mut *pointer;
                    let previous = SelectObject(hdc, GetStockObject(DEFAULT_GUI_FONT));
                    // `DT_END_ELLIPSIS` ends a line too long for the window in an ellipsis, instead
                    // of clipping it on both sides.
                    let flags = DT_CENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS;
                    let _ = SetBkMode(hdc, TRANSPARENT);
                    let _ = SetTextColor(hdc, TEXT);
                    let (left, right) = (client.left + PADDING, client.right - PADDING);
                    let mut top = client.top + PADDING;
                    for line in &mut state.lines {
                        let mut bounds = rect(left, top, right, top + LINE_HEIGHT);
                        let _ = DrawTextW(hdc, line, &raw mut bounds, flags);
                        top += LINE_HEIGHT;
                    }
                    SelectObject(hdc, previous);
                    draw_strip(hdc, &client, state.tick);
                }
            }
        }
        // SAFETY: balanced with the `BeginPaint` above, on the same window and thread.
        let _ = unsafe { EndPaint(hwnd, &raw const paint) };
    }

    /// Paints the light track and the moving segment, whose position depends on the tick alone.
    unsafe fn draw_strip(hdc: HDC, client: &RECT, tick: u32) {
        let width = (client.right - client.left) - STRIP_MARGIN * 2;
        if width <= 0 {
            return;
        }
        let (left, top) = (client.left + STRIP_MARGIN, client.bottom - STRIP_MARGIN);
        let (segment_left, segment_right) = super::strip_segment(tick, width);
        let (segment_left, segment_right) = (left + segment_left, left + segment_right);
        let segment = rect(segment_left, top, segment_right, top + STRIP_HEIGHT);
        let track = rect(left, top, left + width, top + STRIP_HEIGHT);
        // SAFETY: the track and segment lie inside the client area computed above; `fill` owns its brush.
        unsafe {
            fill(hdc, track, TRACK);
            fill(hdc, segment, SEGMENT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strip_stays_inside_the_track_and_moves_right() {
        for width in [1, 50, 400] {
            let mut previous = strip_segment(0, width);
            assert!(previous.0 >= 0 && previous.1 <= width && previous.0 < previous.1);
            let mut wrapped = false;
            for tick in 1..10_000 {
                let current = strip_segment(tick, width);
                assert!(current.0 >= 0 && current.1 <= width && current.0 < current.1);
                if width > 1 && current.0 <= previous.0 {
                    assert_eq!(current.0, 0);
                    wrapped = true;
                }
                previous = current;
            }
            assert!(width == 1 || wrapped);
        }
        assert_eq!(strip_segment(0, 0), (0, 0));
        assert_eq!(strip_segment(12_345, 0), (0, 0));
        assert_eq!(strip_segment(17, 400), strip_segment(17, 400));
    }

    #[cfg(not(windows))]
    #[test]
    fn showing_a_splash_off_windows_does_nothing() {
        let splash = Splash::show("t", &["a"]);
        splash.close();
        // A splash that is just dropped must leave nothing behind either.
        let _splash = Splash::show("t", &["a"]);
    }
}
