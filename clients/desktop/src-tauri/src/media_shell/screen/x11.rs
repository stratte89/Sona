//! Linux/X11 backend: monitor/window enumeration and grabbing, MIT-SHM where offered.
//!
//! SHM matters more than it looks. A plain `GetImage` ships every pixel of the grab
//! back over the X socket — 33 MB per frame on a 4K monitor, which alone is most of a
//! frame budget at 20 fps. With SHM the server writes into memory we already have
//! mapped and the reply is a header. Everything degrades to `GetImage` if the
//! extension, the fd passing (remote X over TCP) or the mapping is unavailable.

use super::{thumb_png, ScreenSourceView, ScreenTarget};
use std::os::fd::AsRawFd;
use x11rb::connection::Connection;
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm;
use x11rb::protocol::xproto::{AtomEnum, ConnectionExt as _, ImageFormat, Window};
use x11rb::rust_connection::RustConnection;

/// A grab area: what to read, and where on it.
pub(super) struct Area {
    pub drawable: u32,
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
    /// Windows move and resize under us; monitors do not (a RandR change bumps the
    /// target epoch instead).
    pub track_geometry: bool,
}

/// A server-allocated shared segment, mapped into this process.
pub(super) struct Shm {
    seg: u32,
    ptr: *mut u8,
    len: usize,
}

impl Shm {
    fn new(conn: &RustConnection, len: usize) -> Option<Shm> {
        let seg = conn.generate_id().ok()?;
        let reply = shm::create_segment(conn, seg, len as u32, false)
            .ok()?
            .reply()
            .ok()?;
        let fd = reply.shm_fd;
        // SAFETY: a read-only shared mapping of a server-provided fd of `len`
        // bytes; unmapped in Drop, and never aliased (one owner, one thread).
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let _ = shm::detach(conn, seg);
            return None;
        }
        Some(Shm {
            seg,
            ptr: ptr.cast(),
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr`/`len` come from a successful mmap and are valid until Drop.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Shm {
    fn drop(&mut self) {
        // SAFETY: undoing our own mapping exactly once.
        unsafe { libc::munmap(self.ptr.cast(), self.len) };
        // The server-side segment is detached by whoever replaces it (see `grab`);
        // the last one goes when the connection closes, which is the same moment
        // this type's owner dies.
    }
}

/// Holds the connection plus whatever fast path this server supports.
pub(super) struct Grabber {
    pub conn: RustConnection,
    pub root: Window,
    shm: Option<Shm>,
    shm_ok: bool,
    buf: Vec<u8>,
}

impl Grabber {
    pub(super) fn open() -> Result<Grabber, String> {
        let (conn, screen_num) = x11rb::connect(None).map_err(|e| format!("X11: {e}"))?;
        let root = conn.setup().roots[screen_num].root;
        // 1.2 is where `create_segment` (server-allocated, fd-passed) arrives; the
        // older SysV path needs shmget/shmat and a matching uid, so we skip it.
        let shm_ok = shm::query_version(&conn)
            .ok()
            .and_then(|c| c.reply().ok())
            .is_some_and(|v| (v.major_version, v.minor_version) >= (1, 2));
        Ok(Grabber {
            conn,
            root,
            shm: None,
            shm_ok,
            buf: Vec::new(),
        })
    }

    /// Grab `area` and hand back the raw Z_PIXMAP bytes (B,G,R,X per pixel on a
    /// little-endian server, which is every desktop this ships to).
    pub(super) fn grab(&mut self, area: &Area) -> Result<&[u8], String> {
        let need = area.w as usize * area.h as usize * 4;
        if self.shm_ok {
            if self.shm.as_ref().is_none_or(|s| s.len < need) {
                // Detach before allocating the replacement so a resize storm can't
                // stack segments in the server.
                if let Some(old) = self.shm.take() {
                    let _ = shm::detach(&self.conn, old.seg);
                }
                self.shm = Shm::new(&self.conn, need.next_power_of_two());
                self.shm_ok = self.shm.is_some();
            }
            if let Some(shm) = self.shm.as_ref() {
                let got = shm::get_image(
                    &self.conn,
                    area.drawable,
                    area.x,
                    area.y,
                    area.w,
                    area.h,
                    !0,
                    ImageFormat::Z_PIXMAP.into(),
                    shm.seg,
                    0,
                )
                .map_err(|e| e.to_string())?
                .reply();
                // A window that vanished between geometry and grab is normal; fall
                // through to the plain path, which reports it properly.
                if got.is_ok() {
                    return Ok(&shm.as_slice()[..need]);
                }
            }
        }
        let img = self
            .conn
            .get_image(
                ImageFormat::Z_PIXMAP,
                area.drawable,
                area.x,
                area.y,
                area.w,
                area.h,
                !0,
            )
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| format!("get_image: {e}"))?;
        self.buf = img.data;
        Ok(&self.buf)
    }
}

fn atom(conn: &RustConnection, name: &str) -> Option<u32> {
    Some(
        conn.intern_atom(true, name.as_bytes())
            .ok()?
            .reply()
            .ok()?
            .atom,
    )
    .filter(|a| *a != 0)
}

fn prop_u32(conn: &RustConnection, win: Window, prop: u32) -> Vec<u32> {
    conn.get_property(false, win, prop, AtomEnum::ANY, 0, 4096)
        .ok()
        .and_then(|c| c.reply().ok())
        .and_then(|r| r.value32().map(|v| v.collect()))
        .unwrap_or_default()
}

fn prop_text(conn: &RustConnection, win: Window, prop: u32) -> Option<String> {
    let r = conn
        .get_property(false, win, prop, AtomEnum::ANY, 0, 256)
        .ok()?
        .reply()
        .ok()?;
    if r.value.is_empty() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&r.value)
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// One monitor as the picker and the capture loop both need it.
pub(super) struct Mon {
    pub index: usize,
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
    pub primary: bool,
    /// Connector name (`DP-1`, `HDMI-A-2`), when the server names it.
    pub name: String,
}

/// Monitors, in RandR order. The index *is* the id handed to the UI: RandR monitor
/// objects have no stable numeric id of their own, and "Screen 2" has to keep
/// meaning the same screen between the picker and the share.
fn monitors(conn: &RustConnection, root: Window) -> Vec<Mon> {
    let Some(reply) = conn
        .randr_get_monitors(root, true)
        .ok()
        .and_then(|c| c.reply().ok())
    else {
        return Vec::new();
    };
    reply
        .monitors
        .iter()
        .enumerate()
        .map(|(index, m)| Mon {
            index,
            x: m.x,
            y: m.y,
            w: m.width,
            h: m.height,
            primary: m.primary,
            name: conn
                .get_atom_name(m.name)
                .ok()
                .and_then(|c| c.reply().ok())
                .map(|r| String::from_utf8_lossy(&r.name).to_string())
                .unwrap_or_default(),
        })
        .collect()
}

/// Ordinary, mapped, non-minimised toplevel windows — topmost first, which is the
/// order someone scanning a picker expects to find what they were just looking at.
fn windows(conn: &RustConnection, root: Window) -> Vec<Window> {
    let list = atom(conn, "_NET_CLIENT_LIST_STACKING")
        .map(|a| prop_u32(conn, root, a))
        .filter(|v| !v.is_empty())
        .map(|mut v| {
            v.reverse();
            v
        })
        .or_else(|| atom(conn, "_NET_CLIENT_LIST").map(|a| prop_u32(conn, root, a)))
        .unwrap_or_default();
    let wtype = atom(conn, "_NET_WM_WINDOW_TYPE");
    let normal = atom(conn, "_NET_WM_WINDOW_TYPE_NORMAL");
    let state = atom(conn, "_NET_WM_STATE");
    let hidden = atom(conn, "_NET_WM_STATE_HIDDEN");
    list.into_iter()
        .filter(|&w| {
            // Dialogs, docks, panels and splashes are noise in a share picker.
            if let (Some(t), Some(n)) = (wtype, normal) {
                let types = prop_u32(conn, w, t);
                if !types.is_empty() && !types.contains(&n) {
                    return false;
                }
            }
            if let (Some(s), Some(h)) = (state, hidden) {
                if prop_u32(conn, w, s).contains(&h) {
                    return false; // minimised: nothing to grab but stale pixels
                }
            }
            true
        })
        .collect()
}

fn window_title(conn: &RustConnection, w: Window) -> (String, String) {
    let title = atom(conn, "_NET_WM_NAME")
        .and_then(|a| prop_text(conn, w, a))
        .or_else(|| prop_text(conn, w, AtomEnum::WM_NAME.into()))
        .unwrap_or_default();
    // WM_CLASS is "instance\0class\0"; the class half is the app name.
    let app = prop_text(conn, w, AtomEnum::WM_CLASS.into())
        .and_then(|s| s.split('\0').nth(1).map(|c| c.to_string()))
        .unwrap_or_default();
    (title, app)
}

/// Resolve the user's choice into something grabbable, falling back to the primary
/// monitor whenever the choice has gone away (a closed window, an unplugged head).
pub(super) fn resolve(g: &Grabber, target: ScreenTarget) -> Option<Area> {
    let area_of = |m: &Mon| Area {
        drawable: g.root,
        x: m.x,
        y: m.y,
        w: m.w,
        h: m.h,
        track_geometry: false,
    };
    let mons = monitors(&g.conn, g.root);
    let primary = || {
        mons.iter()
            .find(|m| m.primary)
            .or_else(|| mons.first())
            .map(area_of)
    };
    match target {
        ScreenTarget::Primary => primary(),
        ScreenTarget::Screen(i) => mons
            .iter()
            .find(|m| m.index == i as usize)
            .map(area_of)
            .or_else(primary),
        ScreenTarget::Window(id) => geometry_of(g, id).or_else(primary),
    }
}

/// Current size of a window, as a grab area rooted at its own origin.
pub(super) fn geometry_of(g: &Grabber, id: u32) -> Option<Area> {
    let geo = g.conn.get_geometry(id).ok()?.reply().ok()?;
    if geo.width < 16 || geo.height < 16 {
        return None;
    }
    Some(Area {
        drawable: id,
        x: 0,
        y: 0,
        w: geo.width,
        h: geo.height,
        track_geometry: true,
    })
}

/// The picker's source list.
pub(super) fn sources() -> Result<Vec<ScreenSourceView>, String> {
    let mut g = Grabber::open()?;
    let mut out = Vec::new();
    for m in monitors(&g.conn, g.root) {
        let area = Area {
            drawable: g.root,
            x: m.x,
            y: m.y,
            w: m.w,
            h: m.h,
            track_geometry: false,
        };
        let (w, h) = (m.w as usize, m.h as usize);
        let thumb = g
            .grab(&area)
            .ok()
            .map(|d| thumb_png(d, w, h, 4, (2, 1, 0)))
            .unwrap_or_default();
        out.push(ScreenSourceView {
            kind: "screen",
            id: m.index as u32,
            name: format!("Screen {}", m.index + 1),
            detail: if m.name.is_empty() {
                format!("{w}×{h}")
            } else {
                format!("{} · {w}×{h}", m.name)
            },
            thumb,
            primary: m.primary,
        });
    }
    for w in windows(&g.conn, g.root) {
        let Some(area) = geometry_of(&g, w) else {
            continue;
        };
        if area.w < 96 || area.h < 96 {
            continue;
        }
        let (title, app) = window_title(&g.conn, w);
        if title.trim().is_empty() && app.trim().is_empty() {
            continue;
        }
        let (aw, ah) = (area.w as usize, area.h as usize);
        let thumb = g
            .grab(&area)
            .ok()
            .map(|d| thumb_png(d, aw, ah, 4, (2, 1, 0)))
            .unwrap_or_default();
        // Application first, window title underneath: the tab is called
        // "Applications", and someone looking for their game is looking for its
        // name, not for whatever it happened to put in its title bar. The title
        // still separates two windows of the same program.
        let (name, detail) = super::window_labels(&app, &title);
        out.push(ScreenSourceView {
            kind: "window",
            id: w,
            name,
            detail,
            thumb,
            primary: false,
        });
    }
    Ok(out)
}
