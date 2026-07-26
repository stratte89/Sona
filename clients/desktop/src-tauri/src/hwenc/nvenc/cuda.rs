//! The CUDA context NVENC wants as its "device", `dlopen`ed for the same reason NVENC is.
//!
//! NVENC does not take a GPU; it takes a device handle, and on Linux the only kind it
//! takes is a `CUcontext`. That is the whole reason `libcuda.so.1` is here — no kernel is
//! launched, no device memory is allocated, and no CUDA toolkit is involved. The driver
//! API lives in `libcuda.so.1`, which ships with the *driver*, so a machine that has
//! `libnvidia-encode.so.1` has this too.
//!
//! Nothing is linked, for the reason spelled out in [`super::api`]: a `NEEDED` entry for
//! `libcuda.so.1` would stop the app starting on every machine without an NVIDIA driver.
//!
//! The context is created and then immediately **popped** off the calling thread. NVENC
//! only needs the handle — it pushes and pops the context around its own work — and
//! leaving a context current on whatever thread happened to open an encoder would make
//! this backend quietly thread-affine, which the `H264Encode` contract does not promise.

use std::ffi::{c_void, CStr};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const CUDA_SONAME: &[u8] = b"libcuda.so.1\0";
const CUDA_SUCCESS: u32 = 0;

/// The driver-API entry points needed to get one context and give it back.
struct Lib {
    init: unsafe extern "C" fn(u32) -> u32,
    device_get_count: unsafe extern "C" fn(*mut i32) -> u32,
    device_get: unsafe extern "C" fn(*mut i32, i32) -> u32,
    ctx_create: unsafe extern "C" fn(*mut *mut c_void, u32, i32) -> u32,
    ctx_destroy: unsafe extern "C" fn(*mut c_void) -> u32,
    ctx_pop_current: unsafe extern "C" fn(*mut *mut c_void) -> u32,
}

fn lib() -> Result<&'static Lib, &'static str> {
    static LIB: OnceLock<Result<Lib, String>> = OnceLock::new();
    LIB.get_or_init(|| load(CUDA_SONAME))
        .as_ref()
        .map_err(|e| e.as_str())
}

fn load(soname: &[u8]) -> Result<Lib, String> {
    let name = CStr::from_bytes_with_nul(soname).map_err(|e| e.to_string())?;
    // SAFETY: NUL-terminated name, documented flags; the handle is intentionally never
    // closed (see `super::api`).
    let h = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if h.is_null() {
        return Err(format!("{} not present", name.to_string_lossy()));
    }
    // The `_v2` suffixes are not optional. `libcuda.so.1` still exports the original
    // `cuCtxCreate` and `cuCtxDestroy` for binaries built before CUDA 3.2, with different
    // semantics; C code gets the modern ones because the header `#define`s the name away.
    // Looked up by hand, that redirection does not happen, so it is spelled out here.
    // SAFETY: each symbol is looked up by its exact exported name, null-checked by `sym`,
    // and given the signature from the CUDA driver API.
    unsafe {
        Ok(Lib {
            init: sym(h, c"cuInit").ok_or("libcuda.so.1 has no cuInit")?,
            device_get_count: sym(h, c"cuDeviceGetCount")
                .ok_or("libcuda.so.1 has no cuDeviceGetCount")?,
            device_get: sym(h, c"cuDeviceGet").ok_or("libcuda.so.1 has no cuDeviceGet")?,
            ctx_create: sym(h, c"cuCtxCreate_v2").ok_or("libcuda.so.1 has no cuCtxCreate_v2")?,
            ctx_destroy: sym(h, c"cuCtxDestroy_v2").ok_or("libcuda.so.1 has no cuCtxDestroy_v2")?,
            ctx_pop_current: sym(h, c"cuCtxPopCurrent_v2")
                .ok_or("libcuda.so.1 has no cuCtxPopCurrent_v2")?,
        })
    }
}

/// # Safety
/// `F` must be the exact signature `name` was compiled with.
unsafe fn sym<F: Copy>(h: *mut c_void, name: &CStr) -> Option<F> {
    let p = libc::dlsym(h, name.as_ptr());
    if p.is_null() {
        return None;
    }
    Some(std::mem::transmute_copy(&p))
}

/// A CUDA context, released when the last encoder using it drops.
pub struct Context {
    raw: *mut c_void,
}

// The handle is a floating context (popped off its creating thread), so it is not bound
// to one thread; and it is only ever handed to NVENC, which does its own synchronisation.
unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// The context every encoder in this process shares, created on first use.
    ///
    /// A CUDA context is not free — it is hundreds of megabytes of device memory — and a
    /// call with the camera on and the screen shared would otherwise pay for two of them
    /// to talk to the same GPU. Held by `Weak`, so the memory goes back when the last
    /// encoder is dropped (which is what happens the moment a track is switched off)
    /// rather than being kept for the life of the process.
    pub fn shared() -> Result<Arc<Context>, String> {
        static SHARED: OnceLock<Mutex<Weak<Context>>> = OnceLock::new();
        let cell = SHARED.get_or_init(|| Mutex::new(Weak::new()));
        let mut slot = cell.lock().map_err(|_| "CUDA context lock poisoned")?;
        if let Some(ctx) = slot.upgrade() {
            return Ok(ctx);
        }
        let ctx = Arc::new(Context::create()?);
        *slot = Arc::downgrade(&ctx);
        Ok(ctx)
    }

    /// A context on the first device that gives one up.
    ///
    /// Iterating rather than assuming device 0 matters on the machines this backend is
    /// for: a laptop with an iGPU *and* an NVIDIA card, or a box with a display GPU and a
    /// compute card, do not agree on which ordinal is which, and a context that fails to
    /// create on one device says nothing about the next.
    pub fn create() -> Result<Context, String> {
        let lib = lib()?;
        // SAFETY: `cuInit(0)` is the documented process-wide initialiser and is safe to
        // call repeatedly; the count is written through a valid pointer.
        let (count, status) = unsafe {
            let s = (lib.init)(0);
            if s != CUDA_SUCCESS {
                return Err(format!("cuInit failed ({s})"));
            }
            let mut n = 0i32;
            let s = (lib.device_get_count)(&mut n);
            (n, s)
        };
        if status != CUDA_SUCCESS {
            return Err(format!("cuDeviceGetCount failed ({status})"));
        }
        if count <= 0 {
            return Err("no CUDA device".into());
        }
        let mut last = String::from("no CUDA device accepted a context");
        for ordinal in 0..count {
            // SAFETY: `ordinal` is in `0..count` as reported by the driver; both out
            // parameters are valid pointers to locals that outlive the call.
            let raw = unsafe {
                let mut dev = 0i32;
                let s = (lib.device_get)(&mut dev, ordinal);
                if s != CUDA_SUCCESS {
                    last = format!("cuDeviceGet({ordinal}) failed ({s})");
                    continue;
                }
                let mut ctx: *mut c_void = std::ptr::null_mut();
                let s = (lib.ctx_create)(&mut ctx, 0, dev);
                if s != CUDA_SUCCESS || ctx.is_null() {
                    last = format!("cuCtxCreate on device {ordinal} failed ({s})");
                    continue;
                }
                // Creating pushes it as current on this thread; NVENC does not need it
                // current, and leaving it would tie the encoder to this thread.
                let mut popped: *mut c_void = std::ptr::null_mut();
                let _ = (lib.ctx_pop_current)(&mut popped);
                ctx
            };
            return Ok(Context { raw });
        }
        Err(last)
    }

    pub fn as_ptr(&self) -> *mut c_void {
        self.raw
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let Ok(lib) = lib() else { return };
        // SAFETY: `raw` came from `cuCtxCreate_v2` and is destroyed exactly once, after
        // every encoder session built on it has been destroyed (the `Arc` in
        // `super::Encoder` is what enforces the ordering).
        unsafe {
            let _ = (lib.ctx_destroy)(self.raw);
        }
    }
}
