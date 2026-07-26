//! Getting at `libnvidia-encode.so.1` without ever linking against it.
//!
//! **The `dlopen` is not a style choice.** Linking NVENC — which is what every NVENC
//! crate on crates.io does — puts a `NEEDED libnvidia-encode.so.1` entry in the binary,
//! and the dynamic loader resolves that *before* `main` runs. Every Linux user without an
//! NVIDIA driver — AMD, Intel, a VM, a headless box, anyone running the flatpak on a
//! laptop with only an iGPU — would then be unable to start Sona at all. A hardware
//! encoder is an optimisation for screen sharing; it is not allowed to be a startup
//! dependency. So the library is opened by name at runtime and its absence is a
//! `None`, which is exactly the "no hardware encoder" case the software path already
//! handles.
//!
//! ## Why the version is checked before any struct is passed
//!
//! NVENC identifies every struct by a `version` field that encodes the API version it was
//! compiled for, and the driver reads the struct according to it. Handing a driver that
//! predates this build's API version a struct it does not know the shape of is the one
//! failure mode that cannot be recovered from politely. `NvEncodeAPIGetMaxSupportedVersion`
//! takes a bare `uint32_t*` — no struct, no version tag — so it is safe to call first, and
//! it is called first. NVIDIA guarantees binary *backward* compatibility, so a driver
//! newer than [`abi_gen::NVENCAPI_VERSION`] is always fine; only an older one is not.

use std::ffi::{c_void, CStr};
use std::sync::OnceLock;

use super::abi::{self, FunctionList};
use super::abi_gen as g;

/// The versioned soname, never the development symlink: `libnvidia-encode.so` only exists
/// when someone installed the SDK, `.so.1` is what a driver ships.
const NVENC_SONAME: &[u8] = b"libnvidia-encode.so.1\0";

/// Entry points read out of the function list, once per process.
pub struct Api {
    pub open_session_ex: abi::PtrOpenSessionEx,
    pub get_preset_config_ex: abi::PtrGetPresetConfigEx,
    pub initialize_encoder: abi::PtrInitializeEncoder,
    pub create_input_buffer: abi::PtrCreateInputBuffer,
    pub destroy_input_buffer: abi::PtrWithResource,
    pub create_bitstream_buffer: abi::PtrCreateBitstreamBuffer,
    pub destroy_bitstream_buffer: abi::PtrWithResource,
    pub encode_picture: abi::PtrEncodePicture,
    pub lock_bitstream: abi::PtrLockBitstream,
    pub unlock_bitstream: abi::PtrWithResource,
    pub lock_input_buffer: abi::PtrLockInputBuffer,
    pub unlock_input_buffer: abi::PtrWithResource,
    pub destroy_encoder: abi::PtrDestroyEncoder,
    pub get_last_error: abi::PtrGetLastError,
}

/// The loaded API, or why it will never load. Resolved once; a driver does not appear
/// mid-process, and retrying a `dlopen` that failed costs a filesystem walk per call.
pub fn api() -> Result<&'static Api, &'static str> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| load(NVENC_SONAME))
        .as_ref()
        .map_err(|e| e.as_str())
}

/// Open `soname`, check the API version, and pull out the function list.
fn load(soname: &[u8]) -> Result<Api, String> {
    let name = CStr::from_bytes_with_nul(soname).map_err(|e| e.to_string())?;
    // SAFETY: a NUL-terminated name and the documented flags. The handle is deliberately
    // never `dlclose`d — the `Api` derived from it outlives every caller, and unloading a
    // driver library out from under its own worker threads is not a recoverable state.
    let lib = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if lib.is_null() {
        return Err(format!("{} not present", name.to_string_lossy()));
    }

    type GetMaxVersion = unsafe extern "C" fn(*mut u32) -> u32;
    type CreateInstance = unsafe extern "C" fn(*mut FunctionList) -> u32;
    // SAFETY: both symbols are looked up by their exact exported names and immediately
    // null-checked; the signatures are those of the vendored header.
    let get_max: GetMaxVersion = unsafe { sym(lib, c"NvEncodeAPIGetMaxSupportedVersion") }
        .ok_or("libnvidia-encode.so.1 has no NvEncodeAPIGetMaxSupportedVersion")?;
    let create: CreateInstance = unsafe { sym(lib, c"NvEncodeAPICreateInstance") }
        .ok_or("libnvidia-encode.so.1 has no NvEncodeAPICreateInstance")?;

    // Before any struct crosses the boundary: `(major << 4) | minor`, as the driver
    // reports it. Ours must be no newer than the driver's.
    let mut driver = 0u32;
    // SAFETY: takes one `uint32_t*` and nothing else — the one call that carries no
    // versioned struct, which is why it is the one that may be made first.
    let status = unsafe { get_max(&mut driver) };
    if status != g::NV_ENC_SUCCESS {
        return Err(format!(
            "NvEncodeAPIGetMaxSupportedVersion failed ({status})"
        ));
    }
    let want = (g::NVENCAPI_MAJOR << 4) | g::NVENCAPI_MINOR;
    if driver < want {
        return Err(format!(
            "driver NVENC API {}.{} is older than the {}.{} this build targets",
            driver >> 4,
            driver & 0xf,
            g::NVENCAPI_MAJOR,
            g::NVENCAPI_MINOR
        ));
    }

    // SAFETY: a zeroed function list is the documented input; `version` is the only field
    // the caller sets, and the driver fills the rest. Now sound to pass a struct: the
    // version check above established the driver understands this shape.
    let mut list: FunctionList = unsafe { abi::zeroed() };
    list.0[..4].copy_from_slice(&g::NV_ENCODE_API_FUNCTION_LIST_VER.to_ne_bytes());
    // SAFETY: `list` is a live, correctly sized and aligned `NV_ENCODE_API_FUNCTION_LIST`.
    let status = unsafe { create(&mut list) };
    if status != g::NV_ENC_SUCCESS {
        return Err(format!("NvEncodeAPICreateInstance failed ({status})"));
    }

    // A driver is allowed to leave an entry null for something it does not implement, so
    // every pointer is checked rather than assumed. `read_fn` is where the compile-time
    // offset assertions in `abi` are cashed in.
    Ok(Api {
        open_session_ex: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncOpenEncodeSessionEx,
        )?,
        get_preset_config_ex: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncGetEncodePresetConfigEx,
        )?,
        initialize_encoder: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncInitializeEncoder)?,
        create_input_buffer: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncCreateInputBuffer)?,
        destroy_input_buffer: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyInputBuffer,
        )?,
        create_bitstream_buffer: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncCreateBitstreamBuffer,
        )?,
        destroy_bitstream_buffer: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyBitstreamBuffer,
        )?,
        encode_picture: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncEncodePicture)?,
        lock_bitstream: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncLockBitstream)?,
        unlock_bitstream: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockBitstream)?,
        lock_input_buffer: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncLockInputBuffer)?,
        unlock_input_buffer: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockInputBuffer)?,
        destroy_encoder: read_fn(&list, g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyEncoder)?,
        get_last_error: read_fn(
            &list,
            g::NV_ENCODE_API_FUNCTION_LIST_nvEncGetLastErrorString,
        )?,
    })
}

/// One function pointer out of the byte-blob function list.
///
/// `at` is only ever one of [`abi::FN_OFFSETS`], which is asserted at compile time to be
/// 8-aligned and in bounds; that is what makes the unaligned-read-free `read` below sound.
fn read_fn<F: Copy>(list: &FunctionList, at: usize) -> Result<F, String> {
    debug_assert!(abi::FN_OFFSETS.contains(&at));
    debug_assert_eq!(size_of::<F>(), size_of::<usize>());
    // SAFETY: `at` is in bounds and 8-aligned by the assertions in `abi`, and the driver
    // filled this region with function pointers. `F` is a fn-pointer type of pointer size.
    let raw = unsafe { list.0.as_ptr().add(at).cast::<usize>().read() };
    if raw == 0 {
        return Err(format!("driver left function list entry {at} null"));
    }
    // SAFETY: non-null, and transmuting a `usize` holding a code address to the matching
    // `extern "C"` fn pointer type is the whole purpose of the function list.
    Ok(unsafe { std::mem::transmute_copy(&raw) })
}

/// `dlsym`, typed. Returns `None` rather than a null pointer nobody would check.
///
/// # Safety
/// `F` must be the exact signature `name` was compiled with.
unsafe fn sym<F: Copy>(lib: *mut c_void, name: &CStr) -> Option<F> {
    let p = libc::dlsym(lib, name.as_ptr());
    if p.is_null() {
        return None;
    }
    Some(std::mem::transmute_copy(&p))
}

/// The driver's own message for the last failure on `encoder`, for error strings that say
/// something more useful than a number.
pub fn last_error(api: &Api, encoder: *mut c_void) -> String {
    if encoder.is_null() {
        return String::new();
    }
    // SAFETY: `encoder` is a live session handle; the driver returns a pointer to a
    // NUL-terminated string it owns, which is copied out immediately.
    let p = unsafe { (api.get_last_error)(encoder) };
    if p.is_null() {
        return String::new();
    }
    // SAFETY: non-null and NUL-terminated per the API contract.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// Turn a `dlopen`able name into the loader's verdict, for tests that need to see the
/// failure path. Keeps [`load`] private while letting the fallback be proven, not assumed.
#[cfg(test)]
pub(super) fn load_for_test(soname: &str) -> Result<Api, String> {
    let c = std::ffi::CString::new(soname).map_err(|e| e.to_string())?;
    load(c.as_bytes_with_nul())
}
