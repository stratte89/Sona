//! Windows hardware H.264 through Media Foundation.
//!
//! One code path covers every vendor: `MFTEnumEx` with `MFT_ENUM_FLAG_HARDWARE` returns
//! whichever encoder MFT the installed driver registered — NVIDIA's (NVENC), AMD's (AMF)
//! or Intel's (Quick Sync) — and they are driven identically. That is the whole reason to
//! prefer Media Foundation here over talking to a vendor SDK: there is no per-GPU code to
//! get wrong, and a machine with no hardware encoder simply enumerates nothing and gets
//! the software encoder.
//!
//! COM is handled by the `windows` crate: interfaces are reference-counted handles that
//! release on drop, and every call returns a `Result`. The `unsafe` here is therefore
//! narrow — buffer locking, and the raw `MFTEnumEx` out-parameter — and each block says
//! what makes it sound.

use std::sync::Once;

use client_core::media::video;
use windows::core::{Interface, GUID};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};

use super::annexb::ParameterSets;

/// Media Foundation is process-wide and must be started exactly once.
static MF_INIT: Once = Once::new();

fn mf_startup() {
    MF_INIT.call_once(|| {
        // SAFETY: both are the documented process-wide initialisers, called once. The
        // apartment may already be initialised by the webview — that returns a non-fatal
        // "already initialised" HRESULT, which is why the result is deliberately ignored.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let _ = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
        }
    });
}

/// A hardware H.264 encoder MFT, plus the NV12 staging buffer feeding it.
pub(super) struct Encoder {
    mft: IMFTransform,
    /// `true` when the MFT allocates its own output samples (hardware ones normally do).
    mft_allocates: bool,
    /// Size the MFT was configured for; a differently-sized frame rebuilds the encoder.
    dims: (u32, u32),
    content: video::Content,
    /// Monotonic sample time in 100 ns units, which is what MF counts in.
    clock: i64,
    frame_ticks: i64,
    /// I420 → NV12 scratch, reused so the steady state does not allocate.
    nv12: Vec<u8>,
    params: ParameterSets,
}

// The MFT is used from one thread at a time (the encode task owns it), which is what the
// `H264Encode` contract requires. MF's async MFTs are not moved between threads here.
unsafe impl Send for Encoder {}

impl Encoder {
    pub(super) fn open(content: video::Content) -> Result<Encoder, String> {
        mf_startup();
        let (w, h) = match content {
            // Only an initial configuration: `encode` reconfigures to whatever the
            // capture actually produces, including when the governor changes it.
            video::Content::Camera => (640, 480),
            video::Content::Screen => (1920, 1080),
        };
        let mut enc = Encoder {
            mft: find_hardware_encoder()?,
            mft_allocates: false,
            dims: (0, 0),
            content,
            clock: 0,
            frame_ticks: 0,
            nv12: Vec::new(),
            params: ParameterSets::default(),
        };
        enc.configure(w, h)?;
        Ok(enc)
    }

    /// Point the MFT at a frame size. Output type first, then input — encoders reject an
    /// input type until they know what they are producing.
    fn configure(&mut self, w: u32, h: u32) -> Result<(), String> {
        let (bitrate, fps) = match self.content {
            video::Content::Camera => (video::CAMERA_BITRATE, video::CAMERA_MAX_FPS),
            video::Content::Screen => (video::SCREEN_BITRATE, video::SCREEN_MAX_FPS),
        };
        let fps = fps.round().max(1.0) as u32;
        self.frame_ticks = 10_000_000 / fps as i64;

        let out = media_type(
            &MFVideoFormat_H264,
            w,
            h,
            fps,
            Some((bitrate, eAVEncH264VProfile_Base.0 as u32)),
        )?;
        let input = media_type(&MFVideoFormat_NV12, w, h, fps, None)?;
        // SAFETY: both types were just built by MF and describe the same frame geometry;
        // stream 0 is the only stream an H.264 encoder MFT exposes.
        unsafe {
            self.mft
                .SetOutputType(0, &out, 0)
                .map_err(|e| format!("H.264 output type {w}x{h}: {e}"))?;
            self.mft
                .SetInputType(0, &input, 0)
                .map_err(|e| format!("NV12 input type {w}x{h}: {e}"))?;
            let info = self
                .mft
                .GetOutputStreamInfo(0)
                .map_err(|e| format!("output stream info: {e}"))?;
            self.mft_allocates = info.dwFlags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0)
                    as u32
                != 0;
            let _ = self
                .mft
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
            let _ = self
                .mft
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        }
        self.dims = (w, h);
        Ok(())
    }

    /// Drain whatever the MFT is willing to give us right now.
    fn pull(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            let sample = if self.mft_allocates {
                None
            } else {
                // SAFETY: size comes from the MFT's own stream info; the buffer is
                // handed straight back to it and released when `sample` drops.
                let info = unsafe { self.mft.GetOutputStreamInfo(0) }
                    .map_err(|e| format!("output stream info: {e}"))?;
                let buf = unsafe { MFCreateMemoryBuffer(info.cbSize.max(1)) }
                    .map_err(|e| format!("output buffer: {e}"))?;
                let s = unsafe { MFCreateSample() }.map_err(|e| format!("output sample: {e}"))?;
                unsafe { s.AddBuffer(&buf) }.map_err(|e| format!("output add buffer: {e}"))?;
                Some(s)
            };
            let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample.clone()),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0u32;
            // SAFETY: one output buffer for stream 0, matching `buffers`' length.
            let r = unsafe { self.mft.ProcessOutput(0, &mut buffers, &mut status) };
            // Whatever came back — either the sample we supplied, or one the MFT
            // allocated and stored here. Taken out of the ManuallyDrop so it is released
            // normally when it goes out of scope; `pEvents` is dropped the same way.
            let produced = unsafe { std::mem::ManuallyDrop::take(&mut buffers[0].pSample) };
            unsafe { std::mem::ManuallyDrop::drop(&mut buffers[0].pEvents) };
            match r {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(out),
                // The MFT wants its types renegotiated. Not fatal, but the caller's
                // configuration is what it already asked for, so treat it as an error and
                // let the probe/fallback decide.
                Err(e) => return Err(format!("ProcessOutput: {e}")),
            }
            let Some(sample) = produced else {
                return Ok(out);
            };
            append_sample(&sample, &mut out)?;
        }
    }
}

impl video::H264Encode for Encoder {
    fn encode(&mut self, frame: &video::Frame) -> Result<Vec<u8>, String> {
        if !frame.valid() {
            return Err("invalid frame".into());
        }
        let (w, h) = (frame.width as u32, frame.height as u32);
        if (w, h) != self.dims {
            // The governor stepped the capture down (or the shared window resized).
            // Renegotiating mid-stream is legal; the MFT emits a fresh IDR after it.
            // SAFETY: draining before a type change is what the MFT expects.
            unsafe {
                let _ = self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
            }
            let _ = self.pull();
            self.configure(w, h)?;
        }
        i420_to_nv12(frame, &mut self.nv12);

        let len = self.nv12.len() as u32;
        // SAFETY: a fresh MF buffer of exactly `len`; `Lock` yields a writable pointer to
        // at least that many bytes, which is the only region written, and it is unlocked
        // before the buffer is handed on.
        let buf = unsafe { MFCreateMemoryBuffer(len) }.map_err(|e| format!("input buffer: {e}"))?;
        unsafe {
            let mut dst: *mut u8 = std::ptr::null_mut();
            let mut max = 0u32;
            buf.Lock(&mut dst, Some(&mut max), None)
                .map_err(|e| format!("input lock: {e}"))?;
            debug_assert!(max >= len && !dst.is_null());
            std::ptr::copy_nonoverlapping(self.nv12.as_ptr(), dst, len as usize);
            let _ = buf.Unlock();
            buf.SetCurrentLength(len)
                .map_err(|e| format!("input length: {e}"))?;
        }
        // SAFETY: sample owns the buffer; times are plain values.
        let sample = unsafe {
            let s = MFCreateSample().map_err(|e| format!("input sample: {e}"))?;
            s.AddBuffer(&buf)
                .map_err(|e| format!("input add buffer: {e}"))?;
            s.SetSampleTime(self.clock)
                .map_err(|e| format!("sample time: {e}"))?;
            s.SetSampleDuration(self.frame_ticks)
                .map_err(|e| format!("sample duration: {e}"))?;
            s
        };
        self.clock += self.frame_ticks;

        // SAFETY: stream 0, a sample the MFT will copy or reference-count itself.
        match unsafe { self.mft.ProcessInput(0, &sample, 0) } {
            Ok(()) => {}
            // Encoder is holding frames: drain and drop this one rather than queueing.
            // Latency beats completeness for a live share, exactly as the software path
            // drops frames when the socket is backlogged.
            Err(e) if e.code() == MF_E_NOTACCEPTING => return self.pull(),
            Err(e) => return Err(format!("ProcessInput: {e}")),
        }
        let au = self.pull()?;
        Ok(if au.is_empty() {
            au
        } else {
            self.params.apply(au)
        })
    }

    fn force_keyframe(&mut self) {
        // Best effort: an encoder without ICodecAPI still emits periodic IDRs, and the
        // peer's request is re-sent if it goes unanswered.
        if let Ok(codec) = self.mft.cast::<ICodecAPI>() {
            let one = windows::Win32::System::Variant::VARIANT::from(1i32);
            // SAFETY: the GUID and a VT_I4 variant are exactly what this property takes.
            unsafe {
                let _ = codec.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &one);
            }
        }
    }
}

/// First hardware H.264 encoder MFT the system offers.
///
/// `MFT_ENUM_FLAG_HARDWARE` is the whole point: without it this returns Microsoft's
/// software H.264 encoder, which is no better than the one already built in and would
/// quietly replace it. `SORTANDFILTER` puts the preferred device first.
fn find_hardware_encoder() -> Result<IMFTransform, String> {
    let out_info = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let mut activate: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: MFTEnumEx allocates the array and reports its length; every element is
    // released below, and the array itself with CoTaskMemFree, per its contract.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG(MFT_ENUM_FLAG_HARDWARE.0 | MFT_ENUM_FLAG_SORTANDFILTER.0),
            None,
            Some(&out_info),
            &mut activate,
            &mut count,
        )
        .map_err(|e| format!("MFTEnumEx: {e}"))?;
    }
    if activate.is_null() || count == 0 {
        return Err("no hardware H.264 encoder registered".into());
    }
    // SAFETY: `activate` points to `count` initialised optional interfaces.
    let list = unsafe { std::slice::from_raw_parts(activate, count as usize) };
    let mut chosen = None;
    let mut last_err = String::from("no hardware H.264 encoder could be activated");
    for entry in list.iter() {
        let Some(act) = entry.as_ref() else { continue };
        if chosen.is_none() {
            // SAFETY: activating a registered MFT; failure is reported, not fatal.
            match unsafe { act.ActivateObject::<IMFTransform>() } {
                Ok(t) => chosen = Some(t),
                Err(e) => last_err = format!("ActivateObject: {e}"),
            }
        }
    }
    // SAFETY: dropping our references to every entry, then the array MF allocated.
    unsafe {
        for entry in list.iter() {
            std::ptr::drop_in_place(
                entry as *const Option<IMFActivate> as *mut Option<IMFActivate>,
            );
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(activate as *const _));
    }
    chosen.ok_or(last_err)
}

/// An `IMFMediaType` for one video format. `rate_profile` is set for the encoder's
/// output type only; an input type carries neither.
fn media_type(
    subtype: &GUID,
    w: u32,
    h: u32,
    fps: u32,
    rate_profile: Option<(u32, u32)>,
) -> Result<IMFMediaType, String> {
    // SAFETY: a freshly created media type; every setter takes the value by copy.
    unsafe {
        let mt = MFCreateMediaType().map_err(|e| format!("MFCreateMediaType: {e}"))?;
        mt.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
            .map_err(|e| e.to_string())?;
        mt.SetGUID(&MF_MT_SUBTYPE, subtype)
            .map_err(|e| e.to_string())?;
        mt.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
            .map_err(|e| e.to_string())?;
        // Frame size and rate are packed as two u32s in one u64 attribute.
        mt.SetUINT64(&MF_MT_FRAME_SIZE, ((w as u64) << 32) | h as u64)
            .map_err(|e| e.to_string())?;
        mt.SetUINT64(&MF_MT_FRAME_RATE, ((fps as u64) << 32) | 1)
            .map_err(|e| e.to_string())?;
        mt.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, (1u64 << 32) | 1)
            .map_err(|e| e.to_string())?;
        if let Some((bitrate, profile)) = rate_profile {
            mt.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)
                .map_err(|e| e.to_string())?;
            mt.SetUINT32(&MF_MT_MPEG2_PROFILE, profile)
                .map_err(|e| e.to_string())?;
        }
        Ok(mt)
    }
}

/// Append an output sample's bytes to `out`.
fn append_sample(sample: &IMFSample, out: &mut Vec<u8>) -> Result<(), String> {
    // SAFETY: buffer count comes from the sample; each buffer is locked for exactly the
    // length it reports and unlocked before the next iteration.
    unsafe {
        let count = sample.GetBufferCount().map_err(|e| e.to_string())?;
        for i in 0..count {
            let buf = sample.GetBufferByIndex(i).map_err(|e| e.to_string())?;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len = 0u32;
            buf.Lock(&mut ptr, None, Some(&mut len))
                .map_err(|e| format!("output lock: {e}"))?;
            if !ptr.is_null() && len > 0 {
                out.extend_from_slice(std::slice::from_raw_parts(ptr, len as usize));
            }
            let _ = buf.Unlock();
        }
    }
    Ok(())
}

/// I420 (three planes) → NV12 (luma plane, then interleaved chroma), which is the format
/// every hardware H.264 encoder on Windows takes.
fn i420_to_nv12(frame: &video::Frame, out: &mut Vec<u8>) {
    let (w, h) = (frame.width, frame.height);
    let (cw, ch) = (w / 2, h / 2);
    out.clear();
    out.reserve(w * h * 3 / 2);
    let (y, uv) = frame.i420.split_at(w * h);
    let (u, v) = uv.split_at(cw * ch);
    out.extend_from_slice(y);
    for i in 0..cw * ch {
        out.push(u[i]);
        out.push(v[i]);
    }
}
