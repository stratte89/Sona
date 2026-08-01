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

/// Media Foundation itself is process-wide and must be started exactly once.
static MF_INIT: Once = Once::new();

thread_local! {
    /// COM apartments are **per thread**, and that is the whole point of this.
    ///
    /// `CoInitializeEx` was being called once for the process, on whichever thread first
    /// opened an encoder. Every thread that touches a COM object afterwards has to have
    /// entered an apartment of its own, and the encoder does not stay on one thread: it
    /// lives on a tokio task, and tokio moves tasks between worker threads whenever it
    /// pleases. So the second a task migrated, every `IMFTransform` call was being made
    /// from a thread that had never initialised COM — undefined behaviour, and the kind
    /// that corrupts a heap rather than failing cleanly.
    ///
    /// It went unnoticed because this code did not *run* until hardware encoding started
    /// working, and the crashes appeared in the same release that made it work: an
    /// access violation inside `ntdll` with a FaultTolerantHeap event beside it, which is
    /// what heap corruption looks like from the outside.
    static COM_THREAD: () = {
        // SAFETY: the documented per-thread apartment initialiser. Deliberately never
        // paired with `CoUninitialize`: a tokio worker outlives any encoder on it, and
        // leaving the apartment while another task on the same thread still holds COM
        // objects would be the same bug pointing the other way.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    };
}

/// Enter a COM apartment on this thread (idempotent) and start Media Foundation once.
///
/// Called at the top of every entry point that touches the MFT, not just at open, because
/// "this thread" is not the same thread each time.
fn mf_startup() {
    COM_THREAD.with(|_| ());
    MF_INIT.call_once(|| {
        // SAFETY: process-wide initialiser, called once, after COM is up on this thread.
        unsafe {
            let _ = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
        }
    });
}

/// A hardware H.264 encoder MFT, plus the NV12 staging buffer feeding it.
pub(super) struct Encoder {
    mft: IMFTransform,
    /// The MFT's own event queue — the only legal way to drive an asynchronous MFT, which
    /// is what every hardware encoder is. See [`Encoder::pump`].
    events: IMFMediaEventGenerator,
    /// Unspent `METransformNeedInput` requests. The MFT decides when it wants a frame;
    /// feeding one it did not ask for is `E_UNEXPECTED`, so they are banked here and a
    /// frame that arrives with none outstanding is dropped rather than forced in.
    need_input: u32,
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
    /// Open the first hardware encoder on this machine that will actually take the job.
    ///
    /// *Every* candidate gets tried, not just the one Media Foundation puts first. A
    /// laptop with an Intel iGPU and a discrete GPU registers an encoder MFT for each, and
    /// the preferred-first ordering has no idea which of them will accept the resolution
    /// being asked for — Intel's Quick Sync MFT in particular is the fussiest of the three
    /// vendors about frame size. Stopping at the first candidate meant one picky encoder
    /// could mask a perfectly good one sitting next to it and send the whole call to the
    /// software path.
    ///
    /// `skip` candidates are passed over first, so the caller can come back for the next
    /// encoder when the one it got failed a test this layer cannot perform — the probe in
    /// [`super::factory`] decodes the output, which is the check that catches an encoder
    /// that configures happily and then emits something unusable.
    pub(super) fn open(content: video::Content, skip: usize) -> Result<Encoder, String> {
        // Only an initial configuration: `encode` rebuilds for whatever the capture
        // actually produces, including when the governor changes it. Shared with the
        // probe (see `super::open_dims`) so what gets proven is what gets used.
        let (w, h) = super::open_dims(content);
        Encoder::open_at(content, w, h, skip)
    }

    /// As [`Encoder::open`], for a size the caller already knows — the resize path, which
    /// needs the same "try every candidate" search rather than a second, weaker one.
    fn open_at(content: video::Content, w: u32, h: u32, skip: usize) -> Result<Encoder, String> {
        mf_startup();
        let candidates = hardware_encoders()?;
        if skip >= candidates.len() {
            return Err(format!(
                "no further hardware H.264 encoder ({} on this machine)",
                candidates.len()
            ));
        }
        let candidates = &candidates[skip..];
        let mut last_err = String::from("no hardware H.264 encoder could be configured");
        for act in candidates {
            // SAFETY: activating a registered MFT; a failure is this candidate's problem,
            // not the machine's, so it is recorded and the next one is tried.
            let mft = match unsafe { act.ActivateObject::<IMFTransform>() } {
                Ok(t) => t,
                Err(e) => {
                    last_err = format!("ActivateObject: {e}");
                    continue;
                }
            };
            if let Err(e) = unlock_async(&mft) {
                last_err = e;
                continue;
            }
            // Every hardware MFT exposes this; a candidate that does not cannot be driven
            // and is skipped rather than guessed at.
            let events = match mft.cast::<IMFMediaEventGenerator>() {
                Ok(g) => g,
                Err(e) => {
                    last_err = format!("no IMFMediaEventGenerator: {e}");
                    continue;
                }
            };
            let mut enc = Encoder {
                mft,
                events,
                need_input: 0,
                mft_allocates: false,
                dims: (0, 0),
                content,
                clock: 0,
                frame_ticks: 0,
                nv12: Vec::new(),
                params: ParameterSets::default(),
            };
            match enc.configure(w, h) {
                Ok(()) => return Ok(enc),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
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

        // Before the types: an encoder configured for a file is no use to a call, and
        // `ICodecAPI` properties are read when the output type is set.
        tune_for_calls(&self.mft, bitrate);

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

    /// Consume every event the MFT has queued right now, without waiting.
    ///
    /// This is the half of the asynchronous MFT contract that was missing, and its absence
    /// is why hardware encoding failed on every Windows machine with the same
    /// `ProcessOutput: 0x8000FFFF` (`E_UNEXPECTED`) on all three of a test box's encoders.
    /// An async MFT — which every hardware encoder is — does not accept being driven like
    /// a synchronous one once it has been unlocked: input may only be delivered against a
    /// `METransformNeedInput` it has issued, and `ProcessOutput` may only be called after
    /// a `METransformHaveOutput`. Calling either on spec is `E_UNEXPECTED`, every time, on
    /// every vendor's driver — which is exactly what the logs showed, three for three.
    ///
    /// Non-blocking on purpose. `encode` is called from the engine's encode task on a
    /// frame deadline; blocking in `GetEvent` for an output the encoder has not finished
    /// yet would turn a pipelined encoder into a stall. Requests to feed are banked in
    /// [`Encoder::need_input`] and output arrives on whichever call it is ready for, which
    /// the caller already handles — an empty access unit means "nothing this frame".
    fn pump(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        loop {
            // SAFETY: the event generator belongs to this MFT; NO_WAIT makes this a poll,
            // and `MF_E_NO_EVENTS_AVAILABLE` is the documented "queue empty".
            let ev = match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(ev) => ev,
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(out),
                Err(e) => return Err(format!("GetEvent: {e}")),
            };
            // SAFETY: a live event object; `GetType` is an accessor.
            let kind = unsafe { ev.GetType() }.map_err(|e| format!("event type: {e}"))?;
            match MF_EVENT_TYPE(kind as i32) {
                METransformNeedInput => self.need_input += 1,
                METransformHaveOutput => self.take_output(&mut out)?,
                // Drain finished, or the MFT wants its types renegotiated. Neither is
                // fatal here: the caller's configuration is what it already asked for, so
                // stop reading and let the probe or the resize path decide.
                _ => return Ok(out),
            }
        }
    }

    /// One `ProcessOutput` against a `METransformHaveOutput` that has already arrived.
    fn take_output(&mut self, out: &mut Vec<u8>) -> Result<(), String> {
        {
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
                // The event promised output, so this should not happen — but if the MFT
                // changes its mind it is not worth failing the encoder over.
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                Err(e) => return Err(format!("ProcessOutput: {e}")),
            }
            let Some(sample) = produced else {
                return Ok(());
            };
            append_sample(&sample, out)?;
        }
        Ok(())
    }
}

impl video::H264Encode for Encoder {
    fn encode(&mut self, frame: &video::Frame) -> Result<Vec<u8>, String> {
        // This may not be the thread that opened the encoder: the encode task is a tokio
        // task and tokio moves those between workers. COM has to be up on *this* thread
        // before any of the calls below.
        mf_startup();
        if !frame.valid() {
            return Err("invalid frame".into());
        }
        let (w, h) = (frame.width as u32, frame.height as u32);
        if (w, h) != self.dims {
            // The governor stepped the capture down (or the shared window resized).
            //
            // A whole new MFT, not a renegotiated one. Setting fresh types on a streaming
            // hardware MFT is legal on paper and unreliable in practice — the same
            // `SetOutputType` that refuses an unexpected resolution outright is the one
            // being asked to change its mind mid-stream, and when it refuses here the
            // error propagates as an encode failure, the engine drops the encoder, the
            // factory hands back a new one configured for the *old* size, and the next
            // frame fails identically: a per-frame rebuild loop for the rest of the call.
            // Building a new MFT for the new size cannot get into that state, and the
            // governor changes resolution rarely enough that the cost is irrelevant.
            // SAFETY: draining tells the outgoing MFT no more input is coming, so it
            // releases what it was holding before its last reference goes away.
            unsafe {
                let _ = self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0);
            }
            let _ = self.pump();
            // Built through the same candidate search as the first one, at the new size:
            // whichever encoder accepts 960-wide is not necessarily the one that accepted
            // 1920-wide. A new MFT also means new parameter sets, and the remembered ones
            // must not be prepended to its stream — a fresh `Encoder` gets that for free.
            let clock = self.clock;
            *self = Encoder::open_at(self.content, w, h, 0)?;
            // Sample times must keep moving forward across the swap; an MFT handed a
            // timeline that restarts at zero is entitled to treat it as a discontinuity.
            self.clock = clock;
        }
        // Collect whatever the encoder has to say before deciding anything: this banks
        // `METransformNeedInput` requests and harvests finished frames.
        let mut out = self.pump()?;
        if self.need_input == 0 {
            // The encoder has not asked for a frame. Feeding one anyway is `E_UNEXPECTED`,
            // so this frame is dropped — the same "latency beats completeness" call the
            // software path makes when the socket is backlogged.
            return Ok(if out.is_empty() {
                out
            } else {
                self.params.apply(out)
            });
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

        // SAFETY: stream 0, a sample the MFT will copy or reference-count itself. Spending
        // a banked request is what makes this call legal on an asynchronous MFT.
        match unsafe { self.mft.ProcessInput(0, &sample, 0) } {
            Ok(()) => self.need_input -= 1,
            // Should not happen while a request is outstanding, but if it does the frame
            // is dropped rather than retried — the request stays banked for the next one.
            Err(e) if e.code() == MF_E_NOTACCEPTING => {}
            Err(e) => return Err(format!("ProcessInput: {e}")),
        }
        // The encode may already be finished (or may not — hardware pipelines). Either way
        // this call returns what exists now; the rest arrives on a later frame.
        out.extend(self.pump()?);
        Ok(if out.is_empty() {
            out
        } else {
            self.params.apply(out)
        })
    }

    fn force_keyframe(&mut self) {
        mf_startup(); // same reason as `encode`
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

/// Every hardware H.264 encoder MFT the system offers, preferred first.
///
/// `MFT_ENUM_FLAG_HARDWARE` is the whole point: without it this returns Microsoft's
/// software H.264 encoder, which is no better than the one already built in and would
/// quietly replace it. `SORTANDFILTER` puts the preferred device first — a preference,
/// not a verdict, which is why the caller gets the whole list and tries them in turn.
fn hardware_encoders() -> Result<Vec<IMFActivate>, String> {
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
    // Clone each interface out (an AddRef we own) before the array is torn down, so the
    // candidates outlive MF's allocation and the caller can try them at its leisure.
    let picked: Vec<IMFActivate> = list.iter().flatten().cloned().collect();
    // SAFETY: dropping our references to every entry, then the array MF allocated.
    unsafe {
        for entry in list.iter() {
            std::ptr::drop_in_place(
                entry as *const Option<IMFActivate> as *mut Option<IMFActivate>,
            );
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(activate as *const _));
    }
    if picked.is_empty() {
        return Err("no hardware H.264 encoder could be activated".into());
    }
    Ok(picked)
}

/// Unlock a hardware encoder MFT so its `IMFTransform` methods can be called at all.
///
/// **This is why hardware encoding never engaged on Windows.** Every hardware encoder MFT
/// is an *asynchronous* MFT (it reports `MF_TRANSFORM_ASYNC`), and an async MFT ships
/// locked: until the client sets `MF_TRANSFORM_ASYNC_UNLOCK`, every `IMFTransform` call —
/// including the very first `SetOutputType` — fails with `MF_E_TRANSFORM_ASYNC_LOCKED`.
/// So `Encoder::open` failed on every machine, the probe wrote the backend off as
/// permanently unavailable, and the gear icon correctly reported software encoding on a
/// box with a perfectly good encoder sitting idle. Enumerating with
/// `MFT_ENUM_FLAG_HARDWARE` and then driving the result like a plain synchronous MFT
/// cannot work, and this is the missing half.
///
/// Unlocking also opts into the async *contract*, and that contract is not optional —
/// which is worth stating plainly because assuming otherwise cost a whole extra release.
/// An unlocked async MFT does **not** accept being driven synchronously: `ProcessOutput`
/// called without a `METransformHaveOutput` in hand answers `E_UNEXPECTED` (`0x8000FFFF`),
/// and it did so on all three encoders of the first machine to try it. The event pump in
/// [`Encoder::pump`] is the other half of this function, not a refinement of it.
fn unlock_async(mft: &IMFTransform) -> Result<(), String> {
    // SAFETY: `GetAttributes` hands back the MFT's own attribute store (or fails on an
    // MFT that has none, which is then not an async MFT and needs no unlocking).
    let attrs = match unsafe { mft.GetAttributes() } {
        Ok(a) => a,
        Err(_) => return Ok(()),
    };
    // SAFETY: both are documented UINT32 attributes on an MFT attribute store.
    unsafe {
        // A synchronous MFT leaves this unset; unlocking one is meaningless, not harmful,
        // but there is no reason to touch an attribute store the MFT did not ask for.
        if attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) != 1 {
            return Ok(());
        }
        attrs
            .SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)
            .map_err(|e| format!("MF_TRANSFORM_ASYNC_UNLOCK: {e}"))?;
    }
    Ok(())
}

/// Ask for the lowest latency the encoder can give, and for the rate control a live call
/// needs. Best effort: an MFT without `ICodecAPI` (or without a given property) still
/// encodes, just with defaults tuned for files rather than calls.
///
/// Low-latency mode is the property that matters most. Left at its default, a hardware
/// H.264 encoder is free to hold several frames for lookahead and B-frame reordering —
/// which is exactly the latency a screen share cannot pay, and it would have made a
/// working hardware encoder *feel* worse than the software one it replaced.
fn tune_for_calls(mft: &IMFTransform, bitrate: u32) {
    let Ok(codec) = mft.cast::<ICodecAPI>() else {
        return;
    };
    use windows::Win32::System::Variant::VARIANT;
    // SAFETY: each GUID is paired with the variant type its property documents —
    // VT_BOOL for the latency flag, VT_UI4 for the two rate-control values.
    unsafe {
        let _ = codec.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true));
        let _ = codec.SetValue(
            &CODECAPI_AVEncCommonRateControlMode,
            // VT_UI4, which is what this property takes — the generated constant is an
            // i32 newtype, so the cast is the conversion and not a widening.
            &VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
        );
        let _ = codec.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bitrate));
    }
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
