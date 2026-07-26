//! Linux hardware H.264 through NVENC.
//!
//! NVIDIA only, deliberately. AMD and Intel keep the software encoder: the one route that
//! would cover all three on Linux is VA-API, and a VA-API stack that is installed but
//! broken is the normal state of a Linux desktop rather than the exception — this very box
//! has `libva` present and `vainfo` failing. A backend that is wrong more often than it is
//! right is worse than no backend, because the fallback costs a call's worth of stutter to
//! discover. NVENC is one vendor's own driver, and the probe in [`super::probe`] still has
//! the last word.
//!
//! Nothing here is linked; see [`api`] for why that is the hard constraint it is.
//!
//! ## Shape of a session
//!
//! One `Session` is one NVENC encoder plus exactly one input and one output buffer. No
//! surface pool, because there is nothing to pipeline: Linux has no asynchronous NVENC
//! (`enableEncodeAsync` is Windows-only), and the configuration below has no B-frames and
//! no lookahead, so `nvEncEncodePicture` returns this frame's bitstream on this call.
//! A pool would buy latency we do not want to spend.
//!
//! A frame of a different size rebuilds the whole session rather than reconfiguring it.
//! The encode governor steps the shared screen down when it cannot keep up, so this does
//! happen — but rarely, and a teardown-then-create never holds two sessions at once,
//! which matters because sessions are the scarce resource (see [`super::OpenFailure`]).

use std::ffi::c_void;
use std::sync::Arc;

use client_core::media::video;

use super::annexb::ParameterSets;
use super::OpenFailure;
use abi_gen as g;
use cuda::Context;

mod abi;
mod abi_gen;
mod api;
mod cuda;

/// Periodic IDR interval in frames, matching the software encoder: bounded damage after a
/// decoder hiccup even if a keyframe request never arrives.
const IDR_INTERVAL_FRAMES: u32 = 300;

/// P4 is the middle of the P1–P7 preset ladder. P1 would leave quality on the table on
/// hardware that is not remotely the bottleneck — the reason this backend exists is that
/// the *CPU* could not keep up — and P7 spends encode latency a live call cannot afford.
/// The tuning info, not the preset, is what actually turns off lookahead and B-frames.
const PRESET: abi::Guid = g::GUID_PRESET_P4;

/// Open an NVENC encoder, or say whether it is worth trying again.
pub(super) fn open(content: video::Content) -> Result<Box<dyn video::H264Encode>, OpenFailure> {
    Encoder::open(content).map(|e| Box::new(e) as Box<dyn video::H264Encode>)
}

/// A live NVENC encoder and the two buffers it works through.
struct Session {
    api: &'static api::Api,
    enc: *mut c_void,
    input: *mut c_void,
    output: *mut c_void,
    dims: (u32, u32),
    /// Row stride the driver handed back for the input buffer. Not the frame width: NVENC
    /// aligns rows to whatever the hardware wants, and the encode call has to be told
    /// which of the two it is looking at.
    pitch: u32,
    /// Input format the driver actually gave us — IYUV where possible, NV12 otherwise.
    fmt: u32,
    /// Held so the CUDA context cannot be destroyed while a session built on it lives.
    _cuda: Arc<Context>,
}

pub(super) struct Encoder {
    cuda: Arc<Context>,
    content: video::Content,
    session: Session,
    params: ParameterSets,
    /// Set by [`video::H264Encode::force_keyframe`], consumed by the next `encode`.
    force_idr: bool,
    frame_idx: u32,
}

// One encode task owns the encoder and drives it from one thread at a time, which is what
// the `H264Encode` contract requires. The CUDA context is floating (never left current on
// a thread), so none of these handles are bound to the thread that created them.
unsafe impl Send for Encoder {}

impl Encoder {
    fn open(content: video::Content) -> Result<Encoder, OpenFailure> {
        let api = api::api().map_err(|e| OpenFailure::Permanent(e.to_string()))?;
        let cuda = Context::shared().map_err(OpenFailure::Permanent)?;
        // Only an opening size: `encode` rebuilds for whatever the capture actually
        // produces, including after the governor steps it down.
        let dims = match content {
            video::Content::Camera => (640, 480),
            video::Content::Screen => (1920, 1080),
        };
        let session = Session::open(api, cuda.clone(), content, dims)?;
        Ok(Encoder {
            cuda,
            content,
            session,
            params: ParameterSets::default(),
            force_idr: false,
            frame_idx: 0,
        })
    }
}

impl video::H264Encode for Encoder {
    fn encode(&mut self, frame: &video::Frame) -> Result<Vec<u8>, String> {
        if !frame.valid() {
            return Err("invalid frame".into());
        }
        let dims = (frame.width as u32, frame.height as u32);
        if dims != self.session.dims {
            // Drop the old session *first*: on a driver whose session limit we are already
            // near, holding two at once is how a resize turns into a failed reopen.
            self.session.close();
            self.session = Session::open(self.session.api, self.cuda.clone(), self.content, dims)
                .map_err(|e| format!("NVENC resize to {}x{}: {e}", dims.0, dims.1))?;
            // A new session starts from an IDR anyway, but its parameter sets are new too,
            // so the remembered ones must not be prepended to it.
            self.params = ParameterSets::default();
        }

        self.session.write_frame(frame)?;
        let flags = if std::mem::take(&mut self.force_idr) {
            g::NV_ENC_PIC_FLAG_FORCEIDR | g::NV_ENC_PIC_FLAG_OUTPUT_SPSPPS
        } else {
            0
        };
        let au = self.session.encode_picture(flags, self.frame_idx)?;
        self.frame_idx = self.frame_idx.wrapping_add(1);
        Ok(if au.is_empty() {
            au
        } else {
            self.params.apply(au)
        })
    }

    fn force_keyframe(&mut self) {
        self.force_idr = true;
    }
}

impl Session {
    fn open(
        api: &'static api::Api,
        cuda: Arc<Context>,
        content: video::Content,
        (w, h): (u32, u32),
    ) -> Result<Session, OpenFailure> {
        let (bitrate, fps) = match content {
            video::Content::Camera => (video::CAMERA_BITRATE, video::CAMERA_MAX_FPS),
            video::Content::Screen => (video::SCREEN_BITRATE, video::SCREEN_MAX_FPS),
        };
        let fps = fps.round().max(1.0) as u32;

        let mut params: abi::OpenSessionExParams = unsafe { abi::zeroed() };
        params.version = g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER;
        params.device_type = g::NV_ENC_DEVICE_TYPE_CUDA;
        params.device = cuda.as_ptr();
        params.api_version = g::NVENCAPI_VERSION;
        let mut enc: *mut c_void = std::ptr::null_mut();
        // SAFETY: `params` is a fully initialised struct of the version it declares (the
        // layout is asserted at compile time in `abi`), and `enc` is a valid out pointer.
        let status = unsafe { (api.open_session_ex)(&mut params, &mut enc) };
        if status != g::NV_ENC_SUCCESS || enc.is_null() {
            return Err(session_failure(status));
        }

        let mut session = Session {
            api,
            enc,
            input: std::ptr::null_mut(),
            output: std::ptr::null_mut(),
            dims: (w, h),
            pitch: 0,
            fmt: g::NV_ENC_BUFFER_FORMAT_IYUV,
            _cuda: cuda,
        };
        session.initialize(w, h, fps, bitrate)?;
        session.create_buffers(w, h)?;
        Ok(session)
    }

    /// Configure the encoder from the preset's own config, changed as little as possible.
    ///
    /// The codec union is never hand-built: `nvEncGetEncodePresetConfigEx` fills a whole
    /// `NV_ENC_CONFIG` including fields this code has no opinion on and no transcription
    /// for, and only the rate control and GOP structure are then overwritten.
    fn initialize(&mut self, w: u32, h: u32, fps: u32, bitrate: u32) -> Result<(), OpenFailure> {
        let mut preset: Box<abi::PresetConfig> = Box::new(unsafe { abi::zeroed() });
        preset.version = g::NV_ENC_PRESET_CONFIG_VER;
        preset.preset_cfg.version = g::NV_ENC_CONFIG_VER;
        // SAFETY: both GUIDs are 16-byte `repr(C)` values passed by value exactly as the
        // header declares; `preset` is a live, correctly versioned out parameter.
        let status = unsafe {
            (self.api.get_preset_config_ex)(
                self.enc,
                g::GUID_H264_CODEC,
                PRESET,
                g::NV_ENC_TUNING_INFO_LOW_LATENCY,
                &mut *preset,
            )
        };
        if status != g::NV_ENC_SUCCESS {
            return Err(self.permanent("nvEncGetEncodePresetConfigEx", status));
        }

        let cfg = &mut preset.preset_cfg;
        cfg.version = g::NV_ENC_CONFIG_VER;
        // Main, not Baseline: CABAC is worth several percent of bitrate and every decoder
        // that can decode our software encoder's output can decode Main.
        cfg.profile_guid = g::GUID_H264_PROFILE_MAIN;
        cfg.gop_length = IDR_INTERVAL_FRAMES;
        // IPP. B-frames reorder, and a reordered frame is a frame the peer cannot display
        // until the next one arrives — latency the software path never spends either.
        cfg.frame_interval_p = 1;
        cfg.rc_params.rate_control_mode = g::NV_ENC_PARAMS_RC_CBR;
        cfg.rc_params.average_bit_rate = bitrate;
        cfg.rc_params.max_bit_rate = bitrate;
        // A one-frame VBV buffer. Anything larger lets the encoder bank bits and spend
        // them on a burst, and a burst is what the pacing on the socket side cannot
        // absorb — the frame arrives late and the voice tick pays for it.
        cfg.rc_params.vbv_buffer_size = bitrate / fps;
        cfg.rc_params.vbv_initial_delay = bitrate / fps;
        abi::h264_idr_period(&mut cfg.codec_config, IDR_INTERVAL_FRAMES);
        // Belt and braces with `annexb::ParameterSets`: ask the encoder to put SPS/PPS in
        // front of every IDR itself, and re-attach them afterwards if it did not.
        abi::h264_repeat_sps_pps(&mut cfg.codec_config);

        let mut init: abi::InitializeParams = unsafe { abi::zeroed() };
        init.version = g::NV_ENC_INITIALIZE_PARAMS_VER;
        init.encode_guid = g::GUID_H264_CODEC;
        init.preset_guid = PRESET;
        init.encode_width = w;
        init.encode_height = h;
        init.dar_width = w;
        init.dar_height = h;
        init.frame_rate_num = fps;
        init.frame_rate_den = 1;
        // Asynchronous encode is a Windows-only feature of NVENC; on Linux this must be 0
        // or initialisation fails outright.
        init.enable_encode_async = 0;
        // Let the driver decide picture types. With `frame_interval_p = 1` that means
        // I then P forever, plus the IDRs we ask for.
        init.enable_ptd = 1;
        init.encode_config = &mut *cfg;
        init.tuning_info = g::NV_ENC_TUNING_INFO_LOW_LATENCY;
        // SAFETY: `init` is fully initialised and points at `cfg`, which lives until this
        // call returns; the driver only reads both.
        let status = unsafe { (self.api.initialize_encoder)(self.enc, &mut init) };
        if status != g::NV_ENC_SUCCESS {
            return Err(self.permanent("nvEncInitializeEncoder", status));
        }
        Ok(())
    }

    /// Allocate the input and output buffers.
    ///
    /// IYUV first, NV12 only if the driver will not give us IYUV. IYUV *is* our frame
    /// layout — three planes, Y then U then V — so the whole colour conversion collapses
    /// into three run-length copies. Interleaving into NV12 by hand cost 6.8 ms of CPU per
    /// 1080p frame here, more than the software encoder spends encoding the entire frame,
    /// which would have made this backend a pessimisation of exactly the thing it exists
    /// to fix. Every NVENC driver in the supported range takes IYUV; the NV12 fallback is
    /// there because being wrong about that would mean no hardware encode at all.
    fn create_buffers(&mut self, w: u32, h: u32) -> Result<(), OpenFailure> {
        let mut last = g::NV_ENC_SUCCESS;
        for fmt in [g::NV_ENC_BUFFER_FORMAT_IYUV, g::NV_ENC_BUFFER_FORMAT_NV12] {
            let mut input: abi::CreateInputBuffer = unsafe { abi::zeroed() };
            input.version = g::NV_ENC_CREATE_INPUT_BUFFER_VER;
            input.width = w;
            input.height = h;
            input.memory_heap = g::NV_ENC_MEMORY_HEAP_AUTOSELECT;
            input.buffer_fmt = fmt;
            // SAFETY: live, versioned struct; the driver writes the handle into
            // `input_buffer`.
            last = unsafe { (self.api.create_input_buffer)(self.enc, &mut input) };
            if last == g::NV_ENC_SUCCESS && !input.input_buffer.is_null() {
                self.input = input.input_buffer;
                self.fmt = fmt;
                break;
            }
        }
        if self.input.is_null() {
            return Err(self.classify("nvEncCreateInputBuffer", last));
        }

        let mut output: abi::CreateBitstreamBuffer = unsafe { abi::zeroed() };
        output.version = g::NV_ENC_CREATE_BITSTREAM_BUFFER_VER;
        output.memory_heap = g::NV_ENC_MEMORY_HEAP_AUTOSELECT;
        // `size` is deprecated and must stay 0; the driver sizes the buffer itself.
        // SAFETY: as above.
        let status = unsafe { (self.api.create_bitstream_buffer)(self.enc, &mut output) };
        if status != g::NV_ENC_SUCCESS || output.bitstream_buffer.is_null() {
            return Err(self.classify("nvEncCreateBitstreamBuffer", status));
        }
        self.output = output.bitstream_buffer;
        Ok(())
    }

    /// Lock the input buffer and lay the frame into it, honouring the driver's pitch
    /// (which is a hardware alignment, not the frame width).
    ///
    /// The mapping is very likely write-combined memory, so this only ever writes whole
    /// rows forwards with `copy_nonoverlapping`. A byte-at-a-time loop over the same
    /// region — which is what an NV12 chroma interleave is — turns each store into its own
    /// bus transaction and costs milliseconds per frame.
    fn write_frame(&mut self, frame: &video::Frame) -> Result<(), String> {
        let mut lock: abi::LockInputBuffer = unsafe { abi::zeroed() };
        lock.version = g::NV_ENC_LOCK_INPUT_BUFFER_VER;
        lock.input_buffer = self.input;
        // SAFETY: `self.input` is a live buffer from this session; the driver fills in a
        // writable mapping and its pitch.
        let status = unsafe { (self.api.lock_input_buffer)(self.enc, &mut lock) };
        if status != g::NV_ENC_SUCCESS || lock.buffer_data_ptr.is_null() {
            return Err(self.msg("nvEncLockInputBuffer", status));
        }
        let pitch = lock.pitch as usize;
        // A pitch narrower than the frame would make every row write run into the next
        // row's memory; refuse rather than corrupt the mapping.
        if pitch < frame.width {
            // SAFETY: unlocking the buffer just locked, before returning.
            unsafe {
                let _ = (self.api.unlock_input_buffer)(self.enc, self.input);
            }
            return Err(format!("NVENC pitch {pitch} < width {}", frame.width));
        }
        // SAFETY: the driver mapped a buffer of this session's dimensions in `self.fmt`,
        // `frame` matches those dimensions (the caller rebuilt the session otherwise), and
        // `pitch >= frame.width` was just checked. Both writers stay inside the region
        // NVENC defines for their format: `height` luma rows at `pitch`, then the chroma
        // planes at the stride that format specifies.
        unsafe {
            let dst = lock.buffer_data_ptr.cast::<u8>();
            if self.fmt == g::NV_ENC_BUFFER_FORMAT_IYUV {
                write_iyuv(frame, dst, pitch);
            } else {
                write_nv12(frame, dst, pitch);
            }
        }
        self.pitch = lock.pitch;
        // SAFETY: unlocking the buffer this call locked.
        let status = unsafe { (self.api.unlock_input_buffer)(self.enc, self.input) };
        if status != g::NV_ENC_SUCCESS {
            return Err(self.msg("nvEncUnlockInputBuffer", status));
        }
        Ok(())
    }

    /// Encode whatever is in the input buffer and return the access unit.
    fn encode_picture(&mut self, flags: u32, frame_idx: u32) -> Result<Vec<u8>, String> {
        let mut pic: abi::PicParams = unsafe { abi::zeroed() };
        pic.version = g::NV_ENC_PIC_PARAMS_VER;
        pic.input_width = self.dims.0;
        pic.input_height = self.dims.1;
        pic.input_pitch = self.pitch;
        pic.encode_pic_flags = flags;
        pic.frame_idx = frame_idx;
        pic.input_buffer = self.input;
        pic.output_bitstream = self.output;
        pic.buffer_fmt = self.fmt;
        pic.picture_struct = g::NV_ENC_PIC_STRUCT_FRAME;
        // Ignored while `enable_ptd` is 1, but "unknown" is the honest value to send.
        pic.picture_type = g::NV_ENC_PIC_TYPE_UNKNOWN;
        // SAFETY: every pointer in `pic` is a live buffer of this session, and the struct
        // layout is asserted against the header at compile time.
        let status = unsafe { (self.api.encode_picture)(self.enc, &mut pic) };
        // Not an error: the encoder is holding this frame back and wants another. It
        // should not happen with no B-frames and no lookahead, but an empty access unit
        // is exactly what "the rate controller skipped this frame" already means upstream.
        if status == g::NV_ENC_ERR_NEED_MORE_INPUT {
            return Ok(Vec::new());
        }
        if status != g::NV_ENC_SUCCESS {
            return Err(self.msg("nvEncEncodePicture", status));
        }

        let mut lock: abi::LockBitstream = unsafe { abi::zeroed() };
        lock.version = g::NV_ENC_LOCK_BITSTREAM_VER;
        lock.output_bitstream = self.output;
        // SAFETY: live output buffer; the driver fills in a readable mapping and its
        // length. `doNotWait` is left 0, so this blocks until the frame is done — which is
        // what the caller wants, since it is timing the encode to drive the governor.
        let status = unsafe { (self.api.lock_bitstream)(self.enc, &mut lock) };
        if status != g::NV_ENC_SUCCESS || lock.bitstream_buffer_ptr.is_null() {
            return Err(self.msg("nvEncLockBitstream", status));
        }
        // SAFETY: the driver reported `bitstream_size_in_bytes` valid bytes at
        // `bitstream_buffer_ptr`, and the copy happens before the buffer is unlocked.
        let au = unsafe {
            std::slice::from_raw_parts(
                lock.bitstream_buffer_ptr.cast::<u8>(),
                lock.bitstream_size_in_bytes as usize,
            )
            .to_vec()
        };
        // SAFETY: unlocking the buffer this call locked.
        let status = unsafe { (self.api.unlock_bitstream)(self.enc, self.output) };
        if status != g::NV_ENC_SUCCESS {
            return Err(self.msg("nvEncUnlockBitstream", status));
        }
        Ok(au)
    }

    /// The driver's message for `call`, which is far more useful than the status number.
    fn msg(&self, call: &str, status: u32) -> String {
        let detail = api::last_error(self.api, self.enc);
        if detail.is_empty() {
            format!("{call} failed ({status})")
        } else {
            format!("{call} failed ({status}): {detail}")
        }
    }

    fn permanent(&self, call: &str, status: u32) -> OpenFailure {
        OpenFailure::Permanent(self.msg(call, status))
    }

    /// Out of memory — host or device — is the one failure at open time that another
    /// process could be causing, so it must not write the backend off.
    fn classify(&self, call: &str, status: u32) -> OpenFailure {
        if status == g::NV_ENC_ERR_OUT_OF_MEMORY {
            OpenFailure::Transient(self.msg(call, status))
        } else {
            OpenFailure::Permanent(self.msg(call, status))
        }
    }

    /// Flush and release, idempotently. Split out of `Drop` so a resize can tear the old
    /// session down *before* asking for the next one.
    fn close(&mut self) {
        if self.enc.is_null() {
            return;
        }
        // An end-of-stream picture is how the API says "no more input"; skipping it can
        // leave the driver waiting on an encode that is never coming.
        let mut eos: abi::PicParams = unsafe { abi::zeroed() };
        eos.version = g::NV_ENC_PIC_PARAMS_VER;
        eos.encode_pic_flags = g::NV_ENC_PIC_FLAG_EOS;
        // SAFETY: an EOS picture carries no buffers, so the null input/output pointers are
        // what the API asks for here. Every call below releases a resource this session
        // owns, once, and `enc` is nulled so a second `close` is a no-op.
        unsafe {
            let _ = (self.api.encode_picture)(self.enc, &mut eos);
            if !self.input.is_null() {
                let _ = (self.api.destroy_input_buffer)(self.enc, self.input);
                self.input = std::ptr::null_mut();
            }
            if !self.output.is_null() {
                let _ = (self.api.destroy_bitstream_buffer)(self.enc, self.output);
                self.output = std::ptr::null_mut();
            }
            let _ = (self.api.destroy_encoder)(self.enc);
        }
        self.enc = std::ptr::null_mut();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

/// Whether a session that would not open is worth asking for again.
///
/// This is the distinction that matters on a machine that is already encoding something:
/// NVENC caps concurrent sessions per process *and* per driver — 8 on Linux drivers from
/// 550.54.14, but 5, 3 and originally 2 before that — and OBS or a browser tab counts
/// against the same cap. Camera plus screen is already two. A second leg losing that race
/// says nothing about the first leg, which is encoding fine, so it must not switch
/// hardware encoding off for the process.
fn session_failure(status: u32) -> OpenFailure {
    let why = format!("nvEncOpenEncodeSessionEx failed ({status})");
    match status {
        g::NV_ENC_ERR_OUT_OF_MEMORY => {
            OpenFailure::Transient(format!("{why}: no free NVENC session"))
        }
        g::NV_ENC_ERR_ENCODER_BUSY => OpenFailure::Transient(format!("{why}: encoder busy")),
        // Everything else is a property of the machine: no NVENC block on this GPU
        // (`INCOMPATIBLE_CLIENT_KEY` is what a GeForce without one answers), an
        // unsupported device, a driver that does not implement the call.
        _ => OpenFailure::Permanent(why),
    }
}

/// I420 → IYUV, which is the same three planes: Y at `pitch`, then U and V at half that.
/// No conversion happens at all, only the restride.
///
/// # Safety
/// `dst` must be writable for `pitch * height * 3 / 2` bytes, `pitch >= frame.width` and
/// even, and `frame` must be [`video::Frame::valid`].
unsafe fn write_iyuv(frame: &video::Frame, dst: *mut u8, pitch: usize) {
    let (w, h) = (frame.width, frame.height);
    let (cw, ch) = (w / 2, h / 2);
    let (y, uv) = frame.i420.split_at(w * h);
    let (u, v) = uv.split_at(cw * ch);
    let cpitch = pitch / 2;
    plane(y, dst, w, h, pitch);
    plane(u, dst.add(pitch * h), cw, ch, cpitch);
    plane(v, dst.add(pitch * h + cpitch * ch), cw, ch, cpitch);
}

/// I420 → NV12 (luma plane, then interleaved chroma), for a driver that would not take
/// IYUV. The interleave is built in ordinary cached memory first and copied over a row at
/// a time, because writing it straight into the mapping byte by byte is what made this the
/// slow path in the first place.
///
/// # Safety
/// As [`write_iyuv`].
unsafe fn write_nv12(frame: &video::Frame, dst: *mut u8, pitch: usize) {
    let (w, h) = (frame.width, frame.height);
    let (cw, ch) = (w / 2, h / 2);
    let (y, uv) = frame.i420.split_at(w * h);
    let (u, v) = uv.split_at(cw * ch);
    plane(y, dst, w, h, pitch);
    let mut row = vec![0u8; w];
    let chroma = dst.add(pitch * h);
    for r in 0..ch {
        for (col, pair) in row.chunks_exact_mut(2).enumerate() {
            pair[0] = u[r * cw + col];
            pair[1] = v[r * cw + col];
        }
        std::ptr::copy_nonoverlapping(row.as_ptr(), chroma.add(r * pitch), w);
    }
}

/// One plane, `rows` rows of `width` bytes, restrided to `pitch`.
///
/// # Safety
/// `src` must hold `width * rows` bytes and `dst` must be writable for `pitch * rows`.
unsafe fn plane(src: &[u8], dst: *mut u8, width: usize, rows: usize, pitch: usize) {
    // Contiguous is the common case (NVENC's pitch is often exactly the width for the
    // sizes we send), and one copy beats `rows` of them.
    if pitch == width {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, width * rows);
        return;
    }
    for r in 0..rows {
        std::ptr::copy_nonoverlapping(src.as_ptr().add(r * width), dst.add(r * pitch), width);
    }
}

#[cfg(test)]
mod tests;
