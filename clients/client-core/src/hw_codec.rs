//! Hardware video codec backend — Windows Media Foundation MFT.
//!
//! On Windows, GPU vendors (NVIDIA NVENC, AMD VCN, Intel QuickSync) register
//! hardware H.264 encoder/decoder MFTs with the system. `MFTEnumEx` with
//! `MFT_ENUM_FLAG_HARDWARE` discovers them. One codepath covers all three vendors.
//!
//! On non-Windows platforms this module compiles to stubs that always return
//! `None`, so the caller falls back to the OpenH264 software codec.
//!
//! License: MIT/Apache-2.0 (the `windows` crate). The H.264 codec itself is
//! covered by the same Cisco OpenH264 royalty-free grant that already applies
//! to the software fallback — hardware acceleration moves the same codec to
//! the GPU, it does not change the codec or its patent situation.

#![allow(dead_code)]

use super::media::video::{Content, Frame};

/// Convert planar I420 to NV12 (interleaved UV). NV12 is the input format
/// expected by hardware H.264 encoder MFTs.
fn i420_to_nv12(frame: &Frame) -> Vec<u8> {
    let (w, h) = (frame.width, frame.height);
    let y_size = w * h;
    let uv_size = w * h / 4;
    let mut nv12 = Vec::with_capacity(y_size + uv_size * 2);
    nv12.extend_from_slice(&frame.i420[..y_size]);
    let u = &frame.i420[y_size..y_size + uv_size];
    let v = &frame.i420[y_size + uv_size..];
    for i in 0..uv_size {
        nv12.push(u[i]);
        nv12.push(v[i]);
    }
    nv12
}

/// Convert NV12 (interleaved UV) back to planar I420.
fn nv12_to_i420(nv12: &[u8], w: usize, h: usize) -> Frame {
    let y_size = w * h;
    let uv_h = h / 2;
    let uv_w = w / 2;
    let mut i420 = vec![0u8; w * h * 3 / 2];
    i420[..y_size].copy_from_slice(&nv12[..y_size]);
    let (upl, vpl) = i420[y_size..].split_at_mut(uv_w * uv_h);
    for i in 0..uv_w * uv_h {
        upl[i] = nv12[y_size + 2 * i];
        vpl[i] = nv12[y_size + 2 * i + 1];
    }
    Frame {
        width: w,
        height: h,
        i420,
    }
}

/// Hardware encoder trait. Implementations are platform-specific.
pub trait HwEncoder: Send {
    fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, String>;
    fn force_keyframe(&mut self);
}

/// Hardware decoder trait.
pub trait HwDecoder: Send {
    fn decode(&mut self, packet: &[u8]) -> Result<Option<Frame>, String>;
}

/// Try to create a hardware encoder. Returns `None` if no hardware encoder is
/// available (non-Windows, or no GPU driver MFT registered).
pub fn try_encoder(content: Content) -> Option<Box<dyn HwEncoder>> {
    // Hardware MFT integration is temporarily disabled — the windows crate v0.61
    // changed the Media Foundation API signatures. Falls back to OpenH264 software.
    let _ = content;
    None
}

/// Try to create a hardware decoder. Returns `None` if unavailable.
pub fn try_decoder() -> Option<Box<dyn HwDecoder>> {
    None
}

// ── Windows: Media Foundation Transform ──────────────────────────────────────────
// Temporarily disabled — the windows crate v0.61 changed MF API signatures.
// TODO: update ProcessOutput, GetUINT64, MFTEnumEx, etc. calls for windows v0.61.

#[cfg(all(target_os = "windows", feature = "hw_mft"))]
mod mf {
    use super::{i420_to_nv12, nv12_to_i420, HwDecoder, HwEncoder};
    use crate::media::video::{Content, Frame, CAMERA_BITRATE, CAMERA_MAX_FPS, SCREEN_BITRATE, SCREEN_MAX_FPS};
    use std::sync::Once;
    use windows::core::{Interface, PCWSTR};
    use windows::Win32::Graphics::DirectX::Direct3D11::ID3D11Device;
    use windows::Win32::Media::MediaFoundation::{
        eAVEncCommonRateControlMode_CBR, eAVEncH264VProfile_High, eAVEncVideoOutputScanType_Progressive,
        MFCreateMediaType, MFCreateSample, MFMediaType_Video, MFStartup, MFVideoFormat_H264,
        MFVideoFormat_NV12, MFVideoInterlace_Progressive, MFStartupType,
        MFT_ENUM_FLAG_ASYNC, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_TRANSCODE_ONLY,
        MFT_REGISTER_TYPE_INFO, MFTEnumEx, MF_TRANSFORM_CATEGORY_VideoEncoder,
        MF_TRANSFORM_CATEGORY_VideoDecoder, IMFActivate, IMFAttributes, IMFMediaBuffer,
        IMFMediaType, IMFSample, IMFTransform, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE,
        MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_MT_VIDEO_OUTPUT_SCAN,
        MFVideoFormat_H264 as MFVideoFormat_H264_Dec, MF_MT_AVG_BIT_RATE, MF_MT_FIXED_SIZE_SAMPLES,
        MF_MT_ALL_SAMPLES_INDEPENDENT, MF_MT_VIDEO_CHROMA_SITING, MFVideoChromaSubsampling_MPEG2,
    };
    use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_MULTITHREADED};
    use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};

    /// Ensure MFStartup is called exactly once per process.
    static MF_INIT: Once = Once::new();

    fn ensure_mf_startup() {
        MF_INIT.call_once(|| {
            unsafe {
                let _ = MFStartup(MFStartupType::MFSTARTUP_LITE);
            }
        });
    }

    /// Activate a hardware H.264 encoder MFT.
    pub struct MfEncoder {
        mft: IMFTransform,
        input_type: IMFMediaType,
        output_type: IMFMediaType,
        width: u32,
        height: u32,
        need_input: bool,
        have_output: bool,
        frame_count: u64,
    }

    impl MfEncoder {
        pub fn new(content: Content) -> Result<Self, String> {
            ensure_mf_startup();
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).ok();
            }

            let (bitrate, fps) = match content {
                Content::Camera => (CAMERA_BITRATE, CAMERA_MAX_FPS),
                Content::Screen => (SCREEN_BITRATE, SCREEN_MAX_FPS),
            };

            // Enumerate hardware H.264 encoder MFTs.
            let output_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };
            let activates = unsafe {
                MFTEnumEx(
                    MF_TRANSFORM_CATEGORY_VideoEncoder,
                    MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_ASYNC,
                    None,
                    Some(&output_info),
                )
            }.map_err(|e| format!("MFTEnumEx encoder: {e}"))?;

            let activate = activates
                .first()
                .ok_or("no hardware H.264 encoder MFT")?;
            let activate: IMFActivate = activate.cast()?;
            let mft: IMFTransform = unsafe { activate.ActivateObject() }
                .map_err(|e| format!("ActivateObject encoder: {e}"))?;

            // Set output type: H.264 with progressive scan.
            let output_type = unsafe { MFCreateMediaType() }
                .map_err(|e| format!("MFCreateMediaType out: {e}"))?;
            unsafe {
                output_type
                    .SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video)
                    .map_err(|e| format!("set major: {e}"))?;
                output_type
                    .SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264)
                    .map_err(|e| format!("set subtype: {e}"))?;
                output_type
                    .SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0)
                    .map_err(|e| format!("set interlace: {e}"))?;
                output_type
                    .SetUINT32(MF_MT_VIDEO_OUTPUT_SCAN, eAVEncVideoOutputScanType_Progressive.0)
                    .map_err(|e| format!("set scan: {e}"))?;
                output_type
                    .SetUINT32(MF_MT_AVG_BIT_RATE, bitrate)
                    .map_err(|e| format!("set bitrate: {e}"))?;
                output_type
                    .SetUINT32(MF_MT_FIXED_SIZE_SAMPLES, 0)
                    .map_err(|e| format!("set fixed: {e}"))?;
            }

            // Configure codec API for rate control and low latency.
            if let Ok(codec_api) = mft.cast::<windows::Win32::Media::MediaFoundation::ICodecAPI>() {
                unsafe {
                    let mut var = VARIANT::default();
                    var.Anonymous.Anonymous.vt = VT_UI4;
                    var.Anonymous.Anonymous.Anonymous.ulVal = eAVEncCommonRateControlMode_CBR.0;
                    let _ = codec_api.SetValue(
                        windows::core::PCWSTR(windows::Win32::Media::MediaFoundation::CODECAPI_AVEncCommonRateControlMode.as_ptr()),
                        &var,
                    );
                    var.Anonymous.Anonymous.Anonymous.ulVal = bitrate;
                    let _ = codec_api.SetValue(
                        windows::core::PCWSTR(windows::Win32::Media::MediaFoundation::CODECAPI_AVEncCommonMeanBitRate.as_ptr()),
                        &var,
                    );
                    var.Anonymous.Anonymous.Anonymous.ulVal = 300; // GOP size
                    let _ = codec_api.SetValue(
                        windows::core::PCWSTR(windows::Win32::Media::MediaFoundation::CODECAPI_AVEncMPVGOPSize.as_ptr()),
                        &var,
                    );
                    // Low latency mode
                    let mut bool_var = VARIANT::default();
                    bool_var.Anonymous.Anonymous.vt = VT_BOOL;
                    bool_var.Anonymous.Anonymous.Anonymous.boolVal = windows::Win32::Foundation::VARIANT_BOOL(1);
                    let _ = codec_api.SetValue(
                        windows::core::PCWSTR(windows::Win32::Media::MediaFoundation::CODECAPI_AVLowLatencyMode.as_ptr()),
                        &bool_var,
                    );
                }
            }

            // Set the output type on the MFT.
            unsafe {
                mft.SetOutputType(0, &output_type, 0)
                    .map_err(|e| format!("SetOutputType: {e}"))?;
            }

            // Create input type: NV12.
            let input_type = unsafe { MFCreateMediaType() }
                .map_err(|e| format!("MFCreateMediaType in: {e}"))?;
            unsafe {
                input_type
                    .SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video)
                    .map_err(|e| format!("set in major: {e}"))?;
                input_type
                    .SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12)
                    .map_err(|e| format!("set in subtype: {e}"))?;
                input_type
                    .SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0)
                    .map_err(|e| format!("set in interlace: {e}"))?;
                input_type
                    .SetUINT32(MF_MT_VIDEO_CHROMA_SITING, MFVideoChromaSubsampling_MPEG2.0)
                    .map_err(|e| format!("set in chroma: {e}"))?;
            }

            // We'll set frame size on first encode (dimensions may vary).
            // For now, use a default; the MFT will reinit on dimension change.
            let (width, height) = (1920u32, 1080u32);
            unsafe {
                let frame_size = (width as u64) | ((height as u64) << 32);
                input_type
                    .SetUINT64(MF_MT_FRAME_SIZE, frame_size)
                    .map_err(|e| format!("set in frame size: {e}"))?;
                let fps_val = ((fps as u64) << 32) | 1; // numerator/denominator
                input_type
                    .SetUINT64(MF_MT_FRAME_RATE, fps_val)
                    .map_err(|e| format!("set in fps: {e}"))?;
            }

            unsafe {
                mft.SetInputType(0, &input_type, 0)
                    .map_err(|e| format!("SetInputType: {e}"))?;
            }

            // Unlock async processing.
            if let Ok(attrs) = mft.cast::<IMFAttributes>() {
                unsafe {
                    let _ = attrs.SetUINT32(
                        windows::core::PCWSTR::null(),
                        0,
                    );
                }
            }

            // Begin streaming.
            unsafe {
                mft.ProcessMessage(
                    windows::Win32::Media::MediaFoundation::MFT_MESSAGE_TYPE_NOTIFY_BEGIN_STREAMING,
                    None,
                ).map_err(|e| format!("begin streaming: {e}"))?;
            }

            Ok(Self {
                mft,
                input_type,
                output_type,
                width,
                height,
                need_input: true,
                have_output: false,
                frame_count: 0,
            })
        }

        fn update_input_dimensions(&mut self, width: u32, height: u32) -> Result<(), String> {
            if width == self.width && height == self.height {
                return Ok(());
            }
            self.width = width;
            self.height = height;
            unsafe {
                let frame_size = (width as u64) | ((height as u64) << 32);
                self.input_type
                    .SetUINT64(MF_MT_FRAME_SIZE, frame_size)
                    .map_err(|e| format!("update frame size: {e}"))?;
                self.mft
                    .SetInputType(0, &self.input_type, 0)
                    .map_err(|e| format!("re-set input type: {e}"))?;
            }
            Ok(())
        }
    }

    impl HwEncoder for MfEncoder {
        fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>, String> {
            if !frame.valid() {
                return Err("invalid frame".into());
            }
            self.update_input_dimensions(frame.width as u32, frame.height as u32)?;

            let nv12 = i420_to_nv12(frame);
            let buf_len = nv12.len();

            unsafe {
                // Create input sample + buffer.
                let sample = MFCreateSample().map_err(|e| format!("create sample: {e}"))?;
                let buffer: IMFMediaBuffer = windows::Win32::Media::MediaFoundation::MFCreateMemoryBuffer(buf_len as u32)
                    .map_err(|e| format!("create buffer: {e}"))?;
                let mut max_len = 0u32;
                let mut cur_len = 0u32;
                buffer.GetMaxLength(&mut max_len).ok();
                buffer.GetCurrentLength(&mut cur_len).ok();

                // Lock and write NV12 data.
                let mut data_ptr = std::ptr::null_mut();
                buffer.Lock(&mut data_ptr, &mut max_len, &mut cur_len)
                    .map_err(|e| format!("lock buffer: {e}"))?;
                std::ptr::copy_nonoverlapping(nv12.as_ptr(), data_ptr as *mut u8, buf_len);
                buffer.SetCurrentLength(buf_len as u32)
                    .map_err(|e| format!("set current length: {e}"))?;
                buffer.Unlock().ok();

                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| format!("add buffer: {e}"))?;
                sample
                    .SetSampleTime((self.frame_count * 1_000_000) as i64)
                    .ok();
                sample
                    .SetSampleDuration(33_333) // ~30fps default
                    .ok();

                // Feed to MFT.
                self.mft
                    .ProcessInput(0, &sample, 0)
                    .map_err(|e| format!("ProcessInput: {e}"))?;

                self.frame_count += 1;

                // Drain output.
                let mut all_output = Vec::new();
                loop {
                    let out_sample: Option<IMFSample> = match self.mft.ProcessOutput(0, 1, None) {
                        Ok((s, _)) => Some(s),
                        Err(e) if e.code() == windows::Win32::Media::MediaFoundation::MF_E_TRANSFORM_NEED_MORE_INPUT => break,
                        Err(e) => return Err(format!("ProcessOutput: {e}")),
                    };
                    if let Some(s) = out_sample {
                        let mut buf_count = 0u32;
                        s.GetBufferCount(&mut buf_count).ok();
                        for i in 0..buf_count {
                            let buf = s.GetBufferByIndex(i).ok();
                            if let Some(b) = buf {
                                let mut ptr = std::ptr::null_mut();
                                let mut max = 0u32;
                                let mut cur = 0u32;
                                b.Lock(&mut ptr, &mut max, &mut cur).ok();
                                let slice = std::slice::from_raw_parts(ptr as *const u8, cur as usize);
                                all_output.extend_from_slice(slice);
                                b.Unlock().ok();
                            }
                        }
                    }
                }
                Ok(all_output)
            }
        }

        fn force_keyframe(&mut self) {
            if let Ok(codec_api) = self.mft.cast::<windows::Win32::Media::MediaFoundation::ICodecAPI>() {
                unsafe {
                    let mut var = VARIANT::default();
                    var.Anonymous.Anonymous.vt = VT_UI4;
                    var.Anonymous.Anonymous.Anonymous.ulVal = 1;
                    let _ = codec_api.SetValue(
                        windows::core::PCWSTR(windows::Win32::Media::MediaFoundation::CODECAPI_AVEncVideoForceKeyFrame.as_ptr()),
                        &var,
                    );
                }
            }
        }
    }

    /// Activate a hardware H.264 decoder MFT.
    pub struct MfDecoder {
        mft: IMFTransform,
        width: u32,
        height: u32,
        initialized: bool,
    }

    impl MfDecoder {
        pub fn new() -> Result<Self, String> {
            ensure_mf_startup();
            unsafe {
                CoInitializeEx(None, COINIT_MULTITHREADED).ok();
            }

            let input_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };
            let activates = unsafe {
                MFTEnumEx(
                    MF_TRANSFORM_CATEGORY_VideoDecoder,
                    MFT_ENUM_FLAG_HARDWARE,
                    Some(&input_info),
                    None,
                )
            }.map_err(|e| format!("MFTEnumEx decoder: {e}"))?;

            let activate = activates
                .first()
                .ok_or("no hardware H.264 decoder MFT")?;
            let activate: IMFActivate = activate.cast()?;
            let mft: IMFTransform = unsafe { activate.ActivateObject() }
                .map_err(|e| format!("ActivateObject decoder: {e}"))?;

            Ok(Self {
                mft,
                width: 0,
                height: 0,
                initialized: false,
            })
        }

        fn ensure_initialized(&mut self, packet: &[u8]) -> Result<(), String> {
            if self.initialized {
                return Ok(());
            }
            // Set input type: H.264 Annex-B.
            let input_type = unsafe { MFCreateMediaType() }
                .map_err(|e| format!("create input type: {e}"))?;
            unsafe {
                input_type
                    .SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video)
                    .map_err(|e| format!("set major: {e}"))?;
                input_type
                    .SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264)
                    .map_err(|e| format!("set subtype: {e}"))?;
                input_type
                    .SetUINT32(MF_MT_ALL_SAMPLES_INDEPENDENT, 0)
                    .map_err(|e| format!("set independent: {e}"))?;
                self.mft
                    .SetInputType(0, &input_type, 0)
                    .map_err(|e| format!("SetInputType decoder: {e}"))?;
            }

            // Get output type from MFT.
            unsafe {
                let out_type = self.mft.GetOutputAvailableType(0, 0)
                    .map_err(|e| format!("GetOutputAvailableType: {e}"))?;
                self.mft
                    .SetOutputType(0, &out_type, 0)
                    .map_err(|e| format!("SetOutputType decoder: {e}"))?;
            }

            unsafe {
                self.mft.ProcessMessage(
                    windows::Win32::Media::MediaFoundation::MFT_MESSAGE_TYPE_NOTIFY_BEGIN_STREAMING,
                    None,
                ).ok();
            }

            self.initialized = true;
            Ok(())
        }
    }

    impl HwDecoder for MfDecoder {
        fn decode(&mut self, packet: &[u8]) -> Result<Option<Frame>, String> {
            if packet.is_empty() {
                return Ok(None);
            }
            self.ensure_initialized(packet)?;

            unsafe {
                let sample = MFCreateSample().map_err(|e| format!("create dec sample: {e}"))?;
                let buffer = windows::Win32::Media::MediaFoundation::MFCreateMemoryBuffer(packet.len() as u32)
                    .map_err(|e| format!("create dec buffer: {e}"))?;
                let mut max_len = 0u32;
                let mut cur_len = 0u32;
                buffer.GetMaxLength(&mut max_len).ok();
                buffer.GetCurrentLength(&mut cur_len).ok();
                let mut data_ptr = std::ptr::null_mut();
                buffer.Lock(&mut data_ptr, &mut max_len, &mut cur_len)
                    .map_err(|e| format!("lock dec buffer: {e}"))?;
                std::ptr::copy_nonoverlapping(packet.as_ptr(), data_ptr as *mut u8, packet.len());
                buffer.SetCurrentLength(packet.len() as u32).ok();
                buffer.Unlock().ok();
                sample.AddBuffer(&buffer).map_err(|e| format!("add dec buffer: {e}"))?;

                self.mft.ProcessInput(0, &sample, 0)
                    .map_err(|e| format!("dec ProcessInput: {e}"))?;

                // Drain output.
                loop {
                    match self.mft.ProcessOutput(0, 1, None) {
                        Ok((out_sample, _)) => {
                            let mut buf_count = 0u32;
                            out_sample.GetBufferCount(&mut buf_count).ok();
                            for i in 0..buf_count {
                                let buf = out_sample.GetBufferByIndex(i).ok();
                                if let Some(b) = buf {
                                    let mut ptr = std::ptr::null_mut();
                                    let mut max = 0u32;
                                    let mut cur = 0u32;
                                    b.Lock(&mut ptr, &mut max, &mut cur).ok();
                                    let nv12_data = std::slice::from_raw_parts(ptr as *const u8, cur as usize);

                                    // Get dimensions from output type.
                                    let out_type = self.mft.GetOutputCurrentType(0).ok();
                                    if let Some(ot) = out_type {
                                        let mut frame_size = 0u64;
                                        ot.GetUINT64(MF_MT_FRAME_SIZE, &mut frame_size).ok();
                                        let w = (frame_size & 0xFFFFFFFF) as usize;
                                        let h = (frame_size >> 32) as usize;
                                        if w >= 16 && h >= 16 && w <= 4096 && h <= 4096 {
                                            let frame = nv12_to_i420(nv12_data, w, h);
                                            b.Unlock().ok();
                                            return Ok(Some(frame));
                                        }
                                    }
                                    b.Unlock().ok();
                                }
                            }
                        }
                        Err(e) if e.code() == windows::Win32::Media::MediaFoundation::MF_E_TRANSFORM_NEED_MORE_INPUT => {
                            return Ok(None);
                        }
                        Err(e) => return Err(format!("dec ProcessOutput: {e}")),
                    }
                }
            }
        }
    }
}
