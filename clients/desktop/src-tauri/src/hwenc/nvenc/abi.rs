//! NVENC structs, transcribed by hand and checked against the header by the compiler.
//!
//! Every struct below is a `#[repr(C)]` mirror of one in the vendored
//! `vendor/ffnvcodec/nvEncodeAPI.h`, and every one is followed by
//! [`const _: () = assert!(...)`] lines pinning its size, its alignment and the offset of
//! each field, against the numbers `abi_probe.c` printed from that same header.
//!
//! That ceremony is the entire safety argument for this backend. A field one word out of
//! place is not a compile error and not a clean runtime failure — the driver writes
//! through a pointer it read from the wrong eight bytes, and no probe can catch that,
//! because a probe only ever catches "the driver said no". Pinning the numbers turns the
//! one class of bug that would corrupt memory into the one class of bug that fails
//! `cargo build`.
//!
//! Two things follow from that, and they are why this file is short:
//!
//! * **Nothing that is not touched is transcribed.** The codec unions
//!   (`NV_ENC_CODEC_CONFIG`, `NV_ENC_CODEC_PIC_PARAMS`) and every reserved tail are
//!   `[u8; N]`. Only their size has to be right, and an opaque array cannot have a field
//!   in the wrong place.
//! * **`NV_ENCODE_API_FUNCTION_LIST` is bytes too.** Transcribing ~40 function pointers
//!   in exact declaration order, when fourteen are ever called, is pure transcription
//!   risk; they are read out at asserted offsets instead ([`super::api`]).
//!
//! Explicit `_pad` fields appear where C's own alignment inserted padding. They are not
//! decoration: without them Rust would pack an `align(1)` opaque array into the hole and
//! every later offset would shift, which is exactly what the assertions catch.

use std::mem::{align_of, offset_of, size_of};
use std::os::raw::{c_char, c_void};

use super::abi_gen as g;

/// The 16-byte `GUID` NVENC identifies codecs, profiles and presets by. Passed **by
/// value** to `nvEncGetEncodePresetConfigEx`, so its layout has to match exactly rather
/// than merely being pointer-compatible.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Guid {
    pub d1: u32,
    pub d2: u16,
    pub d3: u16,
    pub d4: [u8; 8],
}
const _: () = assert!(size_of::<Guid>() == g::GUID_SIZE);
const _: () = assert!(align_of::<Guid>() == g::GUID_ALIGN);

/// `NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS`.
#[repr(C, align(8))]
pub struct OpenSessionExParams {
    pub version: u32,
    pub device_type: u32,
    pub device: *mut c_void,
    pub reserved: *mut c_void,
    pub api_version: u32,
    tail: [u8; g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_SIZE
        - g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_reserved1],
}
const _: () = {
    type T = OpenSessionExParams;
    assert!(size_of::<T>() == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_version);
    assert!(offset_of!(T, device_type) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_deviceType);
    assert!(offset_of!(T, device) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_device);
    assert!(offset_of!(T, reserved) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_reserved);
    assert!(offset_of!(T, api_version) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_apiVersion);
    assert!(offset_of!(T, tail) == g::NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_reserved1);
};

/// `NV_ENC_RC_PARAMS`. Only the rate-control mode and the four bitrate/VBV numbers are
/// ever written; everything from the bitfield word on is whatever the preset put there.
#[repr(C)]
pub struct RcParams {
    pub version: u32,
    pub rate_control_mode: u32,
    pub const_qp: [u32; 3],
    pub average_bit_rate: u32,
    pub max_bit_rate: u32,
    pub vbv_buffer_size: u32,
    pub vbv_initial_delay: u32,
    /// `enableMinQP`…`reservedBitFields` — one word of bitfields, left untouched.
    pub flags: u32,
    tail: [u8; g::NV_ENC_RC_PARAMS_SIZE - g::NV_ENC_RC_PARAMS_minQP],
}
const _: () = {
    type T = RcParams;
    assert!(size_of::<T>() == g::NV_ENC_RC_PARAMS_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_RC_PARAMS_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_RC_PARAMS_version);
    assert!(offset_of!(T, rate_control_mode) == g::NV_ENC_RC_PARAMS_rateControlMode);
    assert!(offset_of!(T, const_qp) == g::NV_ENC_RC_PARAMS_constQP);
    assert!(size_of::<[u32; 3]>() == g::NV_ENC_QP_SIZE);
    assert!(offset_of!(T, average_bit_rate) == g::NV_ENC_RC_PARAMS_averageBitRate);
    assert!(offset_of!(T, max_bit_rate) == g::NV_ENC_RC_PARAMS_maxBitRate);
    assert!(offset_of!(T, vbv_buffer_size) == g::NV_ENC_RC_PARAMS_vbvBufferSize);
    assert!(offset_of!(T, vbv_initial_delay) == g::NV_ENC_RC_PARAMS_vbvInitialDelay);
    assert!(offset_of!(T, tail) == g::NV_ENC_RC_PARAMS_minQP);
};

/// `NV_ENC_CONFIG`. Never built from nothing — always a copy of what
/// `nvEncGetEncodePresetConfigEx` filled in, with a few fields overwritten.
#[repr(C, align(8))]
pub struct Config {
    pub version: u32,
    pub profile_guid: Guid,
    pub gop_length: u32,
    pub frame_interval_p: i32,
    pub mono_chrome_encoding: u32,
    pub frame_field_mode: u32,
    pub mv_precision: u32,
    pub rc_params: RcParams,
    /// `NV_ENC_CODEC_CONFIG`. Opaque: the two H.264 fields that need setting are poked at
    /// probe-verified byte offsets ([`h264_idr_period`], [`h264_repeat_sps_pps`]).
    pub codec_config: [u8; g::NV_ENC_CODEC_CONFIG_SIZE],
    tail: [u8; g::NV_ENC_CONFIG_SIZE - g::NV_ENC_CONFIG_reserved],
}
const _: () = {
    type T = Config;
    assert!(size_of::<T>() == g::NV_ENC_CONFIG_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_CONFIG_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_CONFIG_version);
    assert!(offset_of!(T, profile_guid) == g::NV_ENC_CONFIG_profileGUID);
    assert!(offset_of!(T, gop_length) == g::NV_ENC_CONFIG_gopLength);
    assert!(offset_of!(T, frame_interval_p) == g::NV_ENC_CONFIG_frameIntervalP);
    assert!(offset_of!(T, mono_chrome_encoding) == g::NV_ENC_CONFIG_monoChromeEncoding);
    assert!(offset_of!(T, frame_field_mode) == g::NV_ENC_CONFIG_frameFieldMode);
    assert!(offset_of!(T, mv_precision) == g::NV_ENC_CONFIG_mvPrecision);
    assert!(offset_of!(T, rc_params) == g::NV_ENC_CONFIG_rcParams);
    assert!(offset_of!(T, codec_config) == g::NV_ENC_CONFIG_encodeCodecConfig);
    assert!(offset_of!(T, tail) == g::NV_ENC_CONFIG_reserved);
};

/// `NV_ENC_PRESET_CONFIG`.
#[repr(C, align(8))]
pub struct PresetConfig {
    pub version: u32,
    _pad: u32,
    pub preset_cfg: Config,
    tail: [u8; g::NV_ENC_PRESET_CONFIG_SIZE - g::NV_ENC_PRESET_CONFIG_reserved1],
}
const _: () = {
    type T = PresetConfig;
    assert!(size_of::<T>() == g::NV_ENC_PRESET_CONFIG_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_PRESET_CONFIG_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_PRESET_CONFIG_version);
    assert!(offset_of!(T, preset_cfg) == g::NV_ENC_PRESET_CONFIG_presetCfg);
    assert!(offset_of!(T, tail) == g::NV_ENC_PRESET_CONFIG_reserved1);
};

/// `NV_ENC_INITIALIZE_PARAMS`.
#[repr(C, align(8))]
pub struct InitializeParams {
    pub version: u32,
    pub encode_guid: Guid,
    pub preset_guid: Guid,
    pub encode_width: u32,
    pub encode_height: u32,
    pub dar_width: u32,
    pub dar_height: u32,
    pub frame_rate_num: u32,
    pub frame_rate_den: u32,
    pub enable_encode_async: u32,
    pub enable_ptd: u32,
    /// `reportSliceOffsets`…`reservedBitFields` — all zero for this backend.
    pub flags: u32,
    pub priv_data_size: u32,
    _pad: u32,
    pub priv_data: *mut c_void,
    pub encode_config: *mut Config,
    pub max_encode_width: u32,
    pub max_encode_height: u32,
    /// `maxMEHintCountsPerBlock[2]` — external motion hints, unused, so opaque.
    pub max_me_hint_counts: [u8; 2 * g::NVENC_EXTERNAL_ME_HINT_COUNTS_PER_BLOCKTYPE_SIZE],
    pub tuning_info: u32,
    pub buffer_format: u32,
    tail: [u8; g::NV_ENC_INITIALIZE_PARAMS_SIZE - g::NV_ENC_INITIALIZE_PARAMS_reserved],
}
const _: () = {
    type T = InitializeParams;
    assert!(size_of::<T>() == g::NV_ENC_INITIALIZE_PARAMS_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_INITIALIZE_PARAMS_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_INITIALIZE_PARAMS_version);
    assert!(offset_of!(T, encode_guid) == g::NV_ENC_INITIALIZE_PARAMS_encodeGUID);
    assert!(offset_of!(T, preset_guid) == g::NV_ENC_INITIALIZE_PARAMS_presetGUID);
    assert!(offset_of!(T, encode_width) == g::NV_ENC_INITIALIZE_PARAMS_encodeWidth);
    assert!(offset_of!(T, encode_height) == g::NV_ENC_INITIALIZE_PARAMS_encodeHeight);
    assert!(offset_of!(T, dar_width) == g::NV_ENC_INITIALIZE_PARAMS_darWidth);
    assert!(offset_of!(T, dar_height) == g::NV_ENC_INITIALIZE_PARAMS_darHeight);
    assert!(offset_of!(T, frame_rate_num) == g::NV_ENC_INITIALIZE_PARAMS_frameRateNum);
    assert!(offset_of!(T, frame_rate_den) == g::NV_ENC_INITIALIZE_PARAMS_frameRateDen);
    assert!(offset_of!(T, enable_encode_async) == g::NV_ENC_INITIALIZE_PARAMS_enableEncodeAsync);
    assert!(offset_of!(T, enable_ptd) == g::NV_ENC_INITIALIZE_PARAMS_enablePTD);
    assert!(offset_of!(T, priv_data_size) == g::NV_ENC_INITIALIZE_PARAMS_privDataSize);
    assert!(offset_of!(T, priv_data) == g::NV_ENC_INITIALIZE_PARAMS_privData);
    assert!(offset_of!(T, encode_config) == g::NV_ENC_INITIALIZE_PARAMS_encodeConfig);
    assert!(offset_of!(T, max_encode_width) == g::NV_ENC_INITIALIZE_PARAMS_maxEncodeWidth);
    assert!(offset_of!(T, max_encode_height) == g::NV_ENC_INITIALIZE_PARAMS_maxEncodeHeight);
    let hints = g::NV_ENC_INITIALIZE_PARAMS_maxMEHintCountsPerBlock;
    assert!(offset_of!(T, max_me_hint_counts) == hints);
    assert!(offset_of!(T, tuning_info) == g::NV_ENC_INITIALIZE_PARAMS_tuningInfo);
    assert!(offset_of!(T, buffer_format) == g::NV_ENC_INITIALIZE_PARAMS_bufferFormat);
    assert!(offset_of!(T, tail) == g::NV_ENC_INITIALIZE_PARAMS_reserved);
};

/// `NV_ENC_CREATE_INPUT_BUFFER`.
#[repr(C, align(8))]
pub struct CreateInputBuffer {
    pub version: u32,
    pub width: u32,
    pub height: u32,
    pub memory_heap: u32,
    pub buffer_fmt: u32,
    pub reserved: u32,
    pub input_buffer: *mut c_void,
    pub sys_mem_buffer: *mut c_void,
    tail: [u8; g::NV_ENC_CREATE_INPUT_BUFFER_SIZE - g::NV_ENC_CREATE_INPUT_BUFFER_reserved1],
}
const _: () = {
    type T = CreateInputBuffer;
    assert!(size_of::<T>() == g::NV_ENC_CREATE_INPUT_BUFFER_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_CREATE_INPUT_BUFFER_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_CREATE_INPUT_BUFFER_version);
    assert!(offset_of!(T, width) == g::NV_ENC_CREATE_INPUT_BUFFER_width);
    assert!(offset_of!(T, height) == g::NV_ENC_CREATE_INPUT_BUFFER_height);
    assert!(offset_of!(T, memory_heap) == g::NV_ENC_CREATE_INPUT_BUFFER_memoryHeap);
    assert!(offset_of!(T, buffer_fmt) == g::NV_ENC_CREATE_INPUT_BUFFER_bufferFmt);
    assert!(offset_of!(T, reserved) == g::NV_ENC_CREATE_INPUT_BUFFER_reserved);
    assert!(offset_of!(T, input_buffer) == g::NV_ENC_CREATE_INPUT_BUFFER_inputBuffer);
    assert!(offset_of!(T, sys_mem_buffer) == g::NV_ENC_CREATE_INPUT_BUFFER_pSysMemBuffer);
    assert!(offset_of!(T, tail) == g::NV_ENC_CREATE_INPUT_BUFFER_reserved1);
};

/// `NV_ENC_CREATE_BITSTREAM_BUFFER`.
#[repr(C, align(8))]
pub struct CreateBitstreamBuffer {
    pub version: u32,
    pub size: u32,
    pub memory_heap: u32,
    pub reserved: u32,
    pub bitstream_buffer: *mut c_void,
    pub bitstream_buffer_ptr: *mut c_void,
    tail:
        [u8; g::NV_ENC_CREATE_BITSTREAM_BUFFER_SIZE - g::NV_ENC_CREATE_BITSTREAM_BUFFER_reserved1],
}
const _: () = {
    type T = CreateBitstreamBuffer;
    assert!(size_of::<T>() == g::NV_ENC_CREATE_BITSTREAM_BUFFER_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_CREATE_BITSTREAM_BUFFER_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_version);
    assert!(offset_of!(T, size) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_size);
    assert!(offset_of!(T, memory_heap) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_memoryHeap);
    assert!(offset_of!(T, reserved) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_reserved);
    assert!(offset_of!(T, bitstream_buffer) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_bitstreamBuffer);
    let bsp = g::NV_ENC_CREATE_BITSTREAM_BUFFER_bitstreamBufferPtr;
    assert!(offset_of!(T, bitstream_buffer_ptr) == bsp);
    assert!(offset_of!(T, tail) == g::NV_ENC_CREATE_BITSTREAM_BUFFER_reserved1);
};

/// `NV_ENC_LOCK_INPUT_BUFFER`.
#[repr(C, align(8))]
pub struct LockInputBuffer {
    pub version: u32,
    /// `doNotWait` (bit 0) and reserved bits.
    pub flags: u32,
    pub input_buffer: *mut c_void,
    pub buffer_data_ptr: *mut c_void,
    pub pitch: u32,
    tail: [u8; g::NV_ENC_LOCK_INPUT_BUFFER_SIZE - g::NV_ENC_LOCK_INPUT_BUFFER_reserved1],
}
const _: () = {
    type T = LockInputBuffer;
    assert!(size_of::<T>() == g::NV_ENC_LOCK_INPUT_BUFFER_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_LOCK_INPUT_BUFFER_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_LOCK_INPUT_BUFFER_version);
    assert!(offset_of!(T, input_buffer) == g::NV_ENC_LOCK_INPUT_BUFFER_inputBuffer);
    assert!(offset_of!(T, buffer_data_ptr) == g::NV_ENC_LOCK_INPUT_BUFFER_bufferDataPtr);
    assert!(offset_of!(T, pitch) == g::NV_ENC_LOCK_INPUT_BUFFER_pitch);
    assert!(offset_of!(T, tail) == g::NV_ENC_LOCK_INPUT_BUFFER_reserved1);
};

/// `NV_ENC_LOCK_BITSTREAM`, truncated after the last field that is read.
#[repr(C, align(8))]
pub struct LockBitstream {
    pub version: u32,
    /// `doNotWait` (bit 0), `ltrFrame`, `getRCStats` and reserved bits.
    pub flags: u32,
    pub output_bitstream: *mut c_void,
    pub slice_offsets: *mut u32,
    pub frame_idx: u32,
    pub hw_encode_status: u32,
    pub num_slices: u32,
    pub bitstream_size_in_bytes: u32,
    pub output_time_stamp: u64,
    pub output_duration: u64,
    pub bitstream_buffer_ptr: *mut c_void,
    tail: [u8; g::NV_ENC_LOCK_BITSTREAM_SIZE - g::NV_ENC_LOCK_BITSTREAM_pictureType],
}
const _: () = {
    type T = LockBitstream;
    assert!(size_of::<T>() == g::NV_ENC_LOCK_BITSTREAM_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_LOCK_BITSTREAM_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_LOCK_BITSTREAM_version);
    assert!(offset_of!(T, output_bitstream) == g::NV_ENC_LOCK_BITSTREAM_outputBitstream);
    assert!(offset_of!(T, slice_offsets) == g::NV_ENC_LOCK_BITSTREAM_sliceOffsets);
    assert!(offset_of!(T, frame_idx) == g::NV_ENC_LOCK_BITSTREAM_frameIdx);
    assert!(offset_of!(T, hw_encode_status) == g::NV_ENC_LOCK_BITSTREAM_hwEncodeStatus);
    assert!(offset_of!(T, num_slices) == g::NV_ENC_LOCK_BITSTREAM_numSlices);
    let size_field = g::NV_ENC_LOCK_BITSTREAM_bitstreamSizeInBytes;
    assert!(offset_of!(T, bitstream_size_in_bytes) == size_field);
    assert!(offset_of!(T, output_time_stamp) == g::NV_ENC_LOCK_BITSTREAM_outputTimeStamp);
    assert!(offset_of!(T, output_duration) == g::NV_ENC_LOCK_BITSTREAM_outputDuration);
    let bsp = g::NV_ENC_LOCK_BITSTREAM_bitstreamBufferPtr;
    assert!(offset_of!(T, bitstream_buffer_ptr) == bsp);
    assert!(offset_of!(T, tail) == g::NV_ENC_LOCK_BITSTREAM_pictureType);
};

/// `NV_ENC_PIC_PARAMS`.
#[repr(C, align(8))]
pub struct PicParams {
    pub version: u32,
    pub input_width: u32,
    pub input_height: u32,
    pub input_pitch: u32,
    pub encode_pic_flags: u32,
    pub frame_idx: u32,
    pub input_time_stamp: u64,
    pub input_duration: u64,
    pub input_buffer: *mut c_void,
    pub output_bitstream: *mut c_void,
    pub completion_event: *mut c_void,
    pub buffer_fmt: u32,
    pub picture_struct: u32,
    pub picture_type: u32,
    _pad: u32,
    /// `NV_ENC_CODEC_PIC_PARAMS`, zeroed — nothing in it is needed per frame.
    pub codec_pic_params: [u8; g::NV_ENC_CODEC_PIC_PARAMS_SIZE],
    tail: [u8; g::NV_ENC_PIC_PARAMS_SIZE - g::NV_ENC_PIC_PARAMS_meHintCountsPerBlock],
}
const _: () = {
    type T = PicParams;
    assert!(size_of::<T>() == g::NV_ENC_PIC_PARAMS_SIZE);
    assert!(align_of::<T>() == g::NV_ENC_PIC_PARAMS_ALIGN);
    assert!(offset_of!(T, version) == g::NV_ENC_PIC_PARAMS_version);
    assert!(offset_of!(T, input_width) == g::NV_ENC_PIC_PARAMS_inputWidth);
    assert!(offset_of!(T, input_height) == g::NV_ENC_PIC_PARAMS_inputHeight);
    assert!(offset_of!(T, input_pitch) == g::NV_ENC_PIC_PARAMS_inputPitch);
    assert!(offset_of!(T, encode_pic_flags) == g::NV_ENC_PIC_PARAMS_encodePicFlags);
    assert!(offset_of!(T, frame_idx) == g::NV_ENC_PIC_PARAMS_frameIdx);
    assert!(offset_of!(T, input_time_stamp) == g::NV_ENC_PIC_PARAMS_inputTimeStamp);
    assert!(offset_of!(T, input_duration) == g::NV_ENC_PIC_PARAMS_inputDuration);
    assert!(offset_of!(T, input_buffer) == g::NV_ENC_PIC_PARAMS_inputBuffer);
    assert!(offset_of!(T, output_bitstream) == g::NV_ENC_PIC_PARAMS_outputBitstream);
    assert!(offset_of!(T, completion_event) == g::NV_ENC_PIC_PARAMS_completionEvent);
    assert!(offset_of!(T, buffer_fmt) == g::NV_ENC_PIC_PARAMS_bufferFmt);
    assert!(offset_of!(T, picture_struct) == g::NV_ENC_PIC_PARAMS_pictureStruct);
    assert!(offset_of!(T, picture_type) == g::NV_ENC_PIC_PARAMS_pictureType);
    assert!(offset_of!(T, codec_pic_params) == g::NV_ENC_PIC_PARAMS_codecPicParams);
    assert!(offset_of!(T, tail) == g::NV_ENC_PIC_PARAMS_meHintCountsPerBlock);
};

/// `NV_ENCODE_API_FUNCTION_LIST`, as bytes. `align(8)` so the pointers read out of it at
/// [`super::api`]'s offsets are aligned reads.
#[repr(C, align(8))]
pub struct FunctionList(pub [u8; g::NV_ENCODE_API_FUNCTION_LIST_SIZE]);
const _: () = {
    assert!(size_of::<FunctionList>() == g::NV_ENCODE_API_FUNCTION_LIST_SIZE);
    assert!(align_of::<FunctionList>() == g::NV_ENCODE_API_FUNCTION_LIST_ALIGN);
    // Nothing checks a byte offset for us the way `offset_of!` checks a field, so the
    // property that makes reading pointers out of these bytes sound is asserted directly:
    // every one is 8-aligned and a whole pointer short of the end.
    let mut i = 0;
    while i < FN_OFFSETS.len() {
        assert!(FN_OFFSETS[i].is_multiple_of(8));
        assert!(FN_OFFSETS[i] + size_of::<usize>() <= g::NV_ENCODE_API_FUNCTION_LIST_SIZE);
        i += 1;
    }
};

/// Every offset [`super::api`] reads a function pointer from.
pub const FN_OFFSETS: [usize; 14] = [
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncInitializeEncoder,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncCreateInputBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyInputBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncCreateBitstreamBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyBitstreamBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncEncodePicture,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncLockBitstream,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockBitstream,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncLockInputBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockInputBuffer,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyEncoder,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncOpenEncodeSessionEx,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncGetLastErrorString,
    g::NV_ENCODE_API_FUNCTION_LIST_nvEncGetEncodePresetConfigEx,
];

/// Everything the codec union needs written into it, addressed as bytes because the union
/// itself is never transcribed. Offsets come from the same probe as everything else.
pub fn h264_idr_period(codec_config: &mut [u8; g::NV_ENC_CODEC_CONFIG_SIZE], frames: u32) {
    let at = g::H264_IDR_PERIOD_OFF;
    codec_config[at..at + 4].copy_from_slice(&frames.to_ne_bytes());
}

/// Ask the encoder to put SPS/PPS in front of every IDR itself. Belt and braces with
/// [`crate::hwenc::annexb::ParameterSets`], which re-attaches them if it does not.
pub fn h264_repeat_sps_pps(codec_config: &mut [u8; g::NV_ENC_CODEC_CONFIG_SIZE]) {
    let at = g::H264_REPEAT_SPSPPS_WORD;
    let mut word = u32::from_ne_bytes(codec_config[at..at + 4].try_into().expect("4 bytes"));
    word |= g::H264_REPEAT_SPSPPS_MASK;
    codec_config[at..at + 4].copy_from_slice(&word.to_ne_bytes());
}

/// A zeroed struct. Sound for every type in this file: they are plain data and raw
/// pointers, for which an all-zero bit pattern is a valid (null) value, and NVENC's own
/// contract is that a caller memsets the struct and then sets `version`.
///
/// # Safety
/// Only call for the `#[repr(C)]` types declared above.
pub unsafe fn zeroed<T>() -> T {
    std::mem::zeroed()
}

// Function-pointer types. NVENC is `cdecl` on Linux, which is what `extern "C"` gives.
pub type PtrOpenSessionEx = unsafe extern "C" fn(*mut OpenSessionExParams, *mut *mut c_void) -> u32;
pub type PtrGetPresetConfigEx =
    unsafe extern "C" fn(*mut c_void, Guid, Guid, u32, *mut PresetConfig) -> u32;
pub type PtrInitializeEncoder = unsafe extern "C" fn(*mut c_void, *mut InitializeParams) -> u32;
pub type PtrCreateInputBuffer = unsafe extern "C" fn(*mut c_void, *mut CreateInputBuffer) -> u32;
pub type PtrCreateBitstreamBuffer =
    unsafe extern "C" fn(*mut c_void, *mut CreateBitstreamBuffer) -> u32;
pub type PtrLockInputBuffer = unsafe extern "C" fn(*mut c_void, *mut LockInputBuffer) -> u32;
pub type PtrLockBitstream = unsafe extern "C" fn(*mut c_void, *mut LockBitstream) -> u32;
pub type PtrEncodePicture = unsafe extern "C" fn(*mut c_void, *mut PicParams) -> u32;
/// `nvEncDestroyInputBuffer`, `nvEncDestroyBitstreamBuffer`, `nvEncUnlockInputBuffer`,
/// `nvEncUnlockBitstream` — all `(encoder, resource) -> NVENCSTATUS`.
pub type PtrWithResource = unsafe extern "C" fn(*mut c_void, *mut c_void) -> u32;
pub type PtrDestroyEncoder = unsafe extern "C" fn(*mut c_void) -> u32;
pub type PtrGetLastError = unsafe extern "C" fn(*mut c_void) -> *const c_char;
