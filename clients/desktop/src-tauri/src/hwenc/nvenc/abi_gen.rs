//! NVENC ABI constants, generated — do not edit by hand.
//!
//! Produced by `vendor/ffnvcodec/regen-abi.sh` from the vendored
//! nv-codec-headers `nvEncodeAPI.h` (SDK 11.1). Every number here is asserted
//! against the hand-written `#[repr(C)]` structs in `abi.rs`, so a header
//! change that moves a field breaks the build instead of the driver.

#![allow(dead_code, non_upper_case_globals)]

use super::abi::Guid;

/// NVENC API version this build targets: (major << 4) | minor == 0xb1.
pub const NVENCAPI_MAJOR: u32 = 0x0000000b;
pub const NVENCAPI_MINOR: u32 = 0x00000001;
pub const NVENCAPI_VERSION: u32 = 0x0100000b;

// ── Struct versions (the `version` field every call validates) ───────────────
pub const NV_ENCODE_API_FUNCTION_LIST_VER: u32 = 0x7102000b;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER: u32 = 0x7101000b;
pub const NV_ENC_INITIALIZE_PARAMS_VER: u32 = 0xf105000b;
pub const NV_ENC_CONFIG_VER: u32 = 0xf107000b;
pub const NV_ENC_PRESET_CONFIG_VER: u32 = 0xf104000b;
pub const NV_ENC_CREATE_INPUT_BUFFER_VER: u32 = 0x7101000b;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_VER: u32 = 0x7101000b;
pub const NV_ENC_LOCK_INPUT_BUFFER_VER: u32 = 0x7101000b;
pub const NV_ENC_LOCK_BITSTREAM_VER: u32 = 0x7101000b;
pub const NV_ENC_PIC_PARAMS_VER: u32 = 0xf104000b;

// ── Enum values ─────────────────────────────────────────────────────────────
pub const NV_ENC_SUCCESS: u32 = 0x00000000;
pub const NV_ENC_ERR_NO_ENCODE_DEVICE: u32 = 0x00000001;
pub const NV_ENC_ERR_UNSUPPORTED_DEVICE: u32 = 0x00000002;
pub const NV_ENC_ERR_OUT_OF_MEMORY: u32 = 0x0000000a;
pub const NV_ENC_ERR_INVALID_VERSION: u32 = 0x0000000f;
pub const NV_ENC_ERR_NEED_MORE_INPUT: u32 = 0x00000011;
pub const NV_ENC_ERR_ENCODER_BUSY: u32 = 0x00000012;
pub const NV_ENC_ERR_UNIMPLEMENTED: u32 = 0x00000016;
pub const NV_ENC_ERR_INCOMPATIBLE_CLIENT_KEY: u32 = 0x00000015;
pub const NV_ENC_DEVICE_TYPE_CUDA: u32 = 0x00000001;
pub const NV_ENC_BUFFER_FORMAT_NV12: u32 = 0x00000001;
pub const NV_ENC_BUFFER_FORMAT_IYUV: u32 = 0x00000100;
pub const NV_ENC_MEMORY_HEAP_AUTOSELECT: u32 = 0x00000000;
pub const NV_ENC_PARAMS_RC_CBR: u32 = 0x00000002;
pub const NV_ENC_TUNING_INFO_LOW_LATENCY: u32 = 0x00000002;
pub const NV_ENC_PIC_FLAG_FORCEIDR: u32 = 0x00000002;
pub const NV_ENC_PIC_FLAG_OUTPUT_SPSPPS: u32 = 0x00000004;
pub const NV_ENC_PIC_FLAG_EOS: u32 = 0x00000008;
pub const NV_ENC_PIC_STRUCT_FRAME: u32 = 0x00000001;
pub const NV_ENC_PIC_TYPE_UNKNOWN: u32 = 0x000000ff;
pub const NV_ENC_MULTI_PASS_DISABLED: u32 = 0x00000000;

// ── GUIDs (as the four fields of the C `GUID`, in declaration order) ─────────
pub const GUID_H264_CODEC: Guid = Guid {
    d1: 0x6bc82762,
    d2: 0x4e63,
    d3: 0x4ca4,
    d4: [0xaa, 0x85, 0x1e, 0x50, 0xf3, 0x21, 0xf6, 0xbf],
};
pub const GUID_H264_PROFILE_MAIN: Guid = Guid {
    d1: 0x60b5c1d4,
    d2: 0x67fe,
    d3: 0x4790,
    d4: [0x94, 0xd5, 0xc4, 0x72, 0x6d, 0x7b, 0x6e, 0x6d],
};
pub const GUID_PRESET_P4: Guid = Guid {
    d1: 0x90a7b826,
    d2: 0xdf06,
    d3: 0x4862,
    d4: [0xb9, 0xd2, 0xcd, 0x6d, 0x73, 0xa0, 0x86, 0x81],
};

// ── Sizes of types carried whole but never inspected ────────────────────────
pub const GUID_SIZE: usize = 16;
pub const GUID_ALIGN: usize = 4;
pub const NV_ENC_QP_SIZE: usize = 12;
pub const NV_ENC_CODEC_CONFIG_SIZE: usize = 1792;
pub const NV_ENC_CODEC_PIC_PARAMS_SIZE: usize = 1536;
pub const NVENC_EXTERNAL_ME_HINT_COUNTS_PER_BLOCKTYPE_SIZE: usize = 16;

// ── NV_ENCODE_API_FUNCTION_LIST ─────────────────────────────────────────────
pub const NV_ENCODE_API_FUNCTION_LIST_SIZE: usize = 2552;
pub const NV_ENCODE_API_FUNCTION_LIST_ALIGN: usize = 8;
pub const NV_ENCODE_API_FUNCTION_LIST_version: usize = 0;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncGetEncodeCaps: usize = 64;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncInitializeEncoder: usize = 96;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncCreateInputBuffer: usize = 104;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyInputBuffer: usize = 112;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncCreateBitstreamBuffer: usize = 120;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyBitstreamBuffer: usize = 128;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncEncodePicture: usize = 136;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncLockBitstream: usize = 144;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockBitstream: usize = 152;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncLockInputBuffer: usize = 160;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncUnlockInputBuffer: usize = 168;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncDestroyEncoder: usize = 224;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncOpenEncodeSessionEx: usize = 240;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncGetLastErrorString: usize = 304;
pub const NV_ENCODE_API_FUNCTION_LIST_nvEncGetEncodePresetConfigEx: usize = 320;

// ── NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS ────────────────────────────────────
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_SIZE: usize = 1552;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_ALIGN: usize = 8;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_version: usize = 0;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_deviceType: usize = 4;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_device: usize = 8;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_reserved: usize = 16;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_apiVersion: usize = 24;
pub const NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_reserved1: usize = 28;

// ── NV_ENC_INITIALIZE_PARAMS ────────────────────────────────────────────────
pub const NV_ENC_INITIALIZE_PARAMS_SIZE: usize = 1808;
pub const NV_ENC_INITIALIZE_PARAMS_ALIGN: usize = 8;
pub const NV_ENC_INITIALIZE_PARAMS_version: usize = 0;
pub const NV_ENC_INITIALIZE_PARAMS_encodeGUID: usize = 4;
pub const NV_ENC_INITIALIZE_PARAMS_presetGUID: usize = 20;
pub const NV_ENC_INITIALIZE_PARAMS_encodeWidth: usize = 36;
pub const NV_ENC_INITIALIZE_PARAMS_encodeHeight: usize = 40;
pub const NV_ENC_INITIALIZE_PARAMS_darWidth: usize = 44;
pub const NV_ENC_INITIALIZE_PARAMS_darHeight: usize = 48;
pub const NV_ENC_INITIALIZE_PARAMS_frameRateNum: usize = 52;
pub const NV_ENC_INITIALIZE_PARAMS_frameRateDen: usize = 56;
pub const NV_ENC_INITIALIZE_PARAMS_enableEncodeAsync: usize = 60;
pub const NV_ENC_INITIALIZE_PARAMS_enablePTD: usize = 64;
pub const NV_ENC_INITIALIZE_PARAMS_privDataSize: usize = 72;
pub const NV_ENC_INITIALIZE_PARAMS_privData: usize = 80;
pub const NV_ENC_INITIALIZE_PARAMS_encodeConfig: usize = 88;
pub const NV_ENC_INITIALIZE_PARAMS_maxEncodeWidth: usize = 96;
pub const NV_ENC_INITIALIZE_PARAMS_maxEncodeHeight: usize = 100;
pub const NV_ENC_INITIALIZE_PARAMS_maxMEHintCountsPerBlock: usize = 104;
pub const NV_ENC_INITIALIZE_PARAMS_tuningInfo: usize = 136;
pub const NV_ENC_INITIALIZE_PARAMS_bufferFormat: usize = 140;
pub const NV_ENC_INITIALIZE_PARAMS_reserved: usize = 144;

// ── NV_ENC_CONFIG ───────────────────────────────────────────────────────────
pub const NV_ENC_CONFIG_SIZE: usize = 3584;
pub const NV_ENC_CONFIG_ALIGN: usize = 8;
pub const NV_ENC_CONFIG_version: usize = 0;
pub const NV_ENC_CONFIG_profileGUID: usize = 4;
pub const NV_ENC_CONFIG_gopLength: usize = 20;
pub const NV_ENC_CONFIG_frameIntervalP: usize = 24;
pub const NV_ENC_CONFIG_monoChromeEncoding: usize = 28;
pub const NV_ENC_CONFIG_frameFieldMode: usize = 32;
pub const NV_ENC_CONFIG_mvPrecision: usize = 36;
pub const NV_ENC_CONFIG_rcParams: usize = 40;
pub const NV_ENC_CONFIG_encodeCodecConfig: usize = 168;
pub const NV_ENC_CONFIG_reserved: usize = 1960;

// ── NV_ENC_RC_PARAMS ────────────────────────────────────────────────────────
pub const NV_ENC_RC_PARAMS_SIZE: usize = 128;
pub const NV_ENC_RC_PARAMS_ALIGN: usize = 4;
pub const NV_ENC_RC_PARAMS_version: usize = 0;
pub const NV_ENC_RC_PARAMS_rateControlMode: usize = 4;
pub const NV_ENC_RC_PARAMS_constQP: usize = 8;
pub const NV_ENC_RC_PARAMS_averageBitRate: usize = 20;
pub const NV_ENC_RC_PARAMS_maxBitRate: usize = 24;
pub const NV_ENC_RC_PARAMS_vbvBufferSize: usize = 28;
pub const NV_ENC_RC_PARAMS_vbvInitialDelay: usize = 32;
pub const NV_ENC_RC_PARAMS_minQP: usize = 40;

// ── NV_ENC_PRESET_CONFIG ────────────────────────────────────────────────────
pub const NV_ENC_PRESET_CONFIG_SIZE: usize = 5128;
pub const NV_ENC_PRESET_CONFIG_ALIGN: usize = 8;
pub const NV_ENC_PRESET_CONFIG_version: usize = 0;
pub const NV_ENC_PRESET_CONFIG_presetCfg: usize = 8;
pub const NV_ENC_PRESET_CONFIG_reserved1: usize = 3592;

// ── NV_ENC_CREATE_INPUT_BUFFER ──────────────────────────────────────────────
pub const NV_ENC_CREATE_INPUT_BUFFER_SIZE: usize = 776;
pub const NV_ENC_CREATE_INPUT_BUFFER_ALIGN: usize = 8;
pub const NV_ENC_CREATE_INPUT_BUFFER_version: usize = 0;
pub const NV_ENC_CREATE_INPUT_BUFFER_width: usize = 4;
pub const NV_ENC_CREATE_INPUT_BUFFER_height: usize = 8;
pub const NV_ENC_CREATE_INPUT_BUFFER_memoryHeap: usize = 12;
pub const NV_ENC_CREATE_INPUT_BUFFER_bufferFmt: usize = 16;
pub const NV_ENC_CREATE_INPUT_BUFFER_reserved: usize = 20;
pub const NV_ENC_CREATE_INPUT_BUFFER_inputBuffer: usize = 24;
pub const NV_ENC_CREATE_INPUT_BUFFER_pSysMemBuffer: usize = 32;
pub const NV_ENC_CREATE_INPUT_BUFFER_reserved1: usize = 40;

// ── NV_ENC_CREATE_BITSTREAM_BUFFER ──────────────────────────────────────────
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_SIZE: usize = 776;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_ALIGN: usize = 8;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_version: usize = 0;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_size: usize = 4;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_memoryHeap: usize = 8;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_reserved: usize = 12;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_bitstreamBuffer: usize = 16;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_bitstreamBufferPtr: usize = 24;
pub const NV_ENC_CREATE_BITSTREAM_BUFFER_reserved1: usize = 32;

// ── NV_ENC_LOCK_INPUT_BUFFER ────────────────────────────────────────────────
pub const NV_ENC_LOCK_INPUT_BUFFER_SIZE: usize = 1544;
pub const NV_ENC_LOCK_INPUT_BUFFER_ALIGN: usize = 8;
pub const NV_ENC_LOCK_INPUT_BUFFER_version: usize = 0;
pub const NV_ENC_LOCK_INPUT_BUFFER_inputBuffer: usize = 8;
pub const NV_ENC_LOCK_INPUT_BUFFER_bufferDataPtr: usize = 16;
pub const NV_ENC_LOCK_INPUT_BUFFER_pitch: usize = 24;
pub const NV_ENC_LOCK_INPUT_BUFFER_reserved1: usize = 28;

// ── NV_ENC_LOCK_BITSTREAM ───────────────────────────────────────────────────
pub const NV_ENC_LOCK_BITSTREAM_SIZE: usize = 1544;
pub const NV_ENC_LOCK_BITSTREAM_ALIGN: usize = 8;
pub const NV_ENC_LOCK_BITSTREAM_version: usize = 0;
pub const NV_ENC_LOCK_BITSTREAM_outputBitstream: usize = 8;
pub const NV_ENC_LOCK_BITSTREAM_sliceOffsets: usize = 16;
pub const NV_ENC_LOCK_BITSTREAM_frameIdx: usize = 24;
pub const NV_ENC_LOCK_BITSTREAM_hwEncodeStatus: usize = 28;
pub const NV_ENC_LOCK_BITSTREAM_numSlices: usize = 32;
pub const NV_ENC_LOCK_BITSTREAM_bitstreamSizeInBytes: usize = 36;
pub const NV_ENC_LOCK_BITSTREAM_outputTimeStamp: usize = 40;
pub const NV_ENC_LOCK_BITSTREAM_outputDuration: usize = 48;
pub const NV_ENC_LOCK_BITSTREAM_bitstreamBufferPtr: usize = 56;
pub const NV_ENC_LOCK_BITSTREAM_pictureType: usize = 64;

// ── NV_ENC_PIC_PARAMS ───────────────────────────────────────────────────────
pub const NV_ENC_PIC_PARAMS_SIZE: usize = 3344;
pub const NV_ENC_PIC_PARAMS_ALIGN: usize = 8;
pub const NV_ENC_PIC_PARAMS_version: usize = 0;
pub const NV_ENC_PIC_PARAMS_inputWidth: usize = 4;
pub const NV_ENC_PIC_PARAMS_inputHeight: usize = 8;
pub const NV_ENC_PIC_PARAMS_inputPitch: usize = 12;
pub const NV_ENC_PIC_PARAMS_encodePicFlags: usize = 16;
pub const NV_ENC_PIC_PARAMS_frameIdx: usize = 20;
pub const NV_ENC_PIC_PARAMS_inputTimeStamp: usize = 24;
pub const NV_ENC_PIC_PARAMS_inputDuration: usize = 32;
pub const NV_ENC_PIC_PARAMS_inputBuffer: usize = 40;
pub const NV_ENC_PIC_PARAMS_outputBitstream: usize = 48;
pub const NV_ENC_PIC_PARAMS_completionEvent: usize = 56;
pub const NV_ENC_PIC_PARAMS_bufferFmt: usize = 64;
pub const NV_ENC_PIC_PARAMS_pictureStruct: usize = 68;
pub const NV_ENC_PIC_PARAMS_pictureType: usize = 72;
pub const NV_ENC_PIC_PARAMS_codecPicParams: usize = 80;
pub const NV_ENC_PIC_PARAMS_meHintCountsPerBlock: usize = 1616;

// ── Fields inside the codec union, addressed as bytes ───────────────────────
pub const H264_IDR_PERIOD_OFF: usize = 8;
pub const H264_REPEAT_SPSPPS_WORD: usize = 0;
pub const H264_REPEAT_SPSPPS_MASK: u32 = 0x00001000;
