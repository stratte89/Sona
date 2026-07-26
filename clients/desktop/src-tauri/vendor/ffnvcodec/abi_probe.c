/*
 * Emits the NVENC ABI as Rust constants, straight from the vendored header.
 *
 * The Rust side (`src/hwenc/nvenc/abi.rs`) hand-writes `#[repr(C)]` structs for the
 * handful of NVENC types it touches and then asserts, at compile time, that every one of
 * its sizes and field offsets equals the number printed here. That is the only way to
 * make a transcription slip a *build* failure: passing a struct with a field one word out
 * of place to a driver is not a compile error, and no runtime probe can catch it either —
 * a probe catches "the driver said no", not "the driver wrote through a pointer it read
 * from the wrong eight bytes".
 *
 * Anything not read or written is deliberately NOT transcribed. The big codec unions and
 * the reserved tails only need their *size* to be right, so they are `[u8; N]` on the
 * Rust side and only `SIZE` is emitted for them.
 *
 * Bitfields have no `offsetof`, so the two flags this code sets are located empirically:
 * zero the struct, set the one field, and report which 32-bit word changed and to what.
 * The compiler that owns the bitfield layout is the one answering the question.
 */

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#include "nvEncodeAPI.h"

#define SIZE(ty) printf("pub const %s_SIZE: usize = %zu;\n", #ty, sizeof(ty))
#define ALIGN(ty) printf("pub const %s_ALIGN: usize = %zu;\n", #ty, _Alignof(ty))
#define OFF(ty, f) \
    printf("pub const %s_%s: usize = %zu;\n", #ty, #f, offsetof(ty, f))
#define U32(name, v) printf("pub const %s: u32 = 0x%08x;\n", #name, (uint32_t)(v))

/* Which 32-bit word of `buf` is non-zero, and its value. Used for bitfields. */
static void bitfield(const char *prefix, const void *buf, size_t len)
{
    size_t i;
    for (i = 0; i + 4 <= len; i += 4) {
        uint32_t w;
        memcpy(&w, (const char *)buf + i, 4);
        if (w) {
            printf("pub const %s_WORD: usize = %zu;\n", prefix, i);
            printf("pub const %s_MASK: u32 = 0x%08x;\n", prefix, w);
            return;
        }
    }
    fprintf(stderr, "abi_probe: %s did not set any word\n", prefix);
}

int main(void)
{
    puts("//! NVENC ABI constants, generated — do not edit by hand.");
    puts("//!");
    puts("//! Produced by `vendor/ffnvcodec/regen-abi.sh` from the vendored");
    puts("//! nv-codec-headers `nvEncodeAPI.h` (SDK 11.1). Every number here is asserted");
    puts("//! against the hand-written `#[repr(C)]` structs in `abi.rs`, so a header");
    puts("//! change that moves a field breaks the build instead of the driver.");
    puts("");
    /* Constants keep their C spelling so a reader can grep the header for them; that
     * means `NV_ENC_CONFIG_gopLength` and friends are not SCREAMING_SNAKE_CASE. */
    puts("#![allow(dead_code, non_upper_case_globals)]");
    puts("");
    puts("use super::abi::Guid;");
    puts("");

    printf("/// NVENC API version this build targets: (major << 4) | minor == 0x%02x.\n",
           (NVENCAPI_MAJOR_VERSION << 4) | NVENCAPI_MINOR_VERSION);
    U32(NVENCAPI_MAJOR, NVENCAPI_MAJOR_VERSION);
    U32(NVENCAPI_MINOR, NVENCAPI_MINOR_VERSION);
    U32(NVENCAPI_VERSION, NVENCAPI_VERSION);
    puts("");

    puts("// ── Struct versions (the `version` field every call validates) ───────────────");
    U32(NV_ENCODE_API_FUNCTION_LIST_VER, NV_ENCODE_API_FUNCTION_LIST_VER);
    U32(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER, NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS_VER);
    U32(NV_ENC_INITIALIZE_PARAMS_VER, NV_ENC_INITIALIZE_PARAMS_VER);
    U32(NV_ENC_CONFIG_VER, NV_ENC_CONFIG_VER);
    U32(NV_ENC_PRESET_CONFIG_VER, NV_ENC_PRESET_CONFIG_VER);
    U32(NV_ENC_CREATE_INPUT_BUFFER_VER, NV_ENC_CREATE_INPUT_BUFFER_VER);
    U32(NV_ENC_CREATE_BITSTREAM_BUFFER_VER, NV_ENC_CREATE_BITSTREAM_BUFFER_VER);
    U32(NV_ENC_LOCK_INPUT_BUFFER_VER, NV_ENC_LOCK_INPUT_BUFFER_VER);
    U32(NV_ENC_LOCK_BITSTREAM_VER, NV_ENC_LOCK_BITSTREAM_VER);
    U32(NV_ENC_PIC_PARAMS_VER, NV_ENC_PIC_PARAMS_VER);
    puts("");

    puts("// ── Enum values ─────────────────────────────────────────────────────────────");
    U32(NV_ENC_SUCCESS, NV_ENC_SUCCESS);
    U32(NV_ENC_ERR_NO_ENCODE_DEVICE, NV_ENC_ERR_NO_ENCODE_DEVICE);
    U32(NV_ENC_ERR_UNSUPPORTED_DEVICE, NV_ENC_ERR_UNSUPPORTED_DEVICE);
    U32(NV_ENC_ERR_OUT_OF_MEMORY, NV_ENC_ERR_OUT_OF_MEMORY);
    U32(NV_ENC_ERR_INVALID_VERSION, NV_ENC_ERR_INVALID_VERSION);
    U32(NV_ENC_ERR_NEED_MORE_INPUT, NV_ENC_ERR_NEED_MORE_INPUT);
    U32(NV_ENC_ERR_ENCODER_BUSY, NV_ENC_ERR_ENCODER_BUSY);
    U32(NV_ENC_ERR_UNIMPLEMENTED, NV_ENC_ERR_UNIMPLEMENTED);
    U32(NV_ENC_ERR_INCOMPATIBLE_CLIENT_KEY, NV_ENC_ERR_INCOMPATIBLE_CLIENT_KEY);
    U32(NV_ENC_DEVICE_TYPE_CUDA, NV_ENC_DEVICE_TYPE_CUDA);
    U32(NV_ENC_BUFFER_FORMAT_NV12, NV_ENC_BUFFER_FORMAT_NV12);
    U32(NV_ENC_BUFFER_FORMAT_IYUV, NV_ENC_BUFFER_FORMAT_IYUV);
    U32(NV_ENC_MEMORY_HEAP_AUTOSELECT, NV_ENC_MEMORY_HEAP_AUTOSELECT);
    U32(NV_ENC_PARAMS_RC_CBR, NV_ENC_PARAMS_RC_CBR);
    U32(NV_ENC_TUNING_INFO_LOW_LATENCY, NV_ENC_TUNING_INFO_LOW_LATENCY);
    U32(NV_ENC_PIC_FLAG_FORCEIDR, NV_ENC_PIC_FLAG_FORCEIDR);
    U32(NV_ENC_PIC_FLAG_OUTPUT_SPSPPS, NV_ENC_PIC_FLAG_OUTPUT_SPSPPS);
    U32(NV_ENC_PIC_FLAG_EOS, NV_ENC_PIC_FLAG_EOS);
    U32(NV_ENC_PIC_STRUCT_FRAME, NV_ENC_PIC_STRUCT_FRAME);
    U32(NV_ENC_PIC_TYPE_UNKNOWN, NV_ENC_PIC_TYPE_UNKNOWN);
    U32(NV_ENC_MULTI_PASS_DISABLED, NV_ENC_MULTI_PASS_DISABLED);
    puts("");

    puts("// ── GUIDs (as the four fields of the C `GUID`, in declaration order) ─────────");
    {
        static const struct { const char *name; GUID g; } guids[] = {
            { "H264_CODEC", NV_ENC_CODEC_H264_GUID },
            { "H264_PROFILE_MAIN", NV_ENC_H264_PROFILE_MAIN_GUID },
            { "PRESET_P4", NV_ENC_PRESET_P4_GUID },
        };
        size_t i, j;
        for (i = 0; i < sizeof(guids) / sizeof(guids[0]); i++) {
            printf("pub const GUID_%s: Guid = Guid { d1: 0x%08x, d2: 0x%04x, d3: 0x%04x, d4: [",
                   guids[i].name, guids[i].g.Data1, guids[i].g.Data2, guids[i].g.Data3);
            for (j = 0; j < 8; j++)
                printf("0x%02x%s", guids[i].g.Data4[j], j == 7 ? "" : ", ");
            puts("] };");
        }
    }
    puts("");

    puts("// ── Sizes of types carried whole but never inspected ────────────────────────");
    SIZE(GUID);
    ALIGN(GUID);
    SIZE(NV_ENC_QP);
    SIZE(NV_ENC_CODEC_CONFIG);
    SIZE(NV_ENC_CODEC_PIC_PARAMS);
    SIZE(NVENC_EXTERNAL_ME_HINT_COUNTS_PER_BLOCKTYPE);
    puts("");

    puts("// ── NV_ENCODE_API_FUNCTION_LIST ─────────────────────────────────────────────");
    /* Carried as raw bytes: transcribing ~40 function pointers in exact order is all
     * risk and no benefit when only fourteen of them are ever called. */
    SIZE(NV_ENCODE_API_FUNCTION_LIST);
    ALIGN(NV_ENCODE_API_FUNCTION_LIST);
    OFF(NV_ENCODE_API_FUNCTION_LIST, version);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncGetEncodeCaps);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncInitializeEncoder);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncCreateInputBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncDestroyInputBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncCreateBitstreamBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncDestroyBitstreamBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncEncodePicture);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncLockBitstream);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncUnlockBitstream);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncLockInputBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncUnlockInputBuffer);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncDestroyEncoder);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncOpenEncodeSessionEx);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncGetLastErrorString);
    OFF(NV_ENCODE_API_FUNCTION_LIST, nvEncGetEncodePresetConfigEx);
    puts("");

    puts("// ── NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS ────────────────────────────────────");
    SIZE(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS);
    ALIGN(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, version);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, deviceType);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, device);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, reserved);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, apiVersion);
    OFF(NV_ENC_OPEN_ENCODE_SESSION_EX_PARAMS, reserved1);
    puts("");

    puts("// ── NV_ENC_INITIALIZE_PARAMS ────────────────────────────────────────────────");
    SIZE(NV_ENC_INITIALIZE_PARAMS);
    ALIGN(NV_ENC_INITIALIZE_PARAMS);
    OFF(NV_ENC_INITIALIZE_PARAMS, version);
    OFF(NV_ENC_INITIALIZE_PARAMS, encodeGUID);
    OFF(NV_ENC_INITIALIZE_PARAMS, presetGUID);
    OFF(NV_ENC_INITIALIZE_PARAMS, encodeWidth);
    OFF(NV_ENC_INITIALIZE_PARAMS, encodeHeight);
    OFF(NV_ENC_INITIALIZE_PARAMS, darWidth);
    OFF(NV_ENC_INITIALIZE_PARAMS, darHeight);
    OFF(NV_ENC_INITIALIZE_PARAMS, frameRateNum);
    OFF(NV_ENC_INITIALIZE_PARAMS, frameRateDen);
    OFF(NV_ENC_INITIALIZE_PARAMS, enableEncodeAsync);
    OFF(NV_ENC_INITIALIZE_PARAMS, enablePTD);
    OFF(NV_ENC_INITIALIZE_PARAMS, privDataSize);
    OFF(NV_ENC_INITIALIZE_PARAMS, privData);
    OFF(NV_ENC_INITIALIZE_PARAMS, encodeConfig);
    OFF(NV_ENC_INITIALIZE_PARAMS, maxEncodeWidth);
    OFF(NV_ENC_INITIALIZE_PARAMS, maxEncodeHeight);
    OFF(NV_ENC_INITIALIZE_PARAMS, maxMEHintCountsPerBlock);
    OFF(NV_ENC_INITIALIZE_PARAMS, tuningInfo);
    OFF(NV_ENC_INITIALIZE_PARAMS, bufferFormat);
    OFF(NV_ENC_INITIALIZE_PARAMS, reserved);
    puts("");

    puts("// ── NV_ENC_CONFIG ───────────────────────────────────────────────────────────");
    SIZE(NV_ENC_CONFIG);
    ALIGN(NV_ENC_CONFIG);
    OFF(NV_ENC_CONFIG, version);
    OFF(NV_ENC_CONFIG, profileGUID);
    OFF(NV_ENC_CONFIG, gopLength);
    OFF(NV_ENC_CONFIG, frameIntervalP);
    OFF(NV_ENC_CONFIG, monoChromeEncoding);
    OFF(NV_ENC_CONFIG, frameFieldMode);
    OFF(NV_ENC_CONFIG, mvPrecision);
    OFF(NV_ENC_CONFIG, rcParams);
    OFF(NV_ENC_CONFIG, encodeCodecConfig);
    OFF(NV_ENC_CONFIG, reserved);
    puts("");

    puts("// ── NV_ENC_RC_PARAMS ────────────────────────────────────────────────────────");
    SIZE(NV_ENC_RC_PARAMS);
    ALIGN(NV_ENC_RC_PARAMS);
    OFF(NV_ENC_RC_PARAMS, version);
    OFF(NV_ENC_RC_PARAMS, rateControlMode);
    OFF(NV_ENC_RC_PARAMS, constQP);
    OFF(NV_ENC_RC_PARAMS, averageBitRate);
    OFF(NV_ENC_RC_PARAMS, maxBitRate);
    OFF(NV_ENC_RC_PARAMS, vbvBufferSize);
    OFF(NV_ENC_RC_PARAMS, vbvInitialDelay);
    OFF(NV_ENC_RC_PARAMS, minQP);
    puts("");

    puts("// ── NV_ENC_PRESET_CONFIG ────────────────────────────────────────────────────");
    SIZE(NV_ENC_PRESET_CONFIG);
    ALIGN(NV_ENC_PRESET_CONFIG);
    OFF(NV_ENC_PRESET_CONFIG, version);
    OFF(NV_ENC_PRESET_CONFIG, presetCfg);
    OFF(NV_ENC_PRESET_CONFIG, reserved1);
    puts("");

    puts("// ── NV_ENC_CREATE_INPUT_BUFFER ──────────────────────────────────────────────");
    SIZE(NV_ENC_CREATE_INPUT_BUFFER);
    ALIGN(NV_ENC_CREATE_INPUT_BUFFER);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, version);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, width);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, height);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, memoryHeap);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, bufferFmt);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, reserved);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, inputBuffer);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, pSysMemBuffer);
    OFF(NV_ENC_CREATE_INPUT_BUFFER, reserved1);
    puts("");

    puts("// ── NV_ENC_CREATE_BITSTREAM_BUFFER ──────────────────────────────────────────");
    SIZE(NV_ENC_CREATE_BITSTREAM_BUFFER);
    ALIGN(NV_ENC_CREATE_BITSTREAM_BUFFER);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, version);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, size);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, memoryHeap);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, reserved);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, bitstreamBuffer);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, bitstreamBufferPtr);
    OFF(NV_ENC_CREATE_BITSTREAM_BUFFER, reserved1);
    puts("");

    puts("// ── NV_ENC_LOCK_INPUT_BUFFER ────────────────────────────────────────────────");
    SIZE(NV_ENC_LOCK_INPUT_BUFFER);
    ALIGN(NV_ENC_LOCK_INPUT_BUFFER);
    OFF(NV_ENC_LOCK_INPUT_BUFFER, version);
    OFF(NV_ENC_LOCK_INPUT_BUFFER, inputBuffer);
    OFF(NV_ENC_LOCK_INPUT_BUFFER, bufferDataPtr);
    OFF(NV_ENC_LOCK_INPUT_BUFFER, pitch);
    OFF(NV_ENC_LOCK_INPUT_BUFFER, reserved1);
    puts("");

    puts("// ── NV_ENC_LOCK_BITSTREAM ───────────────────────────────────────────────────");
    SIZE(NV_ENC_LOCK_BITSTREAM);
    ALIGN(NV_ENC_LOCK_BITSTREAM);
    OFF(NV_ENC_LOCK_BITSTREAM, version);
    OFF(NV_ENC_LOCK_BITSTREAM, outputBitstream);
    OFF(NV_ENC_LOCK_BITSTREAM, sliceOffsets);
    OFF(NV_ENC_LOCK_BITSTREAM, frameIdx);
    OFF(NV_ENC_LOCK_BITSTREAM, hwEncodeStatus);
    OFF(NV_ENC_LOCK_BITSTREAM, numSlices);
    OFF(NV_ENC_LOCK_BITSTREAM, bitstreamSizeInBytes);
    OFF(NV_ENC_LOCK_BITSTREAM, outputTimeStamp);
    OFF(NV_ENC_LOCK_BITSTREAM, outputDuration);
    OFF(NV_ENC_LOCK_BITSTREAM, bitstreamBufferPtr);
    OFF(NV_ENC_LOCK_BITSTREAM, pictureType);
    puts("");

    puts("// ── NV_ENC_PIC_PARAMS ───────────────────────────────────────────────────────");
    SIZE(NV_ENC_PIC_PARAMS);
    ALIGN(NV_ENC_PIC_PARAMS);
    OFF(NV_ENC_PIC_PARAMS, version);
    OFF(NV_ENC_PIC_PARAMS, inputWidth);
    OFF(NV_ENC_PIC_PARAMS, inputHeight);
    OFF(NV_ENC_PIC_PARAMS, inputPitch);
    OFF(NV_ENC_PIC_PARAMS, encodePicFlags);
    OFF(NV_ENC_PIC_PARAMS, frameIdx);
    OFF(NV_ENC_PIC_PARAMS, inputTimeStamp);
    OFF(NV_ENC_PIC_PARAMS, inputDuration);
    OFF(NV_ENC_PIC_PARAMS, inputBuffer);
    OFF(NV_ENC_PIC_PARAMS, outputBitstream);
    OFF(NV_ENC_PIC_PARAMS, completionEvent);
    OFF(NV_ENC_PIC_PARAMS, bufferFmt);
    OFF(NV_ENC_PIC_PARAMS, pictureStruct);
    OFF(NV_ENC_PIC_PARAMS, pictureType);
    OFF(NV_ENC_PIC_PARAMS, codecPicParams);
    OFF(NV_ENC_PIC_PARAMS, meHintCountsPerBlock);
    puts("");

    puts("// ── Fields inside the codec union, addressed as bytes ───────────────────────");
    /* `encodeCodecConfig` is carried opaque, but two H.264 fields inside it have to be
     * written: the IDR period (so periodic keyframes follow gopLength) and repeatSPSPPS
     * (so every IDR is self-contained). Their positions are relative to the union. */
    printf("pub const H264_IDR_PERIOD_OFF: usize = %zu;\n",
           offsetof(NV_ENC_CODEC_CONFIG, h264Config.idrPeriod));
    {
        NV_ENC_CODEC_CONFIG cc;
        memset(&cc, 0, sizeof(cc));
        cc.h264Config.repeatSPSPPS = 1;
        bitfield("H264_REPEAT_SPSPPS", &cc, sizeof(cc));
    }
    return 0;
}
