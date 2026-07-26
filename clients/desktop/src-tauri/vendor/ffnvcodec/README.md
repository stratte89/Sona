# `nvEncodeAPI.h` — vendored NVENC interface header

`nvEncodeAPI.h` is taken verbatim from
[FFmpeg/nv-codec-headers](https://github.com/FFmpeg/nv-codec-headers) at tag
**`n11.1.5.3`** (`include/ffnvcodec/nvEncodeAPI.h`), which corresponds to NVIDIA Video
Codec SDK **11.1**. It is MIT licensed; the notice is at the top of the file itself and
is the only licence the file ships with. It is a header — no NVIDIA library, no SDK and
no redistributable binary is involved.

## Why 11.1 and not the newest

NVIDIA guarantees *binary backward compatibility* for NVENC: an application built against
an older API version keeps working on every later driver. Targeting an old version
therefore maximises coverage in both directions, and the only thing it costs is features
we do not use. What the choice actually decides is the **minimum driver** a user needs:

| nv-codec-headers | Minimum Linux driver |
| ---------------- | -------------------- |
| 9.0.18           | 418.30               |
| **11.1.5**       | **470.57.02** (2021) |
| 12.0.16          | 530.41.03            |
| 13.1.15          | 610.0 (2026)         |

11.1 is the oldest version that still has the P1–P7 presets and `NV_ENC_TUNING_INFO`,
which is how the low-latency tuning is selected. 13.x would exclude nearly every machine
in service today.

## Why the header is here at all

Nothing in the build reads it. It is checked in for **provenance**: it is the ground truth
that `abi_probe.c` is compiled against to produce
`../../src/hwenc/nvenc/abi_gen.rs`, and without it that generated file would be a set of
magic numbers nobody could re-derive. The build itself has no NVIDIA dependency of any
kind — not at link time (everything is `dlopen`ed) and not at build time (no SDK, no
`bindgen`, no `libclang`).

## Regenerating `abi_gen.rs`

```sh
./regen-abi.sh
```

Needs `gcc` and nothing else. It compiles `abi_probe.c` against the header next to it and
writes the constants Rust asserts its own struct layout against. If a field moves, the
regenerated constants stop matching the hand-written `#[repr(C)]` structs and
`clients/desktop/src-tauri/src/hwenc/nvenc/abi.rs` **fails to compile** — which is the
entire point, because a wrong field offset against a driver is not a compile error and
not a clean failure, it is memory corruption that no runtime probe can catch.
