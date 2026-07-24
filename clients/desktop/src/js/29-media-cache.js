// ═══════════════════════════════════════════════════════════════════════════════
// Session media caches (RAM only, never disk)
// ═══════════════════════════════════════════════════════════════════════════════
// Split from 30-thread.js (no-monolith). Shared by the thread, gallery (37), voice
// (40 — voiceCache lives there, next to its audio plumbing) and settings (60).

// Decrypted previews, this session only — LRU-bounded so a heavy image/video chat
// can't grow memory until the next lock (an evicted entry just re-fetches).
const imgCache = new LruCache({ max: 200, budget: 48 * 1024 * 1024, cost: (v) => v.length }); // msg_id -> data URL
const vidCache = new LruCache({ max: 6, onEvict: (url) => URL.revokeObjectURL(url) });        // msg_id -> blob URL

// Drop one message's decrypted media from every session cache (message deleted) —
// a removed message must not stay decodable from RAM. voiceCache lives in 40-voice.
function purgeMediaCache(msgId) {
  imgCache.delete(msgId);
  vidCache.delete(msgId);
  voiceCache.delete(msgId);
}
// Everything at once: chat deletion (ids unknown here) and the settings button.
function clearMediaCaches() {
  cancelVoice(); stopNowPlaying();
  imgCache.clear();
  vidCache.clear();
  voiceCache.clear();
}
