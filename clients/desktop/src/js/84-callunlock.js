// Unlock-to-answer, the part that needs a screen (internal/CALL_PLAN.md §3.3, A-19).
//
// Answering from the lock screen costs a check that the person holding the phone is the
// owner. The OS does that check itself wherever it can — a fingerprint, or the device
// PIN/pattern/password, driven from Rust with no UI of ours involved. This file covers the
// one case the OS cannot: a phone with no enrolled factor at all, where Sona's own
// password or unlock PIN is the only thing left to ask for. Never a silent pass.
// A-19 — an answer taken over the OS keyguard, on a phone whose own lock screen can vouch
// for nobody (no fingerprint enrolled, no device PIN/pattern/password): the OS has nothing
// to ask, so Sona asks for its own password or unlock PIN instead. Never a silent pass —
// the backend sends no answer claim until this succeeds, and the attempt times out by
// itself if it never does.
let askingCredential = false;
async function promptAnswerCredential() {
  if (askingCredential) return; // the event and the resync can both arrive
  askingCredential = true;
  try {
    if (!sec) await refreshSec();
    const auth = await unlockAuthPrompt('Unlock to answer',
      'This phone has no fingerprint or screen lock for Sona to check, so it asks here.');
    if (!auth) return; // cancelled: the call's own deadline ends the attempt
    await invoke('answer_with_app_credential',
      { password: auth.password || null, pin: auth.pin || null });
  } catch (e) {
    toast(say(e), 'err');
  } finally {
    askingCredential = false;
  }
}
