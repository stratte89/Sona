// How a ring that ended somewhere else is presented: the reason in the user's words, and
// which overlay states may be closed by it (internal/CALL_PLAN.md §3.4, §3.5).
//
// Kept beside the overlay rather than inside it because both halves are presentation
// decisions the engine deliberately does not make: it reports the terminal reason honestly
// and leaves the wording and the timing here.

// Why a ring ended, in the user's words. Every terminal used to read "Answered on
// another device", which is wrong for a decline, a cancellation, or a busy sibling —
// and wrong in the way that makes people distrust the call log (internal/CALL_PLAN.md §3.4).
const HANDLED_TEXT = {
  answered_here: 'Answered on another device',
  answered_elsewhere: 'Answered on another device',
  declined_here: 'Declined on another device',
  declined_elsewhere: 'Declined on another device',
  caller_cancelled: 'Caller hung up',
  expired: 'Call expired',
  busy: 'Busy on another device',
  transport_error: 'Call ended — connection problem',
};
const handledText = (p) => HANDLED_TEXT[p && p.reason] || 'Ended on another device';

// Which overlay states a `handled` event may close (A-21). `incoming` is the obvious one;
// `connecting` is the one that was missing, and it is the case this project exists for:
// after Answer the overlay is `connecting`, and every terminal that lands while the claim is
// out arrives there — losing the arbitration (§3.5's simultaneous answer), A-3's claim
// timeout, a peer terminal mid-claim. Dropping those left the loser sitting on
// "connecting…" with no toast and no close until they hung up by hand.
//
// Named states, deliberately not "anything but connected". `outgoing` stays out: the caller
// side never receives `handled`, and widening it there would hide a live outgoing overlay on
// a stray event. `connected` stays out: the media pump owns that teardown, and hiding the
// overlay under a live call would leave the user in a call with no UI to end it.
const handledClosesUi = () => callUi.mode === 'incoming' || callUi.mode === 'connecting';
