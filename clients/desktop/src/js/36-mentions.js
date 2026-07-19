// ═══════════════════════════════════════════════════════════════════════════════
// @mentions (groups): composer autocomplete. Typing "@" pops a roster picker above
// the composer; Enter/Tab/click inserts "@username ". Highlighting of mentions in
// bubbles lives in 30-thread.js (appendTextWithMentions); mention-beats-mute lives
// in the Rust notifier. Mentions are plain text on the wire — no protocol change.
// ═══════════════════════════════════════════════════════════════════════════════
const mbox = $('#mentionbox');
let mHits = [];
let mActive = 0;
let mTokenStart = -1;

// The @token under the caret, or null (not a group / no token). A token starts at the
// beginning of the text or after whitespace/"(" — never mid-word, so emails don't pop it.
function mentionCtx() {
  if (cur.kind !== 'group' || !Array.isArray(cur.members) || cur.left) return null;
  const inp = $('#th-input');
  const caret = inp.selectionStart ?? inp.value.length;
  const before = inp.value.slice(0, caret);
  const m = /(^|[\s(])@([A-Za-z0-9_.-]*)$/.exec(before);
  if (!m) return null;
  return { start: caret - m[2].length - 1, query: m[2].toLowerCase() };
}

function closeMentions() {
  mbox.hidden = true;
  mbox.innerHTML = '';
  mHits = [];
  mActive = 0;
}

function paintMentionActive() {
  $$('.m-item', mbox).forEach((el, i) => el.classList.toggle('active', i === mActive));
}

function renderMentions() {
  const ctx = mentionCtx();
  if (!ctx) return closeMentions();
  const me = (myName || '').toLowerCase();
  mHits = cur.members
    .filter((u) => u.toLowerCase() !== me && u.toLowerCase().startsWith(ctx.query))
    .slice(0, 6);
  if (!mHits.length) return closeMentions();
  mActive = 0;
  mTokenStart = ctx.start;
  mbox.innerHTML = '';
  mHits.forEach((u, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'm-item' + (i === 0 ? ' active' : '');
    b.innerHTML =
      `<div class="avatar" style="--av-h:${hue(u)};width:24px;height:24px;font-size:11px">${escapeHtml(initial(u))}</div>
       <span>${escapeHtml(u)}</span>`;
    // pointerdown (not click): fires before the composer loses focus, so the caret
    // position used for the insertion is still the one the user typed at.
    b.onpointerdown = (e) => { e.preventDefault(); pickMention(u); };
    mbox.appendChild(b);
  });
  // Anchor directly above the composer, matching its left edge.
  const r = $('#th-form').getBoundingClientRect();
  mbox.style.left = r.left + 8 + 'px';
  mbox.style.width = Math.min(r.width - 16, 320) + 'px';
  mbox.style.bottom = window.innerHeight - r.top + 6 + 'px';
  mbox.hidden = false;
}

function pickMention(u) {
  const inp = $('#th-input');
  const caret = inp.selectionStart ?? inp.value.length;
  inp.value = inp.value.slice(0, mTokenStart) + '@' + u + ' ' + inp.value.slice(caret);
  const pos = mTokenStart + u.length + 2;
  closeMentions();
  inp.focus();
  inp.setSelectionRange(pos, pos);
  inp.dispatchEvent(new Event('input')); // autoresize + typing signal (real typing)
}

$('#th-input').addEventListener('input', renderMentions);
$('#th-input').addEventListener('click', renderMentions);
$('#th-input').addEventListener('blur', () => setTimeout(closeMentions, 150));

// Capture-phase on document so navigation keys reach the picker BEFORE the composer's
// own Enter-to-send handler (registered earlier on the input itself).
document.addEventListener('keydown', (e) => {
  if (mbox.hidden || e.target !== $('#th-input')) return;
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    e.stopPropagation();
    mActive = e.key === 'ArrowDown'
      ? Math.min(mActive + 1, mHits.length - 1)
      : Math.max(mActive - 1, 0);
    paintMentionActive();
  } else if (e.key === 'Enter' || e.key === 'Tab') {
    e.preventDefault();
    e.stopPropagation();
    if (mHits[mActive]) pickMention(mHits[mActive]);
  } else if (e.key === 'Escape') {
    e.preventDefault();
    e.stopPropagation();
    closeMentions();
  }
}, true);

// Any screen change closes the picker (it is a fixed overlay — it would float over
// whatever comes next). `show` is the global router from 00-core.js.
const showBaseForMentions = show;
show = function (name, fromPop) {
  closeMentions();
  return showBaseForMentions(name, fromPop);
};
