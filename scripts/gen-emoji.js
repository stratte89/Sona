// Regenerate clients/desktop/src/vendor/emoji.js:
//   curl -sLO https://unicode.org/Public/emoji/latest/emoji-test.txt
//   node scripts/gen-emoji.js   # writes ./emoji.js — move it into vendor/
//
// Generates clients/desktop/src/vendor/emoji.js from Unicode emoji-test.txt.
// Keeps fully-qualified emoji up to E15.1 (widely supported by system emoji fonts),
// skips skin-tone variants (the picker applies tones itself), and flags each base
// emoji whose toned form is a valid RGI sequence built by simple modifier insertion.
const fs = require('fs');
const lines = fs.readFileSync('emoji-test.txt', 'utf8').split('\n');
const MAX_VERSION = 15.1;
const TONES = ['1F3FB', '1F3FC', '1F3FD', '1F3FE', '1F3FF'];

let group = null;
const groups = [];            // [{ n, e: [[emoji, name, tonable?]] }]
const byName = new Map();     // name -> { cps, groupIdx, entryIdx }
const toned = new Set();      // "name|tonecp" present in the RGI set

for (const line of lines) {
  const g = /^# group: (.+)$/.exec(line);
  if (g) {
    group = g[1] === 'Component' ? null : { n: g[1], e: [] };
    if (group) groups.push(group);
    continue;
  }
  if (!group) continue;
  const m = /^([0-9A-F ]+?)\s*;\s*fully-qualified\s*#\s*(\S+)\s+E(\d+\.\d+)\s+(.+)$/.exec(line);
  if (!m) continue;
  const [, cpstr, , ver, name] = m;
  if (parseFloat(ver) > MAX_VERSION) continue;
  const cps = cpstr.trim().split(/\s+/);
  const tone = /^(.*?): (?:.*\b)?(light|medium-light|medium|medium-dark|dark) skin tone(.*)$/.exec(name);
  if (tone) {
    // Record which (base name, tone) sequences exist, for the tonable check below.
    if (!name.includes(',')) { // single-tone variants only (no "person: tone, tone")
      const toneCp = cps.find((c) => TONES.includes(c));
      if (toneCp) toned.add(`${tone[1]}${tone[3] || ''}|${toneCp}|${cps.join(' ')}`);
    }
    continue;
  }
  group.e.push([cps.map((c) => String.fromCodePoint(parseInt(c, 16))).join(''), name]);
  byName.set(name, { cps, g: groups.length - 1, i: group.e.length - 1 });
}

// Tonable = for EVERY tone, inserting the modifier after the first scalar (dropping a
// variation selector that follows it) reproduces the exact RGI sequence from the file.
const insertTone = (cps, tone) => {
  const rest = cps[1] === 'FE0F' ? cps.slice(2) : cps.slice(1);
  return [cps[0], tone, ...rest].join(' ');
};
let tonable = 0;
for (const [name, loc] of byName) {
  const ok = TONES.every((t) => toned.has(`${name}|${t}|${insertTone(loc.cps, t)}`));
  if (ok) {
    groups[loc.g].e[loc.i].push(1);
    tonable++;
  }
}

const total = groups.reduce((s, g) => s + g.e.length, 0);
const out =
  '// Generated from unicode.org emoji-test.txt (v17 data, capped at E' + MAX_VERSION + ').\n' +
  '// Format: [{ n: group name, e: [[emoji, name, tonable?], …] }, …]. Regenerate with\n' +
  '// the notes in docs/ if Unicode moves on. Loaded lazily by js/38-emoji.js.\n' +
  'window.EMOJI_DATA = ' + JSON.stringify(groups) + ';\n';
fs.writeFileSync('emoji.js', out);
console.log('groups:', groups.map((g) => `${g.n}:${g.e.length}`).join(' '), '| total', total, '| tonable', tonable, '| bytes', out.length);
