#!/usr/bin/env python3
"""Guard: screen-anchored UI must keep out of the status bar / gesture bar.

The Android build runs edge-to-edge (`viewport-fit=cover`), so the top and bottom strips of
the screen belong to the system: the status bar with the clock and notification icons, and
the gesture/navigation bar. Anything pinned to a screen edge with a bare pixel offset lands
*under* them — that is how the chat-list header, the online badge and (later, identically)
the lightbox buttons all ended up unreachable. The fix each time is the same:

    top: calc(10px + env(safe-area-inset-top, 0px));

so this check makes the rule mechanical instead of remembered. It fails when a rule that
pins itself to the viewport (`position: fixed`, or `position: absolute` inside one of the
full-screen overlays) sets a top/bottom/left/right offset in pixels without an
`env(safe-area-inset-*)` term. The cascade is honoured: a later rule for the same selector
that adds the env() term (as the "Mobile safe areas" section at the end of styles.css does)
settles the matter.

Escape hatch: put `safe-area-ok` in a comment on the offending declaration's line, e.g.

    bottom: 12px; /* safe-area-ok — sits inside .composer, which already pads itself */

Run: python3 clients/desktop/scripts/check-safe-area.py [styles.css ...]
"""

import pathlib
import re
import sys

# Children of the full-screen overlays are screen-anchored too, even though they position
# themselves `absolute` against the overlay (which is itself `inset: 0`). Pseudo-elements
# and descendants are not: they position against a component box, not the screen.
OVERLAY_CHILD = re.compile(r"^\.(lightbox|lb-|callui|call-|cset-|scanui|scan-|msheet)[\w-]*$")
SIDES = ("top", "bottom", "left", "right")
PX = re.compile(r"-?\d*\.?\d+px")
SAFE = "env(safe-area-inset"


def blank_comments(css: str):
    """Strip comments, keeping line numbers intact; return (css, exempt line numbers)."""
    exempt = {i + 1 for i, ln in enumerate(css.split("\n")) if "safe-area-ok" in ln}
    stripped = re.sub(
        r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), css, flags=re.S
    )
    return stripped, exempt


def rules(css: str):
    """Yield (selector list, declarations, line of each declaration). Flat CSS + at-rules."""
    i = 0
    start = 0
    while i < len(css):
        c = css[i]
        if c == "{":
            header = css[start:i].strip()
            if header.startswith("@"):  # @media / @keyframes wrapper: descend into it
                start = i + 1
                i += 1
                continue
            close = css.find("}", i)
            if close < 0:
                return
            body = css[i + 1 : close]
            line = css.count("\n", 0, i + 1) + 1
            decls = {}
            for chunk in body.split(";"):
                if ":" not in chunk:
                    line += chunk.count("\n")
                    continue
                prop, value = chunk.split(":", 1)
                decls[prop.strip().lower()] = (
                    value.strip().lower(),
                    line + prop[: len(prop) - len(prop.lstrip("\n \t"))].count("\n"),
                )
                line += chunk.count("\n")
            yield [s.strip() for s in header.split(",") if s.strip()], decls
            start = close + 1
            i = close + 1
            continue
        if c == "}":
            start = i + 1
        i += 1


def check(path: pathlib.Path) -> list:
    css, exempt = blank_comments(path.read_text())
    state = {}  # selector -> {"pos": str|None, "sides": {side: (value, line)}}
    for selectors, decls in rules(css):
        for sel in selectors:
            st = state.setdefault(sel, {"pos": None, "sides": {}})
            if "position" in decls:
                st["pos"] = decls["position"][0]
            if "inset" in decls:
                for side in SIDES:
                    st["sides"][side] = decls["inset"]
            for side in SIDES:
                if side in decls:
                    st["sides"][side] = decls[side]

    bad = []
    for sel, st in state.items():
        anchored = st["pos"] == "fixed" or (
            st["pos"] == "absolute" and OVERLAY_CHILD.match(sel)
        )
        if not anchored:
            continue
        for side in SIDES:
            if side not in st["sides"]:
                continue
            value, line = st["sides"][side]
            if line in exempt or SAFE in value or not PX.search(value):
                continue
            bad.append((line, sel, side, value))
    return sorted(bad)


def main() -> int:
    paths = [pathlib.Path(p) for p in sys.argv[1:]] or [
        pathlib.Path(__file__).resolve().parents[1] / "src" / "styles.css"
    ]
    failed = False
    for path in paths:
        for line, sel, side, value in check(path):
            failed = True
            print(
                f"{path}:{line}: `{sel}` pins `{side}: {value}` to the screen edge without "
                f"env(safe-area-inset-{side}) — on Android it can land under the system UI "
                f"(status bar, gesture bar, display cutout). Use "
                f"calc(… + env(safe-area-inset-{side}, 0px)), or mark the line "
                f"`/* safe-area-ok */` if it genuinely cannot collide.",
                file=sys.stderr,
            )
    if failed:
        return 1
    print("safe-area check: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
