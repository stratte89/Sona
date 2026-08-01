#!/usr/bin/env python3
"""Screenshot a page in the engine the Linux app actually uses.

The desktop shell is a Tauri webview: **WebKitGTK** on Linux, WebView2 (Chromium) on
Windows, Android WebView (Chromium) on Android. Checking UI in Chrome therefore checks
two of the three, and the one it misses is the one most people run.

That is not hypothetical. The call volume slider was styled as a 4 px rail with a
gradient fill, verified in headless Chrome, and shipped. WebKitGTK ignores `height` on a
range input and paints the background across its full natural height, so it arrived as a
fat green bar with the knob floating inside it and the fill disagreeing with the knob at
both ends. Chromium rendered the identical CSS perfectly.

    python3 clients/desktop/scripts/wk-screenshot.py <url-or-file> <out.png> [w] [h]

Needs `gir1.2-webkit2-4.1` and `python3-gi`, which any machine that can build the app
already has.
"""
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target, out = sys.argv[1], sys.argv[2]
    w = int(sys.argv[3]) if len(sys.argv) > 3 else 1200
    h = int(sys.argv[4]) if len(sys.argv) > 4 else 800
    if "://" not in target:
        target = GLib.filename_to_uri(str(__import__("pathlib").Path(target).resolve()), None)

    win = Gtk.OffscreenWindow()
    win.set_default_size(w, h)
    view = WebKit2.WebView()
    win.add(view)
    win.show_all()
    failed = []

    def snap():
        def done(v, res, _):
            try:
                v.get_snapshot_finish(res).write_to_png(out)
                print("wrote", out)
            except GLib.Error as e:  # nothing rendered
                failed.append(str(e))
            Gtk.main_quit()

        view.get_snapshot(
            WebKit2.SnapshotRegion.FULL_DOCUMENT, WebKit2.SnapshotOptions.NONE, None, done, None
        )

    def on_load(_v, ev):
        # A beat after load so webfonts, layout and any first paint have settled;
        # snapshotting on FINISHED alone catches the page mid-layout.
        if ev == WebKit2.LoadEvent.FINISHED:
            GLib.timeout_add(400, lambda: (snap(), False)[1])

    view.connect("load-changed", on_load)
    view.load_uri(target)
    GLib.timeout_add_seconds(30, Gtk.main_quit)
    Gtk.main()
    if failed:
        print("snapshot failed:", failed[0], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
