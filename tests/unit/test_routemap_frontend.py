"""The Route Map tab's own wording and wiring, read from the shipped files.

There is no JavaScript runtime in the test environment, so these read app.js
and index.html as text, the way test_static_asset_paths does. Each one pins a
bug that reached a real user.
"""
import pathlib
import re

STATIC = pathlib.Path(__file__).resolve().parents[2] / "app" / "static"
APP_JS = (STATIC / "app.js").read_text(encoding="utf-8")
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")


def _function(name):
    """The source of one top-level function in app.js."""
    match = re.search(r"^(?:async )?function %s\(.*?^}" % re.escape(name),
                      APP_JS, re.S | re.M)
    assert match, f"app.js no longer defines {name}"
    return match.group(0)


# ---------- mtr on macOS ----------

def test_the_command_panel_offers_the_macos_mtr_variant():
    assert 'data-os="mtr_macos"' in INDEX
    assert 'data-os="mtr"' in INDEX


def test_the_command_note_is_shown_under_the_command():
    assert 'id="rm-cmd-note"' in INDEX
    paint = _function("rmPaintOsButtons")
    assert "entry.note" in paint and "rm-cmd-note" in paint


# ---------- an unreadable trace ----------

def test_an_unreadable_upload_is_not_reported_as_an_atlas_failure():
    """A Mac upload of mtr's own permissions error was titled "The Atlas
    measurement did not complete"."""
    poll = _function("rmStartPolling")
    branch = poll.index("body.kind === 'parse'")
    assert "rmUnreadableTrace('upload'" in poll[branch:]
    assert branch < poll.index("rmAtlasFail(")
    assert "body.received" in poll


def test_the_unreadable_banner_has_the_right_titles_and_keeps_the_formats():
    unreadable = _function("rmUnreadableTrace")
    assert "'Could not read the uploaded trace'" in unreadable
    assert "'Could not read the pasted trace'" in unreadable
    assert "Atlas" not in unreadable
    assert "RM_SUPPORTED_FORMATS" in unreadable
    assert "mtr --report / --report-wide" in APP_JS


def test_the_banner_shows_at_most_three_received_lines():
    banner = _function("rmBanner")
    assert ".slice(0, 3)" in banner
    assert "rm-atlas-error-received" in banner
    assert 'id="rm-atlas-error-received"' in INDEX


def test_the_paste_path_shows_what_was_pasted():
    paste = _function("rmAnalysePaste")
    assert "rmUnreadableTrace('paste'" in paste
    assert "rmFirstLines(text)" in paste


def test_every_banner_goes_through_one_helper():
    """Otherwise a preview from an unreadable upload stays on screen under the
    next, unrelated message."""
    writes = re.findall(r"RM\('rm-atlas-error-(?:title|body)'\)\.textContent\s*=", APP_JS)
    assert len(writes) == 2, "a banner is written outside rmBanner"
    assert len(re.findall(r"RM\('rm-atlas-error-title'\)", _function("rmBanner"))) == 1


# ---------- the command panel's target ----------

def test_the_run_it_yourself_target_follows_the_main_field():
    """The panel kept vector.co.nz from an earlier trace while the main field
    said heise.de, so Generate command traced the wrong host."""
    init = APP_JS[APP_JS.index("const liveCheck = () => {"):]
    init = init[:init.index("};")]
    assert "RM('rm-target').value = raw" in init


def test_the_panel_names_the_target_its_command_traces():
    assert 'id="rm-cmd-target"' in INDEX
    assert 'id="rm-cmd-stale"' in INDEX
    make = _function("rmMakeCommand")
    assert "_rmCmdTarget = target" in make
    assert "RM('rm-cmd-target').textContent = target" in make
    stale = _function("rmCheckCmdStale")
    assert "target !== _rmCmdTarget" in stale
    assert "addEventListener('input', rmCheckCmdStale)" in APP_JS


# ---------- zoom and pan (v3.36.7) ----------

def test_the_wheel_is_handled_by_the_map_not_by_d3_or_the_page():
    """A trackpad's two-finger scroll zoomed instead of panning, and Safari's
    pinch zoomed the whole page: d3 took every wheel event as zoom and nothing
    caught WebKit's gesture events."""
    draw = _function("rmDrawMap")
    assert "event.type !== 'wheel'" in draw, "d3 must not take the wheel itself"
    assert "rmWireMapInput(svg" in draw
    wire = _function("rmWireMapInput")
    assert "passive: false" in wire and wire.count("preventDefault") >= 4
    for event in ("'wheel'", "'gesturestart'", "'gesturechange'", "'gestureend'", "'keydown'"):
        assert event in wire, event


def test_a_trackpad_scroll_pans_and_a_wheel_notch_or_pinch_zooms():
    action = _function("rmWheelAction")
    assert "e.ctrlKey" in action and "'zoom'" in action and "'pan'" in action
    assert "deltaMode" in action, "a mouse that scrolls by lines is still a mouse"


def test_keys_zoom_pan_and_fit_without_transitions():
    wire = _function("rmWireMapInput")
    for key in ("'+'", "'-'", "'0'", "ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"):
        assert key in wire, key
    keys = wire[wire.index("const keys"):]
    assert ".transition()" not in keys, "a transition stalls in a hidden tab"
    assert "'tabindex', 0" in _function("rmDrawMap")


def test_the_map_cannot_shrink_below_the_world_and_lines_keep_their_width():
    draw = _function("rmDrawMap")
    assert "scaleExtent(RM_ZOOM_EXTENT)" in draw and "translateExtent" in draw
    assert re.search(r"const RM_ZOOM_EXTENT = \[1, \d+\];", APP_JS)
    assert "non-scaling-stroke" in draw
    assert "touch-action', 'none'" in draw, "a touch pinch must not zoom the page"
