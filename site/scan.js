// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
// Progressive enhancement for the scan scene: the figure already shows the finished picture, and this
// script plays it forwards once, on a fixed timeline — the three sources are read in the read beat, one
// result row appears in each beat that follows, and the end frame holds. Nothing is improvised: every
// element comes from the hooks the markup declares and every word from the root's data-msg-* attributes.
// The play stops off screen, in a hidden tab and at the end frame, and any control a person touches ends
// autoplay for good until replay arms it again. With JavaScript off, a missing element or reduced motion,
// the figure stays exactly as written.

(function () {
  "use strict";

  var root = document.querySelector("[data-scan-scene]");
  if (
    !root ||
    typeof window.matchMedia !== "function" ||
    typeof window.IntersectionObserver !== "function" ||
    typeof window.requestAnimationFrame !== "function" ||
    typeof window.cancelAnimationFrame !== "function"
  ) {
    return;
  }

  var playButton = root.querySelector("[data-scan-play]");
  var slider = root.querySelector("[data-scan-window]");
  var outBox = root.querySelector("[data-scan-window-out]");
  var sources = Array.prototype.slice.call(root.querySelectorAll("[data-scan-source]"));
  var rowEls = Array.prototype.slice.call(root.querySelectorAll("[data-scan-row]"));
  var jumpEls = Array.prototype.slice.call(root.querySelectorAll("[data-scan-jump]"));
  var msgPlay = root.getAttribute("data-msg-play");
  var msgPause = root.getAttribute("data-msg-pause");
  var msgReplay = root.getAttribute("data-msg-replay");
  var msgIn = root.getAttribute("data-msg-in");
  var msgOut = root.getAttribute("data-msg-out");
  var reachRaw = slider ? slider.getAttribute("data-reach") : null;
  var reach = reachRaw === null ? NaN : Number(reachRaw);

  // The fixed timeline, in seconds: the read beat runs 0–3, then one row per beat — found 3–5, not
  // found 5–7, not measured 7–9 — and the end frame holds from there on.
  var READ_END = 3;
  var STARTS = [3, 5, 7];
  var END = 9;

  var t = 0;             // seconds into the timeline
  var started = false;   // the first play has begun; there is at most one
  var finished = false;  // the end frame is reached; the button now offers replay
  var want = false;      // the timeline should run (autoplay, or an explicit play)
  var armed = true;      // autoplay is still allowed, until a touch or the end takes it away
  var onscreen = false;
  var tabVisible = true;
  var raf = null;
  var last = 0;

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");

  // Rows and jumps are taken by their state name, not by their position in the markup, so the scene
  // cannot break because two boxes changed place.
  var NAMES = ["found", "not_found", "unmeasured"];

  function pick(els, attr, name) {
    var hit = null;
    els.forEach(function (el) {
      if (!hit && el.getAttribute(attr) === name) {
        hit = el;
      }
    });
    return hit;
  }

  var rows = [];
  var jumps = [];
  NAMES.forEach(function (name) {
    rows.push(pick(rowEls, "data-scan-row", name));
    jumps.push(pick(jumpEls, "data-scan-jump", name));
  });

  if (
    !playButton || !slider || !outBox ||
    !msgPlay || !msgPause || !msgReplay || !msgIn || !msgOut ||
    sources.length !== 3 || rowEls.length !== 3 || jumpEls.length !== 3 ||
    rows.indexOf(null) !== -1 || jumps.indexOf(null) !== -1 || !isFinite(reach)
  ) {
    // A missing piece leaves the whole figure as written, controls still hidden.
    return;
  }

  function setMark(el, name, on) {
    if (on) {
      el.classList.add(name);
    } else {
      el.classList.remove(name);
    }
  }

  // The frame at t: each source is read during its second of the read beat, the wire showing the
  // beat's progress; each row appears when its beat starts and holds the stage until the next one,
  // and its jump tally comes in with it — .scan-in is only ever "reached", and only .scan-active
  // marks a source being read, so the rows carry no live mark of their own.
  function render(at) {
    root.style.setProperty("--scan-wire", (at >= READ_END ? 1 : at / READ_END).toFixed(4));
    NAMES.forEach(function (name, i) {
      var beatStart = STARTS[i];
      setMark(sources[i], "scan-in", at >= i + 1);
      setMark(sources[i], "scan-active", at >= i && at < i + 1);
      setMark(rows[i], "scan-in", at >= beatStart);
      setMark(jumps[i], "scan-in", at >= beatStart);
    });
  }

  function setPlayLabel() {
    var msg = finished ? msgReplay : want ? msgPause : msgPlay;
    if (playButton.textContent !== msg) {
      playButton.textContent = msg;
    }
  }

  function update() {
    var run = started && !finished && want && onscreen && tabVisible && !reduce.matches;
    if (run && raf === null) {
      last = performance.now();
      raf = window.requestAnimationFrame(tick);
    } else if (!run && raf !== null) {
      window.cancelAnimationFrame(raf);
      raf = null;
    }
    // The live state is on while the timeline is under way and unreached rows are meant to stay out
    // of sight; the end frame, the not-yet-started figure and reduced motion all show the page as
    // written.
    if (started && !finished && !reduce.matches) {
      root.setAttribute("data-scan-live", "true");
    } else {
      root.removeAttribute("data-scan-live");
    }
    setPlayLabel();
  }

  function tick(now) {
    var step = (now - last) / 1000;
    last = now;
    if (step > 0.25) {
      // A long stall (a hidden tab, a slow machine) must not leap the timeline forward.
      step = 0.25;
    }
    if (step < 0) {
      step = 0;
    }
    t += step;
    render(t);
    if (t >= END) {
      finished = true;
      want = false;
      armed = false; // one full play has finished; only replay brings the scene back
      raf = null;
      update();
      return;
    }
    raf = window.requestAnimationFrame(tick);
  }

  // Autoplay belongs to the first view: it starts once, only while the scene is seen, the tab is
  // visible and nobody has touched a control yet.
  function mayAutoplay() {
    if (!started && onscreen && tabVisible && armed && !reduce.matches) {
      started = true;
      want = true;
      render(t);
      update();
    }
  }

  // The slider picks a point in the past: min 0 and max 29 mean its value v is 30 minus v days ago,
  // and the example log holds everything from data-reach on. Inside that stretch the example can say
  // "not found"; outside it, the example says nothing at all.
  function windowText() {
    var v = Number(slider.value);
    if (!isFinite(v)) {
      return;
    }
    if (v < 0) {
      v = 0;
    } else if (v > 29) {
      v = 29;
    }
    var text = (v >= reach ? msgIn : msgOut).replace("{n}", String(30 - v));
    outBox.textContent = text;
    slider.setAttribute("aria-valuetext", text);
  }

  playButton.addEventListener("click", function () {
    armed = false; // a touched control ends autoplay until replay arms it again
    if (reduce.matches) {
      // Reduced motion: nothing animates, so play and replay both mean "the finished frame, now".
      t = END;
      started = true;
      finished = true;
      render(t);
    } else if (finished) {
      t = 0;
      started = true;
      finished = false;
      armed = true;
      want = true;
      render(t);
    } else {
      want = !want;
      if (want && !started) {
        started = true;
        render(t);
      }
    }
    update();
  });

  jumps.forEach(function (jumpButton, i) {
    jumpButton.addEventListener("click", function () {
      armed = false; // a touched control ends autoplay until replay arms it again
      started = true;
      finished = false;
      want = false; // the reader asked for one beat; hold it
      t = STARTS[i];
      render(t);
      update();
    });
  });

  slider.addEventListener("input", function () {
    armed = false; // a touched control ends autoplay until replay arms it again
    if (want) {
      want = false; // hold the frame while the reader explores the stretch
    }
    // The slider's message speaks of the not-found row; while the live state still holds that row
    // out of sight, the slider holds the scene at the not-found beat or later, so it never describes
    // a row nobody can see. (With reduced motion the picture stands as written and the row shows.)
    if (started && !finished && !reduce.matches && t < STARTS[1]) {
      t = STARTS[1];
      render(t);
    }
    windowText();
    update();
  });

  function onReduce() {
    want = false; // reduced motion means the timeline never runs by itself
    mayAutoplay();
    update();
  }
  if (typeof reduce.addEventListener === "function") {
    reduce.addEventListener("change", onReduce);
  } else if (typeof reduce.addListener === "function") {
    reduce.addListener(onReduce);
  }

  document.addEventListener("visibilitychange", function () {
    tabVisible = !document.hidden;
    mayAutoplay();
    update();
  });

  new IntersectionObserver(function (entries) {
    onscreen = entries[0].isIntersecting;
    mayAutoplay();
    update();
  }, { threshold: 0.1 }).observe(root);

  // The controls exist only where the script can drive them: reveal them, and show the slider's
  // starting position (23 in the markup, 7 days ago, inside the example log's reach).
  playButton.hidden = false;
  slider.hidden = false;
  outBox.hidden = false;
  windowText();
  update();
})();
