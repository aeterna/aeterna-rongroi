// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
// Progressive enhancement for the hero sample and the three promise cards: the sample leans with the scroll
// and the pointer, and each card takes a soft light under the pointer; both are off when motion is reduced.

(function () {
  "use strict";

  var sample = document.getElementById("specimen");
  if (!sample ||
    typeof window.matchMedia !== "function" ||
    typeof window.requestAnimationFrame !== "function" ||
    typeof window.cancelAnimationFrame !== "function" ||
    typeof window.IntersectionObserver !== "function") {
    return;
  }

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  var fine = window.matchMedia("(hover: hover) and (pointer: fine)");
  var cards = Array.prototype.slice.call(document.querySelectorAll(".ledger li"));
  var lift = 0, tiltX = 0, tiltY = 0, rx = 0, ry = 0;
  var held = false, onScreen = true, visible = !document.hidden, raf = null;

  function enabled() {
    return !reduce.matches && window.innerWidth > 960;
  }

  function tick() {
    raf = null;
    if (!enabled() || !onScreen || !visible) return;
    var goalX = lift + (held ? 0 : tiltX);
    var goalY = held ? 0 : tiltY;
    rx += (goalX - rx) * 0.1;
    ry += (goalY - ry) * 0.1;
    var doneX = Math.abs(goalX - rx) < 0.01;
    var doneY = Math.abs(goalY - ry) < 0.01;
    if (doneX) rx = goalX;
    if (doneY) ry = goalY;
    sample.style.setProperty("--sp-rx", rx.toFixed(3) + "deg");
    sample.style.setProperty("--sp-ry", ry.toFixed(3) + "deg");
    if (!doneX || !doneY) raf = window.requestAnimationFrame(tick);
  }

  function ease() {
    if (raf === null && enabled() && onScreen && visible) raf = window.requestAnimationFrame(tick);
  }

  function stop() {
    if (raf !== null) window.cancelAnimationFrame(raf);
    raf = null;
    rx = 0;
    ry = 0;
    sample.style.removeProperty("--sp-rx");
    sample.style.removeProperty("--sp-ry");
  }

  function sync() {
    lift = Math.min(Math.max(window.scrollY / (window.innerHeight || 1), 0), 1) * 5;
    if (enabled()) ease();
    else stop();
  }

  function aim(x, y) {
    tiltX = x;
    tiltY = y;
    ease();
  }

  sample.addEventListener("pointermove", function (event) {
    if (!enabled() || event.pointerType !== "mouse" || !fine.matches) return;
    var box = sample.getBoundingClientRect();
    var x = (event.clientX - box.left) / box.width;
    var y = (event.clientY - box.top) / box.height;
    aim((0.5 - y) * 2.4, (x - 0.5) * 3.2);
  });
  sample.addEventListener("pointerleave", function () { aim(0, 0); });
  sample.addEventListener("focusin", function () {
    held = true;
    ease();
  });
  sample.addEventListener("focusout", function () {
    held = false;
    aim(0, 0);
  });

  cards.forEach(function (card) {
    card.addEventListener("pointermove", function (event) {
      if (event.pointerType !== "mouse" || reduce.matches) return;
      var box = card.getBoundingClientRect();
      card.style.setProperty("--mx", (event.clientX - box.left) + "px");
      card.style.setProperty("--my", (event.clientY - box.top) + "px");
    });
  });

  new window.IntersectionObserver(function (entries) {
    onScreen = entries[0].isIntersecting;
    if (onScreen) ease();
  }, { rootMargin: "200px" }).observe(sample);
  window.addEventListener("scroll", sync, { passive: true });
  window.addEventListener("resize", sync);
  document.addEventListener("visibilitychange", function () {
    visible = !document.hidden;
    if (visible) ease();
  });
  if (typeof reduce.addEventListener === "function") reduce.addEventListener("change", sync);
  else if (typeof reduce.addListener === "function") reduce.addListener(sync);
  sync();
})();
