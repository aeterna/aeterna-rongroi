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
  var hero = sample.closest(".hero") || sample;
  var cards = Array.prototype.slice.call(document.querySelectorAll(".ledger li"));
  var lift = 0, tiltX = 0, tiltY = 0, rx = 0, ry = 0;
  var rect = null;
  var held = false, onScreen = true, visible = !document.hidden, raf = null;

  function enabled() {
    return !reduce.matches && window.innerWidth > 960;
  }

  function tick() {
    raf = null;
    if (!enabled() || !onScreen || !visible) return;
    // Typing holds the sample where it is: the lift and the pointer aim wait until focus leaves.
    if (held) return;
    var goalX = lift + tiltX;
    var goalY = tiltY;
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
    sample.classList.remove("is-tilting");
    sample.style.removeProperty("--sp-rx");
    sample.style.removeProperty("--sp-ry");
  }

  function sync() {
    rect = null;
    lift = Math.min(Math.max(window.scrollY / (window.innerHeight || 1), 0), 1) * 5;
    if (enabled()) {
      sample.classList.add("is-tilting");
      ease();
    } else {
      stop();
    }
  }

  function aim(x, y) {
    tiltX = x;
    tiltY = y;
    ease();
  }

  // Listen on the hero, not the sample: once the sample tilts, its own edge can slip past a resting
  // pointer and flip leave and enter. The cached rect keeps that edge fixed between scrolls and resizes.
  hero.addEventListener("pointermove", function (event) {
    if (!enabled() || event.pointerType !== "mouse" || !fine.matches) return;
    if (rect === null) rect = sample.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right ||
      event.clientY < rect.top || event.clientY > rect.bottom) {
      aim(0, 0);
      return;
    }
    var x = (event.clientX - rect.left) / rect.width;
    var y = (event.clientY - rect.top) / rect.height;
    aim((0.5 - y) * 2.4, (x - 0.5) * 3.2);
  });
  hero.addEventListener("pointerleave", function () { aim(0, 0); });
  sample.addEventListener("focusin", function (event) {
    if (!event.target || event.target.tagName !== "INPUT") return;
    held = true;
    ease();
  });
  sample.addEventListener("focusout", function () {
    held = false;
    ease();
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
