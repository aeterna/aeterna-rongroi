// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
// Progressive enhancement for the data-flow diagram: the packet dots are SMIL animations inside the SVG,
// so with JavaScript off they simply play. This script pauses them while the diagram is off screen or
// while the visitor asked for reduced motion, so the diagram stands as drawn. It reads nothing from the
// page but the one SVG's id, and a missing SVG or a browser without the interfaces leaves the page as
// written.

(function () {
  "use strict";

  var svg = document.getElementById("flow-svg");
  if (
    !svg ||
    typeof svg.pauseAnimations !== "function" ||
    typeof svg.unpauseAnimations !== "function" ||
    typeof svg.setCurrentTime !== "function" ||
    typeof window.IntersectionObserver !== "function"
  ) {
    return;
  }

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  var onScreen = false;

  function sync() {
    if (reduce.matches) {
      // Reduced motion: no dot travels; CSS also hides the dots, so only the drawn diagram shows.
      svg.setCurrentTime(1.4);
      svg.pauseAnimations();
      return;
    }
    if (onScreen) {
      svg.unpauseAnimations();
    } else {
      svg.pauseAnimations();
    }
  }

  if (typeof reduce.addEventListener === "function") {
    reduce.addEventListener("change", sync);
  } else if (typeof reduce.addListener === "function") {
    reduce.addListener(sync);
  }

  new IntersectionObserver(function (entries) {
    onScreen = entries[0].isIntersecting;
    sync();
  }, { threshold: 0.1 }).observe(svg);
})();
