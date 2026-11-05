// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
// Progressive enhancement for the score-versus-evidence comparison. The markup shows both panels so the
// page reads with JavaScript off; this script adds the two-button control, shows one panel at a time and
// marks the other `hidden` and inert. It builds no markup from strings, and a missing section leaves the
// page as written.

(function () {
  "use strict";

  var root = document.querySelector("[data-compare]");
  if (!root) {
    return;
  }

  var stage = root.querySelector(".cmp");
  var panels = root.querySelector(".panels");
  var rrPanel = document.getElementById("cmp-rr");
  var genPanel = document.getElementById("cmp-gen");
  var big = document.getElementById("cmp-big");
  if (!stage || !panels || !rrPanel || !genPanel) {
    return;
  }

  var reduce = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;

  function reduced() {
    return reduce !== null && reduce.matches;
  }

  function setInert(element, value) {
    element.inert = value;
    if (value) {
      element.setAttribute("inert", "");
    } else {
      element.removeAttribute("inert");
    }
  }

  var group = document.createElement("div");
  group.className = "seg";
  group.setAttribute("role", "group");
  group.setAttribute("aria-label", root.getAttribute("data-label-group") || "View");

  var choices = [
    { name: "rr", label: root.getAttribute("data-label-rr") || "rongroi" },
    { name: "gen", label: root.getAttribute("data-label-gen") || "Made-up picture" }
  ];

  var countToken = 0;

  function countUp() {
    if (!big) {
      return;
    }
    var token = ++countToken;
    if (reduced() || typeof window.requestAnimationFrame !== "function") {
      big.textContent = "87";
      return;
    }
    big.textContent = "0";
    var start = window.performance.now();
    (function frame(now) {
      if (token !== countToken) {
        return;
      }
      if (reduced()) {
        big.textContent = "87";
        return;
      }
      var progress = Math.min(1, (now - start) / 900);
      big.textContent = String(Math.round(87 * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) {
        window.requestAnimationFrame(frame);
      }
    })(start);
  }

  function show(choice) {
    var generic = choice === "gen";
    choices.forEach(function (item) {
      item.button.setAttribute("aria-pressed", String(item.name === choice));
    });

    rrPanel.hidden = generic;
    genPanel.hidden = !generic;
    setInert(rrPanel, generic);
    setInert(genPanel, !generic);
    // Let the newly shown panel take its base style before the draw-in class lands.
    void panels.offsetWidth;
    rrPanel.classList.toggle("on", !generic);
    genPanel.classList.toggle("on", generic);

    if (generic) {
      countUp();
    } else {
      countToken += 1;
      if (big) {
        big.textContent = "87";
      }
    }
  }

  choices.forEach(function (item) {
    var button = document.createElement("button");
    button.type = "button";
    button.textContent = item.label;
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", function () {
      if (button.getAttribute("aria-pressed") === "true") {
        return;
      }
      show(item.name);
    });
    item.button = button;
    group.appendChild(button);
  });

  stage.insertBefore(group, panels);
  root.classList.add("ready");

  // Both panels are in the markup; from here the generic one waits until its button is pressed.
  genPanel.hidden = true;
  setInert(genPanel, true);
  show("rr");
})();
