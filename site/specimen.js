// SPDX-FileCopyrightText: 2026 aeterna-rongroi contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Part of aeterna-rongroi, a cheat-detection tool. Using it to evade detection is out of scope — see AGENTS.md.
// Progressive enhancement for the specimen card: the search box and the tally boxes hide rows the page
// already shows, and a row's copy button puts its JSON on the clipboard. All its words come from the
// figure's data-msg-* attributes, so with JavaScript off, or a missing element, the card stays as written.

(function () {
  "use strict";

  var figure = document.getElementById("specimen");
  var query = document.getElementById("specimen-q");
  var rowsBox = document.getElementById("specimen-rows");
  var empty = document.getElementById("specimen-empty");
  var live = document.getElementById("specimen-live");
  var msgCount = figure && figure.getAttribute("data-msg-count");
  var msgCopied = figure && figure.getAttribute("data-msg-copied");
  var msgFailed = figure && figure.getAttribute("data-msg-copy-failed");
  if (!figure || !query || !rowsBox || !empty || !live || !msgCount || !msgCopied || !msgFailed) {
    return;
  }
  var rows = Array.prototype.slice.call(rowsBox.querySelectorAll(".specimen-row"));
  var boxes = Array.prototype.slice.call(figure.querySelectorAll(".tally-box"));
  var filter = "";

  function say(text) {
    live.textContent = text;
  }

  // A row stays while the search finds its text and the pressed box, if any, names its state.
  function apply() {
    var want = query.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (row) {
      var text = (row.getAttribute("data-search") || "").toLowerCase();
      var state = row.getAttribute("data-state") || "";
      var visible = text.indexOf(want) !== -1 && (filter === "" || state === filter);
      row.hidden = !visible;
      if (visible) {
        shown += 1;
      }
    });
    empty.hidden = shown === 0;
    say(msgCount.replace("{n}", String(shown)).replace("{total}", String(rows.length)));
  }

  // Pressing a box filters by its state; pressing the pressed one again clears the filter.
  function press(next) {
    filter = filter === next ? "" : next;
    boxes.forEach(function (box) {
      var name = box.getAttribute("data-filter") || "";
      box.setAttribute("aria-pressed", name === filter ? "true" : "false");
    });
    apply();
  }

  // The clipboard API can be absent (an insecure context, an old browser) or refuse the write. Both say
  // the failed message; nothing reaches the page as an exception.
  function copy(button) {
    var done = null;
    try {
      var clip = navigator.clipboard;
      if (!clip || typeof clip.writeText !== "function") {
        say(msgFailed);
        return;
      }
      done = clip.writeText(button.getAttribute("data-json") || "");
    } catch (err) {
      say(msgFailed);
      return;
    }
    if (done && typeof done.then === "function") {
      done.then(function () { say(msgCopied); }, function () { say(msgFailed); });
    } else {
      say(msgFailed); // No promise to wait on, so nobody can confirm the text arrived.
    }
  }

  query.addEventListener("input", apply);
  boxes.forEach(function (box) {
    var name = box.getAttribute("data-filter") || "";
    box.addEventListener("click", function () { press(name); });
  });
  Array.prototype.slice.call(figure.querySelectorAll("[data-copy]")).forEach(function (button) {
    button.addEventListener("click", function () { copy(button); });
  });
  apply();
})();
