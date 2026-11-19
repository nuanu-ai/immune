// "As it happens", alive while the page is open: `src/happens.rs` says what it promises.
//
// A running watcher writes view/live.js after every reading of program starts: one object of
// numbers, rule ids and fixed words, never text from an event or a rule. This loads it again
// every ten seconds, as a script because a browser refuses to fetch a local file, and redraws
// the section's numbers in place: the day's count and its bars, the week's matches, what was
// lost (its line shown only while something was), the file events checked, and each rule's
// count, found by its id; every rule's title stays as the page wrote it. Without the file, or with
// scripting off, the section is the page as it was made, and says when. It also shows what a
// technique's square is about, in a pop-up (`tips`).
(function () {
  "use strict";
  var EVERY = 10000; // milliseconds between loads
  var STALE = 60; // seconds without a new file before the page says it is not updating
  var H = 32; // the height of the bars, as the page drew them
  var sec = document.getElementById("as-it-happens");
  if (!sec) return;
  var latest = null;

  function one(name) {
    return sec.querySelector('[data-live="' + name + '"]');
  }
  function all(sel) {
    return sec.querySelectorAll(sel);
  }
  function num(n) {
    return Number(n).toLocaleString("en-US");
  }
  function hhmm(t) {
    return new Date(t * 1000).toISOString().slice(11, 16);
  }
  function set(name, text) {
    var el = one(name);
    if (el) el.textContent = text;
    return el;
  }

  // What the header says: how fresh the numbers are, or that nothing updates them.
  function said(live, now) {
    var age = live ? now - live.written_at_seconds : NaN;
    if (!(age <= STALE)) return "not updating: no watcher is running";
    var s = Math.max(0, Math.round(age));
    return "updated " + s + (s === 1 ? " second ago" : " seconds ago");
  }

  function bars(svg, h) {
    if (!svg || !h) return;
    var rects = svg.querySelectorAll("rect");
    var n = rects.length;
    if (n !== h.counts.length) return;
    var top = Math.max(1, Math.max.apply(null, h.counts));
    for (var i = 0; i < n; i++) {
      var c = h.counts[i];
      var bh = c > 0 ? Math.max(1.5, (c / top) * H) : 1.5;
      rects[i].setAttribute("y", (H - bh).toFixed(1));
      rects[i].setAttribute("height", bh.toFixed(1));
      rects[i].style.fill = c > 0 ? "var(--bar)" : "var(--sep)";
      var end = h.ends_at_seconds - (n - 1 - i) * h.step;
      var t = rects[i].querySelector("title");
      if (t)
        t.textContent =
          hhmm(end - h.step) + "–" + hhmm(end) + " UTC: " + num(c) +
          (c === 1 ? " program start" : " program starts");
    }
    svg.setAttribute(
      "aria-label",
      "Program starts by hour over the last 24 hours; the most in one hour: " + num(top)
    );
  }

  function rules(week) {
    var id;
    var sum = 0;
    for (id in week) sum += week[id];
    set("week", num(sum));
    var made = (sec.getAttribute("data-matched") || "").split(" ");
    var known = {};
    for (var k = 0; k < made.length; k++) known[made[k]] = true;
    var rows = all("[data-rule]");
    for (var i = 0; i < rows.length; i++) {
      var n = week[rows[i].getAttribute("data-rule")] || 0;
      var count = rows[i].querySelector(".rc");
      if (count) count.textContent = num(n);
    }
    var more = 0;
    for (id in week) if (week[id] > 0 && !known[id]) more++;
    var line = set(
      "more",
      more
        ? (more === 1 ? "1 more rule" : num(more) + " more rules") +
            " matched since the page was made; open it again from the app to see " +
            (more === 1 ? "it." : "them.")
        : ""
    );
    if (line) line.hidden = !more;
    var none = one("none");
    if (none) none.hidden = more > 0;
  }

  function draw(live) {
    var moved = live.state !== sec.getAttribute("data-state");
    var note = set(
      "moved",
      moved
        ? "Program starts are " + live.state_words +
            " now. The rest of this section is as the page was made; open it again from the app."
        : ""
    );
    if (note) note.hidden = !moved;
    sec.setAttribute("data-moved", moved ? "yes" : "no");
    if (moved || live.state !== "running") return;
    set("last_day", num(live.last_day));
    bars(one("hours"), live.by_hour);
    var lost = one("lost");
    if (lost && lost.textContent !== live.lost) {
      lost.textContent = live.lost;
      var notes = all('[data-live="lost-note"]');
      var shorts = live.caveats.map(function (c) {
        return c.short;
      });
      for (var i = 0; i < notes.length; i++) {
        notes[i].textContent = i === 0 ? shorts.join(" · ") : "";
        notes[i].hidden = i > 0;
      }
    }
    // The line of what was lost shows only while something was.
    var lostline = one("lostline");
    if (lostline) lostline.hidden = live.lost === "0";
    var files = live.file_events_last_day;
    if (typeof files === "number")
      set(
        "files",
        num(files) + (files === 1 ? " file event" : " file events") + " checked in the last day"
      );
    rules(live.matches_last_week || {});
  }

  function tell() {
    set("said", said(latest, Date.now() / 1000));
  }

  function load() {
    var s = document.createElement("script");
    s.src = "view/live.js?" + Date.now();
    s.onload = s.onerror = function () {
      s.remove();
      if (window.immunityLive) {
        latest = window.immunityLive;
        window.immunityLive = undefined;
        draw(latest);
      }
      tell();
    };
    document.head.appendChild(s);
  }

  // The grid of techniques: one pop-up for every square, shown while a square is pointed at or
  // has the keyboard's focus, with the technique's id and name, MITRE's first sentence of what
  // it is, and its state, read from the square's data- attributes and set as text. It goes
  // below the square, or above when there is no room below, never over it, and stays inside the
  // page's width. A square's title, which says the same with the script off, is taken off when
  // the square is pointed at, so the browser draws no second tooltip. The grid is one tab stop,
  // and the arrow keys move along it. Listened for on the grid, so a square drawn again works.
  function tips() {
    var grid = sec.querySelector(".tactics");
    var squares = grid ? grid.querySelectorAll(".m[data-t]") : [];
    if (!squares.length) return;
    var EDGE = 8; // the least space between the pop-up and the page's edge, in pixels
    var GAP = 6; // between the pop-up and its square
    var tip = document.createElement("div");
    tip.className = "tip";
    tip.id = "technique-tip";
    tip.setAttribute("role", "tooltip");
    tip.hidden = true;
    var lines = ["tt", "td", "ts"].map(function (name) {
      var line = document.createElement("span");
      line.className = name;
      tip.appendChild(line);
      return line;
    });
    document.body.appendChild(tip);
    for (var i = 0; i < squares.length; i++) squares[i].tabIndex = i ? -1 : 0;

    function square(e) {
      var t = e.target;
      return t && t.matches && t.matches(".m[data-t]") ? t : null;
    }
    function show(sq) {
      sq.removeAttribute("title");
      sq.setAttribute("aria-describedby", tip.id);
      lines[0].textContent = sq.getAttribute("data-t") + " " + sq.getAttribute("data-n");
      lines[1].textContent = sq.getAttribute("data-d");
      lines[2].textContent = sq.getAttribute("data-s");
      tip.hidden = false;
      var r = sq.getBoundingClientRect();
      var w = tip.offsetWidth;
      var h = tip.offsetHeight;
      var left = Math.max(EDGE, Math.min(r.left, document.documentElement.clientWidth - w - EDGE));
      var below = r.bottom + GAP + h <= window.innerHeight || r.top - GAP - h < 0;
      tip.style.left = left + window.scrollX + "px";
      tip.style.top = (below ? r.bottom + GAP : r.top - GAP - h) + window.scrollY + "px";
    }
    function hide() {
      tip.hidden = true;
    }
    grid.addEventListener("pointerover", function (e) {
      var sq = square(e);
      if (sq) show(sq);
    });
    // A touch leaves the pop-up up until the next touch elsewhere.
    grid.addEventListener("pointerout", function (e) {
      if (square(e) && e.pointerType !== "touch") hide();
    });
    document.addEventListener("pointerdown", function (e) {
      if (!square(e)) hide();
    });
    grid.addEventListener("focusin", function (e) {
      var sq = square(e);
      if (sq) show(sq);
    });
    grid.addEventListener("focusout", hide);
    grid.addEventListener("keydown", function (e) {
      var sq = square(e);
      if (!sq) return;
      if (e.key === "Escape") return hide();
      var step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
      var all = grid.querySelectorAll(".m[data-t]");
      var next = step && all[Array.prototype.indexOf.call(all, sq) + step];
      if (!next) return;
      e.preventDefault();
      sq.tabIndex = -1;
      next.tabIndex = 0;
      next.focus();
    });
  }

  tips();
  load();
  setInterval(load, EVERY);
  setInterval(tell, 1000);
})();
