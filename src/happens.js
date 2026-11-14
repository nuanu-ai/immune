// "As it happens", alive while the page is open: `src/happens.rs` says what it promises.
//
// A running watcher writes view/live.js after every reading of program starts: one object of
// numbers, rule ids and fixed words, never text from an event or a rule. This loads it again
// every ten seconds, as a script because a browser refuses to fetch a local file, and redraws
// the section's numbers in place: the day's count and its bars, the week's matches, what was
// lost (its line shown only while something was), the file events checked, and each rule's
// count, found by its id; every title stays as the page wrote it. Without the file, or with
// scripting off, the section is the page as it was made, and says when.
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
      if (window.immuneLive) {
        latest = window.immuneLive;
        window.immuneLive = undefined;
        draw(latest);
      }
      tell();
    };
    document.head.appendChild(s);
  }

  load();
  setInterval(load, EVERY);
  setInterval(tell, 1000);
})();
