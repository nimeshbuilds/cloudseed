/* cloudseed site behaviour (no dependencies): the landing page's typed terminal demo, copy buttons, the console
 * screenshot tabs and the GitHub star count; on docs pages, unbreakable short inline code and full-size diagrams.
 * Runs on every page load, including Material's instant navigation (document$), and does nothing on pages without
 * these elements. */
(function () {
  "use strict";

  var running = [];   // stop functions of the current page's animations (instant navigation swaps the page)

  function reducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  /* ---------------------------------------------------------------- terminal demo */
  function initTerminal(root) {
    if (root.dataset.csReady) return;
    root.dataset.csReady = "1";
    if (reducedMotion()) return;          // the full transcript stays visible and scrollable

    var screen = root.querySelector(".cs-term__screen");
    var lines = Array.prototype.slice.call(screen.querySelectorAll(".l"));
    var steps = Array.prototype.slice.call(root.querySelectorAll("[data-cs-step]"));
    var cursor = document.createElement("span");
    cursor.className = "cs-term__cursor";
    var stopped = false, visible = true, gen = 0;

    root.classList.add("is-live");

    var observer = "IntersectionObserver" in window ? new IntersectionObserver(function (entries) {
      visible = entries[0].isIntersecting;
    }, { threshold: 0.15 }) : null;
    if (observer) observer.observe(root);

    function sleep(ms) {
      var my = gen;
      return new Promise(function (resolve) {
        var left = ms;
        (function tick() {
          if (stopped || my !== gen) return;        // abandoned: never resolves, the loop just ends
          var paused = !visible || document.hidden;
          if (!paused) left -= 50;
          if (left <= 0) resolve(); else setTimeout(tick, 50);
        })();
      });
    }

    function setStep(n) {
      steps.forEach(function (s) { s.classList.toggle("is-active", String(n) === s.getAttribute("data-cs-step")); });
    }

    function scroll() { screen.scrollTop = screen.scrollHeight; }

    async function typeCommand(line) {
      var target = line.querySelector(".c");
      var text = target.getAttribute("data-text") || target.textContent;
      target.setAttribute("data-text", text);
      target.textContent = "";
      line.classList.add("on");
      line.appendChild(cursor);
      scroll();
      await sleep(550);
      for (var i = 0; i < text.length; i++) {
        target.textContent = text.slice(0, i + 1);
        await sleep(38 + Math.random() * 55);
      }
      await sleep(420);
      if (cursor.parentNode) cursor.parentNode.removeChild(cursor);
    }

    async function play() {
      var my = gen;
      lines.forEach(function (l) { l.classList.remove("on"); });
      screen.scrollTop = 0;
      for (var i = 0; i < lines.length; i++) {
        if (stopped || my !== gen) return;
        var line = lines[i];
        if (line.classList.contains("cmd")) {
          setStep(line.getAttribute("data-step"));
          await typeCommand(line);
        } else {
          await sleep(parseInt(line.getAttribute("data-d") || "140", 10));
          line.classList.add("on");
          scroll();
        }
      }
      await sleep(5200);
      if (stopped || my !== gen) return;
      gen++;
      play();
    }

    play();
    running.push(function () { stopped = true; if (observer) observer.disconnect(); });
  }

  /* ---------------------------------------------------------------- copy buttons */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); } catch (e) { reject(e); }
      document.body.removeChild(area);
    });
  }

  function initCopy(button) {
    if (button.dataset.csReady) return;
    button.dataset.csReady = "1";
    button.addEventListener("click", function () {
      copyText(button.getAttribute("data-cs-copy")).then(function () {
        button.classList.add("is-copied");
        var label = button.getAttribute("aria-label");
        button.setAttribute("aria-label", "Copied to clipboard");
        setTimeout(function () { button.classList.remove("is-copied"); button.setAttribute("aria-label", label); }, 1600);
      }, function () {});
    });
  }

  /* ---------------------------------------------------------------- screenshot tabs (ARIA tabs pattern) */
  function initTabs(root) {
    if (root.dataset.csReady) return;
    root.dataset.csReady = "1";
    var tabs = Array.prototype.slice.call(root.querySelectorAll('[role="tab"]'));
    var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute("aria-controls")); });
    root.classList.add("is-ready");

    function select(index, focus) {
      tabs.forEach(function (tab, i) {
        var on = i === index;
        tab.setAttribute("aria-selected", on ? "true" : "false");
        tab.tabIndex = on ? 0 : -1;
        panels[i].hidden = !on;
        panels[i].classList.toggle("is-entering", on);
      });
      if (focus) tabs[index].focus();
      var strip = tabs[index].parentNode;
      if (strip.scrollWidth > strip.clientWidth) {
        strip.scrollTo({ left: tabs[index].offsetLeft - 16, behavior: reducedMotion() ? "auto" : "smooth" });
      }
    }

    tabs.forEach(function (tab, i) {
      tab.addEventListener("click", function () { select(i, false); });
      tab.addEventListener("keydown", function (e) {
        var next = null;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") next = (i + 1) % tabs.length;
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") next = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") next = 0;
        else if (e.key === "End") next = tabs.length - 1;
        if (next !== null) { e.preventDefault(); select(next, true); }
      });
    });
    var first = tabs.findIndex(function (t) { return t.getAttribute("aria-selected") === "true"; });
    select(first < 0 ? 0 : first, false);
    panels.forEach(function (p) { p.classList.remove("is-entering"); });
  }

  /* ---------------------------------------------------------------- GitHub stars
   * Material already asks the GitHub API for the repository's facts (header widget) and caches them for the session
   * (__source); reuse them instead of making a second request. */
  function formatCount(n) {
    return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1).replace(/\.0$/, "") + "k" : String(n);
  }

  function sourceFacts() {
    try { return typeof window.__md_get === "function" ? window.__md_get("__source", sessionStorage) : null; } catch (e) { return null; }
  }

  function initStars(targets) {
    if (!targets.length) return;
    var tries = 0;
    (function poll() {
      var facts = sourceFacts();
      if (facts && typeof facts.stars === "number") {
        if (facts.stars > 0) targets.forEach(function (el) { el.textContent = formatCount(facts.stars); el.hidden = false; });
        return;
      }
      if (++tries < 16 && document.contains(targets[0])) setTimeout(poll, 500);
    })();
  }

  /* ---------------------------------------------------------------- inline code
   * Short inline code (a flag, an identifier, a short command) never breaks across lines: "--dry-run" must not end
   * a line with "--". Longer spans still wrap at spaces (extra.css). */
  function keepShortCodeTogether() {
    var spans = document.querySelectorAll(".md-typeset :not(pre) > code:not(.cs-nw)");
    for (var i = 0; i < spans.length; i++) if (spans[i].textContent.length <= 28) spans[i].classList.add("cs-nw");
  }
  keepShortCodeTogether();              // before the first paint: this script runs at the end of <body>

  /* ---------------------------------------------------------------- diagrams at full size
   * Material draws each mermaid diagram into a closed shadow root that fits the content column, so a wide diagram
   * gets small text. Each diagram (overrides/hooks.py wraps it in .cs-diagram) gets a button that draws it again,
   * at its natural size, in a dialog that scrolls. The source is kept before Material replaces the <pre>: Material
   * swaps it only after an asynchronous render, so it is still there when this runs. */
  var lightbox = null, drawn = 0;

  function openDiagram(src) {
    if (typeof window.mermaid === "undefined" || !window.mermaid.render) return;
    if (!lightbox) {
      lightbox = document.createElement("dialog");
      lightbox.className = "cs-lightbox";
      lightbox.setAttribute("aria-label", "Diagram at full size");
      lightbox.innerHTML = '<button type="button" class="cs-lightbox__close" aria-label="Close">&times;</button><div class="cs-lightbox__body"></div>';
      lightbox.addEventListener("click", function (e) { if (e.target === lightbox || e.target.closest(".cs-lightbox__close")) lightbox.close(); });
      document.body.appendChild(lightbox);
    }
    var body = lightbox.querySelector(".cs-lightbox__body");
    window.mermaid.render("cs-lightbox-" + (++drawn), src).then(function (out) {
      body.innerHTML = out.svg;
      var svg = body.querySelector("svg");
      var natural = svg && parseFloat(svg.style.maxWidth);
      if (svg && natural) { svg.style.maxWidth = "none"; svg.style.width = natural + "px"; svg.removeAttribute("height"); }
      if (!lightbox.open) lightbox.showModal();
      body.scrollTop = 0; body.scrollLeft = 0;
    }, function () {});
  }

  function initDiagram(frame) {
    if (frame.dataset.csReady) return;
    var pre = frame.querySelector("pre");
    if (!pre) return;                                   // already drawn: its source is gone
    frame.dataset.csReady = "1";
    var src = pre.textContent;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "cs-diagram__expand";
    button.setAttribute("aria-label", "Open the diagram at full size");
    button.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10 21v-2H6.41l4.5-4.5-1.41-1.41-4.5 4.5V14H3v7zm4.5-10.09 4.5-4.5V10h2V3h-7v2h3.59l-4.5 4.5z"/></svg><span>Full size</span>';
    button.addEventListener("click", function () { openDiagram(src); });
    frame.appendChild(button);
  }

  /* ---------------------------------------------------------------- page lifecycle */
  function init() {
    keepShortCodeTogether();
    var search = document.querySelector('.md-search[role="dialog"]:not([aria-label])');
    if (search) search.setAttribute("aria-label", "Search the documentation");   // Material leaves its dialog unnamed
    running.splice(0).forEach(function (stop) { stop(); });
    document.querySelectorAll("[data-cs-term]").forEach(initTerminal);
    document.querySelectorAll("[data-cs-copy]").forEach(initCopy);
    document.querySelectorAll("[data-cs-tabs]").forEach(initTabs);
    document.querySelectorAll(".cs-diagram").forEach(initDiagram);
    initStars(Array.prototype.slice.call(document.querySelectorAll("[data-cs-stars-count]")));
  }

  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(init);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
