/* cloudseed site behaviour (no dependencies): copy buttons, architecture and console tabs;
 * on docs pages, unbreakable short inline code and full-size diagrams.
 * Runs on every page load, including Material's instant navigation (document$), and does nothing on pages without
 * these elements. */
(function () {
  "use strict";

  function reducedMotion() {
    return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
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
        var status = document.querySelector("[data-cs-copy-status]");
        if (status) status.textContent = "Copied to clipboard.";
        var label = button.getAttribute("aria-label");
        button.setAttribute("aria-label", "Copied to clipboard");
        setTimeout(function () { button.classList.remove("is-copied"); button.setAttribute("aria-label", label); }, 1600);
      }, function () {
        var status = document.querySelector("[data-cs-copy-status]");
        if (status) status.textContent = "Copy unavailable. Select and copy the command manually.";
      });
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
    document.querySelectorAll("[data-cs-copy]").forEach(initCopy);
    document.querySelectorAll("[data-cs-tabs]").forEach(initTabs);
    document.querySelectorAll(".cs-diagram").forEach(initDiagram);
  }

  if (typeof window.document$ !== "undefined" && window.document$.subscribe) {
    window.document$.subscribe(init);
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
