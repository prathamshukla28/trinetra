// Tricky negatives: text sinks, static HTML, and sanitized HTML.

function safeText() {
  document.getElementById("out").textContent = location.hash; // ok: dom-xss (textContent is not an HTML sink)
}

function staticHtml(el) {
  el.innerHTML = "<b>Loading…</b>"; // ok: dom-xss (static markup)
}

function purified(el) {
  el.innerHTML = DOMPurify.sanitize(location.hash); // ok: dom-xss (sanitized with DOMPurify)
}

function cleared(el) {
  el.innerHTML = ""; // ok: dom-xss (clearing)
}

function escaped(el, s) {
  el.innerHTML = escapeHtml(s); // ok: dom-xss (HTML-escaped)
}

export { safeText, staticHtml, purified, cleared, escaped };
