// DOM-based XSS: URL-derived or caller-supplied HTML written to the DOM.

function render() {
  document.getElementById("out").innerHTML = location.hash.slice(1); // expect: dom-xss
}

function greet() {
  const name = new URLSearchParams(location.search).get("name");
  document.write("<h1>Hello " + name + "</h1>"); // expect: dom-xss
}

function banner(msg) {
  document.querySelector("#banner").outerHTML = `<div>${msg}</div>`; // expect: dom-xss
}

function append(el, items) {
  el.insertAdjacentHTML("beforeend", items.join("")); // expect: dom-xss
}

export { render, greet, banner, append };
