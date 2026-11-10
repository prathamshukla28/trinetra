// DOM XSS sinks the analyzer is expected to miss (documented limits).

export function viaJquery() {
  $("#out").html(location.hash); // expect: dom-xss (jQuery .html() is not modelled)
}

export function viaRange() {
  const frag = document.createRange().createContextualFragment(location.hash); // expect: dom-xss (createContextualFragment is not modelled)
  document.body.appendChild(frag);
}

export function Preview() {
  return <div dangerouslySetInnerHTML={{ __html: location.hash }} />; // expect: dom-xss (React dangerouslySetInnerHTML is not modelled)
}
