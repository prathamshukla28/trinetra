// Security-relevant randomness the analyzer is expected to miss (documented limits).

function makeInvite() {
  const r = Math.random(); // expect: insecure-random (sensitive use only visible later)
  return r.toString(36).slice(2);
}

function login(req, res) {
  res.cookie("sid", Math.random().toString(36)); // expect: insecure-random (cookie value, neutral names)
}

module.exports = { makeInvite, login };
