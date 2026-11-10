// Outbound requests to request-controlled URLs.
const axios = require("axios");
const https = require("https");

async function proxy(req, res) {
  const r = await fetch(req.query.url); // expect: ssrf
  res.send(await r.text());
}

async function preview(req) {
  return axios.get(req.body.link); // expect: ssrf
}

function avatar(req, res) {
  const target = "http://" + req.query.host + "/avatar.png";
  https.get(target, (r) => r.pipe(res)); // expect: ssrf
}

module.exports = { proxy, preview, avatar };
