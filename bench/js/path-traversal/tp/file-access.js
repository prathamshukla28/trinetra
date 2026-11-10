// Filesystem paths built from request input.
const fs = require("fs");
const path = require("path");
const fsp = require("fs/promises");

function download(req, res) {
  const file = path.join("/srv/files", req.query.name);
  fs.createReadStream(file).pipe(res); // expect: path-traversal
}

async function readUpload(req) {
  return fsp.readFile(`./uploads/${req.params.id}`); // expect: path-traversal
}

function sendIt(req, res) {
  res.sendFile(req.params[0], { root: "/" }); // expect: path-traversal
}

function remove(req) {
  const target = req.body.path;
  const resolved = path.resolve(target);
  fs.unlinkSync(resolved); // expect: path-traversal
}

module.exports = { download, readUpload, sendIt, remove };
