// Modules loaded from attacker-influenced paths.

function loadPlugin(req) {
  return require(req.query.plugin); // expect: dynamic-require
}

async function loadLocale(req) {
  return import(`./locales/${req.params.lang}.js`); // expect: dynamic-require
}

function fromArgv() {
  const mod = process.argv[2];
  const name = "./handlers/" + mod;
  return require(name); // expect: dynamic-require
}

module.exports = { loadPlugin, loadLocale, fromArgv };
