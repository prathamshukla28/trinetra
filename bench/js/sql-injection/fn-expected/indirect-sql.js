// SQL injection the analyzer is expected to miss (documented limits).

async function byName(db, name) {
  return db.query(`SELECT * FROM users WHERE name = '${name}'`); // expect: sql-injection (taint arrives through a parameter)
}

function handler(req, db) {
  return byName(db, req.query.name);
}

async function joined(req, db) {
  const sql = ["SELECT * FROM t WHERE id =", req.query.id].join(" ");
  return db.query(sql); // expect: sql-injection (query assembled with Array.join)
}

module.exports = { handler, joined };
