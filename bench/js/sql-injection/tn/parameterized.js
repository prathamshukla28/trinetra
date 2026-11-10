// Tricky negatives: parameterized queries, numeric coercion, regex exec.

async function param(req, db) {
  return db.query("SELECT * FROM users WHERE id = $1", [req.params.id]); // ok: sql-injection (placeholder + values)
}

async function paramObj(req, pool) {
  return pool.query({ text: "SELECT * FROM t WHERE name = $1", values: [req.query.name] }); // ok: sql-injection (query config object)
}

async function placeholders(req, conn) {
  const sql = "SELECT * FROM items WHERE owner = ? AND status = ?";
  return conn.execute(sql, [req.user.id, req.query.status]); // ok: sql-injection (placeholders in a variable)
}

function regexExec(req) {
  return /^\d+$/.exec(req.query.id); // ok: sql-injection (RegExp.prototype.exec)
}

async function numeric(req, db) {
  return db.query(`SELECT * FROM t LIMIT ${parseInt(req.query.limit, 10)}`); // ok: sql-injection (parseInt)
}

async function staticQuery(db) {
  return db.query("SELECT 1"); // ok: sql-injection (literal)
}

module.exports = { param, paramObj, placeholders, regexExec, numeric, staticQuery };
