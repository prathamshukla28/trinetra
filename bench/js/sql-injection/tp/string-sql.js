// SQL strings built from request input.

async function find(req, db) {
  return db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`); // expect: sql-injection
}

async function del(req, pool) {
  return pool.query("DELETE FROM posts WHERE id = " + req.params.id); // expect: sql-injection
}

async function search(req, conn) {
  const term = req.body.term;
  const sql = "SELECT * FROM items WHERE title LIKE '%" + term + "%'";
  return conn.execute(sql); // expect: sql-injection (query built in a variable first)
}

async function knexRaw(req, knex) {
  return knex.raw(`SELECT * FROM t ORDER BY ${req.query.sort}`); // expect: sql-injection
}

module.exports = { find, del, search, knexRaw };
