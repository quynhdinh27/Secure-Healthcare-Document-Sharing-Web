// Minimal mysql2/promise double. SQL reaches the handler with whitespace collapsed,
// so tests can match on stable fragments. Transaction calls are recorded in events.
function createFakeMysql(handler) {
  const events = [];
  const run = async (sql, args = []) => handler(sql.replace(/\s+/g, ' ').trim(), args, events);
  const connection = {
    execute: run,
    query: run,
    async beginTransaction() { events.push('begin'); },
    async commit() { events.push('commit'); },
    async rollback() { events.push('rollback'); },
    release() { events.push('release'); },
  };
  const pool = { execute: run, query: run, async getConnection() { return connection; } };
  return { connection, events, pool };
}

module.exports = { createFakeMysql };
