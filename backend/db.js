// db.js (backend del website)
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const DB_PATH =
  process.env.DATABASE_PATH ||
  path.join(__dirname, "data", "hyperion-site.sqlite");

// crear carpeta /data si no existe
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

module.exports = db;
