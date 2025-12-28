// db.js (backend del website)
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

// En Render: setear DATABASE_PATH=/var/data/hyperion-site.sqlite
// En local: cae a ./data/hyperion-site.sqlite dentro del repo
const DEFAULT_DB_PATH = path.join(process.cwd(), "data", "hyperion-site.sqlite");
const DB_PATH = process.env.DATABASE_PATH || DEFAULT_DB_PATH;

// crear carpeta si no existe
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);

// pragmas recomendados
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

console.log("[db] SQLite path =", DB_PATH);

module.exports = db;
