// backend/server.js (WEBSITE BACKEND)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./db");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ⚠️ En producción: SI O SI setearlos como env vars (no hardcode)
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_ME_IN_PROD_JWT_SECRET";
const ADMIN_API_KEY =
  process.env.ADMIN_API_KEY || "CHANGE_ME_IN_PROD_ADMIN_KEY";

// DB schema (se crea al boot)
db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  plan TEXT DEFAULT 'starter',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL,
  plan_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', -- active | revoked | suspended | expired
  max_activations INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS license_activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL,
  install_id TEXT NOT NULL,
  device_name TEXT,
  first_activated_at TEXT,
  last_seen_at TEXT,
  app_version TEXT,
  UNIQUE(license_id, install_id),
  FOREIGN KEY(license_id) REFERENCES licenses(id)
);

-- ✅ NUEVO: denylist por dispositivo (revocar un PC)
CREATE TABLE IF NOT EXISTS revoked_installs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  install_id TEXT NOT NULL,
  reason TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, install_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS contact_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  company TEXT,
  message TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  source TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  priority TEXT NOT NULL DEFAULT 'normal',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ticket_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_id INTEGER NOT NULL,
  sender TEXT NOT NULL DEFAULT 'user',
  message TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(ticket_id) REFERENCES tickets(id)
);
`);

// =========================
// Planes + límites técnicos
// =========================
const PLANS = [
  {
    id: "starter",
    name: "Starter",
    tag: "Gratis",
    price: "$0",
    price_suffix: "/ mes",
    highlight: false,
    cta: "Empezar gratis",
    features: [
      "1 cuenta de WhatsApp",
      "Validación local de contactos",
      "Warmup desactivado",
      "1 dispositivo instalado",
    ],
  },
  {
    id: "pro",
    name: "Pro",
    tag: "Recomendado",
    price: "$79",
    price_suffix: "/ mes",
    highlight: true,
    cta: "Probar Hyperion Pro",
    features: [
      "Hasta 5 cuentas de WhatsApp",
      "Warmup inteligente",
      "Stats avanzadas por cuenta",
      "Soporte prioritario",
      "Hasta 2 dispositivos instalados",
    ],
  },
  {
    id: "lifetime",
    name: "Lifetime",
    tag: "Pago único",
    price: "$699",
    price_suffix: "pago único",
    highlight: false,
    cta: "Comprar licencia Lifetime",
    features: [
      "Hasta 20 cuentas de WhatsApp",
      "Mensajes diarios elevados",
      "Warmup habilitado",
      "Soporte prioritario",
      "Hasta 5 dispositivos instalados",
    ],
  },
  {
    id: "agency",
    name: "Agency",
    tag: "Agencias",
    price: "$299",
    price_suffix: "/ mes",
    highlight: false,
    cta: "Hablar con ventas",
    features: [
      "14 cuentas de WhatsApp",
      "Warmup agresivo ajustable",
      "Soporte dedicado",
      "Asistencia en onboarding y setup",
      "Hasta 3 dispositivos instalados",
    ],
  },
];

const PLAN_LIMITS = {
  starter: { maxAccounts: 1, maxWorkers: 1, maxMessagesPerDay: 30, warmupEnabled: false, maxDevices: 1 },
  pro: { maxAccounts: 5, maxWorkers: 5, maxMessagesPerDay: 800, warmupEnabled: true, maxDevices: 2 },
  lifetime: { maxAccounts: 20, maxWorkers: 20, maxMessagesPerDay: 50000000, warmupEnabled: true, maxDevices: 5 },
  agency: { maxAccounts: 14, maxWorkers: 14, maxMessagesPerDay: 5000, warmupEnabled: true, maxDevices: 3 },
};

const PLAN_DEVICE_LIMIT = { starter: 1, pro: 2, lifetime: 5, agency: 3 };
const DEFAULT_MAX_ACTIVATIONS = 1;

function getPlanLimits(planId) {
  return PLAN_LIMITS[planId] || PLAN_LIMITS.starter;
}

// =========================
// CORS (configurable)
const CORS_ALLOW_ORIGINS = String(process.env.CORS_ALLOW_ORIGINS || "");
const CORS_ALLOW_LIST = CORS_ALLOW_ORIGINS.split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || CORS_ALLOW_LIST.length === 0 || CORS_ALLOW_LIST.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

function createToken(userRow) {
  return jwt.sign({ id: userRow.id, email: userRow.email }, JWT_SECRET, { expiresIn: "30d" });
}

function authMiddleware(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Token requerido" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    return next();
  } catch (_err) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireAdmin(req, res, next) {
  const key =
    req.headers["x-admin-api-key"] ||
    req.headers["x-admin-key"] ||
    req.query.admin_key ||
    req.query.api_key;

  if (!key || key !== ADMIN_API_KEY) return res.status(403).json({ error: "No autorizado" });
  return next();
}

function generateLicenseKey() {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function cmpSemver(a, b) {
  const pa = String(a || "0.0.0")
    .split(".")
    .map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b || "0.0.0")
    .split(".")
    .map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    if (pa[i] > pb[i]) return 1;
    if (pa[i] < pb[i]) return -1;
  }
  return 0;
}

function isLicenseActiveNow(l) {
  if (!l) return false;
  if (l.status !== "active") return false;
  if (!l.expires_at) return true;
  return Date.parse(l.expires_at) > Date.now();
}

// prioridad (ajustala a tu gusto)
const PLAN_RANK = { starter: 0, pro: 1, lifetime: 2, agency: 3 };

function pickBestPlan(planIds = []) {
  let best = "starter";
  for (const p of planIds) {
    const k = String(p || "starter").toLowerCase();
    if ((PLAN_RANK[k] ?? -1) > (PLAN_RANK[best] ?? 0)) best = k;
  }
  return best;
}

function getEffectivePlanForUser(userId) {
  const rows = db
    .prepare("SELECT plan_id, status, expires_at FROM licenses WHERE user_id = ?")
    .all(userId);

  const active = rows.filter(isLicenseActiveNow).map((r) => r.plan_id);
  return pickBestPlan(active);
}

function enrichUserForClient(userRow) {
  const planId = getEffectivePlanForUser(userRow.id); // ✅ plan real por licencias activas
  const limits = getPlanLimits(planId);
  return {
    id: userRow.id,
    email: userRow.email,
    plan: planId,
    max_accounts: limits.maxAccounts,
    messages_per_day: limits.maxMessagesPerDay,
    warmup_enabled: !!limits.warmupEnabled,
    max_workers: limits.maxWorkers,
    max_devices: limits.maxDevices,
  };
}

function isValidEmail(email) {
  const value = String(email || "").trim().toLowerCase();
  if (!value) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isInstallRevoked(userId, installId) {
  try {
    const row = db
      .prepare("SELECT id FROM revoked_installs WHERE user_id = ? AND install_id = ? LIMIT 1")
      .get(userId, String(installId || "").trim());
    return !!row;
  } catch (_) {
    return false;
  }
}

// =========================
// Update policy: /api/app/version
// =========================
app.get("/api/app/version", (req, res) => {
  const current = String(req.query.current || req.query.version || req.headers["x-app-version"] || "0.0.0");
  const minVersion = String(process.env.HYPERION_MIN_VERSION || "0.0.0");
  const latest = String(process.env.HYPERION_LATEST_VERSION || minVersion);
  const downloadUrl = String(process.env.HYPERION_DOWNLOAD_URL || "");
  const notes = String(process.env.HYPERION_RELEASE_NOTES || "");

  res.json({
    ok: true,
    current,
    min_version: minVersion,
    latest,
    download_url: downloadUrl,
    notes,
    update_required: cmpSemver(current, minVersion) < 0,
  });
});

// =========================
// Rutas públicas
// =========================
app.get("/api/health", (_req, res) => res.json({ ok: true }));
app.get("/api/plans", (_req, res) => res.json({ plans: PLANS }));

// ✅ NUEVO: /api/me (para refrescar plan real desde la app / postman)
app.get("/api/me", authMiddleware, (req, res) => {
  try {
    const userRow = db.prepare("SELECT id, email, plan FROM users WHERE id = ?").get(req.user.id);
    if (!userRow) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });

    const user = enrichUserForClient(userRow);
    return res.json({ ok: true, user });
  } catch (err) {
    console.error("Error en /api/me", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.post("/api/contact", (req, res) => {
  try {
    const { name, email, company, message } = req.body || {};
    if (!name || !email || !message) {
      return res.status(400).json({ ok: false, error: "Nombre, email y mensaje son requeridos" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Email inválido" });
    }

    const nowIso = new Date().toISOString();
    const info = db
      .prepare(
        `INSERT INTO contact_messages (name, email, company, message, created_at)
         VALUES (?,?,?,?,?)`
      )
      .run(String(name).trim(), String(email).trim().toLowerCase(), company || null, String(message).trim(), nowIso);

    return res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error("Error en /api/contact", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

app.post("/api/newsletter", (req, res) => {
  try {
    const { email, source } = req.body || {};
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: "Email inválido" });
    }

    const stmt = db.prepare(
      `INSERT INTO newsletter_subscribers (email, source, status, created_at)
       VALUES (?,?,?,?)`
    );
    try {
      stmt.run(String(email).trim().toLowerCase(), source || "site", "active", new Date().toISOString());
    } catch (err) {
      if (String(err?.message || "").includes("UNIQUE")) {
        return res.json({ ok: true, status: "already_subscribed" });
      }
      throw err;
    }

    return res.json({ ok: true, status: "subscribed" });
  } catch (err) {
    console.error("Error en /api/newsletter", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// =========================
// Auth: registro / login
// =========================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(emailNorm);
    if (existing) return res.status(400).json({ error: "Ese email ya está registrado" });

    const passwordHash = await bcrypt.hash(password, 10);
    const plan = "starter";

    const info = db
      .prepare("INSERT INTO users (email, password_hash, plan) VALUES (?,?,?)")
      .run(emailNorm, passwordHash, plan);

    const userRow = db.prepare("SELECT id, email, plan FROM users WHERE id = ?").get(info.lastInsertRowid);
    const user = enrichUserForClient(userRow);
    const token = createToken(userRow);

    return res.json({ token, user });
  } catch (err) {
    console.error("Error en /api/auth/register", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const userRow = db.prepare("SELECT * FROM users WHERE email = ?").get(emailNorm);
    if (!userRow) return res.status(400).json({ error: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, userRow.password_hash);
    if (!ok) return res.status(400).json({ error: "Credenciales inválidas" });

    const token = createToken(userRow);
    const user = enrichUserForClient(userRow);

    return res.json({ token, user });
  } catch (err) {
    console.error("Error en /api/auth/login", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.get("/api/auth/oauth/:provider", (req, res) => {
  const provider = String(req.params.provider || "").toLowerCase();
  if (!["google", "github"].includes(provider)) {
    return res.status(400).json({ error: "Proveedor inválido" });
  }
  return res.status(501).json({
    error: "OAuth no configurado. Definí credenciales para habilitar login social.",
    provider,
  });
});

app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Contraseña actual y nueva son requeridas" });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: "La nueva contraseña debe tener al menos 6 caracteres" });
    }

    const userRow = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!userRow) return res.status(404).json({ error: "Usuario no encontrado" });

    const ok = await bcrypt.compare(currentPassword, userRow.password_hash);
    if (!ok) return res.status(400).json({ error: "Contraseña actual incorrecta" });

    const newHash = await bcrypt.hash(newPassword, 10);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(newHash, userRow.id);

    return res.json({ ok: true });
  } catch (err) {
    console.error("Error en /api/auth/change-password", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Licencias: user (mis licencias)
app.get("/api/licenses/my", authMiddleware, (req, res) => {
  try {
    const rows = db
      .prepare("SELECT * FROM licenses WHERE user_id = ? ORDER BY created_at DESC")
      .all(req.user.id);

    const stmtCount = db.prepare("SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?");

    const response = rows.map((l) => {
      const activationsUsed = stmtCount.get(l.id).n;
      return {
        id: l.id,
        keyMasked: `${l.key.slice(0, 4)}-****-****`,
        planId: l.plan_id,
        status: l.status,
        createdAt: l.created_at,
        expiresAt: l.expires_at,
        maxActivations: l.max_activations,
        activationsUsed,
      };
    });

    return res.json({ licenses: response });
  } catch (err) {
    console.error("Error en /api/licenses/my", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Tickets / Soporte
// =========================
app.get("/api/tickets", authMiddleware, (req, res) => {
  try {
    const tickets = db
      .prepare("SELECT * FROM tickets WHERE user_id = ? ORDER BY updated_at DESC")
      .all(req.user.id);

    const msgStmt = db.prepare("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC");

    const response = tickets.map((t) => ({
      id: t.id,
      subject: t.subject,
      status: t.status,
      priority: t.priority,
      createdAt: t.created_at,
      updatedAt: t.updated_at,
      messages: msgStmt.all(t.id).map((m) => ({
        id: m.id,
        sender: m.sender,
        message: m.message,
        createdAt: m.created_at,
      })),
    }));

    return res.json({ tickets: response });
  } catch (err) {
    console.error("Error en /api/tickets", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/tickets", authMiddleware, (req, res) => {
  try {
    const { subject, message, priority } = req.body || {};
    if (!subject || !message) {
      return res.status(400).json({ error: "Asunto y mensaje son requeridos" });
    }

    const nowIso = new Date().toISOString();
    const info = db
      .prepare(
        `INSERT INTO tickets (user_id, subject, status, priority, created_at, updated_at)
         VALUES (?,?,?,?,?,?)`
      )
      .run(req.user.id, String(subject).trim(), "open", String(priority || "normal"), nowIso, nowIso);

    db.prepare(
      `INSERT INTO ticket_messages (ticket_id, sender, message, created_at)
       VALUES (?,?,?,?)`
    ).run(info.lastInsertRowid, "user", String(message).trim(), nowIso);

    return res.json({ ok: true, id: info.lastInsertRowid });
  } catch (err) {
    console.error("Error en /api/tickets", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/tickets/:id/reply", authMiddleware, (req, res) => {
  try {
    const ticketId = Number(req.params.id);
    const { message } = req.body || {};
    if (!ticketId || !message) {
      return res.status(400).json({ error: "Mensaje requerido" });
    }

    const ticket = db
      .prepare("SELECT * FROM tickets WHERE id = ? AND user_id = ?")
      .get(ticketId, req.user.id);
    if (!ticket) return res.status(404).json({ error: "Ticket no encontrado" });

    const nowIso = new Date().toISOString();
    db.prepare(
      `INSERT INTO ticket_messages (ticket_id, sender, message, created_at)
       VALUES (?,?,?,?)`
    ).run(ticketId, "user", String(message).trim(), nowIso);

    db.prepare("UPDATE tickets SET updated_at = ? WHERE id = ?").run(nowIso, ticketId);

    return res.json({ ok: true });
  } catch (err) {
    console.error("Error en /api/tickets/:id/reply", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Admin: emitir licencia
// =========================
app.post("/api/licenses/issue", requireAdmin, (req, res) => {
  try {
    const { email, planId, maxActivations, expiresInDays } = req.body || {};
    if (!email || !planId) {
      return res.status(400).json({ error: "email y planId son requeridos" });
    }

    const plan = PLANS.find((p) => p.id === planId);
    if (!plan) return res.status(400).json({ error: "planId inválido" });

    const emailNorm = String(email).trim().toLowerCase();
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(emailNorm);
    if (!user) return res.status(404).json({ error: "Usuario no encontrado" });

    const key = generateLicenseKey(planId);
    const now = new Date();

    let expiresAt = null;
    if (typeof expiresInDays === "number" && expiresInDays > 0 && planId !== "lifetime") {
      expiresAt = new Date(now.getTime() + expiresInDays * 24 * 60 * 60 * 1000);
    }

    const maxAct =
      maxActivations || PLAN_DEVICE_LIMIT[planId] || DEFAULT_MAX_ACTIVATIONS;

    const info = db
      .prepare(
        `INSERT INTO licenses (key, user_id, plan_id, status, max_activations, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?)`
      )
      .run(key, user.id, planId, "active", maxAct, now.toISOString(), expiresAt ? expiresAt.toISOString() : null);

    // opcional: actualizar plan del user (display)
    db.prepare("UPDATE users SET plan = ? WHERE id = ?").run(planId, user.id);

    const lic = db.prepare("SELECT * FROM licenses WHERE id = ?").get(info.lastInsertRowid);

    return res.json({
      ok: true,
      license: {
        id: lic.id,
        key,
        planId: lic.plan_id,
        status: lic.status,
        createdAt: lic.created_at,
        expiresAt: lic.expires_at,
        maxActivations: lic.max_activations,
      },
    });
  } catch (err) {
    console.error("Error en /api/licenses/issue", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Activación para la APP (alineado a Electron)
// Requiere Bearer token + acepta snake_case
// =========================
app.post("/api/licenses/activate", authMiddleware, (req, res) => {
  try {
    const rawKey = req.body?.license_key || req.body?.key || "";
    const installId = req.body?.install_id || req.body?.installId || "";
    const deviceName = req.body?.device_name || req.body?.deviceName || null;
    const appVersion = req.body?.app_version || req.body?.appVersion || null;

    const key = String(rawKey).trim();
    const iid = String(installId).trim();

    if (!key || !iid) {
      return res.status(400).json({ ok: false, error: "license_key/key e install_id/installId son requeridos" });
    }

    // ✅ denylist por dispositivo
    if (isInstallRevoked(req.user.id, iid)) {
      return res.status(403).json({ ok: false, error: "INSTALL_REVOKED" });
    }

    const license = db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);
    if (!license) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    // Seguridad: la licencia debe pertenecer al user logueado
    if (Number(license.user_id) !== Number(req.user.id)) {
      return res.status(403).json({ ok: false, error: "LICENSE_NOT_OWNED" });
    }

    if (license.status !== "active") {
      return res.status(403).json({ ok: false, error: "LICENCE_INACTIVE", status: license.status });
    }

    if (license.expires_at && new Date(license.expires_at) < new Date()) {
      return res.status(403).json({ ok: false, error: "LICENCE_EXPIRED" });
    }

    const nowIso = new Date().toISOString();

    const activation = db
      .prepare("SELECT * FROM license_activations WHERE license_id = ? AND install_id = ?")
      .get(license.id, iid);

    if (!activation) {
      const usedRow = db
        .prepare("SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?")
        .get(license.id);

      const used = usedRow.n || 0;
      const maxAllowed =
        license.max_activations || PLAN_DEVICE_LIMIT[license.plan_id] || DEFAULT_MAX_ACTIVATIONS;

      if (used >= maxAllowed) {
        return res.status(403).json({ ok: false, error: "MAX_INSTALLS_REACHED" });
      }

      db.prepare(
        `INSERT INTO license_activations
         (license_id, install_id, device_name, first_activated_at, last_seen_at, app_version)
         VALUES (?,?,?,?,?,?)`
      ).run(license.id, iid, deviceName, nowIso, nowIso, appVersion);
    } else {
      db.prepare(
        `UPDATE license_activations
         SET last_seen_at = ?, app_version = ?, device_name = COALESCE(?, device_name)
         WHERE id = ?`
      ).run(nowIso, appVersion || activation.app_version, deviceName, activation.id);
    }

    const plan = PLANS.find((p) => p.id === license.plan_id) || PLANS[0];
    const limits = getPlanLimits(license.plan_id);

    const countRow = db
      .prepare("SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?")
      .get(license.id);

    const userRow = db.prepare("SELECT id, email, plan FROM users WHERE id = ?").get(req.user.id);
    const enrichedUser = enrichUserForClient(userRow);

    const newToken = createToken(userRow);

    return res.json({
      ok: true,
      user: enrichedUser,
      token: newToken,
      license: {
        plan_key: license.plan_id,
        plan_name: plan.name,
        status: license.status,
        expires_at: license.expires_at,
        max_activations: license.max_activations,
        activations_used: countRow.n || 0,
        key_masked: `${license.key.slice(0, 4)}-****-****`,
        limits: {
          maxAccounts: limits.maxAccounts,
          maxWorkers: limits.maxWorkers,
          maxMessagesPerDay: limits.maxMessagesPerDay,
          warmupEnabled: limits.warmupEnabled,
          maxDevices: limits.maxDevices,
        },
      },
    });
  } catch (err) {
    console.error("Error en /api/licenses/activate", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// =========================
// ✅ ADMIN: revocar / desbloquear (para Postman)
// =========================

// Debug admin: ver user + licencias + activaciones
app.get("/api/admin/users/:email", requireAdmin, (req, res) => {
  try {
    const email = String(req.params.email || "").trim().toLowerCase();
    const user = db.prepare("SELECT id, email, plan, created_at FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });

    const licenses = db.prepare("SELECT * FROM licenses WHERE user_id = ? ORDER BY created_at DESC").all(user.id);
    const actsStmt = db.prepare("SELECT * FROM license_activations WHERE license_id = ? ORDER BY last_seen_at DESC");

    const revoked = db.prepare("SELECT install_id, reason, created_at FROM revoked_installs WHERE user_id = ?").all(user.id);

    return res.json({
      ok: true,
      user,
      effectivePlan: getEffectivePlanForUser(user.id),
      revoked_installs: revoked,
      licenses: licenses.map((l) => ({
        ...l,
        key_masked: `${String(l.key).slice(0, 4)}-****-****`,
        activations: actsStmt.all(l.id),
      })),
    });
  } catch (err) {
    console.error("Error en /api/admin/users/:email", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Revocar una licencia específica (por key)
app.post("/api/admin/licenses/revoke", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    const reason = String(req.body?.reason || "").slice(0, 200) || null;
    if (!key) return res.status(400).json({ ok: false, error: "key requerida" });

    const lic = db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);
    if (!lic) return res.status(404).json({ ok: false, error: "LICENSE_NOT_FOUND" });

    db.prepare("UPDATE licenses SET status = 'revoked' WHERE id = ?").run(lic.id);

    // opcional: limpiar activaciones para que no sigan “ocupando”
    db.prepare("DELETE FROM license_activations WHERE license_id = ?").run(lic.id);

    return res.json({ ok: true, revoked: true, key_masked: `${key.slice(0, 4)}-****-****`, reason });
  } catch (err) {
    console.error("Error en /api/admin/licenses/revoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Des-revocar una licencia (volver a active)
app.post("/api/admin/licenses/unrevoke", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    if (!key) return res.status(400).json({ ok: false, error: "key requerida" });

    const lic = db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);
    if (!lic) return res.status(404).json({ ok: false, error: "LICENSE_NOT_FOUND" });

    db.prepare("UPDATE licenses SET status = 'active' WHERE id = ?").run(lic.id);

    return res.json({ ok: true, active: true, key_masked: `${key.slice(0, 4)}-****-****` });
  } catch (err) {
    console.error("Error en /api/admin/licenses/unrevoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Revocar TODAS las licencias de un usuario (por email)
app.post("/api/admin/users/revoke", requireAdmin, (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: "email requerido" });

    const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });

    db.prepare("UPDATE licenses SET status = 'revoked' WHERE user_id = ?").run(user.id);

    // opcional: limpiar TODAS las activaciones del user (libera cupos)
    db.prepare(`
      DELETE FROM license_activations
      WHERE license_id IN (SELECT id FROM licenses WHERE user_id = ?)
    `).run(user.id);

    return res.json({ ok: true, userRevoked: true, email });
  } catch (err) {
    console.error("Error en /api/admin/users/revoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Revocar un dispositivo (bloquear install_id) para un user
app.post("/api/admin/devices/revoke", requireAdmin, (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const installId = String(req.body?.installId || req.body?.install_id || "").trim();
    const reason = String(req.body?.reason || "manual").slice(0, 200);

    if (!email || !installId) {
      return res.status(400).json({ ok: false, error: "email + installId requeridos" });
    }

    const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });

    // upsert denylist
    db.prepare(`
      INSERT INTO revoked_installs(user_id, install_id, reason, created_at)
      VALUES (?,?,?,?)
      ON CONFLICT(user_id, install_id) DO UPDATE SET
        reason = excluded.reason,
        created_at = excluded.created_at
    `).run(user.id, installId, reason, new Date().toISOString());

    // opcional: borrar activaciones existentes en ese device para liberar cupo
    db.prepare(`
      DELETE FROM license_activations
      WHERE install_id = ?
        AND license_id IN (SELECT id FROM licenses WHERE user_id = ?)
    `).run(installId, user.id);

    return res.json({ ok: true, installRevoked: true, email, installId, reason });
  } catch (err) {
    console.error("Error en /api/admin/devices/revoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// Desbloquear dispositivo
app.post("/api/admin/devices/unrevoke", requireAdmin, (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const installId = String(req.body?.installId || req.body?.install_id || "").trim();
    if (!email || !installId) {
      return res.status(400).json({ ok: false, error: "email + installId requeridos" });
    }

    const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });

    db.prepare("DELETE FROM revoked_installs WHERE user_id = ? AND install_id = ?").run(user.id, installId);

    return res.json({ ok: true, installUnrevoked: true, email, installId });
  } catch (err) {
    console.error("Error en /api/admin/devices/unrevoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// =========================
// Start
// =========================
app.listen(PORT, () => {
  console.log(`Hyperion website backend escuchando en :${PORT}`);
});
