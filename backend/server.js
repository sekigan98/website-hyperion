// backend/server.js (WEBSITE BACKEND) - max_devices + /api/me + user_sessions + ADMIN API
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
  process.env.JWT_SECRET || "guk26ljOkyzbusaV7uK0ilw4s1b0AO3762AHxDiOrQw=";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "hyperion-sekigan-1998";

// -------------------------
// DB schema (se crea al boot)
// -------------------------
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
  status TEXT NOT NULL DEFAULT 'active',
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

-- ✅ sesiones por dispositivo para LOGIN (max_devices)
CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  install_id TEXT NOT NULL,
  device_name TEXT,
  app_version TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT,
  revoked_at TEXT,
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
      "Hasta 8 cuentas de WhatsApp",
      "Warmup inteligente",
      "Stats avanzadas por cuenta",
      "Soporte prioritario",
      "Hasta 2 dispositivos instalados",
    ],
  },
  {
    id: "freelancer",
    name: "Freelancer",
    tag: "Independientes",
    price: "$29",
    price_suffix: "/ mes",
    highlight: false,
    cta: "Elegir Freelancer",
    features: [
      "3 cuentas vinculadas",
      "Warmup habilitado",
      "3000 mensajes por día",
      "1 dispositivo instalado",
    ],
  },
  {
    id: "lifetime",
    name: "Lifetime",
    tag: "Pago único",
    price: "$1499",
    price_suffix: "pago único",
    highlight: false,
    cta: "Comprar licencia Lifetime",
    features: [
      "Hasta 20 cuentas de WhatsApp",
      "Mensajes ilimitados",
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

// ✅ límites reales usados por Electron (plan -> features)
const PLAN_LIMITS = {
  starter: {
    maxAccounts: 1,
    maxWorkers: 1,
    maxMessagesPerDay: 30,
    warmupEnabled: false,
    maxDevices: 1,
  },
  pro: {
    maxAccounts: 15,
    maxWorkers: 15,
    maxMessagesPerDay: 5000,
    warmupEnabled: true,
    maxDevices: 2,
  },
  freelancer: {
    maxAccounts: 3,
    maxWorkers: 3,
    maxMessagesPerDay: 3000,
    warmupEnabled: true,
    maxDevices: 1,
  },
  lifetime: {
    maxAccounts: 20,
    maxWorkers: 20,
    maxMessagesPerDay: -1,
    warmupEnabled: true,
    maxDevices: 5,
  },
  agency: {
    maxAccounts: 14,
    maxWorkers: 14,
    maxMessagesPerDay: 10000,
    warmupEnabled: true,
    maxDevices: 3,
  },
};

const PLAN_DEVICE_LIMIT = { starter: 1, pro: 2, freelancer: 1, lifetime: 5, agency: 3 };
const DEFAULT_MAX_ACTIVATIONS = 1;

// =========================
// CORS (configurable)
// =========================
function getPlanLimits(planId) {
  return PLAN_LIMITS[planId] || PLAN_LIMITS.starter;
}

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

// =========================
// ✅ user_sessions helpers (max_devices)
// =========================
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 60 * 60 * 1000); // 1h

function isoNow() {
  return new Date().toISOString();
}
function isoCutoff() {
  return new Date(Date.now() - SESSION_TTL_MS).toISOString();
}

function listActiveSessions(userId) {
  return db
    .prepare(
      `
    SELECT install_id, device_name, app_version, created_at, last_seen_at
    FROM user_sessions
    WHERE user_id = ?
      AND revoked_at IS NULL
      AND COALESCE(last_seen_at, created_at) >= ?
    ORDER BY COALESCE(last_seen_at, created_at) DESC
  `
    )
    .all(userId, isoCutoff());
}

function revokeOldestSessions(userId, count) {
  if (count <= 0) return;
  const rows = db
    .prepare(
      `
    SELECT id
    FROM user_sessions
    WHERE user_id = ?
      AND revoked_at IS NULL
      AND COALESCE(last_seen_at, created_at) >= ?
    ORDER BY COALESCE(last_seen_at, created_at) ASC
    LIMIT ?
  `
    )
    .all(userId, isoCutoff(), count);

  const now = isoNow();
  const upd = db.prepare(`UPDATE user_sessions SET revoked_at = ? WHERE id = ?`);
  for (const r of rows) upd.run(now, r.id);
}

function upsertSession({ userId, installId, deviceName, appVersion }) {
  const now = isoNow();
  db.prepare(
    `
    INSERT INTO user_sessions(user_id, install_id, device_name, app_version, last_seen_at, revoked_at)
    VALUES(?,?,?,?,?,NULL)
    ON CONFLICT(user_id, install_id) DO UPDATE SET
      device_name = COALESCE(excluded.device_name, device_name),
      app_version = COALESCE(excluded.app_version, app_version),
      last_seen_at = excluded.last_seen_at,
      revoked_at = NULL
  `
  ).run(userId, installId, deviceName || null, appVersion || null, now);
}

function isSessionAllowed(userId, installId) {
  const row = db
    .prepare(
      `
    SELECT id
    FROM user_sessions
    WHERE user_id = ?
      AND install_id = ?
      AND revoked_at IS NULL
      AND COALESCE(last_seen_at, created_at) >= ?
    LIMIT 1
  `
    )
    .get(userId, installId, isoCutoff());
  return !!row;
}

// =========================
// Auth middleware
// ✅ FIX: si NO viene X-Install-Id => es WEB => NO validar sesiones
// =========================
function authMiddleware(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Token requerido" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;

    const iid = String(req.headers["x-install-id"] || "").trim();
    if (iid) {
      if (!isSessionAllowed(payload.id, iid)) {
        return res.status(401).json({ error: "session_revoked" });
      }
    }

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

function generateLicenseKey(planId = "starter") {
  const plan = String(planId).toUpperCase(); // AGENCY / PRO / LIFETIME / STARTER
  const part1 = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6 chars
  const part2 = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6 chars
  return `HYP-${plan}-${part1}-${part2}`;
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

function isValidEmail(email) {
  const value = String(email || "").trim().toLowerCase();
  if (!value) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

// prioridad (más alto = “mejor plan”)
const PLAN_RANK = { starter: 0, freelancer: 1, pro: 2, agency: 3, lifetime: 4 };

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
  const planId = getEffectivePlanForUser(userRow.id); // ✅ plan real por licencias
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

// =========================
// Update policy: /api/app/version
// =========================
app.get("/api/app/version", (req, res) => {
  const current = String(
    req.query.current || req.query.version || req.headers["x-app-version"] || "0.0.0"
  );
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
      .run(
        String(name).trim(),
        String(email).trim().toLowerCase(),
        company || null,
        String(message).trim(),
        nowIso
      );

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
      stmt.run(
        String(email).trim().toLowerCase(),
        source || "site",
        "active",
        new Date().toISOString()
      );
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

// ✅ Login con max_devices + force
// ✅ FIX: WEB login permitido sin install_id (no crea user_session)
// Body Electron: { email, password, install_id, device_name, app_version, force }
// Body Web:     { email, password }
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password, install_id, device_name, app_version, force } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const userRow = db.prepare("SELECT * FROM users WHERE email = ?").get(emailNorm);
    if (!userRow) return res.status(400).json({ error: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, userRow.password_hash);
    if (!ok) return res.status(400).json({ error: "Credenciales inválidas" });

    const enriched = enrichUserForClient(userRow);

    const token = createToken(userRow);

    // ✅ FIX: si NO hay install_id => es login web, devolvemos token y user y listo
    const iid = String(install_id || "").trim();
    if (!iid) {
      return res.json({
        token,
        user: enriched,
        mode: "web",
      });
    }

    // ✅ enforce max_devices SOLO cuando viene install_id (Electron)
    const planId = String(enriched.plan || "starter");
    const limits = getPlanLimits(planId);

    const maxDevicesRaw = typeof limits.maxDevices === "number" ? limits.maxDevices : 1;
    const maxDevices = maxDevicesRaw === -1 ? -1 : Math.max(1, maxDevicesRaw);

    const dname = String(device_name || "").trim() || null;
    const aver = String(app_version || "").trim() || null;
    const wantsForce = !!force;

    if (maxDevices !== -1) {
      const active = listActiveSessions(userRow.id);
      const alreadyThisDevice = active.some((s) => s.install_id === iid);

      if (!alreadyThisDevice && active.length >= maxDevices) {
        if (!wantsForce) {
          return res.status(409).json({
            ok: false,
            code: "MAX_DEVICES_REACHED",
            error: "MAX_DEVICES_REACHED",
            max_devices: maxDevices,
            activeSessions: active.map((s) => ({
              install_id: s.install_id,
              device_name: s.device_name,
              last_seen_at: s.last_seen_at,
            })),
          });
        }

        // force => revocar las más viejas para hacer lugar
        const toRevoke = active.length - maxDevices + 1;
        revokeOldestSessions(userRow.id, toRevoke);
      }

      // registrar/refresh de sesión (Electron)
      upsertSession({
        userId: userRow.id,
        installId: iid,
        deviceName: dname,
        appVersion: aver,
      });
    }

    return res.json({ token, user: enriched, mode: "device" });
  } catch (err) {
    console.error("Error en /api/auth/login", err);
    return res.status(500).json({ error: "Error interno" });
  }
});

// ✅ /api/me para Electron refreshSessionFromServer()
// Requiere Authorization + (opcional) X-Install-Id (si viene, valida sesión)
app.get("/api/me", authMiddleware, (req, res) => {
  try {
    const userRow = db.prepare("SELECT id, email, plan FROM users WHERE id = ?").get(req.user.id);
    if (!userRow) return res.status(404).json({ error: "Usuario no encontrado" });

    // refresh last_seen de la sesión si viene header
    const iid = String(req.headers["x-install-id"] || "").trim();
    const aver = String(req.headers["x-app-version"] || "").trim() || null;
    if (iid) {
      try {
        upsertSession({
          userId: userRow.id,
          installId: iid,
          deviceName: null,
          appVersion: aver,
        });
      } catch (_) {}
    }

    const user = enrichUserForClient(userRow);
    return res.json({ ok: true, user });
  } catch (err) {
    console.error("Error en /api/me", err);
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

    const key = generateLicenseKey();
    const now = new Date();
    
// ✅ opcional: desactivar cualquier licencia activa anterior del usuario
    db.prepare(`UPDATE licenses SET status = 'revoked' WHERE user_id = ? AND status = 'active'`)
    .run(user.id);
    
    const expDays = Number(expiresInDays);
    let expiresAt = null;
    if (Number.isFinite(expDays) && expDays > 0 && planId !== "lifetime") {
      expiresAt = new Date(now.getTime() + expDays * 24 * 60 * 60 * 1000);
    }

    const maxActParsed = Number(maxActivations);
    const maxAct =
      (Number.isFinite(maxActParsed) && maxActParsed > 0 ? Math.trunc(maxActParsed) : null) ||
      PLAN_DEVICE_LIMIT[planId] ||
      DEFAULT_MAX_ACTIVATIONS;

    const info = db
      .prepare(
        `INSERT INTO licenses (key, user_id, plan_id, status, max_activations, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?)`
      )
      .run(
        key,
        user.id,
        planId,
        "active",
        maxAct,
        now.toISOString(),
        expiresAt ? expiresAt.toISOString() : null
      );

    // opcional: actualizar plan del user (igual el "real" lo calcula por licencias)
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

    const license = db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);
    if (!license) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

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

// =====================================================================
// ✅ ADMIN API (para Postman): licencias + vencimiento + activaciones + sesiones
// =====================================================================
const DAY_MS = 24 * 60 * 60 * 1000;

function remainingDaysFromExpires(expiresAt) {
  if (!expiresAt) return null; // lifetime/no expiry
  const ms = Date.parse(expiresAt) - Date.now();
  return Math.ceil(ms / DAY_MS);
}

function toInt(v, def = null) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : def;
}

function addDaysIso(baseIsoOrNull, days) {
  const d = toInt(days, null);
  if (d == null) return null;
  const base = baseIsoOrNull ? new Date(baseIsoOrNull) : new Date();
  if (Number.isNaN(base.getTime())) return null;
  return new Date(base.getTime() + d * DAY_MS).toISOString();
}

function getLicenseByKey(key) {
  return db.prepare("SELECT * FROM licenses WHERE key = ?").get(key);
}

function getUserByEmail(emailNorm) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(emailNorm);
}

function countLicenseActivations(licenseId) {
  const row = db.prepare("SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?").get(licenseId);
  return row?.n || 0;
}

function getLicenseActivations(licenseId) {
  return db.prepare(
    `SELECT install_id, device_name, app_version, first_activated_at, last_seen_at
     FROM license_activations
     WHERE license_id = ?
     ORDER BY COALESCE(last_seen_at, first_activated_at) DESC`
  ).all(licenseId);
}

function isValidPlanId(planId) {
  const p = String(planId || "").toLowerCase();
  return PLANS.some((x) => x.id === p);
}

// 1) Lookup user + licencias + sesiones activas
// GET /api/admin/users/lookup?email=...
app.get("/api/admin/users/lookup", requireAdmin, (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "email inválido" });

    const userRow = getUserByEmail(email);
    if (!userRow) return res.status(404).json({ ok: false, error: "Usuario no encontrado" });

    const effectivePlan = getEffectivePlanForUser(userRow.id);
    const enriched = enrichUserForClient(userRow);

    const licenses = db
      .prepare("SELECT * FROM licenses WHERE user_id = ? ORDER BY created_at DESC")
      .all(userRow.id)
      .map((l) => ({
        id: l.id,
        key: l.key, // admin ve la key completa
        plan_id: l.plan_id,
        status: l.status,
        created_at: l.created_at,
        expires_at: l.expires_at,
        remaining_days: remainingDaysFromExpires(l.expires_at),
        max_activations: l.max_activations,
        activations_used: countLicenseActivations(l.id),
      }));

    const sessions = listActiveSessions(userRow.id);

    return res.json({
      ok: true,
      user: { ...enriched, created_at: userRow.created_at },
      effective_plan: effectivePlan,
      licenses,
      active_sessions: sessions,
      session_ttl_ms: SESSION_TTL_MS,
    });
  } catch (err) {
    console.error("Error /api/admin/users/lookup", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 2) Admin: cambiar password usuario
// POST /api/admin/users/set-password
// body: { email, new_password }
app.post("/api/admin/users/set-password", requireAdmin, async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const newPass = String(req.body?.new_password || "").trim();

    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "email inválido" });
    if (!newPass || newPass.length < 6)
      return res.status(400).json({ ok: false, error: "new_password mínimo 6 chars" });

    const user = getUserByEmail(email);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario no encontrado" });

    const hash = await bcrypt.hash(newPass, 10);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);

    return res.json({ ok: true });
  } catch (err) {
    console.error("Error /api/admin/users/set-password", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 3) Admin: lookup licencia + activaciones
// GET /api/admin/licenses/lookup?key=...
app.get("/api/admin/licenses/lookup", requireAdmin, (req, res) => {
  try {
    const key = String(req.query.key || "").trim();
    if (!key) return res.status(400).json({ ok: false, error: "key requerido" });

    const lic = getLicenseByKey(key);
    if (!lic) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    const activations = getLicenseActivations(lic.id);

    return res.json({
      ok: true,
      license: {
        id: lic.id,
        key: lic.key,
        user_id: lic.user_id,
        plan_id: lic.plan_id,
        status: lic.status,
        created_at: lic.created_at,
        expires_at: lic.expires_at,
        remaining_days: remainingDaysFromExpires(lic.expires_at),
        max_activations: lic.max_activations,
        activations_used: activations.length,
      },
      activations,
    });
  } catch (err) {
    console.error("Error /api/admin/licenses/lookup", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 4) Admin: update licencia (vencimiento/plan/status/max_activations)
// POST /api/admin/licenses/update
// body soporta:
// { key, expires_at?, clear_expires?, set_expires_in_days?, extend_days?, plan_id?, status?, max_activations? }
app.post("/api/admin/licenses/update", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    if (!key) return res.status(400).json({ ok: false, error: "key requerido" });

    const lic = getLicenseByKey(key);
    if (!lic) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    const patch = {};
    const status = req.body?.status != null ? String(req.body.status).trim() : null;
    const planId = req.body?.plan_id != null ? String(req.body.plan_id).trim().toLowerCase() : null;
    const maxAct = req.body?.max_activations != null ? toInt(req.body.max_activations, null) : null;

    const clearExpires = !!req.body?.clear_expires;
    const expiresAt = req.body?.expires_at != null ? String(req.body.expires_at).trim() : null;
    const setDays = req.body?.set_expires_in_days != null ? toInt(req.body.set_expires_in_days, null) : null;
    const extendDays = req.body?.extend_days != null ? toInt(req.body.extend_days, null) : null;

    if (status) patch.status = status;

    if (planId) {
      if (!isValidPlanId(planId)) return res.status(400).json({ ok: false, error: "plan_id inválido" });
      patch.plan_id = planId;
    }

    if (maxAct != null) {
      if (maxAct <= 0) return res.status(400).json({ ok: false, error: "max_activations debe ser > 0" });
      patch.max_activations = maxAct;
    }

    // expires handling (prioridad: clear > expires_at > set_days > extend_days)
    if (clearExpires) {
      patch.expires_at = null;
    } else if (expiresAt) {
      const t = Date.parse(expiresAt);
      if (Number.isNaN(t)) return res.status(400).json({ ok: false, error: "expires_at inválido (ISO)" });
      patch.expires_at = new Date(t).toISOString();
    } else if (setDays != null) {
      if (setDays <= 0) return res.status(400).json({ ok: false, error: "set_expires_in_days debe ser > 0" });
      patch.expires_at = addDaysIso(null, setDays);
    } else if (extendDays != null) {
      if (extendDays === 0) return res.status(400).json({ ok: false, error: "extend_days no puede ser 0" });
      const base = lic.expires_at && Date.parse(lic.expires_at) > Date.now() ? lic.expires_at : null;
      patch.expires_at = addDaysIso(base, extendDays);
    }

    const keys = Object.keys(patch);
    if (keys.length === 0) return res.status(400).json({ ok: false, error: "Nada para actualizar" });

    const setSql = keys.map((k) => `${k} = ?`).join(", ");
    const values = keys.map((k) => patch[k]);

    db.prepare(`UPDATE licenses SET ${setSql} WHERE id = ?`).run(...values, lic.id);

    // opcional: si cambiás plan, actualizar users.plan también (el real lo calcula por licencias)
    if (planId) {
      try {
        db.prepare("UPDATE users SET plan = ? WHERE id = ?").run(planId, lic.user_id);
      } catch (_) {}
    }

    const updated = getLicenseByKey(key);

    return res.json({
      ok: true,
      license: {
        id: updated.id,
        key: updated.key,
        user_id: updated.user_id,
        plan_id: updated.plan_id,
        status: updated.status,
        created_at: updated.created_at,
        expires_at: updated.expires_at,
        remaining_days: remainingDaysFromExpires(updated.expires_at),
        max_activations: updated.max_activations,
        activations_used: countLicenseActivations(updated.id),
      },
    });
  } catch (err) {
    console.error("Error /api/admin/licenses/update", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 5) Admin: revocar activación puntual (liberar cupo)
// POST /api/admin/licenses/revoke-activation
// body: { key, install_id }
app.post("/api/admin/licenses/revoke-activation", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    const iid = String(req.body?.install_id || "").trim();
    if (!key || !iid) return res.status(400).json({ ok: false, error: "key e install_id son requeridos" });

    const lic = getLicenseByKey(key);
    if (!lic) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    const info = db
      .prepare("DELETE FROM license_activations WHERE license_id = ? AND install_id = ?")
      .run(lic.id, iid);

    return res.json({ ok: true, deleted: info.changes });
  } catch (err) {
    console.error("Error /api/admin/licenses/revoke-activation", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 6) Admin: resetear todas las activaciones de una licencia
// POST /api/admin/licenses/reset-activations
// body: { key }
app.post("/api/admin/licenses/reset-activations", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    if (!key) return res.status(400).json({ ok: false, error: "key requerido" });

    const lic = getLicenseByKey(key);
    if (!lic) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    const info = db.prepare("DELETE FROM license_activations WHERE license_id = ?").run(lic.id);
    return res.json({ ok: true, deleted: info.changes });
  } catch (err) {
    console.error("Error /api/admin/licenses/reset-activations", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 7) Admin: sesiones activas por usuario (max_devices)
// GET /api/admin/sessions/lookup?email=...
app.get("/api/admin/sessions/lookup", requireAdmin, (req, res) => {
  try {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "email inválido" });

    const user = getUserByEmail(email);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario no encontrado" });

    const sessions = listActiveSessions(user.id);
    return res.json({ ok: true, user_id: user.id, email: user.email, session_ttl_ms: SESSION_TTL_MS, sessions });
  } catch (err) {
    console.error("Error /api/admin/sessions/lookup", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 8) Admin: revocar una sesión puntual
// POST /api/admin/sessions/revoke
// body: { email, install_id }
app.post("/api/admin/sessions/revoke", requireAdmin, (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const iid = String(req.body?.install_id || "").trim();
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "email inválido" });
    if (!iid) return res.status(400).json({ ok: false, error: "install_id requerido" });

    const user = getUserByEmail(email);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario no encontrado" });

    const now = isoNow();
    const info = db
      .prepare(`UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND install_id = ?`)
      .run(now, user.id, iid);

    return res.json({ ok: true, revoked: info.changes });
  } catch (err) {
    console.error("Error /api/admin/sessions/revoke", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 9) Admin: revocar TODAS las sesiones activas de un usuario
// POST /api/admin/sessions/reset
// body: { email }
app.post("/api/admin/sessions/reset", requireAdmin, (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    if (!email || !isValidEmail(email)) return res.status(400).json({ ok: false, error: "email inválido" });

    const user = getUserByEmail(email);
    if (!user) return res.status(404).json({ ok: false, error: "Usuario no encontrado" });

    const now = isoNow();
    const info = db
      .prepare(`UPDATE user_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`)
      .run(now, user.id);

    return res.json({ ok: true, revoked: info.changes });
  } catch (err) {
    console.error("Error /api/admin/sessions/reset", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// 10) Admin: eliminar licencia (y activaciones asociadas)
// POST /api/admin/licenses/delete
// body: { key }
app.post("/api/admin/licenses/delete", requireAdmin, (req, res) => {
  try {
    const key = String(req.body?.key || "").trim();
    if (!key) return res.status(400).json({ ok: false, error: "key requerido" });

    const lic = getLicenseByKey(key);
    if (!lic) return res.status(404).json({ ok: false, error: "Licencia no encontrada" });

    // primero activaciones, porque tienen FK a licenses
    db.prepare("DELETE FROM license_activations WHERE license_id = ?").run(lic.id);

    // luego la licencia
    const info = db.prepare("DELETE FROM licenses WHERE id = ?").run(lic.id);

    return res.json({ ok: true, deleted: info.changes });
  } catch (err) {
    console.error("Error /api/admin/licenses/delete", err);
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// =========================
// Start
// =========================
app.listen(PORT, () => {
  console.log(`Hyperion website backend escuchando en :${PORT}`);
});
