// backend/server.js (WEBSITE BACKEND)
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET =
  process.env.JWT_SECRET || "super-secreto-hyperion-2025-1998";
const ADMIN_API_KEY =
  process.env.ADMIN_API_KEY || "hyperion-sekigan-1998"; // para emitir licencias

app.use(cors());
app.use(express.json());

// =========================
// DB: schema
// =========================
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
    highlight: false,
    cta: "Empezar gratis",
    features: [
      "1 cuenta de WhatsApp",
      "Campañas manuales básicas",
      "Validación local de contactos",
      "Warmup desactivado",
      "1 dispositivo instalado",
    ],
  },
  {
    id: "pro",
    name: "Pro",
    tag: "Recomendado",
    price: "$19",
    highlight: true,
    cta: "Probar Hyperion Pro",
    features: [
      "Hasta 5 cuentas de WhatsApp",
      "Campañas automáticas + avanzadas",
      "Warmup inteligente",
      "Stats avanzadas por cuenta",
      "Soporte prioritario",
      "Hasta 2 dispositivos instalados",
    ],
  },
  {
    id: "lifetime",
    name: "Lifetime",
    tag: "Lifetime",
    price: "$499 (único pago)",
    highlight: false,
    cta: "Comprar licencia Lifetime",
    features: [
      "Hasta 10 cuentas de WhatsApp",
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
    price: "$49",
    highlight: false,
    cta: "Hablar con ventas",
    features: [
      "20+ cuentas de WhatsApp",
      "Warmup agresivo ajustable",
      "Soporte dedicado",
      "Asistencia en onboarding y setup",
      "Hasta 3 dispositivos instalados",
    ],
  },
];

// Límites técnicos por plan (lo que va a usar la APP)
const PLAN_LIMITS = {
  starter: {
    maxAccounts: 1,
    maxWorkers: 1,
    maxMessagesPerDay: 30,
    warmupEnabled: false,
    maxDevices: 1,
  },
  pro: {
    maxAccounts: 5,
    maxWorkers: 5,
    maxMessagesPerDay: 800,
    warmupEnabled: true,
    maxDevices: 2,
  },
  lifetime: {
    maxAccounts: 10,
    maxWorkers: 10,
    maxMessagesPerDay: 50000,
    warmupEnabled: true,
    maxDevices: 5,
  },
  agency: {
    maxAccounts: 20,
    maxWorkers: 20,
    maxMessagesPerDay: 5000,
    warmupEnabled: true,
    maxDevices: 3,
  },
};

// Cuántas PCs distintas permite cada plan por defecto
const PLAN_DEVICE_LIMIT = {
  starter: 1,
  pro: 2,
  lifetime: 5,
  agency: 3,
};

const DEFAULT_MAX_ACTIVATIONS = 1;

// =========================
// Helpers
// =========================
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      plan: user.plan || "starter",
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || "";
  const [, token] = auth.split(" ");
  if (!token) return res.status(401).json({ error: "No autorizado" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"];
  if (!key || key !== ADMIN_API_KEY) {
    return res.status(403).json({ error: "Admin API key inválida" });
  }
  next();
}

function generateLicenseKey(planId = "pro") {
  const segment = () =>
    crypto.randomBytes(3).toString("hex").toUpperCase();
  const prefix = "HYP";
  return `${prefix}-${planId.toUpperCase()}-${segment()}-${segment()}`;
}

// =========================
// Rutas públicas
// =========================
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/plans", (_req, res) => {
  res.json({ plans: PLANS });
});

// -------------------------
// Auth: registro / login
// -------------------------
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email y contraseña son requeridos" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const existing = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(emailNorm);
    if (existing) {
      return res
        .status(400)
        .json({ error: "Ese email ya está registrado" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const plan = "starter"; // plan base por defecto

    const info = db
      .prepare(
        "INSERT INTO users (email, password_hash, plan) VALUES (?,?,?)"
      )
      .run(emailNorm, passwordHash, plan);

    const user = db
      .prepare("SELECT id, email, plan FROM users WHERE id = ?")
      .get(info.lastInsertRowid);

    const token = createToken(user);
    res.json({
      token,
      user,
    });
  } catch (err) {
    console.error("Error en /api/auth/register", err);
    res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email y contraseña son requeridos" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(emailNorm);

    if (!user) {
      return res.status(400).json({ error: "Credenciales inválidas" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(400).json({ error: "Credenciales inválidas" });
    }

    const token = createToken(user);
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan,
      },
    });
  } catch (err) {
    console.error("Error en /api/auth/login", err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Cambiar contraseña (usuario logueado)
app.post("/api/auth/change-password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};

    if (!currentPassword || !newPassword) {
      return res
        .status(400)
        .json({ error: "Contraseña actual y nueva son requeridas" });
    }

    if (String(newPassword).length < 6) {
      return res
        .status(400)
        .json({ error: "La nueva contraseña debe tener al menos 6 caracteres" });
    }

    // buscamos al usuario en DB
    const user = db
      .prepare("SELECT * FROM users WHERE id = ?")
      .get(req.user.id);

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // comparamos la contraseña actual
    const ok = await bcrypt.compare(currentPassword, user.password_hash);
    if (!ok) {
      return res.status(400).json({ error: "Contraseña actual incorrecta" });
    }

    // generamos nuevo hash
    const newHash = await bcrypt.hash(newPassword, 10);

    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(
      newHash,
      user.id
    );

    return res.json({ ok: true });
  } catch (err) {
    console.error("Error en /api/auth/change-password", err);
    return res.status(500).json({ error: "Error interno" });
  }
});



// =========================
// Rutas protegidas (usuario)
// =========================
app.get("/api/me", authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// Lista licencias del usuario logueado (para dashboard web)
app.get("/api/licenses/my", authMiddleware, (req, res) => {
  try {
    const userId = req.user.id;

    const rows = db
      .prepare("SELECT * FROM licenses WHERE user_id = ? ORDER BY id DESC")
      .all(userId);

    const stmtCount = db.prepare(
      "SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?"
    );

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

    res.json({ licenses: response });
  } catch (err) {
    console.error("Error en /api/licenses/my", err);
    res.status(500).json({ error: "Error interno" });
  }
});

// Checkout (stub para futuro integrarlo con MP/Stripe)
app.post("/api/checkout", authMiddleware, (req, res) => {
  const { planId, method } = req.body || {};

  if (!planId || !method) {
    return res
      .status(400)
      .json({ error: "planId y método de pago son requeridos" });
  }

  const fakePaymentUrl = `https://ejemplo-pago.com/checkout?plan=${encodeURIComponent(
    planId
  )}&method=${encodeURIComponent(method)}`;

  res.json({
    ok: true,
    redirectUrl: fakePaymentUrl,
  });
});

// =========================
// Rutas de licencias (admin)
// =========================

// Emitir licencia para un usuario (ej: llamado desde un panel interno o webhook de pago)
app.post("/api/licenses/issue", requireAdmin, (req, res) => {
  try {
    const { email, planId, maxActivations, expiresInDays } = req.body || {};
    if (!email || !planId) {
      return res
        .status(400)
        .json({ error: "email y planId son requeridos" });
    }

    const plan = PLANS.find((p) => p.id === planId);
    if (!plan) {
      return res.status(400).json({ error: "planId inválido" });
    }

    const emailNorm = String(email).trim().toLowerCase();
    const user = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(emailNorm);

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const key = generateLicenseKey(planId);
    const now = new Date();
    let expiresAt = null;

    // mensual salvo lifetime (0 días => sin expiración)
    if (
      typeof expiresInDays === "number" &&
      expiresInDays > 0 &&
      planId !== "lifetime"
    ) {
      expiresAt = new Date(
        now.getTime() + expiresInDays * 24 * 60 * 60 * 1000
      );
    }

    const maxAct =
      maxActivations ||
      PLAN_DEVICE_LIMIT[planId] ||
      DEFAULT_MAX_ACTIVATIONS;

    const info = db
      .prepare(
        `
      INSERT INTO licenses (key, user_id, plan_id, status, max_activations, created_at, expires_at)
      VALUES (?,?,?,?,?,?,?)
    `
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

    // opcional: actualizar plan "principal" del user
    db.prepare("UPDATE users SET plan = ? WHERE id = ?").run(planId, user.id);

    const lic = db
      .prepare("SELECT * FROM licenses WHERE id = ?")
      .get(info.lastInsertRowid);

    res.json({
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
    res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Endpoint de activación para la APP
// =========================
app.post("/api/licenses/activate", (req, res) => {
  try {
    const { key, installId, deviceName, appVersion } = req.body || {};
    if (!key || !installId) {
      return res
        .status(400)
        .json({ error: "key e installId son requeridos" });
    }

    const license = db
      .prepare("SELECT * FROM licenses WHERE key = ?")
      .get(String(key).trim());

    if (!license) {
      return res.status(404).json({ error: "Licencia no encontrada" });
    }

    if (license.status !== "active") {
      return res.status(403).json({
        error: "LICENCE_INACTIVE",
        status: license.status,
      });
    }

    if (
      license.expires_at &&
      new Date(license.expires_at) < new Date()
    ) {
      return res.status(403).json({ error: "LICENCE_EXPIRED" });
    }

    const nowIso = new Date().toISOString();

    // verificar activaciones anteriores
    let activation = db
      .prepare(
        "SELECT * FROM license_activations WHERE license_id = ? AND install_id = ?"
      )
      .get(license.id, installId);

    if (!activation) {
      const countRow = db
        .prepare(
          "SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?"
        )
        .get(license.id);
      const used = countRow.n || 0;

      const maxAllowed =
        license.max_activations ||
        PLAN_DEVICE_LIMIT[license.plan_id] ||
        DEFAULT_MAX_ACTIVATIONS;

      if (used >= maxAllowed) {
        return res
          .status(403)
          .json({ error: "MAX_INSTALLS_REACHED" });
      }

      db.prepare(
        `
        INSERT INTO license_activations
        (license_id, install_id, device_name, first_activated_at, last_seen_at, app_version)
        VALUES (?,?,?,?,?,?)
      `
      ).run(
        license.id,
        installId,
        deviceName || null,
        nowIso,
        nowIso,
        appVersion || null
      );
    } else {
      db.prepare(
        `
        UPDATE license_activations
        SET last_seen_at = ?, app_version = ?, device_name = COALESCE(?, device_name)
        WHERE id = ?
      `
      ).run(
        nowIso,
        appVersion || activation.app_version,
        deviceName || activation.device_name,
        activation.id
      );
    }

    const plan =
      PLANS.find((p) => p.id === license.plan_id) || PLANS[0];
    const limits =
      PLAN_LIMITS[license.plan_id] || PLAN_LIMITS["starter"];

    const countRow2 = db
      .prepare(
        "SELECT COUNT(*) AS n FROM license_activations WHERE license_id = ?"
      )
      .get(license.id);

    res.json({
      ok: true,
      license: {
        planId: license.plan_id,
        planName: plan.name,
        status: license.status,
        expiresAt: license.expires_at,
        maxActivations: license.max_activations,
        activationsUsed: countRow2.n || 0,
        keyMasked: `${license.key.slice(0, 4)}-****-****`,
        limits,
      },
    });
  } catch (err) {
    console.error("Error en /api/licenses/activate", err);
    res.status(500).json({ error: "Error interno" });
  }
});

// =========================
// Start
// =========================
app.listen(PORT, () => {
  console.log(
    `Hyperion website backend escuchando en http://localhost:${PORT}`
  );
});
