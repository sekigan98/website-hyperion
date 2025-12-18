// backend/server.js
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "hyperion-demo-secret";
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || "dev-admin-key"; // para emitir licencias

app.use(cors());
app.use(express.json());

// =========================
// "DB" en memoria (demo)
// =========================
const users = [];   // { id, email, passwordHash, plan }
const licenses = []; // { id, key, userId, planId, status, maxActivations, activations[], createdAt, expiresAt }

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
      "Soporte estándar por email"
    ]
  },
  {
    id: "pro",
    name: "Pro",
    tag: "Recomendado",
    price: "$XX",
    highlight: true,
    cta: "Probar Hyperion Pro",
    features: [
      "Hasta 5 cuentas de WhatsApp",
      "Campañas automáticas + avanzadas",
      "Warmup inteligente",
      "Stats avanzadas por cuenta",
      "Soporte prioritario"
    ]
  },
  {
    id: "agency",
    name: "Agency",
    tag: "Agencias",
    price: "$XX",
    highlight: false,
    cta: "Hablar con ventas",
    features: [
      "10+ cuentas de WhatsApp",
      "Warmup agresivo ajustable",
      "Soporte dedicado",
      "Asistencia en onboarding y setup"
    ]
  }
];

// Límites técnicos por plan (lo que va a usar el cliente)
const PLAN_LIMITS = {
  starter: {
    maxAccounts: 1,
    maxWorkers: 1,
    maxMessagesPerDay: 100,
    warmupEnabled: false
  },
  pro: {
    maxAccounts: 5,
    maxWorkers: 5,
    maxMessagesPerDay: 800,
    warmupEnabled: true
  },
  agency: {
    maxAccounts: 20,
    maxWorkers: 20,
    maxMessagesPerDay: 5000,
    warmupEnabled: true
  }
};

const DEFAULT_MAX_ACTIVATIONS = 3;

// =========================
// Helpers
// =========================
function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, plan: user.plan || "pro_demo" },
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
  const segment = () => crypto.randomBytes(3).toString("hex").toUpperCase();
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

    const existing = users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (existing) {
      return res.status(400).json({ error: "Ese email ya está registrado" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = {
      id: String(users.length + 1),
      email,
      passwordHash,
      // Plan "virtual" hasta que compre licencia
      plan: "pro_demo"
    };
    users.push(user);

    const token = createToken(user);
    res.json({
      token,
      user: { id: user.id, email: user.email, plan: user.plan }
    });
  } catch (err) {
    console.error("Error en /auth/register", err);
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

    const user = users.find(
      (u) => u.email.toLowerCase() === String(email).toLowerCase()
    );
    if (!user) {
      return res.status(400).json({ error: "Credenciales inválidas" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(400).json({ error: "Credenciales inválidas" });
    }

    const token = createToken(user);
    res.json({
      token,
      user: { id: user.id, email: user.email, plan: user.plan }
    });
  } catch (err) {
    console.error("Error en /auth/login", err);
    res.status(500).json({ error: "Error interno" });
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
  const userLicenses = licenses.filter((l) => l.userId === req.user.id);
  const response = userLicenses.map((l) => ({
    id: l.id,
    keyMasked: `${l.key.slice(0, 4)}-****-****`,
    planId: l.planId,
    status: l.status,
    createdAt: l.createdAt,
    expiresAt: l.expiresAt,
    maxActivations: l.maxActivations,
    activationsUsed: l.activations.length
  }));
  res.json({ licenses: response });
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
    redirectUrl: fakePaymentUrl
  });
});

// =========================
// Rutas de licencias (admin)
// =========================

// Emitir licencia para un usuario (ej: llamado desde un panel interno o webhook de pago)
app.post("/api/licenses/issue", requireAdmin, (req, res) => {
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

  const user = users.find(
    (u) => u.email.toLowerCase() === String(email).toLowerCase()
  );
  if (!user) {
    return res.status(404).json({ error: "Usuario no encontrado" });
  }

  const key = generateLicenseKey(planId);
  const now = new Date();
  let expiresAt = null;
  if (typeof expiresInDays === "number" && expiresInDays > 0) {
    expiresAt = new Date(now.getTime() + expiresInDays * 24 * 60 * 60 * 1000);
  }

  const lic = {
    id: String(licenses.length + 1),
    key,
    userId: user.id,
    planId,
    status: "active",
    maxActivations: maxActivations || DEFAULT_MAX_ACTIVATIONS,
    activations: [],
    createdAt: now.toISOString(),
    expiresAt: expiresAt ? expiresAt.toISOString() : null
  };

  licenses.push(lic);

  // opcional: actualizar plan "principal" del user
  user.plan = planId;

  res.json({
    ok: true,
    license: {
      id: lic.id,
      key,
      planId: lic.planId,
      status: lic.status,
      createdAt: lic.createdAt,
      expiresAt: lic.expiresAt,
      maxActivations: lic.maxActivations
    }
  });
});

// =========================
// Endpoint de activación para la APP
// =========================

app.post("/api/licenses/activate", async (req, res) => {
  try {
    const { key, installId, deviceName, appVersion } = req.body || {};
    if (!key || !installId) {
      return res
        .status(400)
        .json({ error: "key e installId son requeridos" });
    }

    const license = licenses.find((l) => l.key === key.trim());
    if (!license) {
      return res.status(404).json({ error: "Licencia no encontrada" });
    }

    if (license.status !== "active") {
      return res
        .status(403)
        .json({ error: "LICENCE_INACTIVE", status: license.status });
    }

    if (license.expiresAt && new Date(license.expiresAt) < new Date()) {
      return res.status(403).json({ error: "LICENCE_EXPIRED" });
    }

    // verificar activaciones anteriores
    let activation = license.activations.find(
      (a) => a.installId === installId
    );

    if (!activation) {
      if (license.activations.length >= (license.maxActivations || DEFAULT_MAX_ACTIVATIONS)) {
        return res.status(403).json({ error: "MAX_INSTALLS_REACHED" });
      }

      activation = {
        installId,
        deviceName: deviceName || null,
        firstActivatedAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
        appVersion: appVersion || null
      };
      license.activations.push(activation);
    } else {
      activation.lastSeenAt = new Date().toISOString();
      activation.appVersion = appVersion || activation.appVersion;
    }

    const plan = PLANS.find((p) => p.id === license.planId) || PLANS[0];
    const limits =
      PLAN_LIMITS[license.planId] || PLAN_LIMITS["starter"];

    // Esta es la info que la APP va a guardar localmente
    res.json({
      ok: true,
      license: {
        planId: license.planId,
        planName: plan.name,
        status: license.status,
        expiresAt: license.expiresAt,
        maxActivations: license.maxActivations,
        activationsUsed: license.activations.length,
        // máscara para mostrar en UI
        keyMasked: `${license.key.slice(0, 4)}-****-****`,
        // límites técnicos que tu backend dentro de la app va a usar
        limits
      }
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
  console.log(`Hyperion backend escuchando en http://localhost:${PORT}`);
});
