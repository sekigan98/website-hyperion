// frontend/app.js
// Requiere <script type="module" src="app.js"></script>

// ------------------------------------------------------------
// Config API base + links (soporta override por <meta> o window config)
// ------------------------------------------------------------
const DEFAULT_LOCAL_API = "http://localhost:4000/api";
const DEFAULT_PROD_API = "https://hyperion-site-backend.onrender.com/api";

// ✅ Link fijo (GitHub Releases latest)
const DEFAULT_DOWNLOAD_WIN =
  "https://github.com/sekigan98/hyperion-updates/releases/latest/download/Hyperion-Setup.exe";

function isLocalhostHost(hostname) {
  return hostname === "localhost" || hostname === "127.0.0.1";
}

function normalizeBaseUrl(url) {
  const s = String(url || "").trim();
  if (!s) return "";
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

function readMeta(name) {
  const el = document.querySelector(`meta[name="${name}"]`);
  return el?.getAttribute("content") || "";
}

/**
 * Orden de prioridad:
 * 1) <meta name="hyperion-api-base" content="https://.../api">
 * 2) window.__HYPERION_CONFIG__.apiBase
 * 3) DEFAULT_LOCAL_API (si localhost)
 * 4) DEFAULT_PROD_API
 */
function getApiBase() {
  const meta = normalizeBaseUrl(readMeta("hyperion-api-base"));
  if (meta) return meta;

  const w = window.__HYPERION_CONFIG__?.apiBase;
  const winCfg = normalizeBaseUrl(w);
  if (winCfg) return winCfg;

  const host = window.location.hostname;
  return normalizeBaseUrl(isLocalhostHost(host) ? DEFAULT_LOCAL_API : DEFAULT_PROD_API);
}

function getDownloadWinUrl() {
  // Opcional:
  // <meta name="hyperion-download-win" content="https://.../Hyperion-Setup.exe">
  const meta = String(readMeta("hyperion-download-win") || "").trim();
  if (meta) return meta;

  const w = window.__HYPERION_CONFIG__?.downloadWin;
  const winCfg = String(w || "").trim();
  if (winCfg) return winCfg;

  // ✅ fallback fijo
  return DEFAULT_DOWNLOAD_WIN;
}

const API_BASE = getApiBase();
const DOWNLOAD_WIN_URL = getDownloadWinUrl();
const GA4_ID = String(readMeta("hyperion-ga4-id") || "").trim();

const THEME_KEY = "hyperion_theme";
const COOKIE_KEY = "hyperion_cookie_consent";
const CHAT_STORAGE_KEY = "hyperion_chat_history";
const CHAT_STATE_KEY = "hyperion_chat_open";

// ------------------------------------------------------------
// Utils DOM
// ------------------------------------------------------------
function $(selector) {
  return document.querySelector(selector);
}

function $all(selector) {
  return Array.from(document.querySelectorAll(selector));
}

function on(el, ev, fn) {
  if (!el) return;
  el.addEventListener(ev, fn);
}

function setText(el, text) {
  if (!el) return;
  el.textContent = text == null ? "" : String(text);
}

function showError(el, msg) {
  if (!el) return;
  el.hidden = false;
  el.textContent = msg || "Ocurrió un error.";
}

function hideError(el) {
  if (!el) return;
  el.hidden = true;
  el.textContent = "";
}

function escapeHtml(input) {
  const s = String(input ?? "");
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Para usar strings en class="" sin romper el DOM
function safeClassToken(input, fallback = "unknown") {
  const s = String(input || "").toLowerCase().trim();
  const cleaned = s.replace(/[^a-z0-9_-]/g, "");
  return cleaned || fallback;
}

function toDateLabel(iso) {
  if (!iso) return "Sin vencimiento";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Sin vencimiento";
  return `Vence: ${d.toLocaleDateString()}`;
}

function toDateShort(iso) {
  if (!iso) return "Sin fecha";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Sin fecha";
  return d.toLocaleDateString();
}

function toChatTime(date = new Date()) {
  return date.toLocaleTimeString("es-AR", {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function setBusy(form, isBusy) {
  if (!form) return;
  form.classList.toggle("is-busy", !!isBusy);
  const btn = form.querySelector('button[type="submit"]');
  if (btn) btn.disabled = !!isBusy;
}

function loadScript(src, attrs = {}) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    Object.entries(attrs).forEach(([key, value]) => s.setAttribute(key, value));
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "light") {
    root.setAttribute("data-theme", "light");
  } else {
    root.setAttribute("data-theme", "dark");
  }
}

function initThemeToggle() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  const saved = localStorage.getItem(THEME_KEY);
  if (saved) {
    applyTheme(saved);
  } else {
    applyTheme("dark");
  }

  btn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "light" ? "dark" : "light";
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });
}

async function initGa4IfAllowed() {
  const consent = localStorage.getItem(COOKIE_KEY);
  if (consent !== "accepted") return;
  if (!GA4_ID || GA4_ID === "G-XXXXXXXXXX") return;

  try {
    await loadScript(`https://www.googletagmanager.com/gtag/js?id=${GA4_ID}`, { async: "true" });
    window.dataLayer = window.dataLayer || [];
    function gtag() {
      window.dataLayer.push(arguments);
    }
    gtag("js", new Date());
    gtag("config", GA4_ID);
  } catch (err) {
    console.warn("[ga4] failed to load", err);
  }
}

function initCookieBanner() {
  const banner = document.getElementById("cookie-banner");
  if (!banner) return;

  const consent = localStorage.getItem(COOKIE_KEY);
  if (consent === "accepted" || consent === "rejected") {
    initGa4IfAllowed();
    return;
  }

  banner.hidden = false;

  const acceptBtn = document.getElementById("cookie-accept");
  const rejectBtn = document.getElementById("cookie-reject");

  on(acceptBtn, "click", () => {
    localStorage.setItem(COOKIE_KEY, "accepted");
    banner.hidden = true;
    initGa4IfAllowed();
  });

  on(rejectBtn, "click", () => {
    localStorage.setItem(COOKIE_KEY, "rejected");
    banner.hidden = true;
  });
}

// Redirect con next
function redirectToLogin() {
  const here = window.location.pathname.split("/").pop() || "dashboard.html";
  const next = encodeURIComponent(here);
  window.location.href = `login.html?next=${next}`;
}

// ------------------------------------------------------------
// Footer year
// ------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  const yearEl = $("#year");
  if (yearEl) yearEl.textContent = String(new Date().getFullYear());
});

// ------------------------------------------------------------
// Setear links de descarga (robusto)
// ------------------------------------------------------------
function applyDownloadLinks() {
  const url = String(DOWNLOAD_WIN_URL || "").trim() || DEFAULT_DOWNLOAD_WIN;
  if (!url) return;

  const selectors = [
    "#download-win",
    "#download-win-dashboard",
    "#download-windows",
    "#download-windows-hero",
    "#download-windows-dashboard",
    'a[data-hyperion-download="win"]',
  ];

  selectors.forEach((sel) => {
    $all(sel).forEach((a) => {
      try {
        a.setAttribute("href", url);
      } catch (_) {}
    });
  });
}

// ------------------------------------------------------------
// Fetch robusto: timeout + JSON safe
// ------------------------------------------------------------
async function safeJson(res) {
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  const text = await res.text().catch(() => "");
  if (!text) return {};

  if (ct.includes("application/json")) {
    try {
      return JSON.parse(text);
    } catch {
      return {};
    }
  }

  // Si devolvió HTML (error page / proxy), no rompemos
  return { _raw: text };
}

async function safeFetch(url, options = {}, timeoutMs = 15000) {
  const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
  const t = setTimeout(() => {
    try { controller?.abort(); } catch (_) {}
  }, timeoutMs);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller ? controller.signal : undefined,
      cache: "no-store",
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

async function requestJson(path, { method = "GET", token, body } = {}) {
  const url = `${API_BASE}${path.startsWith("/") ? "" : "/"}${path}`;

  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const res = await safeFetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await safeJson(res);
  return { res, data, url };
}

// ------------------------------------------------------------
// Auth helpers (token localStorage)
// ------------------------------------------------------------
const TOKEN_KEY = "hyperion_token";
const USER_KEY = "hyperion_user";

export function setSession(token, user) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  if (user != null) localStorage.setItem(USER_KEY, JSON.stringify(user || {}));
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export function getSession() {
  const token = localStorage.getItem(TOKEN_KEY);
  let user = null;
  try {
    const raw = localStorage.getItem(USER_KEY);
    if (raw) user = JSON.parse(raw);
  } catch {
    user = null;
  }
  return { token, user };
}

// ------------------------------------------------------------
// Plan label
// ------------------------------------------------------------
function formatPlanLabel(planKey) {
  if (!planKey) return "Sin plan";
  const k = String(planKey).toLowerCase();

  switch (k) {
    case "free": return "Free";
    case "starter": return "Starter";
    case "basic": return "Básico";
    case "trial": return "Trial (demo)";
    case "entrepreneur":
    case "emprendedor": return "Emprendedor";
    case "pro": return "Pro";
    case "pro_demo": return "Pro (demo)";
    case "agency": return "Agency";
    case "lifetime": return "Lifetime";
    default: return planKey;
  }
}

// ------------------------------------------------------------
// Login / Register page
// ------------------------------------------------------------
function initAuthPage() {
  const loginForm = $("#login-form");
  const registerForm = $("#register-form");
  const loginError = $("#login-error");
  const registerError = $("#register-error");
  const showRegisterLink = $("#show-register");
  const socialButtons = $all("[data-oauth]");

  if (!loginForm && !registerForm) return;

  // Si venimos con ?next=..., luego del login vamos ahí
  const params = new URLSearchParams(window.location.search);
  const next = params.get("next") || "dashboard.html";

  // Toggle login / register
  on(showRegisterLink, "click", (e) => {
    e.preventDefault();
    if (!registerForm || !loginForm) return;

    const isHidden = registerForm.hasAttribute("hidden");
    if (isHidden) {
      registerForm.removeAttribute("hidden");
      loginForm.setAttribute("hidden", "true");
    } else {
      loginForm.removeAttribute("hidden");
      registerForm.setAttribute("hidden", "true");
    }
  });

  // Social login (placeholder until OAuth config)
  socialButtons.forEach((btn) => {
    on(btn, "click", async () => {
      hideError(loginError);
      const provider = btn.getAttribute("data-oauth");
      if (!provider) return;

      try {
        const { res, data } = await requestJson(`/auth/oauth/${provider}`);
        const msg = data?.error || "OAuth no disponible.";
        showError(loginError, msg);
        if (res.ok && data?.url) {
          window.location.href = data.url;
        }
      } catch (err) {
        console.warn("[oauth] error", err);
        showError(loginError, "OAuth no disponible por ahora.");
      }
    });
  });

  // Login
  on(loginForm, "submit", async (e) => {
    e.preventDefault();
    hideError(loginError);
    setBusy(loginForm, true);

    const formData = new FormData(loginForm);
    const email = String(formData.get("email") || "").trim().toLowerCase();
    const password = String(formData.get("password") || "");

    if (!email || !password) {
      showError(loginError, "Completá email y contraseña.");
      setBusy(loginForm, false);
      return;
    }

    try {
      const { res, data, url } = await requestJson("/auth/login", {
        method: "POST",
        body: { email, password },
      });

      if (!res.ok || data?.ok === false || !data?.token) {
        const serverMsg = data?.error ? ` — ${data.error}` : "";
        showError(loginError, `Login rechazado (${res.status})${serverMsg}`);
        console.warn("[auth] login failed:", url, data);
        return;
      }

      setSession(data.token, data.user);
      window.location.href = next;
    } catch (err) {
      console.error("[auth] login error:", err);
      showError(loginError, "No se pudo conectar con el servidor. Intentá de nuevo.");
    } finally {
      setBusy(loginForm, false);
    }
  });

  // Registro
  on(registerForm, "submit", async (e) => {
    e.preventDefault();
    hideError(registerError);
    setBusy(registerForm, true);

    const formData = new FormData(registerForm);
    const email = String(formData.get("email") || "").trim().toLowerCase();
    const password = String(formData.get("password") || "");

    if (!email || !password) {
      showError(registerError, "Completá email y contraseña.");
      setBusy(registerForm, false);
      return;
    }

    if (password.length < 6) {
      showError(registerError, "La contraseña debe tener al menos 6 caracteres.");
      setBusy(registerForm, false);
      return;
    }

    try {
      // 1) Register
      const { res, data } = await requestJson("/auth/register", {
        method: "POST",
        body: { email, password },
      });

      if (!res.ok || data?.ok === false) {
        showError(registerError, data?.error || "Error al registrarse.");
        return;
      }

      // 2) Autologin
      const login = await requestJson("/auth/login", {
        method: "POST",
        body: { email, password },
      });

      if (!login.res.ok || login.data?.ok === false || !login.data?.token) {
        window.location.href = "login.html";
        return;
      }

      setSession(login.data.token, login.data.user);
      window.location.href = "dashboard.html";
    } catch (err) {
      console.error("[auth] register error:", err);
      showError(registerError, "No se pudo conectar con el servidor. Intentá de nuevo.");
    } finally {
      setBusy(registerForm, false);
    }
  });
}

// ------------------------------------------------------------
// Dashboard
// ------------------------------------------------------------
function initDashboard() {
  const logoutBtn = $("#logout-btn");
  const emailEl = $("#user-email");
  const planEl = $("#user-plan");
  const plansContainer = $("#dashboard-plans");
  const changePassForm = $("#change-password-form");
  const changePassMsg = $("#change-password-msg");
  const licensesContainer = $("#licenses-list");

  if (!logoutBtn) return;

  const { token, user } = getSession();
  if (!token) {
    redirectToLogin();
    return;
  }

  // Pintado rápido con cache local
  if (emailEl && user?.email) setText(emailEl, user.email);
  if (planEl && user?.plan) setText(planEl, formatPlanLabel(user.plan));

  on(logoutBtn, "click", () => {
    clearSession();
    window.location.href = "index.html";
  });

  // ✅ Asegura que los botones queden con link
  applyDownloadLinks();

  // Refrescar /me (solo invalidamos sesión si es 401/403)
  (async () => {
    try {
      const { res, data } = await requestJson("/me", { token });

      if (res.status === 401 || res.status === 403) {
        clearSession();
        redirectToLogin();
        return;
      }

      if (!res.ok) {
        console.warn("[me] bad response:", res.status, data);
        return;
      }

      const u = data.user || {};
      setSession(token, u);

      if (emailEl && u.email) setText(emailEl, u.email);
      if (planEl) setText(planEl, formatPlanLabel(u.plan));
    } catch (err) {
      console.warn("[me] network error:", err);
      // No limpiamos sesión por error de red/transitorio
    }
  })();

  // Cambio de contraseña
  if (changePassForm) {
    changePassForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      if (!token) {
        redirectToLogin();
        return;
      }

      if (changePassMsg) {
        changePassMsg.hidden = true;
        changePassMsg.textContent = "";
        changePassMsg.style.color = "";
      }

      setBusy(changePassForm, true);

      const formData = new FormData(changePassForm);
      const currentPassword = String(formData.get("currentPassword") || "");
      const newPassword = String(formData.get("newPassword") || "");

      if (!currentPassword || !newPassword) {
        if (changePassMsg) {
          changePassMsg.hidden = false;
          changePassMsg.textContent = "Completá ambos campos.";
        }
        setBusy(changePassForm, false);
        return;
      }

      try {
        const { res, data } = await requestJson("/auth/change-password", {
          method: "POST",
          token,
          body: { currentPassword, newPassword },
        });

        if (res.status === 401 || res.status === 403) {
          clearSession();
          redirectToLogin();
          return;
        }

        if (!res.ok || data?.ok === false) {
          if (changePassMsg) {
            changePassMsg.hidden = false;
            changePassMsg.textContent = data?.error || "No se pudo cambiar la contraseña.";
          }
          return;
        }

        if (changePassMsg) {
          changePassMsg.hidden = false;
          changePassMsg.style.color = "#22c55e";
          changePassMsg.textContent = "Contraseña actualizada correctamente.";
        }
        changePassForm.reset();
      } catch (err) {
        console.error("[change-password] error:", err);
        if (changePassMsg) {
          changePassMsg.hidden = false;
          changePassMsg.textContent = "Error de conexión. Intentá de nuevo.";
        }
      } finally {
        setBusy(changePassForm, false);
      }
    });
  }

  // Licencias del usuario
  (async () => {
    if (!licensesContainer) return;

    try {
      const { res, data } = await requestJson("/licenses/my", { token });

      if (res.status === 401 || res.status === 403) {
        clearSession();
        redirectToLogin();
        return;
      }

      if (!res.ok) {
        licensesContainer.innerHTML =
          '<p class="muted small">No se pudieron cargar tus licencias.</p>';
        return;
      }

      const list = Array.isArray(data.licenses) ? data.licenses : [];
      if (!list.length) {
        licensesContainer.innerHTML =
          '<p class="muted small">Todavía no tenés licencias emitidas. Cuando tengas un plan activo, vas a ver la licencia acá.</p>';
        return;
      }

      licensesContainer.innerHTML = "";

      list.forEach((lic) => {
        const item = document.createElement("div");
        item.className = "license-item";

        const planLabel = formatPlanLabel(lic.planId);
        const statusRaw = String(lic.status || "").toLowerCase();
        const status = safeClassToken(statusRaw, "unknown");

        let statusLabel = statusRaw || "desconocido";
        if (statusRaw === "active") statusLabel = "Activa";
        else if (statusRaw === "expired") statusLabel = "Vencida";
        else if (statusRaw === "revoked") statusLabel = "Revocada";

        const activationsUsed = Number(lic.activationsUsed || 0);
        const maxActivations = Number.isFinite(lic.maxActivations) ? lic.maxActivations : 0;

        item.innerHTML = `
          <div class="license-main">
            <div class="license-plan">${escapeHtml(planLabel)}</div>
            <div class="license-key">${escapeHtml(lic.keyMasked || "****-****-****")}</div>
          </div>
          <div class="license-meta">
            <span class="license-status-pill license-status-${status}">
              ${escapeHtml(statusLabel)}
            </span>
            <span class="license-activations">
              ${activationsUsed}/${maxActivations} instalaciones
            </span>
            <span class="license-expiry">
              ${escapeHtml(toDateLabel(lic.expiresAt))}
            </span>
          </div>
        `;

        licensesContainer.appendChild(item);
      });
    } catch (err) {
      console.error("[licenses] error:", err);
      licensesContainer.innerHTML =
        '<p class="muted small">No se pudieron cargar tus licencias.</p>';
    }
  })();

  // Planes (público)
  (async () => {
    if (!plansContainer) return;
    try {
      const { res, data } = await requestJson("/plans");
      if (!res.ok || !Array.isArray(data.plans)) return;

      plansContainer.innerHTML = "";
      data.plans.forEach((p) => {
        const el = document.createElement("div");
        el.className = "pricing-inline-item";
        const name = escapeHtml(p.name || "Plan");
        const price = escapeHtml(p.price || "");
        el.textContent = `${name}${price ? ": " + price : ""}`;
        plansContainer.appendChild(el);
      });
    } catch (_) {
      // fallback: no hacemos nada
    }
  })();
}

// ------------------------------------------------------------
// Landing (index): cargar planes desde API (opcional)
// ------------------------------------------------------------
function initLanding() {
  const cardsContainer = document.getElementById("pricing-cards");
  if (!cardsContainer) return;

  // ✅ Asegura que el botón quede con link
  applyDownloadLinks();

  (async () => {
    try {
      const { res, data } = await requestJson("/plans");
      if (!res.ok || !Array.isArray(data.plans) || data.plans.length === 0) return;

      cardsContainer.innerHTML = "";

      data.plans.forEach((plan) => {
        const article = document.createElement("article");
        article.className = "card pricing-card";

        const tag = escapeHtml(plan.tag || "Plan");
        const name = escapeHtml(plan.name || "Plan");
        const price = escapeHtml(plan.price || "");
        const suffix = escapeHtml(plan.price_suffix || "");
        const cta = escapeHtml(plan.cta || "Elegir plan");
        const highlight = !!plan.highlight;

        const features = Array.isArray(plan.features)
          ? plan.features.map((f) => `<li>${escapeHtml(f)}</li>`).join("")
          : "";

        article.innerHTML = `
          <div class="badge">${tag}</div>
          <h3>${name}</h3>
          <p class="price">${price} <span>${suffix}</span></p>
          <ul class="pricing-list">${features}</ul>
          <a href="login.html" class="btn ${highlight ? "btn-primary" : "btn-outline"} btn-block">
            ${cta}
          </a>
        `;

        if (highlight) article.classList.add("pricing-featured");
        cardsContainer.appendChild(article);
      });
    } catch (_) {
      // si falla, quedan los planes hardcodeados del HTML
    }
  })();
}

// ------------------------------------------------------------
// Contact form
// ------------------------------------------------------------
function initContactForm() {
  const form = document.getElementById("contact-form");
  if (!form) return;

  const successEl = document.getElementById("contact-success");
  const errorEl = document.getElementById("contact-error");

  on(form, "submit", async (e) => {
    e.preventDefault();
    if (successEl) successEl.hidden = true;
    hideError(errorEl);
    setBusy(form, true);

    const formData = new FormData(form);
    const payload = {
      name: String(formData.get("name") || "").trim(),
      email: String(formData.get("email") || "").trim(),
      company: String(formData.get("company") || "").trim(),
      message: String(formData.get("message") || "").trim(),
    };

    try {
      const { res, data } = await requestJson("/contact", { method: "POST", body: payload });
      if (!res.ok || data?.ok === false) {
        showError(errorEl, data?.error || "No se pudo enviar el mensaje.");
        return;
      }
      if (successEl) successEl.hidden = false;
      form.reset();
    } catch (err) {
      console.error("[contact] error", err);
      showError(errorEl, "Error de conexión. Intentá de nuevo.");
    } finally {
      setBusy(form, false);
    }
  });
}

// ------------------------------------------------------------
// Newsletter
// ------------------------------------------------------------
function initNewsletterForm() {
  const form = document.getElementById("newsletter-form");
  const msgEl = document.getElementById("newsletter-msg");
  if (!form) return;

  on(form, "submit", async (e) => {
    e.preventDefault();
    if (msgEl) msgEl.hidden = true;
    setBusy(form, true);

    const formData = new FormData(form);
    const email = String(formData.get("email") || "").trim();

    try {
      const { res, data } = await requestJson("/newsletter", {
        method: "POST",
        body: { email, source: "landing" },
      });

      if (!res.ok || data?.ok === false) {
        if (msgEl) {
          msgEl.hidden = false;
          msgEl.textContent = data?.error || "No se pudo suscribir.";
        }
        return;
      }

      if (msgEl) {
        msgEl.hidden = false;
        msgEl.textContent =
          data?.status === "already_subscribed"
            ? "Ya estabas suscripto. ¡Gracias!"
            : "✅ Suscripción confirmada.";
      }
      form.reset();
    } catch (err) {
      console.error("[newsletter] error", err);
      if (msgEl) {
        msgEl.hidden = false;
        msgEl.textContent = "Error de conexión.";
      }
    } finally {
      setBusy(form, false);
    }
  });
}

// ------------------------------------------------------------
// Quote calculator
// ------------------------------------------------------------
function initQuoteCalculator() {
  const form = document.getElementById("quote-form");
  const totalEl = document.getElementById("quote-total");
  if (!form || !totalEl) return;

  const compute = () => {
    const data = new FormData(form);
    const accounts = Number(data.get("accounts") || 0);
    const campaigns = Number(data.get("campaigns") || 0);
    const support = String(data.get("support") || "standard");

    const base = 200;
    const accountCost = accounts * 80;
    const campaignCost = campaigns * 40;
    const supportMultiplier = support === "dedicated" ? 1.6 : support === "priority" ? 1.3 : 1;

    const total = Math.round((base + accountCost + campaignCost) * supportMultiplier);
    totalEl.textContent = `Desde $${total} USD / mes`;
  };

  on(form, "input", compute);
  on(form, "submit", (e) => {
    e.preventDefault();
    compute();
    window.location.href = "#contact";
  });

  compute();
}

// ------------------------------------------------------------
// Tickets (dashboard)
// ------------------------------------------------------------
function initTickets() {
  const form = document.getElementById("ticket-form");
  const list = document.getElementById("tickets-list");
  const msgEl = document.getElementById("ticket-msg");
  if (!form || !list) return;

  const { token } = getSession();
  if (!token) return;

  const loadTickets = async () => {
    try {
      const { res, data } = await requestJson("/tickets", { token });
      if (res.status === 401 || res.status === 403) {
        clearSession();
        redirectToLogin();
        return;
      }
      if (!res.ok) {
        list.innerHTML = '<p class="muted small">No se pudieron cargar los tickets.</p>';
        return;
      }
      const tickets = Array.isArray(data.tickets) ? data.tickets : [];
      if (!tickets.length) {
        list.innerHTML = '<p class="muted small">Todavía no tenés tickets.</p>';
        return;
      }
      list.innerHTML = "";
      tickets.forEach((ticket) => {
        const item = document.createElement("div");
        item.className = "ticket-item";
        const messages = (ticket.messages || [])
          .map(
            (msg) =>
              `<div class="ticket-message"><strong>${escapeHtml(msg.sender)}</strong>: ${escapeHtml(
                msg.message
              )}</div>`
          )
          .join("");

        item.innerHTML = `
          <strong>${escapeHtml(ticket.subject || "Ticket")}</strong>
          <div class="ticket-meta">
            <span>Estado: ${escapeHtml(ticket.status || "open")}</span>
            <span>Prioridad: ${escapeHtml(ticket.priority || "normal")}</span>
            <span>Actualizado: ${escapeHtml(toDateShort(ticket.updatedAt))}</span>
          </div>
          <div class="ticket-messages">${messages}</div>
        `;
        list.appendChild(item);
      });
    } catch (err) {
      console.error("[tickets] error", err);
      list.innerHTML = '<p class="muted small">No se pudieron cargar los tickets.</p>';
    }
  };

  on(form, "submit", async (e) => {
    e.preventDefault();
    if (msgEl) msgEl.hidden = true;
    setBusy(form, true);

    const data = new FormData(form);
    const payload = {
      subject: String(data.get("subject") || "").trim(),
      priority: String(data.get("priority") || "normal"),
      message: String(data.get("message") || "").trim(),
    };

    try {
      const { res, data: resp } = await requestJson("/tickets", {
        method: "POST",
        token,
        body: payload,
      });
      if (!res.ok || resp?.ok === false) {
        if (msgEl) {
          msgEl.hidden = false;
          msgEl.textContent = resp?.error || "No se pudo crear el ticket.";
        }
        return;
      }
      form.reset();
      await loadTickets();
    } catch (err) {
      console.error("[tickets] create error", err);
      if (msgEl) {
        msgEl.hidden = false;
        msgEl.textContent = "Error de conexión.";
      }
    } finally {
      setBusy(form, false);
    }
  });

  loadTickets();
}

// ------------------------------------------------------------
// Blog
// ------------------------------------------------------------
function renderBlogCards(container, posts) {
  if (!container) return;
  container.innerHTML = "";
  posts.forEach((post) => {
    const card = document.createElement("article");
    card.className = "card";
    card.innerHTML = `
      <span class="badge">${escapeHtml(post.tag || "Artículo")}</span>
      <h3>${escapeHtml(post.title || "Título")}</h3>
      <p class="muted">${escapeHtml(post.excerpt || "")}</p>
      <p class="muted small">${escapeHtml(post.date || "")} · ${escapeHtml(post.readTime || "")}</p>
    `;
    container.appendChild(card);
  });
}

async function initBlog() {
  const preview = document.getElementById("blog-preview");
  const list = document.getElementById("blog-list");
  if (!preview && !list) return;

  try {
    const res = await fetch("data/blog.json", { cache: "no-store" });
    if (!res.ok) return;
    const posts = await res.json();
    if (preview) renderBlogCards(preview, posts.slice(0, 3));
    if (list) renderBlogCards(list, posts);
  } catch (err) {
    console.warn("[blog] error", err);
  }
}

// ------------------------------------------------------------
// Chat widget
// ------------------------------------------------------------
function initChatWidget() {
  const widget = document.getElementById("chat-widget");
  if (!widget) return;
  const toggle = document.getElementById("chat-toggle");
  const panel = widget.querySelector(".chat-panel");
  const messages = document.getElementById("chat-messages");
  const typing = document.getElementById("chat-typing");
  const quick1 = document.getElementById("chat-quick-1");
  const quick2 = document.getElementById("chat-quick-2");
  const quick3 = document.getElementById("chat-quick-3");
  const minimize = document.getElementById("chat-minimize");
  const controls = [quick1, quick2, quick3].filter(Boolean);
  const history = [];
  const maxMessages = 24;
  const primaryAction = quick1 || quick2 || quick3;

  const setControlsDisabled = (isDisabled) => {
    controls.forEach((control) => {
      control.disabled = !!isDisabled;
    });
  };

  const persistHistory = () => {
    if (!history.length) return;
    try {
      localStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(history.slice(-maxMessages)));
    } catch (err) {
      console.warn("[chat] persist error", err);
    }
  };

  const loadHistory = () => {
    try {
      const raw = localStorage.getItem(CHAT_STORAGE_KEY);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      return parsed
        .filter((item) => item && typeof item.text === "string")
        .slice(-maxMessages);
    } catch (err) {
      console.warn("[chat] load error", err);
      return [];
    }
  };

  const renderMessage = (entry) => {
    if (!messages) return;
    const item = document.createElement("div");
    item.className = `chat-message chat-message--${entry.variant || "bot"}`;
    const body = document.createElement("p");
    body.textContent = entry.text;
    const time = document.createElement("span");
    time.className = "chat-message-time";
    time.textContent = entry.time || toChatTime();
    item.append(body, time);
    messages.appendChild(item);
  };

  const addMessage = (text, variant = "bot", meta = {}) => {
    if (!messages) return;
    const entry = {
      text,
      variant,
      time: meta.time || toChatTime(),
    };
    history.push(entry);
    renderMessage(entry);
    messages.scrollTop = messages.scrollHeight;
    persistHistory();
  };

  const setTyping = (isVisible) => {
    if (!typing) return;
    typing.hidden = !isVisible;
    setControlsDisabled(isVisible);
  };

  const respondWith = (text) => {
    const delay = Math.min(1400, 420 + text.length * 12);
    setTyping(true);
    window.setTimeout(() => {
      setTyping(false);
      addMessage(text, "bot");
    }, delay);
  };

  const sendMessage = (userText, replyText) => {
    if (!userText) return;
    addMessage(userText, "user");
    respondWith(replyText);
  };

  const openPanel = () => {
    if (!panel) return;
    panel.removeAttribute("hidden");
    window.requestAnimationFrame(() => widget.classList.add("is-open"));
    toggle?.setAttribute("aria-expanded", "true");
    primaryAction?.focus();
    localStorage.setItem(CHAT_STATE_KEY, "true");
  };

  const closePanel = () => {
    if (!panel) return;
    widget.classList.remove("is-open");
    window.setTimeout(() => {
      if (!widget.classList.contains("is-open")) {
        panel.setAttribute("hidden", "true");
      }
    }, 200);
    toggle?.setAttribute("aria-expanded", "false");
    localStorage.setItem(CHAT_STATE_KEY, "false");
  };

  const stored = loadHistory();
  stored.forEach((entry) => {
    history.push(entry);
    renderMessage(entry);
  });

  if (!stored.length) {
    addMessage(
      "Hola 👋 Soy Hyperion Assistant. Puedo ayudarte con planes, licencias, soporte o demos. ¿Qué necesitás?",
      "bot"
    );
  } else if (messages) {
    messages.scrollTop = messages.scrollHeight;
  }

  on(toggle, "click", () => {
    const isOpen = panel && !panel.hasAttribute("hidden");
    if (!panel) return;
    if (isOpen) {
      closePanel();
    } else {
      openPanel();
    }
  });

  on(minimize, "click", () => {
    closePanel();
  });

  on(quick1, "click", () => {
    sendMessage("Ver planes", "Te comparto los planes y beneficios clave. ¿Querés que te recomiende el ideal?");
  });

  on(quick2, "click", () => {
    sendMessage("Agendar demo", "Perfecto. Contame cuántas cuentas y qué volumen mensual estimás.");
  });

  on(quick3, "click", () => {
    sendMessage(
      "Soporte",
      "Para soporte urgente, abrí un ticket en tu dashboard o escribinos a soporte@hyperion.com."
    );
  });

  if (localStorage.getItem(CHAT_STATE_KEY) === "true") {
    openPanel();
  }
}

// ------------------------------------------------------------
// Bootstrap
// ------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  // ✅ aplica link de descarga en cualquier página que cargue app.js
  applyDownloadLinks();

  initThemeToggle();
  initCookieBanner();
  initAuthPage();
  initDashboard();
  initLanding();
  initContactForm();
  initNewsletterForm();
  initQuoteCalculator();
  initTickets();
  initBlog();
  initChatWidget();
});

// Debug útil (podés borrarlo cuando quieras)
console.log("[hyperion-web] API_BASE =", API_BASE);
console.log("[hyperion-web] DOWNLOAD_WIN_URL =", DOWNLOAD_WIN_URL || "(no seteado)");
