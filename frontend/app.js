// frontend/app.js
// Requiere <script type="module" src="app.js"></script>

// ------------------------------------------------------------
// Config API base + links (soporta override por <meta> o window config)
// ------------------------------------------------------------
const DEFAULT_LOCAL_API = "http://localhost:4000/api";
const DEFAULT_PROD_API = "https://hyperion-site-backend.onrender.com/api";

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
  // <meta name="hyperion-download-win" content="https://.../HyperionSetup.exe">
  const meta = String(readMeta("hyperion-download-win") || "").trim();
  if (meta) return meta;

  const w = window.__HYPERION_CONFIG__?.downloadWin;
  const winCfg = String(w || "").trim();
  return winCfg || "";
}

const API_BASE = getApiBase();
const DOWNLOAD_WIN_URL = getDownloadWinUrl();

// ------------------------------------------------------------
// Utils DOM
// ------------------------------------------------------------
function $(selector) {
  return document.querySelector(selector);
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

function setBusy(form, isBusy) {
  if (!form) return;
  form.classList.toggle("is-busy", !!isBusy);
  const btn = form.querySelector('button[type="submit"]');
  if (btn) btn.disabled = !!isBusy;
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

  // Botones de descarga (si existen)
  const dl1 = $("#download-win");        // sugerido en index.html
  const dl2 = $("#download-win-dashboard"); // sugerido en dashboard.html
  [dl1, dl2].forEach((a) => {
    if (!a) return;
    if (DOWNLOAD_WIN_URL) a.setAttribute("href", DOWNLOAD_WIN_URL);
  });

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

  // Botón descarga en landing (si existe)
  const dl = $("#download-win");
  if (dl && DOWNLOAD_WIN_URL) dl.setAttribute("href", DOWNLOAD_WIN_URL);

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
// Bootstrap
// ------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  initAuthPage();
  initDashboard();
  initLanding();
});

// Debug útil (podés borrarlo cuando quieras)
console.log("[hyperion-web] API_BASE =", API_BASE);
console.log("[hyperion-web] DOWNLOAD_WIN_URL =", DOWNLOAD_WIN_URL || "(no seteado)");
