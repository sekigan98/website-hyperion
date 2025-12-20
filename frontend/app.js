// frontend/app.js

// Detectar si estamos en local o en producción (Netlify + Render)
const isLocal =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";

const API_BASE = isLocal
  ? "http://localhost:4000/api" // cuando desarrollás en local
  : "https://website-hyperion.onrender.com/api"; // URL de Render

// Util simple
function $(selector) {
  return document.querySelector(selector);
}

function on(el, ev, fn) {
  if (!el) return;
  el.addEventListener(ev, fn);
}

// Año footer
document.addEventListener("DOMContentLoaded", () => {
  const yearEl = $("#year");
  if (yearEl) yearEl.textContent = new Date().getFullYear();
});

// -------------------------
// Auth helpers (token localStorage)
// -------------------------
const TOKEN_KEY = "hyperion_token";
const USER_KEY = "hyperion_user";

export function setSession(token, user) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user || {}));
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
  } catch (_) {
    user = null;
  }
  return { token, user };
}

function authHeaders(token) {
  return token
    ? {
        Authorization: `Bearer ${token}`,
      }
    : {};
}

// Helper para mostrar el nombre lindo del plan
function formatPlanLabel(planKey) {
  if (!planKey) return "Sin plan";
  const k = String(planKey).toLowerCase();

  switch (k) {
    case "free":
      return "Free";
    case "starter":
      return "Starter";
    case "basic":
      return "Básico";
    case "trial":
      return "Trial (demo)";
    case "entrepreneur":
    case "emprendedor":
      return "Emprendedor";
    case "pro":
      return "Pro";
    case "pro_demo":
      return "Pro (demo)";
    case "agency":
      return "Agency";
    case "lifetime":
      return "Lifetime";
    default:
      // por si en el futuro agregás otros
      return planKey;
  }
}

// -------------------------
// Login / Registro
// -------------------------
function initAuthPage() {
  const loginForm = $("#login-form");
  const registerForm = $("#register-form");
  const loginError = $("#login-error");
  const registerError = $("#register-error");
  const showRegisterLink = $("#show-register");

  if (!loginForm && !registerForm) return;

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
    if (!loginError) return;

    loginError.hidden = true;
    loginError.textContent = "";

    const formData = new FormData(loginForm);
    const payload = {
      email: formData.get("email"),
      password: formData.get("password"),
    };

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok || data.ok === false) {
        loginError.hidden = false;
        loginError.textContent =
          data.error || "Error al iniciar sesión";
        return;
      }

      // login devuelve { token, user }
      setSession(data.token, data.user);
      window.location.href = "dashboard.html";
    } catch (err) {
      loginError.hidden = false;
      loginError.textContent = "No se pudo conectar con el servidor.";
    }
  });

  // Registro
  on(registerForm, "submit", async (e) => {
    e.preventDefault();
    if (!registerError) return;

    registerError.hidden = true;
    registerError.textContent = "";

    const formData = new FormData(registerForm);
    const payload = {
      email: formData.get("email"),
      password: formData.get("password"),
    };

    try {
      // 1) Registrar usuario en backend (/auth/register)
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok || data.ok === false) {
        registerError.hidden = false;
        registerError.textContent =
          data.error || "Error al registrarse";
        return;
      }

      // 2) Autologin con las mismas credenciales
      try {
        const loginRes = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const loginData = await loginRes.json();

        if (!loginRes.ok || loginData.ok === false) {
          // si por algún motivo falla, simplemente lo mandamos a login
          window.location.href = "login.html";
          return;
        }

        setSession(loginData.token, loginData.user);
        window.location.href = "dashboard.html";
      } catch (_) {
        // fallback: ir a login
        window.location.href = "login.html";
      }
    } catch (err) {
      registerError.hidden = false;
      registerError.textContent =
        "No se pudo conectar con el servidor.";
    }
  });
}

// -------------------------
// Dashboard
// -------------------------
function initDashboard() {
  const logoutBtn = $("#logout-btn");
  const emailEl = $("#user-email");
  const planEl = $("#user-plan");
  const plansContainer = $("#dashboard-plans");
  const changePassForm = $("#change-password-form");
  const changePassMsg = $("#change-password-msg");

  if (!logoutBtn) return; // no estamos en dashboard

  const { token, user } = getSession();
  if (!token) {
    window.location.href = "login.html";
    return;
  }

  // Mostrar algo rápido con lo que tengamos en localStorage
  if (emailEl && user?.email) {
    emailEl.textContent = user.email;
  }
  if (planEl && user?.plan) {
    planEl.textContent = formatPlanLabel(user.plan);
  }

  // Logout
  on(logoutBtn, "click", () => {
    clearSession();
    window.location.href = "index.html";
  });

  // Refrescar datos de usuario desde /me (valida token + plan actual)
  (async () => {
    try {
      const res = await fetch(`${API_BASE}/me`, {
        headers: {
          "Content-Type": "application/json",
          ...authHeaders(token),
        },
      });

      if (!res.ok) {
        clearSession();
        window.location.href = "login.html";
        return;
      }

      const data = await res.json();
      const u = data.user || {};

      setSession(token, u);

      if (emailEl && u.email) {
        emailEl.textContent = u.email;
      }
      if (planEl) {
        planEl.textContent = formatPlanLabel(u.plan);
      }
    } catch (err) {
      // Si falla el /me, asumimos sesión inválida
      clearSession();
      window.location.href = "login.html";
    }
  })();

  // Cambio de contraseña (si agregás el form en dashboard.html)
  if (changePassForm) {
    changePassForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!token) {
        window.location.href = "login.html";
        return;
      }

      if (changePassMsg) {
        changePassMsg.hidden = true;
        changePassMsg.textContent = "";
        changePassMsg.style.color = ""; // reset
      }

      const formData = new FormData(changePassForm);
      const payload = {
        currentPassword: formData.get("currentPassword"),
        newPassword: formData.get("newPassword"),
      };

      try {
        const res = await fetch(`${API_BASE}/auth/change-password`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...authHeaders(token),
          },
          body: JSON.stringify(payload),
        });

        const data = await res.json();

        if (!res.ok || data.ok === false) {
          if (changePassMsg) {
            changePassMsg.hidden = false;
            changePassMsg.style.color = ""; // usa rojo de .form-error si existe
            changePassMsg.textContent =
              data.error || "No se pudo cambiar la contraseña.";
          }
          return;
        }

        if (changePassMsg) {
          changePassMsg.hidden = false;
          changePassMsg.style.color = "#22c55e"; // verde éxito
          changePassMsg.textContent = "Contraseña actualizada correctamente.";
        }
        changePassForm.reset();
      } catch (err) {
        console.error("Error cambiando contraseña", err);
        if (changePassMsg) {
          changePassMsg.hidden = false;
          changePassMsg.style.color = ""; // rojo por CSS
          changePassMsg.textContent =
            "Error de conexión. Intentá de nuevo más tarde.";
        }
      }
    });
  }

  // Pedir planes al backend (público)
  (async () => {
    try {
      const res = await fetch(`${API_BASE}/plans`);
      if (!res.ok) return;
      const data = await res.json();
      if (!Array.isArray(data.plans) || !plansContainer) return;

      plansContainer.innerHTML = "";
      data.plans.forEach((p) => {
        const el = document.createElement("div");
        el.className = "pricing-inline-item";
        const price = p.price || "";
        el.textContent = `${p.name}: ${price}`;
        plansContainer.appendChild(el);
      });
    } catch (_) {
      // no hacemos nada, fallback visual ya está en el HTML
    }
  })();
}

// -------------------------
// Landing: cargar planes desde API (opcional)
// -------------------------
function initLanding() {
  const cardsContainer = document.getElementById("pricing-cards");
  if (!cardsContainer) return;

  (async () => {
    try {
      const res = await fetch(`${API_BASE}/plans`);
      if (!res.ok) return;
      const data = await res.json();
      if (!Array.isArray(data.plans)) return;

      // si hay planes desde backend, sobrescribimos cards
      cardsContainer.innerHTML = "";
      data.plans.forEach((plan) => {
        const article = document.createElement("article");
        article.className = "card pricing-card";

        article.innerHTML = `
          <div class="badge">${plan.tag || "Plan"}</div>
          <h3>${plan.name}</h3>
          <p class="price">${plan.price || ""} <span>${
          plan.price_suffix || ""
        }</span></p>
          <ul class="pricing-list">
            ${
              Array.isArray(plan.features)
                ? plan.features.map((f) => `<li>${f}</li>`).join("")
                : ""
            }
          </ul>
          <a href="login.html" class="btn ${
            plan.highlight ? "btn-primary" : "btn-outline"
          } btn-block">
            ${plan.cta || "Elegir plan"}
          </a>
        `;

        if (plan.highlight) {
          article.classList.add("pricing-featured");
        }

        cardsContainer.appendChild(article);
      });
    } catch (_) {
      // si falla, quedan los 3 planes hardcodeados del HTML
    }
  })();
}

// -------------------------
// Bootstrap por página
// -------------------------
document.addEventListener("DOMContentLoaded", () => {
  initAuthPage();
  initDashboard();
  initLanding();
});

