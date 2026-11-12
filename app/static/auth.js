"use strict";
window.ClipForgeAuth = (() => {
  let user = null, token = null;
  const isLogin = ["/login", "/recover"].includes(location.pathname);
  const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);
  function clearLocal() {
    try { localStorage.removeItem("clipforge-last-job"); if (user) localStorage.removeItem(`clipforge-last-job:${user.id}`); } catch (_) {}
    user = null; token = null;
  }
  async function raw(url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (!safeMethods.has((options.method || "GET").toUpperCase()) && token) headers.set("X-CSRF-Token", token);
    return fetch(url, {...options, headers, credentials:"same-origin", cache:"no-store"});
  }
  async function json(url, options = {}) {
    const response = await raw(url, options);
    let body;
    try { body = await response.json(); } catch (_) { throw new Error("No se pudo leer la respuesta del servidor."); }
    if (!response.ok) {
      const error = new Error(typeof body.detail === "string" ? body.detail : "Revisa los datos e inténtalo de nuevo.");
      error.status = response.status;
      if (response.status === 429) error.message += " Espera antes de volver a intentarlo.";
      throw error;
    }
    return body;
  }
  function payload(data) {return {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)};}
  async function login(username, password) {
    token = (await json("/auth/csrf")).csrf_token;
    const result = await json("/auth/login", payload({username,password}));
    user = result.user; token = result.csrf_token;
    return user;
  }
  async function recover(code, newPassword) {
    token = (await json("/auth/csrf")).csrf_token;
    try {return await json("/auth/recover", payload({code,new_password:newPassword}));}
    finally {token = null;}
  }
  const ready = isLogin ? Promise.resolve(null) : json("/auth/me").then(result => {
    user = result.user; token = result.csrf_token;
    document.querySelectorAll("[data-auth-user]").forEach(n => n.textContent = user.username);
    return user;
  }).catch(error => {
    if (error.status === 401) location.replace("/login");
    document.querySelectorAll("[data-auth-error]").forEach(n => n.textContent = error.message);
    return null;
  });
  async function authenticatedFetch(url, options = {}) {
    if (!await ready) throw new Error("No se pudo confirmar tu sesión. Vuelve a iniciar sesión.");
    const response = await raw(url, options);
    if (response.status === 401) {clearLocal();location.replace("/login");}
    return response;
  }
  async function logout() {
    if (!await ready) return;
    await json("/auth/logout", payload({}));
    clearLocal(); location.replace("/login");
  }
  document.addEventListener("DOMContentLoaded", () => {
    fetch("/environment", {credentials:"same-origin", cache:"no-store"}).then(async response => {
      if (!response.ok) throw new Error("Ambiente sin identificar");
      const value = await response.json();
      if (!value.environment) return;
      const badge = document.createElement("div");
      badge.id = "environment-badge";
      badge.setAttribute("role", "status");
      badge.style.cssText = "padding:8px 16px;background:#212d3d;color:#fff;font:14px system-ui;text-align:center";
      badge.textContent = `${value.environment} · revisión ${value.revision.slice(0, 12)}`;
      badge.title = value.revision;
      document.body.prepend(badge);
    }).catch(() => {
      const badge = document.createElement("div");
      badge.setAttribute("role", "alert");
      badge.textContent = "No se pudo comprobar la identificación del ambiente.";
      document.body.prepend(badge);
    });
    document.querySelectorAll("[data-auth-logout]").forEach(button => button.addEventListener("click", async () => {
      button.disabled = true;
      try {await logout();} catch (error) {button.disabled=false;document.querySelectorAll("[data-auth-error]").forEach(n=>n.textContent=error.message);}
    }));
  });
  return {ready, login, recover, logout, json, payload, fetch:authenticatedFetch,
    storageKey:() => user ? `clipforge-last-job:${user.id}` : null};
})();
