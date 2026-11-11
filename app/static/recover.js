"use strict";
(() => {
  const form = document.getElementById("recovery-form");
  const code = document.getElementById("recovery-code");
  const password = document.getElementById("recovery-new-password");
  const confirmation = document.getElementById("recovery-confirm-password");
  const status = document.getElementById("recovery-status");
  const clear = () => {code.value="";password.value="";confirmation.value="";};
  window.addEventListener("pagehide", clear);
  form.addEventListener("submit", async event => {
    event.preventDefault();status.textContent="";
    if(password.value!==confirmation.value) {status.textContent="Las contraseñas no coinciden.";return;}
    const button=form.querySelector("button[type=submit]");button.disabled=true;
    try {
      await window.ClipForgeAuth.recover(code.value,password.value);
      form.hidden=true;
      status.textContent="Contraseña actualizada. Tus sesiones anteriores se cerraron. Inicia sesión para continuar.";
      document.getElementById("recovery-login-link").hidden=false;
    } catch(error) {status.textContent=error.message;}
    finally {clear();button.disabled=false;}
  });
})();
