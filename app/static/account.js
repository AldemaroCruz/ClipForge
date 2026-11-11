"use strict";
const auth = window.ClipForgeAuth;
const accountElement = id => document.getElementById(id);
function submitAccount(form, statusId, action) {
  form.addEventListener("submit", async event => {
    event.preventDefault(); const button=form.querySelector("button[type=submit]"),status=accountElement(statusId);
    button.disabled=true;status.textContent="";
    try {await action();} catch(error) {status.textContent=error.message;} finally {button.disabled=false;}
  });
}
if (accountElement("login-form")) {
  submitAccount(accountElement("login-form"), "login-status", async () => {
    try {await auth.login(accountElement("username").value,accountElement("password").value);location.replace("/");}
    finally {accountElement("password").value="";}
  });
} else {
  let currentUser=null;
  async function refreshUsers() {
    const result=await auth.json("/auth/users"), list=accountElement("user-list");list.replaceChildren();
    for(const user of result.users) {
      const row=document.createElement("div"),label=document.createElement("span");row.className="user-row";
      label.textContent=`${user.username} · ${user.is_active ? "Activa" : "Desactivada"}${user.is_admin ? " · Administrador" : ""}`;row.append(label);
      if(user.is_active && user.id!==currentUser.id) {
        const button=document.createElement("button");button.type="button";button.className="secondary";button.textContent="Desactivar";
        button.setAttribute("aria-label",`Desactivar a ${user.username}`);
        button.addEventListener("click",async()=>{
          if(!confirm(`¿Desactivar a ${user.username}? Sus sesiones se cerrarán.`))return;
          button.disabled=true;
          try {await auth.json(`/auth/users/${encodeURIComponent(user.id)}/deactivate`,auth.payload({}));await refreshUsers();}
          catch(error){accountElement("users-status").textContent=error.message;button.disabled=false;}
        });row.append(button);
      }
      list.append(row);
    }
  }
  auth.ready.then(async user=>{
    if(!user)return; currentUser=user;
    accountElement("account-role").textContent=user.is_admin?"Administrador de usuarios":"Usuario";
    if(user.permissions.includes("users:manage")){accountElement("users-panel").hidden=false;try{await refreshUsers();}catch(error){accountElement("users-status").textContent=error.message;}}
  });
  submitAccount(accountElement("password-form"),"password-status",async()=>{
    try {await auth.json("/auth/password",auth.payload({current_password:accountElement("current-password").value,new_password:accountElement("new-password").value}));location.replace("/login");}
    finally {accountElement("password-form").reset();}
  });
  submitAccount(accountElement("create-user-form"),"users-status",async()=>{
    try{await auth.json("/auth/users",auth.payload({username:accountElement("new-username").value,password:accountElement("user-password").value}));accountElement("create-user-form").reset();accountElement("users-status").textContent="Cuenta creada.";await refreshUsers();}
    finally{accountElement("user-password").value="";}
  });
  accountElement("refresh-users").addEventListener("click",()=>refreshUsers().catch(error=>{accountElement("users-status").textContent=error.message;}));
}
