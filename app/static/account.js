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
  let currentUser=null,auditPage=1,recoveryGeneration=0;
  const auditActions={"user.created":"Cuenta creada","user.deactivated":"Cuenta desactivada","recovery.issued":"Código emitido","recovery.consumed":"Recuperación completada","password.changed":"Contraseña cambiada"};
  function clearRecovery() {
    recoveryGeneration+=1;
    accountElement("issued-recovery-code").value="";
    accountElement("issued-recovery-code").type="password";
    accountElement("recovery-issued").hidden=true;
    accountElement("recovery-expiry").textContent="";
    accountElement("recovery-recipient").textContent="";
    accountElement("recovery-admin-password").value="";
  }
  window.addEventListener("pagehide",clearRecovery);
  document.addEventListener("visibilitychange",()=>{if(document.hidden)clearRecovery();});
  async function refreshAudit(page=1) {
    const query=new URLSearchParams({page:String(page),page_size:"25"});
    for(const [name,id] of [["action","audit-filter-action"],["result","audit-filter-result"],["target_id","audit-filter-target"]]) {
      if(accountElement(id).value)query.set(name,accountElement(id).value);
    }
    const result=await auth.json(`/auth/admin/audit?${query}`),list=accountElement("audit-list");
    list.replaceChildren();auditPage=result.page;
    for(const event of result.items) {
      const row=document.createElement("tr");
      for(const value of [event.created_at,auditActions[event.action]||event.action,event.actor_id||"Recuperación",event.target_id||"—",event.result==="success"?"Correcto":"Fallido",event.correlation_id]) {
        const cell=document.createElement("td");cell.textContent=value;row.append(cell);
      }
      list.append(row);
    }
    accountElement("audit-page-info").textContent=`Página ${result.page} · ${result.total} eventos`;
    accountElement("audit-prev").disabled=result.page<=1;
    accountElement("audit-next").disabled=result.page*result.page_size>=result.total;
    accountElement("audit-status").textContent=result.items.length?"":"No hay eventos con estos filtros.";
  }
  async function refreshUsers() {
    const result=await auth.json("/auth/users"), list=accountElement("user-list");list.replaceChildren();
    for(const [id,recoveryOnly] of [["recovery-target",true],["audit-filter-target",false]]) {
      const select=accountElement(id),previous=select.value;select.replaceChildren();
      const empty=document.createElement("option");empty.value="";empty.textContent=recoveryOnly?"Selecciona una cuenta":"Todas";select.append(empty);
      for(const user of result.users) {
        if(recoveryOnly&&(!user.is_active||user.is_admin))continue;
        const option=document.createElement("option");option.value=user.id;option.textContent=user.username;select.append(option);
      }
      select.value=[...select.options].some(option=>option.value===previous)?previous:"";
    }
    for(const user of result.users) {
      const row=document.createElement("div"),label=document.createElement("span");row.className="user-row";
      label.textContent=`${user.username} · ${user.is_active ? "Activa" : "Desactivada"}${user.is_admin ? " · Administrador" : ""}`;row.append(label);
      if(user.is_active && user.id!==currentUser.id) {
        const button=document.createElement("button");button.type="button";button.className="secondary";button.textContent="Desactivar";
        button.setAttribute("aria-label",`Desactivar a ${user.username}`);
        button.addEventListener("click",async()=>{
          if(!confirm(`¿Desactivar a ${user.username}? Sus sesiones se cerrarán.`))return;
          button.disabled=true;
          try {await auth.json(`/auth/users/${encodeURIComponent(user.id)}/deactivate`,auth.payload({}));clearRecovery();await refreshUsers();await refreshAudit();}
          catch(error){accountElement("users-status").textContent=error.message;button.disabled=false;}
        });row.append(button);
      }
      list.append(row);
    }
  }
  auth.ready.then(async user=>{
    if(!user)return; currentUser=user;
    accountElement("account-role").textContent=user.is_admin?"Administrador de usuarios":"Usuario";
    if(user.permissions.includes("users:manage")){
      for(const id of ["users-panel","recovery-panel","audit-panel"])accountElement(id).hidden=false;
      try{await refreshUsers();await refreshAudit();}catch(error){accountElement("users-status").textContent=error.message;}
    }
  });
  submitAccount(accountElement("password-form"),"password-status",async()=>{
    try {await auth.json("/auth/password",auth.payload({current_password:accountElement("current-password").value,new_password:accountElement("new-password").value}));location.replace("/login");}
    finally {accountElement("password-form").reset();}
  });
  submitAccount(accountElement("create-user-form"),"users-status",async()=>{
    try{await auth.json("/auth/users",auth.payload({username:accountElement("new-username").value,password:accountElement("user-password").value}));accountElement("create-user-form").reset();accountElement("users-status").textContent="Cuenta creada.";await refreshUsers();await refreshAudit();}
    finally{accountElement("user-password").value="";}
  });
  accountElement("refresh-users").addEventListener("click",()=>refreshUsers().catch(error=>{accountElement("users-status").textContent=error.message;}));
  // Keep the password only for the duration of this request; never in storage.
  accountElement("issue-recovery-form").addEventListener("submit",async event=>{
    event.preventDefault();
    const form=event.currentTarget,button=form.querySelector("button[type=submit]");
    const status=accountElement("recovery-issue-status"),password=accountElement("recovery-admin-password").value;
    const target=accountElement("recovery-target"),targetId=target.value,targetLabel=target.selectedOptions[0].textContent;
    clearRecovery();status.textContent="";button.disabled=true;
    const generation=recoveryGeneration;target.disabled=true;
    try {
      const result=await auth.json(`/auth/admin/users/${encodeURIComponent(targetId)}/recovery`,auth.payload({current_password:password}));
      if(generation!==recoveryGeneration||document.hidden)return;
      if(typeof result.recovery_code!=="string"||typeof result.expires_at!=="string")throw new Error("No se pudo confirmar la emisión del código.");
      accountElement("issued-recovery-code").value=result.recovery_code;
      accountElement("recovery-recipient").textContent=`Cuenta: ${targetLabel}`;
      accountElement("recovery-expiry").textContent=`Caduca: ${result.expires_at} (UTC).`;
      accountElement("show-recovery-code").disabled=false;
      accountElement("recovery-issued").hidden=false;
      status.textContent="Código emitido. Se ha invalidado cualquier código anterior de esta cuenta.";
      try {await refreshAudit();}catch(error){accountElement("audit-status").textContent=error.message;}
    } catch(error) {clearRecovery();status.textContent=error.message;}
    finally {accountElement("recovery-admin-password").value="";button.disabled=false;target.disabled=false;}
  });
  accountElement("show-recovery-code").addEventListener("click",event=>{
    accountElement("issued-recovery-code").type="text";event.currentTarget.disabled=true;
  });
  accountElement("dismiss-recovery-code").addEventListener("click",clearRecovery);
  accountElement("recovery-target").addEventListener("change",clearRecovery);
  accountElement("audit-filter-form").addEventListener("submit",event=>{
    event.preventDefault();refreshAudit().catch(error=>{accountElement("audit-status").textContent=error.message;});
  });
  for(const [id,delta] of [["audit-prev",-1],["audit-next",1]])accountElement(id).addEventListener("click",()=>{
    refreshAudit(auditPage+delta).catch(error=>{accountElement("audit-status").textContent=error.message;});
  });
}
