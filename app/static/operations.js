"use strict";
const el=id=>document.getElementById(id);
let rows=[],pending=null,loading=false;
const stageNames={queue:"Espera en cola",validation:"Validación de archivo",model_load:"Carga / verificación del modelo",transcription:"Transcripción",selection:"Selección heurística",render:"Render FFmpeg"};
const num=n=>Number(n).toLocaleString("es-SV",{maximumFractionDigits:2});
function bytes(n){if(!Number.isFinite(n))return "No medido";return n>=1024**3?`${num(n/1024**3)} GiB`:`${num(n/1024**2)} MiB`;}
function node(tag,text){const n=document.createElement(tag);n.textContent=text;return n;}
async function json(url,options={}){const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),30000);try{const response=await fetch(url,{...options,cache:"no-store",signal:controller.signal});const body=await response.json();if(!response.ok)throw new Error(typeof body.detail==="string"?body.detail:`Error HTTP ${response.status}`);return body;}finally{clearTimeout(timer);}}
function selected(){return rows.find(r=>r.job_id===el("project").value);}
function draw(){const r=selected();el("stages").replaceChildren();el("details").replaceChildren();el("save-review").disabled=!r||loading;el("detail-note").textContent="";if(!r)return;
  el("detail-note").textContent=`Proyecto ${r.job_id} · ${r.status} · ${bytes(r.data_bytes)} · ${r.timed_runs} ejecución(es) medidas. ${r.warnings_count?"Aviso: hay registros ilegibles; totales parciales.":""}`;
  for(const [key,label]of Object.entries(stageNames)){const tr=document.createElement("tr");tr.append(node("td",label),node("td",Number.isFinite(r.stage_seconds?.[key])?num(r.stage_seconds[key]):"No medido"));el("stages").append(tr);}
  const stats=[`Variantes: ${r.completed_exports} completas · ${r.approved_exports} aprobadas · ${r.failed_exports} fallidas`,
    `Peticiones IA intentadas: ${r.ai_requests_attempted} · sin consumo conocido: ${r.ai_usage_missing}`,
    r.tokens_reported?`Tokens reportados: ${num(r.tokens_reported.input_tokens)} entrada / ${num(r.tokens_reported.output_tokens)} salida`:"Tokens: sin reporte guardado",
    `Tiempo de análisis IA guardado: ${num(r.ai_elapsed_seconds)} s`,
    `Revisión: ${num(r.review_minutes)} min en ${r.review_sessions} registros`,
    r.review_minutes_per_approved===null?"Minutos por aprobado: faltan aprobados o tiempo registrado":`Minutos de revisión por aprobado: ${num(r.review_minutes_per_approved)}`,
    `Registros de tiempo sin final: ${r.unfinished_metric_records}`,"Costo monetario: no calculado"];
  stats.forEach(s=>el("details").append(node("p",s)));
}
async function refresh(){loading=true;el("refresh").disabled=true;el("save-review").disabled=true;const previous=el("project").value;try{const data=await json("/ops/summary");rows=data.projects;el("count").textContent=rows.length;el("approved").textContent=rows.reduce((n,r)=>n+r.approved_exports,0);el("free").textContent=bytes(data.disk_free_bytes);el("human").textContent=`${num(rows.reduce((n,r)=>n+r.review_minutes,0))} min`;el("runtime").textContent=`v${data.version} · RSS API: ${bytes(data.api_rss_bytes)} · Modelo: ${data.model_pinned?"lock configurado (verificado al cargar)":"sin lock configurado"}`;el("project").replaceChildren(node("option","Selecciona un proyecto"));el("project").firstChild.value="";for(const row of rows){const option=node("option",`${row.job_id.slice(0,8)} · ${row.status} · ${row.approved_exports} aprobadas`);option.value=row.job_id;el("project").append(option);}if(rows.some(r=>r.job_id===previous))el("project").value=previous;el("status").textContent=data.partial?"Inventario parcial: se alcanzó el límite de proyectos.":"Lectura local completada. Sin consultas al proveedor de IA.";}catch(e){el("status").textContent=`No se pudo actualizar: ${e.message}`;}finally{loading=false;el("refresh").disabled=false;draw();}}
el("project").addEventListener("change",()=>{pending=null;el("review-status").textContent="";draw();});
el("minutes").addEventListener("input",()=>{pending=null;});
el("save-review").addEventListener("click",async()=>{const r=selected(),minutes=Number(el("minutes").value);if(!r||!Number.isFinite(minutes)||minutes<=0||minutes>1440){el("review-status").textContent="Escribe un valor mayor que 0 y hasta 1440 minutos.";return;}if(!pending){const random=new Uint8Array(16);crypto.getRandomValues(random);pending={id:Array.from(random,b=>b.toString(16).padStart(2,"0")).join(""),minutes,job:r.job_id};}el("save-review").disabled=true;try{await json(`/jobs/${r.job_id}/review-time`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:pending.id,minutes:pending.minutes})});pending=null;el("minutes").value="";el("review-status").textContent="Minutos guardados. No se modificaron clips ni borradores.";await refresh();}catch(e){el("review-status").textContent=`No se confirmó el guardado: ${e.message}. Reintenta sin cambiar el valor para evitar duplicados.`;}finally{el("save-review").disabled=false;}});
el("refresh").addEventListener("click",refresh);
refresh();
