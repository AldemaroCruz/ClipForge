"use strict";
const $ = (id) => document.getElementById(id);
const fileInput = $("file"), uploadButton = $("upload-button"), statusText = $("status");
const mediaInfo = $("media-info"), clipsList = $("clips"), jobInput = $("job-id"), jobLink = $("job-link");
const labels = {validating:"Validando que el MP4 tenga video, audio y duración suficiente.",queued:"En cola: esperando el turno de procesamiento.",transcribing:"Transcribiendo. En el primer uso también se descarga el modelo Whisper.",rendering:"Generando clips verticales con FFmpeg.",completed:"Procesamiento completado.",failed:"El procesamiento falló."};
const modeNames = {contain:"Imagen completa",blur:"Fondo desenfocado",crop:"Recorte vertical"};
const MAX_RETRIES = 5;
let pollTimer = null, session = 0, currentJob = null, clipSignature = "", exportSignature = "";
let editorData = null, dirty = false, exporting = false, exportTimer = null, uploadURL = null, editorRequest = 0;

const selectedDeliveries=new Map(), reviewEdits=new Map();
let currentExports=[], packaging=false, templateItems=[], templateSequence=0, deliverySequence=0;

class RequestError extends Error {
  constructor(message, status = 0, retryAfter = 2) {super(message); this.status = status; this.retryAfter = retryAfter;}
}
function busy(value) {uploadButton.disabled = value; fileInput.disabled = value;}
function resetPolling() {resetAI();selectedDeliveries.clear();reviewEdits.clear();currentExports=[];$('deliveries-panel').hidden=true;$('deliveries-list').replaceChildren();$('delivery-status').textContent='';updateDeliverySelection();session += 1; clearTimeout(pollTimer); clearTimeout(exportTimer); clipSignature = ""; exportSignature = ""; return session;}
async function requestJSON(url, options = {}, timeout = 15000) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await window.ClipForgeAuth.fetch(url, {...options,cache:"no-store",signal:controller.signal});
    let body;
    try {body = await response.json();} catch (_) {throw new RequestError("El servidor devolvió una respuesta no válida.",response.status);}
    if (!response.ok) {
      const message = typeof body.detail === "string" ? body.detail : Array.isArray(body.detail) ? body.detail.map(d => `${(d.loc || []).join(".")}: ${d.msg}`).join("\n") : `Error HTTP ${response.status}`;
      const delay = Number(response.headers.get("Retry-After")) || 2;
      throw new RequestError(message,response.status,Math.min(10,Math.max(1,delay)));
    }
    return body;
  } catch (error) {
    if (error.name === "AbortError") throw new RequestError("Se agotó el tiempo de espera de la consulta.");
    throw error;
  } finally {clearTimeout(timer);}
}
function rememberJob(id) {currentJob = id; jobInput.value = id; jobLink.textContent = `Job: ${id}`; try {const key=window.ClipForgeAuth.storageKey();if(key)localStorage.setItem(key,id);} catch (_) {}}
function node(tag, text, className) {const n=document.createElement(tag); if(text !== undefined) n.textContent=text; if(className) n.className=className; return n;}
function downloadLink(url, label, filename) {const link=node("a",label); link.href=url; if(filename) link.download=filename; return link;}
function renderMedia(media) {
  mediaInfo.hidden = !media; mediaInfo.textContent = ""; if(!media) return;
  const duration = Number.isFinite(media.duration_seconds) ? `${media.duration_seconds.toFixed(2)} s` : "desconocida";
  mediaInfo.textContent=`Duración: ${duration} · Pistas de video: ${media.video_streams} · Pistas de audio: ${media.audio_streams}`;
}
function makePlayer(url) {const v=node("video"); v.controls=true; v.playsInline=true; v.preload="metadata"; v.src=url; return v;}
// Only one audible player at a time.
document.addEventListener("play",(event)=>{if(event.target.tagName === "VIDEO") document.querySelectorAll("video").forEach(v=>{if(v!==event.target) v.pause();});},true);
function renderClips(id, clips) {
  const signature=JSON.stringify([id,clips]); if(signature===clipSignature) return; clipSignature=signature;
  clipsList.replaceChildren();
  for(const clip of clips) {
    if(!clip || !/^clip_\d{2}\.mp4$/.test(clip.file || "")) continue;
    const item=node("li",undefined,"clip-card"), base=`/jobs/${id}/clips/${clip.file}`;
    item.append(node("h3",clip.file.replace(".mp4","").replace("_"," ")));
    item.append(node("div",`${Number(clip.start).toFixed(2)}–${Number(clip.end).toFixed(2)} s · ${(clip.end-clip.start).toFixed(2)} s`,"meta"));
    item.append(makePlayer(`${base}?inline=true`));
    item.append(node("div",`${modeNames[clip.options?.framing] || modeNames.contain} · ${clip.options?.burn_subtitles ? "Subtítulos incrustados" : "Sin texto incrustado"}`,"meta"));
    if(clip.options?.subtitle_font_size || clip.options?.burn_subtitles) item.append(styleSummary(clip.options));
    const actions=node("div",undefined,"actions");
    actions.append(downloadLink(base,"MP4",clip.file),downloadLink(`${base}/subtitles/srt`,"SRT",clip.file.replace(".mp4",".srt")));
    const edit=node("button","Editar clip","secondary"); edit.type="button"; edit.addEventListener("click",()=>openEditor(id,clip.file));
    actions.append(edit); item.append(actions); clipsList.append(item);
  }
}
async function poll(id, currentSession, failures=0) {
  if(currentSession!==session) return;
  try {
    const job=await requestJSON(`/jobs/${encodeURIComponent(id)}`); if(currentSession!==session) return;
    if(!job || job.id!==id || !Object.hasOwn(labels,job.status) || !Array.isArray(job.clips)) throw new RequestError("La respuesta no contiene un estado de job válido.");
    const headline=job.status==="failed" && job.error_code ? "El archivo no pudo procesarse." : labels[job.status];
    statusText.textContent=(job.message || headline)+(job.error_code ? ` [${job.error_code}]` : "")+(job.error ? `\n${job.error}` : "");
    renderMedia(job.media); renderClips(id,job.clips);
    if(["completed","failed"].includes(job.status)) {busy(false); $("project-actions").hidden=false;refreshExports(id,currentSession);refreshDrafts(id,currentSession);refreshProjects();refreshAI(id,currentSession);return;}
    pollTimer=setTimeout(()=>poll(id,currentSession),2500);
  } catch(error) {
    if(currentSession!==session) return;
    if((error.status>=400 && error.status<500) || failures>=MAX_RETRIES) {
      statusText.textContent=`No se pudo consultar el estado: ${error.message}\nNo se ha eliminado el video. Usa «Consultar estado» para volver a consultar.`; busy(false); return;
    }
    const retry=failures+1; statusText.textContent=`Estado temporalmente no disponible. Reintentando (${retry}/${MAX_RETRIES})…\n${error.message}`;
    pollTimer=setTimeout(()=>poll(id,currentSession,retry),(error.retryAfter || Math.min(8,2*retry))*1000);
  }
}
function readOptions(prefix) {
  return {framing:$(`${prefix}-framing`).value,burn_subtitles:$(`${prefix}-burn`).checked,
    crop_x:Number($(`${prefix}-x`).value)/100,crop_y:Number($(`${prefix}-y`).value)/100,crop_zoom:Number($(`${prefix}-zoom`).value),
    subtitle_font_size:Number($(`${prefix}-subtitle-size`).value),subtitle_color:$(`${prefix}-subtitle-hex`).value.toUpperCase(),
    subtitle_position:$(`${prefix}-subtitle-position`).value,
    subtitle_margin_v:Number($(`${prefix}-subtitle-margin`).value),
    subtitle_outline:Number($(`${prefix}-subtitle-outline`).value),
    subtitle_outline_color:$(`${prefix}-outline-hex`).value.toUpperCase(),
    subtitle_shadow:Number($(`${prefix}-subtitle-shadow`).value)};
}
function validSubtitleStyle(o={}) {
  // Preview/legacy defaults only. Invalid user values must fail validation on save.
  return {size:Number.isInteger(o.subtitle_font_size) && o.subtitle_font_size>=24 && o.subtitle_font_size<=120 ? o.subtitle_font_size : 52,
    color:/^#[0-9a-f]{6}$/i.test(o.subtitle_color || "") ? o.subtitle_color.toUpperCase() : "#FFFFFF"};
}
function validateStyleControls(prefix) {
  for(const name of ["subtitle-size","subtitle-hex","subtitle-margin","subtitle-outline","outline-hex","subtitle-shadow"]) {
    const input=$(`${prefix}-${name}`);
    if(!input.checkValidity()) {input.reportValidity();return false;}
  }
  return true;
}
function styleSummary(options) {
  const style=validSubtitleStyle(options), line=node("div",undefined,"style-meta"), chip=node("span",undefined,"color-chip");
  chip.style.backgroundColor=style.color;
  line.append(chip,node("span",`Tamaño ${style.size} · ${style.color}${options?.burn_subtitles ? "" : " · guardado, no incrustado"}`));
  return line;
}
function setOptions(prefix, o) {
  $(`${prefix}-framing`).value=o.framing || "contain"; $(`${prefix}-burn`).checked=!!o.burn_subtitles;
  $(`${prefix}-x`).value=(o.crop_x ?? .5)*100; $(`${prefix}-y`).value=(o.crop_y ?? .5)*100; $(`${prefix}-zoom`).value=o.crop_zoom ?? 1;
  const style=validSubtitleStyle(o);
  $(`${prefix}-subtitle-size`).value=style.size;$(`${prefix}-subtitle-size-range`).value=style.size;
  $(`${prefix}-subtitle-color`).value=style.color;$(`${prefix}-subtitle-hex`).value=style.color;
  $(`${prefix}-subtitle-position`).value=o.subtitle_position ?? "bottom";
  $(`${prefix}-subtitle-margin`).value=o.subtitle_margin_v ?? 230;
  $(`${prefix}-subtitle-outline`).value=o.subtitle_outline ?? 3;
  $(`${prefix}-outline-color`).value=o.subtitle_outline_color ?? "#201510";
  $(`${prefix}-outline-hex`).value=o.subtitle_outline_color ?? "#201510";
  $(`${prefix}-subtitle-shadow`).value=o.subtitle_shadow ?? 1;
}
function updateOptionLabels(prefix) {
  const o=readOptions(prefix); $(`${prefix}-crop`).hidden=o.framing!=="crop";
  $(`${prefix}-x-value`).textContent=`${Math.round(o.crop_x*100)}%`; $(`${prefix}-y-value`).textContent=`${Math.round(o.crop_y*100)}%`; $(`${prefix}-zoom-value`).textContent=`${o.crop_zoom.toFixed(2)}×`;
  const style=validSubtitleStyle(o), sample=$(`${prefix}-style-sample`);
  sample.style.fontSize=`${style.size/2}px`;sample.style.color=style.color;
  sample.style.webkitTextStroke=`${Math.max(0,Math.min(12,o.subtitle_outline))/2}px ${/^#[0-9a-f]{6}$/i.test(o.subtitle_outline_color) ? o.subtitle_outline_color : '#201510'}`;
  sample.style.textShadow=o.subtitle_shadow ? `${o.subtitle_shadow/2}px ${o.subtitle_shadow/2}px 0 #0008` : 'none';
  $(`${prefix}-subtitle-margin`).disabled=o.subtitle_position==='center';
  $(`${prefix}-margin-note`).textContent=o.subtitle_position==='center' ? 'El margen se conserva, pero no se aplica en la posición central.' : 'Distancia desde el borde, en la salida de 1080 × 1920.';
  $(`${prefix}-style-note`).textContent=o.burn_subtitles
    ? "Se aplicará al MP4 al procesar o generar la variante. El SRT conserva solo texto y tiempos."
    : "Activa «Incrustar subtítulos» para ver este estilo en el MP4. Puedes guardar los ajustes sin incrustar texto.";
  if(prefix==="upload") $("upload-preview-label").textContent=o.burn_subtitles ? "Encuadre + texto de muestra · aún no transcrito" : "Encuadre aproximado";
}
function getCrop(w,h,o) {
  const cw=Math.max(2,Math.floor(Math.min(w,h*9/16)/o.crop_zoom/2)*2), ch=Math.max(2,Math.floor(Math.min(h,w*16/9)/o.crop_zoom/2)*2);
  return {w:cw,h:ch,x:Math.floor((w-cw)*o.crop_x/2)*2,y:Math.floor((h-ch)*o.crop_y/2)*2};
}
function drawCaption(ctx, text, options, width, height) {
  const style=validSubtitleStyle(options), scale=width/1080, fontSize=style.size*scale;
  ctx.save();ctx.font=`bold ${fontSize}px "DejaVu Sans", Arial, sans-serif`;
  ctx.textAlign="center";ctx.textBaseline="alphabetic";ctx.fillStyle=style.color;
  const outline=Number.isFinite(options.subtitle_outline) ? Math.max(0,Math.min(12,options.subtitle_outline)) : 3;
  ctx.strokeStyle=/^#[0-9a-f]{6}$/i.test(options.subtitle_outline_color || '') ? options.subtitle_outline_color : '#201510';
  ctx.lineWidth=Math.max(.01,2*outline*scale);ctx.lineJoin="round";
  ctx.shadowColor='#0008';ctx.shadowOffsetX=ctx.shadowOffsetY=(options.subtitle_shadow ?? 1)*scale;
  const maxWidth=width-190*scale, lines=[];let line="";
  for(const word of String(text).split(/\s+/).filter(Boolean)) {
    if(line && ctx.measureText(`${line} ${word}`).width<=maxWidth) {line+=` ${word}`;continue;}
    if(line) {lines.push(line);line="";}
    // Split long tokens rather than squeezing text horizontally in the preview.
    for(const char of word) {
      if(line && ctx.measureText(line+char).width>maxWidth) {lines.push(line);line="";}
      line+=char;
    }
  }
  if(line) lines.push(line);
  const margin=(Number.isFinite(options.subtitle_margin_v) ? options.subtitle_margin_v : 230)*scale, lineHeight=fontSize*1.2;
  const blockHeight=lines.length*lineHeight;
  const bottom=options.subtitle_position==='top' ? margin+blockHeight-fontSize*.2 : options.subtitle_position==='center' ? height/2+blockHeight/2-fontSize*.2 : height-margin;
  lines.forEach((value,index)=>{
    const y=bottom-(lines.length-1-index)*lineHeight;
    if(outline>0) ctx.strokeText(value,width/2,y);ctx.fillText(value,width/2,y);
  });ctx.restore();
}
class FramePreview {
  constructor(prefix, context) {
    this.prefix=prefix; this.video=$(`${prefix}-source`); this.canvas=$(`${prefix}-canvas`); this.box=$(`${prefix}-box`); this.context=context; this.raf=null;
    const draw=()=>this.draw();
    ["loadeddata","seeked","pause","timeupdate"].forEach(e=>this.video.addEventListener(e,draw));
    this.video.addEventListener("loadedmetadata",()=>{const ctx=this.context(); if(ctx) this.video.currentTime=Math.min(ctx.start,this.video.duration || ctx.start); this.draw();});
    this.video.addEventListener("play",()=>this.tick());
    this.video.addEventListener("timeupdate",()=>{const ctx=this.context(); if(ctx && this.video.currentTime>=ctx.end) this.video.pause();});
    ["framing","burn","x","y","zoom"].forEach(name=>$(`${prefix}-${name}`).addEventListener("input",()=>{updateOptionLabels(prefix); if(prefix==="editor") setDirty(true); this.draw();}));
    const refreshStyle=()=>{updateOptionLabels(prefix);if(prefix==="editor") setDirty(true);this.draw();};
    const size=$(`${prefix}-subtitle-size`), range=$(`${prefix}-subtitle-size-range`), color=$(`${prefix}-subtitle-color`), hex=$(`${prefix}-subtitle-hex`);
    range.addEventListener("input",()=>{size.value=range.value;refreshStyle();});
    size.addEventListener("input",()=>{if(size.checkValidity()) range.value=size.value;refreshStyle();});
    color.addEventListener("input",()=>{hex.value=color.value.toUpperCase();refreshStyle();});
    hex.addEventListener("input",()=>{if(hex.checkValidity()) color.value=hex.value;refreshStyle();});
    hex.addEventListener("blur",()=>{if(hex.checkValidity()) hex.value=hex.value.toUpperCase();});
    $(`${prefix}-style-reset`).addEventListener("click",()=>{
      const before=readOptions(prefix);
      setOptions(prefix,{...before,subtitle_font_size:52,subtitle_color:'#FFFFFF',subtitle_position:'bottom',subtitle_margin_v:230,subtitle_outline:3,subtitle_outline_color:'#201510',subtitle_shadow:1});refreshStyle();
    });
    ["subtitle-position","subtitle-margin","subtitle-outline","subtitle-shadow"].forEach(name=>$(`${prefix}-${name}`).addEventListener('input',refreshStyle));
    const border=$(`${prefix}-outline-color`),borderHex=$(`${prefix}-outline-hex`);
    border.addEventListener('input',()=>{borderHex.value=border.value.toUpperCase();refreshStyle();});
    borderHex.addEventListener('input',()=>{if(borderHex.checkValidity()) border.value=borderHex.value;refreshStyle();});
    window.addEventListener("resize",draw); updateOptionLabels(prefix); this.draw();
  }
  tick() {cancelAnimationFrame(this.raf); this.draw(); if(!this.video.paused) this.raf=requestAnimationFrame(()=>this.tick());}
  draw() {
    const v=this.video,c=this.canvas,ctx=c.getContext("2d"),o=readOptions(this.prefix),w=v.videoWidth,h=v.videoHeight;
    ctx.clearRect(0,0,c.width,c.height); ctx.fillStyle="#05080d";ctx.fillRect(0,0,c.width,c.height); this.box.hidden=true;
    if(!w || !h || v.readyState<2) {ctx.fillStyle="#91a8c7";ctx.font="12px system-ui";ctx.textAlign="center";ctx.fillText("Vista de encuadre",c.width/2,c.height/2); return;}
    ctx.save();
    if(o.framing==="crop") {
      const r=getCrop(w,h,o); ctx.drawImage(v,r.x,r.y,r.w,r.h,0,0,c.width,c.height);
      const rect=v.getBoundingClientRect(), fit=Math.min(rect.width/w,rect.height/h),offsetX=(rect.width-w*fit)/2,offsetY=(rect.height-h*fit)/2;
      this.box.hidden=false; Object.assign(this.box.style,{left:`${offsetX+r.x*fit}px`,top:`${offsetY+r.y*fit}px`,width:`${r.w*fit}px`,height:`${r.h*fit}px`});
    } else {
      if(o.framing==="blur") {const k=Math.max(c.width/w,c.height/h); ctx.filter="blur(9px)"; ctx.drawImage(v,(c.width-w*k)/2-5,(c.height-h*k)/2-5,w*k+10,h*k+10); ctx.filter="none";}
      const k=Math.min(c.width/w,c.height/h); ctx.drawImage(v,(c.width-w*k)/2,(c.height-h*k)/2,w*k,h*k);
    }
    const data=this.context();
    if(o.burn_subtitles) {
      const t=data ? v.currentTime-data.start : 0;
      const text=data ? data.cues.find(q=>q.start<=t && q.end>t)?.text : "Texto de muestra";
      if(text) drawCaption(ctx,text,o,c.width,c.height);
    }
    ctx.restore();
  }
}
const uploadPreview=new FramePreview("upload",()=>null);
const editorPreview=new FramePreview("editor",()=>editorData);
fileInput.addEventListener("change",()=>{
  if(uploadURL) URL.revokeObjectURL(uploadURL);
  const file=fileInput.files[0]; $("upload-preview").hidden=!file;
  if(file) {uploadURL=URL.createObjectURL(file);uploadPreview.video.src=uploadURL;} else {uploadURL=null;uploadPreview.video.removeAttribute("src");uploadPreview.video.load();}
});
window.addEventListener("beforeunload",(e)=>{if(dirty || reviewEdits.size) {e.preventDefault();e.returnValue="";}});
$("close-editor").addEventListener("click",()=>{if(!exporting && canLeaveEditor()) hideEditor();});
function renderCues() {
  const list=$("cue-list");list.replaceChildren(); if(!editorData) return;
  editorData.cues.forEach((cue,index)=>{
    const row=node("div",undefined,"cue-row"), times=node("div",undefined,"cue-times");
    for(const key of ["start","end"]) {
      const label=node("label",key==="start"?"Inicio (s)":"Fin (s)"), input=node("input");
      input.type="number";input.step="0.001";input.min="0";input.max=String(editorData.duration);input.value=cue[key];input.setAttribute("aria-label",`${key==="start"?"Inicio":"Fin"} subtítulo ${index+1}`);
      input.addEventListener("input",()=>{cue[key]=Number(input.value);setDirty(true);editorPreview.draw();});label.append(input);times.append(label);
    }
    const seek=node("button","▶","subtle");seek.type="button";seek.setAttribute("aria-label",`Escuchar subtítulo ${index+1}`);seek.addEventListener("click",()=>{editorPreview.video.currentTime=editorData.start+cue.start;editorPreview.video.play().catch(()=>{});});times.append(seek);
    const text=node("textarea");text.value=cue.text;text.maxLength=500;text.setAttribute("aria-label",`Texto subtítulo ${index+1}`);text.addEventListener("input",()=>{cue.text=text.value;setDirty(true);editorPreview.draw();});
    const tools=node("div",undefined,"cue-tools"), remove=node("button","Quitar","subtle");remove.type="button";remove.addEventListener("click",()=>{editorData.cues.splice(index,1);setDirty(true);renderCues();editorPreview.draw();});
    tools.append(node("span",`Subtítulo ${index+1}`),remove);row.append(times,text,tools);list.append(row);
  });
  if(!editorData.cues.length) list.append(node("p","Sin subtítulos. Agrega texto o exporta sin incrustarlo.","muted"));
}
$("play-range").addEventListener("click",()=>{if(editorData){editorPreview.video.currentTime=editorData.start;editorPreview.video.play().catch(()=>{});}});
$("add-cue").addEventListener("click",()=>{
  if(!editorData || editorData.cues.length>=400) return;
  let start=0;for(const cue of editorData.cues) {if(cue.start-start>=.1) break;start=Math.max(start,cue.end);}
  const next=editorData.cues.find(c=>c.start>start), end=Math.min(start+2,next?.start ?? editorData.duration,editorData.duration);
  if(end-start<.04) {$("export-status").hidden=false;$("export-status").textContent="No hay un espacio libre. Ajusta los tiempos existentes antes de agregar otro subtítulo.";return;}
  editorData.cues.push({start:Math.round(start*1000)/1000,end:Math.round(end*1000)/1000,text:"Nuevo subtítulo"});editorData.cues.sort((a,b)=>a.start-b.start);setDirty(true);renderCues();
});
async function pollExport(id,exportId,currentSession,failures=0) {
  if(currentSession!==session) {exportBusy(false);return;}
  try {
    const item=await requestJSON(`/jobs/${id}/exports/${exportId}`);if(currentSession!==session) {exportBusy(false);return;}
    $("export-status").textContent=item.status==="completed" ? "Variante lista. Reproduce el nuevo MP4 en «Variantes guardadas» y comprueba encuadre, audio y subtítulos." : item.status==="failed" ? `La variante falló: ${item.error}\nEl original y el borrador guardado se conservan.` : item.status==="rendering" ? "Renderizando con FFmpeg. El original se conserva; Whisper no se ejecuta." : "Variante en cola: esperando el turno de procesamiento.";
    await refreshExports(id,currentSession);
    if(["completed","failed"].includes(item.status)) {exportBusy(false);refreshProjects();return;}
    exportTimer=setTimeout(()=>pollExport(id,exportId,currentSession),2500);
  } catch(error) {
    if(currentSession!==session) {exportBusy(false);return;}
    if(failures>=MAX_RETRIES || (error.status>=400 && error.status<500)) {$("export-status").textContent=`No se pudo consultar la variante: ${error.message}. Vuelve a consultar el job para recuperar su estado; no se borraron los archivos.`;exportBusy(false);return;}
    $("export-status").textContent=`Estado de variante no disponible. Reintentando (${failures+1}/${MAX_RETRIES})…`;
    exportTimer=setTimeout(()=>pollExport(id,exportId,currentSession,failures+1),2000);
  }
}
async function refreshExports(id,currentSession) {
  try {
    const result=await requestJSON(`/jobs/${id}/exports`);if(currentSession!==session || !Array.isArray(result.exports)) return;
    const items=result.exports, signature=JSON.stringify(items.map(e=>[e.id,e.status,e.error,e.review]));
    $("exports-panel").hidden=items.length===0;$("exports-note").textContent=result.has_more ? "Se muestran las 100 variantes más recientes. Los archivos anteriores permanecen en data/." : "";
    currentExports=items;
    for(const selected of selectedDeliveries.keys()) {
      const item=items.find(e=>e.id===selected);
      if(!item || item.review?.status!=="approved" || item.review?.revision!==selectedDeliveries.get(selected)) selectedDeliveries.delete(selected);
    }
    updateDeliverySelection();refreshDeliveries(id,currentSession);
    if(signature===exportSignature) return;exportSignature=signature; const list=$("exports-list");list.replaceChildren();
    for(const item of items) {
      const card=node("article",undefined,"clip-card"), base=`/jobs/${id}/exports/${item.id}/files`;
      card.append(node("h3",`${item.title || item.clip_file.replace(".mp4","")} · ${item.id.slice(0,8)}`),node("div",`${modeNames[item.options.framing]} · ${item.options.burn_subtitles ? "Con subtítulos" : "Sin texto incrustado"}`,"meta"));
      card.append(styleSummary(item.options));
      card.append(node("div",`${Number(item.start).toFixed(3)}–${Number(item.end).toFixed(3)} s · ${(item.end-item.start).toFixed(3)} s`,"meta"));
      if(item.status==="completed") {
        card.append(makePlayer(`${base}/clip.mp4?inline=true`));
        const links=node("div",undefined,"actions");links.append(downloadLink(`${base}/clip.mp4`,"MP4"),downloadLink(`${base}/clip.srt`,"SRT"));card.append(links);
      } else {card.append(node("p",item.status==="failed" ? `Error: ${item.error}` : item.status==="rendering" ? "Renderizando…" : "En cola…","export-summary"));}
      const button=node("button","Usar estos ajustes","subtle");button.type="button";button.addEventListener("click",()=>openEditor(id,item.clip_file,item));const actions=node("div",undefined,"actions");actions.append(button);card.append(actions);if(item.status==="completed") card.append(makeReviewPanel(id,item));list.append(card);
    }
    // When reopening a job after a browser reload, recover an in-progress export.
    if(!exporting && items.some(e=>["queued","rendering"].includes(e.status))) {
      clearTimeout(exportTimer);exportTimer=setTimeout(()=>refreshExports(id,currentSession),3000);
    }
  } catch(error) {if(currentSession===session) {$("exports-panel").hidden=false;$("exports-note").textContent=`No se pudo cargar el historial de variantes: ${error.message}`;}}
}
// --- Local library and revisioned editorial drafts (v0.3.0) ---
let libraryOffset=0, librarySequence=0, draftOffset=0, draftSequence=0, rangeUndo=null, projectLabel="";
const projectStates={completed:"LISTO",failed:"REVISAR",unreadable:"ESTADO ILEGIBLE",queued:"EN COLA",validating:"VALIDANDO",transcribing:"TRANSCRIBIENDO",rendering:"RENDERIZANDO"};
function showEditorMessage(text) {$('export-status').hidden=false;$('export-status').textContent=text;}
function displayDate(value) {return Number.isFinite(value) && value>0 ? new Date(value*1000).toLocaleString() : "Fecha no disponible";}
function clock(value) {const n=Math.max(0,Math.floor(value || 0));return `${Math.floor(n/60)}:${String(n%60).padStart(2,"0")}`;}
function setDirty(value) {
  dirty=value;
  $('dirty-note').textContent=value ? "Cambios sin guardar. Guarda el borrador o genera una variante."
    : editorData?.draft_id ? `Borrador guardado · revisión ${editorData.revision}. El original se conserva.` : "El original se conserva. Guarda para recuperar este trabajo después.";
}
function canLeaveEditor() {return !dirty || confirm("Hay cambios sin guardar. ¿Descartarlos?");}
function hideEditor() {editorRequest+=1;editorPreview.video.pause();editorData=null;rangeUndo=null;setDirty(false);$('editor').hidden=true;}
function exportBusy(value) {
  exporting=value;
  for(const id of ["export-button","save-draft","copy-draft","edit-fields","close-editor"]) $(id).disabled=value;
  $('undo-range').disabled=value || !rangeUndo;
}
function mountEditor(data, label) {
  editorData=data; rangeUndo=null;setDirty(false);$('editor').hidden=false;$('export-status').hidden=true;
  $('editor-title').textContent=label;$('editor-name').value=data.title || "Nuevo clip";
  setOptions("editor",data.options);updateOptionLabels("editor");syncRangeFields();renderCues();
  $('range-note').textContent=data.warning || "Puedes ajustar los límites sin volver a transcribir.";
  editorPreview.video.src=data.source_url;editorPreview.video.load();
  $('editor').scrollIntoView({behavior:"smooth",block:"start"});
}
function syncRangeFields() {
  if(!editorData) return;
  for(const k of ["start","end"]) { $(`range-${k}`).max=editorData.source_duration;$(`range-${k}`).value=editorData[k];$(`range-${k}-slider`).max=editorData.source_duration;$(`range-${k}-slider`).value=editorData[k]; }
  $('source-duration-label').textContent=`Original ${clock(editorData.source_duration)} · ${editorData.source_duration.toFixed(3)} s`;
  $('editor-meta').textContent=`Origen: ${editorData.start.toFixed(3)}–${editorData.end.toFixed(3)} s · Duración: ${editorData.duration.toFixed(3)} s${editorData.draft_id ? ` · revisión ${editorData.revision}` : ""}`;
  $('undo-range').disabled=!rangeUndo;paintRange();
}
function paintRange() {
  if(!editorData) return;
  const a=Number($('range-start').value),b=Number($('range-end').value),total=editorData.source_duration;
  const valid=$('range-start').value!=="" && $('range-end').value!=="" && a>=0 && b<=total+.001 && b-a>=.9999 && b-a<=60.0001;
  const pending=Math.abs(a-editorData.start)>.0004 || Math.abs(b-editorData.end)>.0004;
  $('range-duration').textContent=valid ? `Selección: ${(b-a).toFixed(3)} s${pending ? " · pendiente de aplicar" : " · aplicada"} · Reproductor: ${editorPreview.video.currentTime.toFixed(2)} s` : "Rango inválido: elige 1–60 segundos dentro del original.";
  Object.assign($('range-bar').style,{left:`${Math.max(0,Math.min(100,a/total*100))}%`,width:`${Math.max(0,Math.min(100,(b-a)/total*100))}%`});
}
function rangeIsPending() {return Number($('range-start').value)!==editorData.start || Number($('range-end').value)!==editorData.end;}
async function applyEditorRange() {
  if(!editorData) return;
  for(const k of ["start","end"]) {const input=$(`range-${k}`);if(!input.checkValidity()) {input.reportValidity();throw new Error("Revisa los límites del fragmento.");}}
  if(!rangeIsPending()) return;
  const previous=structuredClone({start:editorData.start,end:editorData.end,duration:editorData.duration,cues:editorData.cues});
  const payload={start:Number($('range-start').value),end:Number($('range-end').value),previous_start:editorData.start,previous_end:editorData.end,cues:editorData.cues};
  const result=await requestJSON(`/jobs/${editorData.job_id}/editor/range`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  rangeUndo=previous;Object.assign(editorData,{start:result.start,end:result.end,duration:result.duration,cues:result.cues});
  syncRangeFields();renderCues();setDirty(true);editorPreview.video.currentTime=editorData.start;editorPreview.draw();
  $('range-note').textContent=`Rango aplicado. ${result.changes.preserved} subtítulos conservados, ${result.changes.removed} fuera del rango y ${result.changes.added} añadidos desde la transcripción.\n${result.timing_note}${result.warning ? `\n${result.warning}` : ""}`;
}
async function openEditor(id,filename,variant=null) {
  if(exporting || !canLeaveEditor()) return;
  const token=session, request=++editorRequest;
  try {
    const workspace=await requestJSON(`/jobs/${id}/workspace`);
    let data;
    if(variant) {
      data={job_id:id,clip_file:Object.hasOwn(variant,"source_clip_file") ? variant.source_clip_file : /^clip_\d{2}\.mp4$/.test(filename || "") ? filename : null,
        start:variant.start,end:variant.end,duration:Math.round((variant.end-variant.start)*1000)/1000,
        cues:structuredClone(variant.cues),options:structuredClone(variant.options),title:(variant.title || filename.replace('.mp4',''))+" · copia"};
    } else data=await requestJSON(`/jobs/${id}/clips/${filename}/editor`);
    if(token!==session || request!==editorRequest) return;
    mountEditor({...workspace,...data,source_duration:workspace.source_duration,source_url:workspace.source_url,title:(data.title || filename.replace('.mp4','').replace('_',' ')).slice(0,120),draft_id:null,revision:null},variant ? "Editar una copia de la variante" : `Editar ${filename}`);
  } catch(error) {statusText.textContent=`No se pudo abrir el editor: ${error.message}`;}
}
async function openManual(id) {
  if(exporting || !canLeaveEditor()) return;
  const token=session,request=++editorRequest;
  try {
    const workspace=await requestJSON(`/jobs/${id}/workspace`);
    const end=Math.min(30,Math.floor(workspace.source_duration*1000)/1000);
    const selection=await requestJSON(`/jobs/${id}/editor/range`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({start:0,end})});
    if(token!==session || request!==editorRequest) return;
    const options={...workspace.options};if(!selection.cues.length) options.burn_subtitles=false;
    mountEditor({...workspace,...selection,job_id:id,options,clip_file:null,title:"Nuevo clip manual",draft_id:null,revision:null},"Crear clip manual");
  } catch(error) {statusText.textContent=`No se pudo abrir el clip manual: ${error.message}`;}
}
async function openDraft(id,draftId) {
  if(exporting || !canLeaveEditor()) return;
  const token=session,request=++editorRequest;
  try {
    const [workspace,draft]=await Promise.all([requestJSON(`/jobs/${id}/workspace`),requestJSON(`/jobs/${id}/drafts/${draftId}`)]);
    if(token!==session || request!==editorRequest) return;
    mountEditor({...workspace,...draft,duration:Math.round((draft.end-draft.start)*1000)/1000,draft_id:draft.id},"Editar borrador");
  } catch(error) {statusText.textContent=`No se pudo abrir el borrador: ${error.message}`;}
}
async function persistEditorDraft(asCopy=false) {
  if(!validateStyleControls("editor")) throw new Error("Revisa tamaño, colores, posición, margen, contorno y sombra.");
  if(!$('editor-name').checkValidity()) {$('editor-name').reportValidity();throw new Error("Escribe un nombre para el borrador.");}
  await applyEditorRange();
  const payload={title:$('editor-name').value.trim(),clip_file:editorData.clip_file,start:editorData.start,end:editorData.end,options:readOptions("editor"),cues:structuredClone(editorData.cues)};
  const update=!!editorData.draft_id && !asCopy;
  if(update) payload.revision=editorData.revision;
  const url=`/jobs/${editorData.job_id}/drafts${update ? `/${editorData.draft_id}` : ""}`;
  const item=await requestJSON(url,{method:update ? "PUT" : "POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  Object.assign(editorData,{title:item.title,draft_id:item.id,revision:item.revision,options:item.options,cues:item.cues});
  $('editor-name').value=item.title;setDirty(false);syncRangeFields();
  refreshDrafts(editorData.job_id,session);refreshProjects();
  return item;
}
async function saveDraftOnly(asCopy=false) {
  if(!editorData || exporting) return;
  exportBusy(true);showEditorMessage("Guardando borrador, sin renderizar…");
  try {const item=await persistEditorDraft(asCopy);showEditorMessage(`Borrador guardado · revisión ${item.revision}. No se generó un MP4 ni se ejecutó Whisper. Puedes cerrar y retomarlo desde «Borradores».`);}
  catch(error) {showEditorMessage(`No se pudo guardar: ${error.message}`);}
  finally {exportBusy(false);}
}
$('save-draft').addEventListener('click',()=>saveDraftOnly());
$('copy-draft').addEventListener('click',()=>saveDraftOnly(true));
$('editor-name').addEventListener('input',()=>setDirty(true));
for(const key of ["start","end"]) {
  $(`range-${key}`).addEventListener('input',()=>{const value=Number($(`range-${key}`).value);if(Number.isFinite(value)) $(`range-${key}-slider`).value=value;setDirty(true);paintRange();});
  $(`range-${key}-slider`).addEventListener('input',()=>{$(`range-${key}`).value=$(`range-${key}-slider`).value;setDirty(true);paintRange();});
  $(`mark-${key}`).addEventListener('click',()=>{$(`range-${key}`).value=Math.min(editorPreview.video.currentTime,editorData.source_duration).toFixed(3);$(`range-${key}-slider`).value=$(`range-${key}`).value;setDirty(true);paintRange();});
}
editorPreview.video.addEventListener('timeupdate',paintRange);
$('apply-range').addEventListener('click',async()=>{
  if(!editorData || exporting) return;exportBusy(true);
  try {await applyEditorRange();} catch(error) {$('range-note').textContent=`No se aplicó el rango: ${error.message}`;} finally {exportBusy(false);}
});
$('undo-range').addEventListener('click',()=>{
  if(!rangeUndo || !editorData || exporting || !confirm("¿Restaurar el rango y los subtítulos anteriores al último ajuste? Esto también deshace el texto editado después de ese ajuste.")) return;
  Object.assign(editorData,structuredClone(rangeUndo));rangeUndo=null;syncRangeFields();renderCues();setDirty(true);editorPreview.video.currentTime=editorData.start;editorPreview.draw();$('range-note').textContent="Último ajuste deshecho. Guarda para conservar este estado.";
});
$('export-button').addEventListener('click',async()=>{
  if(!editorData || exporting) return;
  if(!validateStyleControls("editor")) {showEditorMessage("Revisa tamaño, colores, posición, margen, contorno y sombra. No se ha creado una variante.");return;}
  exportBusy(true);showEditorMessage("Guardando borrador y creando variante…");
  const id=editorData.job_id, token=session;
  let saved=false;
  try {
    const draft=await persistEditorDraft();saved=true;
    const item=await requestJSON(`/jobs/${id}/drafts/${draft.id}/exports`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({revision:draft.revision})});
    if(token!==session) {exportBusy(false);return;}
    showEditorMessage(`Borrador guardado. Variante ${item.id.slice(0,8)} en cola; no se repite la transcripción.`);
    refreshExports(id,token);pollExport(id,item.id,token);
  } catch(error) {showEditorMessage(`${saved ? "El borrador quedó guardado; no se pudo exportar" : "No se pudo guardar"}: ${error.message}`);exportBusy(false);}
});
async function refreshDrafts(id,token,offset=draftOffset) {
  const request=++draftSequence;draftOffset=offset;
  try {
    const result=await requestJSON(`/jobs/${id}/drafts?offset=${offset}&limit=12`);
    if(token!==session || request!==draftSequence) return;
    $('drafts-panel').hidden=false;const list=$('draft-list');list.replaceChildren();
    for(const item of result.drafts) {
      const card=node('article',undefined,'draft-card');card.append(node('h3',item.title));
      card.append(node('p',`${item.start.toFixed(3)}–${item.end.toFixed(3)} s del original · ${(item.end-item.start).toFixed(3)} s`),node('p',`Revisión ${item.revision} · ${displayDate(item.updated_at)}`),styleSummary(item.options));
      const button=node('button','Abrir borrador','secondary');button.type='button';button.addEventListener('click',()=>openDraft(id,item.id));const actions=node('div',undefined,'actions');actions.append(button);card.append(actions);list.append(card);
    }
    $('drafts-note').textContent=result.total ? `${result.total} borrador(es) guardado(s).${result.unreadable ? ` ${result.unreadable} archivo(s) ilegible(s) conservado(s).` : ""}` : "Todavía no hay borradores. Edita un clip o crea uno manual y pulsa «Guardar borrador».";
    $('drafts-page').textContent=result.total ? `${offset+1}–${Math.min(offset+12,result.total)} de ${result.total}` : "";
    $('drafts-prev').disabled=offset===0;$('drafts-next').disabled=!result.has_more;
  } catch(error) {if(token===session) {$('drafts-panel').hidden=false;$('drafts-note').textContent=`No se pudieron cargar los borradores: ${error.message}`;}}
}
async function refreshProjects() {
  const request=++librarySequence, query=$('library-query').value.trim();
  $('library-status').textContent='Cargando proyectos…';
  try {
    const result=await requestJSON(`/projects?offset=${libraryOffset}&limit=6&q=${encodeURIComponent(query)}`);
    if(request!==librarySequence) return;
    if(libraryOffset>=result.total && libraryOffset>0) {libraryOffset=0;return refreshProjects();}
    const list=$('project-list');list.replaceChildren();
    for(const item of result.projects) {
      const card=node('article',undefined,'project-card'),thumb=node('div',undefined,'project-thumb');
      if(item.source_available && ["completed","failed"].includes(item.status)) {
        const img=node('img');img.src=item.thumbnail_url;img.loading='lazy';img.alt='Miniatura del video original';
        img.addEventListener('error',()=>{thumb.replaceChildren(node('span','Vista no disponible'));},{once:true});thumb.append(img);
      } else thumb.append(node('span',item.source_available ? 'Procesando…' : 'Original no disponible'));
      card.append(thumb,node('span',projectStates[item.status] || item.status,'project-status'),node('h3',item.title));
      card.append(node('div',`${Number.isFinite(item.duration) ? `${clock(item.duration)} · ` : ""}${item.clips_count} clips · ${item.drafts_count} borradores · ${item.exports_count} variantes`,'meta'));
      card.append(node('div',`${item.date_kind==='legacy_file' ? 'Fecha de archivo' : 'Cargado'}: ${displayDate(item.created_at)}`,'meta'));
      const actions=node('div',undefined,'actions'),open=node('button','Abrir proyecto','secondary');open.type='button';open.addEventListener('click',()=>selectProject(item.id,item.title));actions.append(open);
      if(item.source_available && ["completed","failed"].includes(item.status)) {const manual=node('button','+ Clip manual','subtle');manual.type='button';manual.addEventListener('click',()=>selectProject(item.id,item.title,true));actions.append(manual);}
      card.append(actions);list.append(card);
      if(item.id===currentJob) {projectLabel=item.title;$('current-project-title').textContent=item.title;$('current-project-title').hidden=false;}
    }
    $('library-status').textContent=result.total ? `${result.total} proyecto(s) · ordenados por actividad reciente.${result.unreadable ? ` ${result.unreadable} con datos ilegibles; se conservan sus archivos.` : ""}` : query ? 'No hay proyectos con esa búsqueda.' : 'Tu biblioteca está vacía. Carga un MP4 para comenzar.';
    $('library-page').textContent=result.total ? `${libraryOffset+1}–${Math.min(libraryOffset+6,result.total)} de ${result.total}` : '';
    $('library-prev').disabled=libraryOffset===0;$('library-next').disabled=!result.has_more;
  } catch(error) {if(request===librarySequence) $('library-status').textContent=`No se pudo leer la biblioteca: ${error.message}`;}
}
async function selectProject(id,title='',manual=false) {
  if(exporting || !canLeaveEditor()) return;
  if(reviewEdits.size && !confirm('Hay revisiones editoriales sin guardar. ¿Descartarlas y cambiar de proyecto?')) return;
  const token=resetPolling();hideEditor();rememberJob(id);projectLabel=title || `Proyecto ${id.slice(0,8)}`;
  $('current-project-title').textContent=projectLabel;$('current-project-title').hidden=false;
  $('project-actions').hidden=true;$('drafts-panel').hidden=true;draftOffset=0;renderMedia(null);clipsList.replaceChildren();$('exports-panel').hidden=true;busy(true);statusText.textContent='Consultando estado…';
  await poll(id,token);
  if(manual && token===session) await openManual(id);
  else if(token===session) $('results-panel').scrollIntoView({behavior:'smooth',block:'start'});
}
$('library-form').addEventListener('submit',event=>{event.preventDefault();libraryOffset=0;refreshProjects();});
$('library-refresh').addEventListener('click',refreshProjects);
$('library-prev').addEventListener('click',()=>{libraryOffset=Math.max(0,libraryOffset-6);refreshProjects();});
$('library-next').addEventListener('click',()=>{libraryOffset+=6;refreshProjects();});
$('drafts-refresh').addEventListener('click',()=>{if(currentJob) refreshDrafts(currentJob,session,0);});
$('drafts-prev').addEventListener('click',()=>refreshDrafts(currentJob,session,Math.max(0,draftOffset-12)));
$('drafts-next').addEventListener('click',()=>refreshDrafts(currentJob,session,draftOffset+12));
$('new-manual').addEventListener('click',()=>{if(currentJob) openManual(currentJob);});
$('project-rename').addEventListener('click',async()=>{
  if(!currentJob) return;const title=prompt('Nombre del proyecto (máximo 120 caracteres)',projectLabel || '');if(title===null) return;
  const id=currentJob;
  try {const result=await requestJSON(`/projects/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({title})});
    if(id===currentJob) {projectLabel=result.title;$('current-project-title').textContent=result.title;}refreshProjects();
  } catch(error) {statusText.textContent=`No se pudo renombrar: ${error.message}`;}
});
$('upload-mode').addEventListener('change',()=>{
  const manual=$('upload-mode').value==='manual';
  $('upload-mode-note').textContent=manual ? 'Solo valida y guarda el original. No transcribe ni genera clips. Después usa «+ Clip manual»; podrás escribir subtítulos o trabajar sin ellos.' : 'La selección automática sigue siendo heurística. Después podrás cambiar sus límites o crear otros clips.';
  if(manual) {$('upload-burn').checked=false;updateOptionLabels('upload');uploadPreview.draw();}
});

$("upload-form").addEventListener("submit",async(event)=>{
  event.preventDefault();if(!validateStyleControls("upload")) return;const file=fileInput.files[0];if(!file || !/\.mp4$/i.test(file.name)) {statusText.textContent="Selecciona un archivo MP4.";return;}
  if(exporting || !canLeaveEditor()) return;
  if(reviewEdits.size && !confirm('Hay revisiones editoriales sin guardar. ¿Descartarlas y cargar otro video?')) return;
  const currentSession=resetPolling();hideEditor();clipsList.replaceChildren();$("exports-panel").hidden=true;$("drafts-panel").hidden=true;$("project-actions").hidden=true;$("current-project-title").hidden=true;draftOffset=0;renderMedia(null);jobLink.textContent="";busy(true);uploadPreview.video.pause();statusText.textContent="Subiendo video…";
  const form=new FormData();form.append("file",file);form.append("processing_mode",$("upload-mode").value);for(const [k,v] of Object.entries(readOptions("upload"))) form.append(k,String(v));
  try {const job=await requestJSON("/jobs",{method:"POST",body:form},300000);if(currentSession!==session) return;if(!/^[0-9a-f]{32}$/.test(job?.id || "")) throw new RequestError("La respuesta no contiene un ID de job válido.");rememberJob(job.id);await poll(job.id,currentSession);}
  catch(error) {if(currentSession===session) {statusText.textContent=`No se pudo confirmar la carga: ${error.message}`;busy(false);}}
});
$("job-form").addEventListener("submit",event=>{
  event.preventDefault();const id=jobInput.value.trim();if(!/^[0-9a-f]{32}$/.test(id)) {statusText.textContent="El ID debe contener 32 caracteres hexadecimales en minúsculas.";return;}
  selectProject(id);
});
initDeliveryAndTemplates();
window.ClipForgeAuth.ready.then(user=>{if(!user)return;try {const id=localStorage.getItem(window.ClipForgeAuth.storageKey());if(/^[0-9a-f]{32}$/.test(id || "")) {rememberJob(id);busy(true);poll(id,session);}} catch (_) {}});

refreshProjects();


// v0.3.1: snapshots of visual options only, never cue text or editorial ranges.
async function refreshTemplates(selectedId=null) {
  const seq=++templateSequence;
  try {
    const result=await requestJSON('/templates');if(seq!==templateSequence) return;
    templateItems=result.templates;
    for(const prefix of ['upload','editor']) {
      const select=$(`${prefix}-template-select`), previous=selectedId || select.value;
      select.replaceChildren(new Option('Sin plantilla seleccionada',''));
      for(const item of templateItems) select.add(new Option(item.name,item.id));
      select.value=templateItems.some(p=>p.id===previous) ? previous : '';
      if(result.unreadable) $(`${prefix}-template-status`).textContent=`${result.unreadable} plantilla(s) ilegible(s) conservada(s).`;
    }
  } catch(error) {for(const prefix of ['upload','editor']) $(`${prefix}-template-status`).textContent=`No se pudieron cargar las plantillas: ${error.message}`;}
}
function initDeliveryAndTemplates() {
  for(const prefix of ['upload','editor']) {
    $(`${prefix}-template-apply`).addEventListener('click',()=>{
      const item=templateItems.find(p=>p.id===$(`${prefix}-template-select`).value);
      if(!item) {$(`${prefix}-template-status`).textContent='Selecciona una plantilla guardada.';return;}
      setOptions(prefix,item.options);updateOptionLabels(prefix);
      (prefix==='editor' ? editorPreview : uploadPreview).draw();
      if(prefix==='editor') setDirty(true);
      $(`${prefix}-template-status`).textContent=`Aplicada: ${item.name}. Texto y tiempos conservados. Guarda el borrador o genera una variante para conservar el cambio.`;
    });
    $(`${prefix}-template-save`).addEventListener('click',async()=>{
      if(!validateStyleControls(prefix)) return;
      const name=$(`${prefix}-template-name`).value.trim(), button=$(`${prefix}-template-save`);
      if(!name) {$(`${prefix}-template-status`).textContent='Escribe un nombre para la nueva plantilla.';return;}
      button.disabled=true;
      try {
        const item=await requestJSON('/templates',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,options:readOptions(prefix)})});
        await refreshTemplates(item.id);$(`${prefix}-template-name`).value='';
        $(`${prefix}-template-status`).textContent='Plantilla guardada en data/templates/. No se guardó ni renderizó el borrador.';
      } catch(error) {$(`${prefix}-template-status`).textContent=error.message;} finally {button.disabled=false;}
    });
  }
  $('exports-refresh').addEventListener('click',()=>{if(currentJob) {exportSignature='';refreshExports(currentJob,session);}});
  $('select-approved').addEventListener('click',()=>{
    selectedDeliveries.clear();
    for(const item of currentExports) {
      if(item.status==='completed' && item.review?.status==='approved' && !reviewEdits.has(item.id)) {
        if(selectedDeliveries.size>=30) break;
        selectedDeliveries.set(item.id,item.review.revision);
      }
    }
    document.querySelectorAll('[data-delivery-id]').forEach(c=>{c.checked=selectedDeliveries.has(c.dataset.deliveryId);});updateDeliverySelection();
  });
  $('create-delivery').addEventListener('click',async()=>{
    if(!currentJob || packaging || !selectedDeliveries.size) return;
    const id=currentJob,token=session;
    packaging=true;updateDeliverySelection();$('delivery-status').textContent='Preparando ZIP local. No se repite Whisper ni el render.';
    try {
      const result=await requestJSON(`/jobs/${id}/deliveries`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({selections:Array.from(selectedDeliveries,([export_id,review_revision])=>({export_id,review_revision}))})},300000);
      if(token===session) {$('delivery-status').textContent=`Entrega lista: ${result.clips.length} variante(s). Descárgala en «Paquetes preparados».`;await refreshDeliveries(id,token);}
    } catch(error) {
      if(token===session) {$('delivery-status').textContent=`No se pudo confirmar la entrega: ${error.message}. Consulta «Paquetes preparados» antes de reintentar; una respuesta perdida puede dejar un ZIP listo.`;await refreshDeliveries(id,token);}
    } finally {packaging=false;updateDeliverySelection();}
  });
  updateDeliverySelection();refreshTemplates();
}
function updateDeliverySelection() {
  $('delivery-selection').textContent=`${selectedDeliveries.size} variante(s) seleccionada(s) · máximo 30 / 2 GiB por entrega.`;
  $('create-delivery').disabled=packaging || !selectedDeliveries.size;
  $('select-approved').disabled=packaging;
  document.querySelectorAll('[data-delivery-id]').forEach(c=>{const item=currentExports.find(i=>i.id===c.dataset.deliveryId);c.disabled=packaging || item?.review?.status!=='approved' || reviewEdits.has(c.dataset.deliveryId);});
}
function makeReviewPanel(id,item) {
  const stored=item.review || {status:'pending',revision:0,title:'',notes:''};
  const panel=node('div',undefined,'review-box');
  if(stored.status==='unreadable') {panel.append(node('p',stored.error));return panel;}
  const names={pending:'Pendiente',approved:'Aprobada',rejected:'Descartada'};
  const badge=node('span',names[stored.status] || 'Pendiente',`review-badge ${stored.status}`);panel.append(badge);
  const selected=reviewEdits.get(item.id) || stored;
  const title=node('input');title.type='text';title.maxLength=120;title.value=selected.title;title.placeholder=item.title || item.clip_file;
  const status=node('select');for(const [v,name] of Object.entries(names)) status.add(new Option(name,v));status.value=selected.status;
  const notes=node('textarea');notes.maxLength=2000;notes.value=selected.notes;
  for(const [text,control,key] of [['Título para entrega',title,'title'],['Estado editorial',status,'status'],['Notas para el cliente (se incluirán en el ZIP)',notes,'notes']]) {
    const label=node('label',text);control.id=`review-${item.id}-${key}`;label.htmlFor=control.id;panel.append(label,control);
  }
  const message=node('small',reviewEdits.has(item.id) ? 'Cambios sin guardar.' : 'La aprobación corresponde a este MP4, no al borrador.','review-message');
  const choice=node('label',undefined,'check delivery-choice'),checkbox=node('input');checkbox.type='checkbox';checkbox.dataset.deliveryId=item.id;
  checkbox.disabled=packaging || stored.status!=='approved' || reviewEdits.has(item.id);checkbox.checked=selectedDeliveries.has(item.id);
  choice.append(checkbox,node('span','Incluir en entrega'));
  const markChanged=()=>{reviewEdits.set(item.id,{status:status.value,title:title.value,notes:notes.value,revision:selected.revision});selectedDeliveries.delete(item.id);checkbox.checked=false;message.textContent='Cambios sin guardar. Guarda la revisión para volver a seleccionar esta variante.';message.classList.add('review-dirty');updateDeliverySelection();};
  [title,status,notes].forEach(c=>c.addEventListener('input',markChanged));
  checkbox.addEventListener('change',()=>{
    if(checkbox.checked && selectedDeliveries.size>=30) {checkbox.checked=false;message.textContent='Máximo 30 variantes por entrega.';return;}
    if(checkbox.checked) selectedDeliveries.set(item.id,stored.revision);else selectedDeliveries.delete(item.id);updateDeliverySelection();
  });
  const save=node('button','Guardar revisión','secondary');save.type='button';
  save.addEventListener('click',async()=>{
    const token=session;save.disabled=true;
    try {
      const result=await requestJSON(`/jobs/${id}/exports/${item.id}/review`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:status.value,title:title.value,notes:notes.value,revision:selected.revision})});
      if(token!==session) return;
      reviewEdits.delete(item.id);selectedDeliveries.delete(item.id);exportSignature='';await refreshExports(id,token);
    } catch(error) {if(token===session) message.textContent=`No se guardó: ${error.message}`;}
    finally {save.disabled=false;}
  });
  const reload=node('button','Recargar revisión','subtle');reload.type='button';
  reload.addEventListener('click',()=>{
    if(reviewEdits.has(item.id) && !confirm('¿Descartar los cambios sin guardar de esta revisión y cargar la versión guardada?')) return;
    reviewEdits.delete(item.id);selectedDeliveries.delete(item.id);exportSignature='';refreshExports(id,session);
  });
  const actions=node('div',undefined,'actions');actions.append(save,reload);panel.append(actions,message,choice);return panel;
}
async function refreshDeliveries(id,token) {
  const seq=++deliverySequence;
  try {
    const result=await requestJSON(`/jobs/${id}/deliveries`);if(token!==session || seq!==deliverySequence) return;
    $('deliveries-panel').hidden=result.deliveries.length===0 && !result.unreadable;
    const list=$('deliveries-list');list.replaceChildren();
    for(const item of result.deliveries) {
      const card=node('article',undefined,'draft-card delivery-card');card.append(node('h3',`Entrega ${item.id.slice(0,8)}`),node('p',`${item.clips_count} variantes · ${(item.zip_bytes/1024/1024).toFixed(1)} MB · ${displayDate(item.created_at)}`),downloadLink(item.download_url,'Descargar ZIP'));list.append(card);
    }
    $('deliveries-note').textContent=(result.has_more ? 'Se muestran las 100 entregas más recientes. ' : '')+(result.unreadable ? `${result.unreadable} entrega(s) ilegible(s) conservada(s).` : 'Las entregas permanecen en data/<job>/deliveries/. No incluyen el video original.');
  } catch(error) {if(token===session && seq===deliverySequence) {$('deliveries-panel').hidden=false;$('deliveries-note').textContent=`No se pudieron consultar las entregas: ${error.message}`;}}
}

// v0.4.0: preview/consent before any provider call. Untrusted text uses textContent.
let aiPreview=null, aiConfig=null, aiContext=null, aiBusy=false, aiTimer=null,
    aiRequestSequence=0, aiRunSequence=0, aiHistorySequence=0, aiCurrentRun=null;
function resetAI() {
  clearTimeout(aiTimer);aiRequestSequence++;aiRunSequence++;aiHistorySequence++;
  aiPreview=null;aiCurrentRun=null;aiContext=null;aiBusy=false;
  $('ai-panel').hidden=true;$('ai-preview').hidden=true;$('ai-result').hidden=true;$('ai-history').hidden=true;
  $('ai-consent').checked=false;$('ai-status').textContent='';$('ai-fields').disabled=false;
  $('ai-run').disabled=true;$('ai-count').value=3;$('ai-start').value=0;$('ai-end').value='';
}
function invalidateAIPreview() {aiPreview=null;$('ai-preview').hidden=true;$('ai-consent').checked=false;$('ai-run').disabled=true;}
function aiMessage(text) {$('ai-status').textContent=text;}
function paintAIConfig(config) {
    $('ai-config').textContent=`${config.reason}${config.configured ? `\nProveedor: ${config.provider} · modelo: ${config.model}\nDestino: ${config.destination}\nLímite local: ${config.daily_used_utc}/${config.daily_limit} consultas IA reservadas hoy (UTC). Este panel solo lee configuración; no envía una consulta.` : ''}`;
}
async function refreshAI(id,token) {
  const seq=++aiRequestSequence;
  $('ai-panel').hidden=false;
  try {
    const [config,ctx]=await Promise.all([requestJSON('/ai/config'),requestJSON(`/jobs/${id}/selections/context`)]);
    if(token!==session || seq!==aiRequestSequence) return;
    const first=aiContext===null;aiConfig=config;aiContext=ctx;
    paintAIConfig(config);
    $('ai-context').textContent=ctx.available ? `${ctx.segments} segmentos guardados · original ${clock(ctx.duration)} · última marca transcrita ${clock(ctx.last_transcript_end)}. ${ctx.note}` : ctx.note;
    $('ai-preview-button').disabled=!ctx.available || aiBusy;
    $('ai-start').max=ctx.duration;$('ai-end').max=ctx.duration;
    if(first) {$('ai-mode').value=config.configured ? 'llm' : 'heuristic';$('ai-end').value=ctx.duration.toFixed(3);}
    await refreshAIHistory(id,token);
  } catch(error) {if(token===session && seq===aiRequestSequence) {$('ai-config').textContent=`No se pudo comprobar la selección asistida: ${error.message}`;$('ai-preview-button').disabled=true;}}
}
function readAISpec() {
  return {mode:$('ai-mode').value,brief:$('ai-brief').value.trim(),max_clips:Number($('ai-count').value),
    min_seconds:Number($('ai-min').value),max_seconds:Number($('ai-max').value),window_start:Number($('ai-start').value),
    window_end:$('ai-end').value.trim()==='' ? null : Number($('ai-end').value)};
}
for(const id of ['ai-mode','ai-brief','ai-count','ai-min','ai-max','ai-start','ai-end']) $(id).addEventListener('input',invalidateAIPreview);
$('ai-form').addEventListener('submit',async event=>{
  event.preventDefault();if(!currentJob || aiBusy) return;
  const id=currentJob,token=session,seq=++aiRequestSequence,submittedSpec=readAISpec();
  invalidateAIPreview();aiMessage('Preparando vista previa local; todavía no se contacta a ningún modelo…');$('ai-preview-button').disabled=true;
  try {
    const result=await requestJSON(`/jobs/${id}/selections/preview`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(submittedSpec)});
    if(token!==session || seq!==aiRequestSequence) return;
    // An edit made during preview must not authorize a different request.
    if(JSON.stringify(submittedSpec)!==JSON.stringify(readAISpec())) {aiMessage('Los ajustes cambiaron; vuelve a preparar la vista previa.');return;}
    aiPreview={...result,job_id:id,request_id:Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('')};
    const p=result.provider,local=result.spec.mode==='heuristic';
    $('ai-preview-description').textContent=`${result.segment_count} de ${result.total_segments} segmentos · tramo ${result.payload_text.analysis_window.start.toFixed(3)}–${result.payload_text.analysis_window.end.toFixed(3)} s. ${result.note}`;
    $('ai-range-note').hidden=local;
    $('ai-range-note').textContent=local ? '' : `${result.eligible_range_count} intervalos válidos calculados localmente. El modelo debe elegir sus IDs; ClipForge conserva los tiempos y vuelve a comprobar solapamientos. Esto no garantiza calidad editorial.`;
    $('ai-budget').textContent=`${result.budget.request_chars.toLocaleString()} caracteres de solicitud; tokens exactos no calculados. ${local ? 'Sin proveedor ni coste de API.' : `Destino: ${p.destination} · ${p.model} · máximo de salida ${p.max_output_tokens} tokens.`}`;
    $('ai-preview-text').textContent=JSON.stringify(result.payload_text,null,2);
    $('ai-preview-instructions').textContent=result.system_instructions;
    $('ai-privacy').textContent=local ? 'Esta opción ejecuta la heurística actual. No utiliza IA ni envía texto fuera de ClipForge. El brief no modifica esta selección.'
      : p.external ? 'Se enviarán estos segmentos y tiempos, el brief y las instrucciones de selección a OpenAI. No se envía el MP4 ni el audio. Puede haber cargos de API; store:false no equivale a retención cero. Usa solo texto autorizado.'
      : 'Se enviará el texto al servidor Ollama configurado. Usa un modelo descargado localmente y desactiva las funciones cloud en Ollama. ClipForge no descarga ni verifica el modelo y no evalúa imágenes.';
    $('ai-consent-label').textContent=local ? 'Revisé los ajustes y autorizo esta comparación local.' : `Revisé texto y destino, tengo autorización para procesarlo y autorizo esta consulta a ${p.provider}${p.external ? ' con posibles cargos de API' : ''}.`;
    $('ai-preview').hidden=false;aiMessage('Vista previa preparada. No se envió ninguna solicitud a un modelo.');
  } catch(error) {if(token===session) aiMessage(`No se pudo preparar: ${error.message}`);}
  finally {if(token===session) $('ai-preview-button').disabled=!aiContext?.available || aiBusy;}
});
$('ai-consent').addEventListener('change',()=>{$('ai-run').disabled=!aiPreview || !$('ai-consent').checked || aiBusy;});
$('ai-discard-preview').addEventListener('click',()=>{invalidateAIPreview();aiMessage('Vista previa descartada. No se enviará ninguna solicitud.');});
$('ai-run').addEventListener('click',async()=>{
  if(!aiPreview || !$('ai-consent').checked || aiBusy || aiPreview.job_id!==currentJob) return;
  const snapshot=structuredClone(aiPreview),id=currentJob,token=session;
  aiBusy=true;$('ai-run').disabled=true;$('ai-fields').disabled=true;aiMessage('Iniciando una sola consulta. No se renderiza ningún video…');
  try {
    const result=await requestJSON(`/jobs/${id}/selections`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...snapshot.spec,preview_token:snapshot.preview_token,request_id:snapshot.request_id,consent:true})},20000);
    if(token!==session) return;
    aiCurrentRun=result.id;invalidateAIPreview();await viewAIRun(id,result.id,token);refreshAIHistory(id,token,false);
  } catch(error) {
    if(token!==session) return;
    aiMessage(`No se pudo confirmar el inicio: ${error.message}\nActualiza el historial antes de volver a solicitarlo. Repetir este botón conserva el mismo ID para evitar una segunda consulta.`);
    aiBusy=false;$('ai-fields').disabled=false;$('ai-run').disabled=!aiPreview || !$('ai-consent').checked;
  }
});
async function refreshAIHistory(id,token,restore=true) {
  const seq=++aiHistorySequence;
  try {
    const result=await requestJSON(`/jobs/${id}/selections?limit=10`);
    if(token!==session || seq!==aiHistorySequence) return;
    $('ai-history').hidden=!result.analyses.length && !result.unreadable;
    const list=$('ai-run-list');list.replaceChildren();
    for(const item of result.analyses) {
      const b=node('button',`${item.mode==='llm' ? 'IA' : 'Local'} · ${item.id.slice(0,8)} · ${item.status==='running' ? 'En curso' : item.status==='completed' ? `${item.candidates.length} propuestas` : 'Falló'}`,'subtle');b.type='button';
      b.addEventListener('click',()=>{if(!aiBusy || aiCurrentRun===item.id){clearTimeout(aiTimer);aiCurrentRun=item.id;viewAIRun(id,item.id,token);}});list.append(b);
    }
    $('ai-history-note').textContent=`${result.total} análisis guardados.${result.has_more ? ' Se muestran los 10 más recientes.' : ''}${result.unreadable ? ` ${result.unreadable} archivos ilegibles conservados.` : ''}`;
    if(restore && !aiCurrentRun && result.analyses.length) {const item=result.analyses.find(a=>a.status==='running') || result.analyses[0];aiCurrentRun=item.id;viewAIRun(id,item.id,token);}
  } catch(error) {if(token===session) aiMessage(`No se pudo leer el historial: ${error.message}`);}
}
function aiCard(id,run,candidate,baseline=false) {
  const card=node('article',undefined,'ai-candidate');
  card.append(node('span',baseline || candidate.origin==='heuristic' ? 'HEURÍSTICA · SIN IA' : 'PROPUESTA DEL MODELO','eyebrow'),node('h3',candidate.title),node('p',`${candidate.start.toFixed(3)}–${candidate.end.toFixed(3)} s del original · ${candidate.duration.toFixed(3)} s`,'ai-stats'),node('p',candidate.reason));
  if(candidate.criteria) {const c=candidate.criteria;card.append(node('div',`Gancho ${c.hook}/5 · Claridad ${c.clarity}/5 · Cierre ${c.completeness}/5 · valoración subjetiva`,'ai-criteria'));}
  const text=node('blockquote',candidate.transcript_excerpt);card.append(text);
  const context=node('details');context.append(node('summary','Ver contexto anterior y posterior'),node('p',`Antes: ${candidate.context_before || '(Inicio de la transcripción)'}`),node('p',`Después: ${candidate.context_after || '(Fin de la transcripción)'}`));card.append(context);
  if(!baseline) {
    const button=node('button','Crear / abrir borrador','secondary');button.type='button';
    const note=node('p','No renderiza ni aprueba el clip. Conserva los originales.','ai-stats');
    button.addEventListener('click',async()=>{
      if(exporting || !canLeaveEditor()) return;
      const token=session;button.disabled=true;
      try {
        const draft=await requestJSON(`/jobs/${id}/selections/${run.id}/candidates/${candidate.id}/draft`,{method:'POST'});
        if(token!==session) return;
        // Leave confirmation already happened above; don't prompt twice on opening.
        hideEditor();refreshDrafts(id,token);refreshProjects();await openDraft(id,draft.id);
        note.textContent='Borrador guardado. Puedes ajustar límites, texto y estilo antes de exportar.';
      } catch(error) {note.textContent=`No se pudo crear el borrador: ${error.message}`;}
      finally {button.disabled=false;}
    });card.append(node('div',undefined,'actions'));card.lastChild.append(button);card.append(note);
  }
  return card;
}
async function viewAIRun(id,runId,token,failures=0) {
  const seq=++aiRunSequence;
  try {
    const item=await requestJSON(`/jobs/${id}/selections/${runId}`);
    if(token!==session || seq!==aiRunSequence || aiCurrentRun!==runId) return;
    aiBusy=item.status==='running';$('ai-fields').disabled=aiBusy;
    $('ai-preview-button').disabled=aiBusy || !aiContext?.available;
    $('ai-result').hidden=false;$('ai-result-title').textContent=item.mode==='llm' ? 'Selección editorial asistida' : 'Comparación heurística local';
    $('ai-result-badge').textContent=item.mode==='llm' ? `${item.provider} · ${item.model}` : 'Sin IA · sin red';
    $('ai-result-summary').textContent=item.summary || (aiBusy ? 'Analizando la transcripción. El resultado todavía no está disponible.' : 'No se generaron propuestas.');
    const u=item.usage;
    $('ai-result-stats').textContent=`Análisis ${item.id.slice(0,8)} · ${displayDate(item.created_at)} · ${item.segment_count} segmentos${item.elapsed_seconds!==undefined ? ` · ${item.elapsed_seconds.toFixed(1)} s` : ''}.\n${u ? `Tokens reportados: entrada ${u.input_tokens ?? 'no disponible'}, salida ${u.output_tokens ?? 'no disponible'}.` : item.mode==='llm' ? 'Consumo no reportado todavía; no equivale a cero.' : 'No se usó un modelo.'} ${item.mode==='llm' ? 'Coste monetario no calculado. No hay reintentos automáticos.' : ''}`;
    const warning=[item.error ? `[${item.error_code}] ${item.error}` : '',...(item.warnings || [])].filter(Boolean).join('\n');
    $('ai-result-warning').hidden=!warning;$('ai-result-warning').textContent=warning;
    const legacyFailure=item.mode==='llm' && item.status==='failed' && ['AI_NO_VALID_CANDIDATES','AI_SCHEMA_INVALID'].includes(item.error_code) && !item.validation;
    const received=item.provider_response_received===true || legacyFailure;
    if(item.mode==='llm' && !aiBusy) $('ai-result-stats').textContent+=received ? '\nRespuesta JSON del proveedor recibida; validación editorial local: '+(item.status==='completed' ? 'completada.' : 'rechazada.') : '\nEste registro no acredita una respuesta JSON completa del proveedor.';
    $('ai-diagnostics').hidden=!item.validation && !legacyFailure;
    $('ai-diagnostics-note').textContent=legacyFailure ? 'El análisis anterior de v0.4.0 no conservó los motivos individuales ni la respuesta original. No se pueden reconstruir aquí. Actualizar o abrir el historial no vuelve a consultar al modelo; un análisis nuevo requiere otra autorización.' : 'Diagnóstico local: cuenta propuestas aceptadas y rechazadas con sus motivos. No incluye clave ni respuesta cruda del proveedor. Verlo no ejecuta otra consulta.';
    $('ai-diagnostics-json').hidden=!item.validation;
    $('ai-diagnostics-json').textContent=item.validation ? JSON.stringify(item.validation,null,2) : '';
    const list=$('ai-candidates');list.replaceChildren();for(const c of item.candidates) list.append(aiCard(id,item,c));
    if(item.status==='completed' && !item.candidates.length) list.append(node('p','El análisis terminó sin propuestas. Cambia el objetivo o el tramo, o usa el editor manual. No se inventarán clips.','muted'));
    $('ai-baseline').hidden=item.mode!=='llm' || !item.baseline?.length;
    $('ai-baseline-list').replaceChildren();if(item.mode==='llm') for(const c of item.baseline || []) $('ai-baseline-list').append(aiCard(id,item,c,true));
    if(aiBusy) {aiMessage('Análisis en curso. Puedes cerrar la página; el estado quedará en este proyecto si el servicio sigue ejecutándose.');clearTimeout(aiTimer);aiTimer=setTimeout(()=>viewAIRun(id,runId,token),2500);}
    else {aiMessage(item.status==='completed' ? 'Resultado guardado. Revisa las propuestas antes de crear un borrador.' : 'El análisis falló. No hubo fallback silencioso ni cambios en los clips.');refreshAIHistory(id,token,false);
      requestJSON('/ai/config').then(config=>{if(token===session){aiConfig=config;paintAIConfig(config);}}).catch(()=>{});
    }
  } catch(error) {
    if(token!==session || seq!==aiRunSequence) return;
    aiMessage(`No se pudo consultar el análisis: ${error.message}`);
    if(failures<MAX_RETRIES && !(error.status>=400 && error.status<500)) {clearTimeout(aiTimer);aiTimer=setTimeout(()=>viewAIRun(id,runId,token,failures+1),3000);}
    else {aiBusy=false;$('ai-fields').disabled=false;$('ai-preview-button').disabled=!aiContext?.available;aiMessage('No se pudo confirmar el resultado. Usa «Actualizar análisis»; no vuelvas a enviar una consulta todavía.');}
  }
}
$('ai-refresh').addEventListener('click',()=>{if(currentJob) {invalidateAIPreview();clearTimeout(aiTimer);aiCurrentRun=null;refreshAI(currentJob,session);}});
