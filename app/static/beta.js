"use strict";

const BETA_JOB_ID = /^[a-f0-9]{32}$/;
const BETA_CLIP = /^clip_[0-9]{2}\.mp4$/;
const BETA_CHUNK_BYTES = 8 * 1024 * 1024;
const BETA_PAGE_SIZE = 12;
const BETA_STATUS = {
  awaiting_upload: "Carga pendiente",
  queued: "Pendiente",
  validating: "Procesando · validando el video",
  transcribing: "Procesando · transcribiendo la voz",
  rendering: "Procesando · generando los clips",
  completed: "Completado",
  failed: "Fallido",
};
const BETA_CAPTION_STATUS = {
  unmodified: "Puedes generar subtítulos desde el original guardado.",
  queued: "Subtítulos en cola.",
  rendering: "Generando una nueva versión del clip.",
  failed: "Falló la generación de subtítulos.",
  no_speech: "No hay voz detectable en este recorte.",
};
const BETA_PROJECT_DELETED = "Proyecto eliminado de tu cuenta";
const BETA_PROJECT_UNAVAILABLE = "Trabajo no disponible.";

function betaUploadLocation(value) {
  let url;
  try {
    url = new URL(value);
  } catch (_) {
    throw new Error("No se pudo validar la autorización de carga.");
  }
  if (url.origin !== "https://storage.googleapis.com" || url.username || url.password || url.hash) {
    throw new Error("El destino de carga no está autorizado.");
  }
  return url.href;
}

function betaCommittedOffset(range, size) {
  if (!range) return 0;
  const match = /^bytes=0-([0-9]+)$/.exec(range);
  const next = match ? Number(match[1]) + 1 : NaN;
  if (!Number.isSafeInteger(next) || next <= 0 || next >= size) {
    throw new Error("El almacenamiento devolvió un avance de carga inválido.");
  }
  return next;
}

async function betaUploadFile(url, file, onProgress) {
  const location = betaUploadLocation(url);
  const maximumRequests = Math.ceil(file.size / BETA_CHUNK_BYTES) + 8;
  let offset = 0;
  let checkStatus = false;
  let wholeFile = false;
  let failures = 0;
  for (let attempt = 0; attempt < maximumRequests; attempt += 1) {
    const end = wholeFile ? file.size : Math.min(offset + BETA_CHUNK_BYTES, file.size);
    const headers = { "Content-Range": checkStatus
      ? "bytes */" + file.size
      : "bytes " + offset + "-" + (end - 1) + "/" + file.size };
    if (!checkStatus) headers["Content-Type"] = "video/mp4";
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 120_000);
    let response;
    try {
      response = await fetch(location, {
        method: "PUT",
        headers,
        body: checkStatus ? undefined : file.slice(offset, end),
        credentials: "omit",
        referrerPolicy: "no-referrer",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch (_) {
      // The upload URL is private. Do not display network diagnostics containing it.
    } finally {
      clearTimeout(timer);
    }
    if (response?.redirected) throw new Error("El almacenamiento cambió el destino de carga.");
    if (!response || response.status === 408 || response.status === 429 || response.status >= 500) {
      failures += 1;
      if (failures > 2) throw new Error("La carga se interrumpió. Mantén el archivo seleccionado y vuelve a pulsar «Subir y procesar».");
      checkStatus = true;
      await new Promise(resolve => setTimeout(resolve, 350 * failures));
      continue;
    }
    if (response.status === 200 || response.status === 201) {
      onProgress(file.size);
      return;
    }
    if (response.status === 412) {
      // Another response may have already completed the same create-only object.
      // The authenticated start endpoint verifies the object before enqueuing.
      return;
    }
    if (response.status !== 308) {
      throw new Error("La carga se rechazó o venció. Vuelve a pulsar «Subir y procesar» para continuar.");
    }
    const next = betaCommittedOffset(response.headers.get("Range"), file.size);
    if (next < offset || (!checkStatus && next <= offset)) {
      // Some cross-origin responses omit Range. Resend the complete bounded
      // object on this same resumable session instead of assuming any bytes.
      if (wholeFile) throw new Error("El almacenamiento no pudo confirmar el avance de la carga.");
      offset = 0;
      wholeFile = true;
      onProgress(0);
    } else {
      if (!checkStatus && next > end) throw new Error("El almacenamiento devolvió un avance de carga inesperado.");
      offset = next;
      onProgress(offset);
    }
    checkStatus = false;
  }
  throw new Error("La carga quedó incompleta. Vuelve a pulsar «Subir y procesar».");
}

function betaText(tag, content, className) {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
}

function betaStatus(status, leaseExpired = false) {
  if (leaseExpired === true) return "Verificando el intento de procesamiento…";
  return Object.hasOwn(BETA_STATUS, status) ? BETA_STATUS[status] : "Estado pendiente de confirmar";
}

function betaFileSize(bytes) {
  return (bytes / 1024 / 1024).toLocaleString("es", { maximumFractionDigits: 1 }) + " MiB";
}

function betaLimitsAreValid(limits) {
  return limits && ["max_bytes", "min_duration_seconds", "max_duration_seconds", "max_dimension",
    "worker_concurrency", "active_jobs_per_user"].every(key => Number.isSafeInteger(limits[key]) && limits[key] > 0)
    && limits.max_duration_seconds >= limits.min_duration_seconds
    && Array.isArray(limits.formats) && limits.formats.length > 0
    && limits.formats.every(item => typeof item === "string" && item.length > 0)
    && limits.selection_mode === "heuristic_voice";
}

function betaValidateFile(file, limits) {
  if (!file || !/\.mp4$/i.test(file.name)) throw new Error("Selecciona un archivo MP4.");
  if (file.size === 0) throw new Error("El archivo está vacío.");
  if (file.size > limits.max_bytes) throw new Error("El video supera el máximo de " + betaFileSize(limits.max_bytes) + ".");
}

function betaSafeMessage(value, fallback) {
  return typeof value === "string" && value.length <= 200 && !value.includes("://") ? value : fallback;
}

function betaCaptionOutput(jobId, file, captions) {
  if (!["completed", "no_speech"].includes(captions?.status)
    || !BETA_CLIP.test(file) || !BETA_JOB_ID.test(jobId)) return null;
  const output = captions.output;
  const jobPath = "/jobs/" + jobId;
  const original = jobPath + "/clips/" + file;
  const variant = BETA_JOB_ID.test(output?.id) ? jobPath + "/exports/" + output.id + "/files/clip" : "";
  if (!output || (output.mp4 !== original && (!variant || output.mp4 !== variant + ".mp4"))) return null;
  const files = {mp4: output.mp4, burn_subtitles: output.burn_subtitles === true};
  for (const format of ["srt", "vtt"]) {
    const expected = output.mp4 === original ? original + "/subtitles/" + format : variant + "." + format;
    if (output[format] === expected) files[format] = expected;
  }
  return files;
}

function betaCaptionMessage(captions, output) {
  if (captions?.status === "queued" || captions?.status === "rendering") {
    return BETA_CAPTION_STATUS[captions.status];
  }
  const fallback = output?.burn_subtitles ? "Subtítulos incrustados"
    : BETA_CAPTION_STATUS[captions?.status] || "";
  return betaSafeMessage(captions?.notice, fallback);
}

function betaCaptionSidecars(container, output, file) {
  for (const [format, name] of [["srt", "SRT"], ["vtt", "WebVTT"]]) {
    if (!output?.[format]) continue;
    const link = betaText("a", "Descargar " + name);
    link.href = output[format];
    link.download = file.replace(/mp4$/, format);
    container.append(link);
  }
}

async function betaJson(auth, path, options) {
  const response = await auth.fetch(path, options);
  let payload;
  try {
    payload = await response.json();
  } catch (_) {
    if (response.ok) throw new Error("No se pudo leer la respuesta. Inténtalo de nuevo en un momento.");
  }
  if (!response.ok) {
    const message = betaSafeMessage(payload?.detail, "No se pudo completar la solicitud. Inténtalo de nuevo en un momento.");
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return payload;
}

async function initBeta() {
  const auth = window.ClipForgeAuth;
  const element = id => document.getElementById(id);
  const workspace = element("beta-workspace");
  const user = await auth.ready;
  if (!workspace || !user) return;
  const json = (path, options) => betaJson(auth, path, options);
  const uploadForm = element("upload-form");
  const uploadInput = element("upload-video");
  const uploadSubmit = element("upload-submit");
  const uploadProgress = element("upload-progress");
  const uploadStatus = element("upload-status");
  const uploadBurnSubtitles = element("upload-burn-subtitles");
  const caption = suffix => element("clip-caption-" + suffix);
  const captionFields = window.ClipForgeCaptionFields;
  const deleteDialog = element("project-delete-dialog");

  let limits;
  let uploadBusy = false;
  let pendingUpload;
  let job;
  let selectedId;
  let jobRequest;
  let pollTimer;
  let projects = [];
  let projectsRequest;
  let projectsOffset = 0;
  let renderKey;
  let captionView;
  let deleteTarget;
  let deleteBusy = false;
  const unavailableProjects = new Set();
  const projectEvents = typeof BroadcastChannel === "function" && BETA_JOB_ID.test(user.id)
    ? new BroadcastChannel("clipforge-beta-projects:" + user.id) : null;

  function renderProjects() {
    const list = element("project-list");
    list.replaceChildren();
    for (const project of projects) {
      if (!BETA_JOB_ID.test(project.id)) continue;
      const item = document.createElement("li");
      const link = betaText("a", project.title || "Video " + project.id.slice(0, 8));
      link.href = "/?job=" + project.id;
      if (selectedId === project.id) link.setAttribute("aria-current", "true");
      link.addEventListener("click", event => {
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        void openJob(project.id);
      });
      item.append(link, betaText("p", betaStatus(project.status, project.lease_expired), "muted"));
      list.append(item);
    }
  }

  async function loadProjects(append = false) {
    if (append && projectsRequest) return;
    projectsRequest?.abort();
    const request = new AbortController();
    projectsRequest = request;
    const status = element("projects-status");
    const more = element("more-projects");
    more.disabled = true;
    try {
      const offset = append ? projectsOffset : 0;
      const data = await json("/projects?limit=" + BETA_PAGE_SIZE + "&offset=" + offset, {signal: request.signal});
      if (request.signal.aborted) return;
      const loaded = new Set(append ? projects.map(project => project.id) : []);
      const incoming = data.projects.filter(project => !unavailableProjects.has(project.id) && !loaded.has(project.id));
      projects = append ? [...projects, ...incoming] : incoming;
      projectsOffset = offset + data.projects.length;
      renderProjects();
      more.hidden = data.has_more !== true;
      status.textContent = projects.length ? "" : "Todavía no tienes trabajos. Sube un video para empezar.";
    } catch (error) {
      if (!request.signal.aborted) status.textContent = error.message;
    } finally {
      if (projectsRequest === request) {
        projectsRequest = undefined;
        more.disabled = false;
      }
    }
  }

  function renderJob() {
    window.ClipForgeMvp?.selectJob(job);
    window.ClipForgeEditorial?.selectJob(job);
    const title = projects.find(project => project.id === selectedId)?.title;
    element("job-title").textContent = title || job?.source_filename || "Revisar clips";
    const startExisting = element("start-existing");
    startExisting.hidden = !["awaiting_upload", "queued"].includes(job?.status);
    startExisting.textContent = job?.status === "queued" ? "Intentar activar el trabajo" : "Procesar video guardado";
    const retryJob = element("retry-job");
    retryJob.hidden = job?.status !== "failed" || job.retryable !== true;
    const removeJob = element("delete-project");
    removeJob.hidden = !job;
    element("job-actions").hidden = startExisting.hidden && retryJob.hidden && removeJob.hidden;
    if (captionView?.id !== selectedId) closeCaptions();
    element("job-error").textContent = job?.status === "failed"
      ? betaSafeMessage(job.pilot === true ? job.error : null, "El procesamiento falló.")
      : "";
    const clips = job?.status === "completed" && Array.isArray(job.clips)
      ? job.clips.filter(clip => BETA_CLIP.test(clip.file)) : [];
    element("heuristic-heading").hidden = !clips.length;
    element("job-status").textContent = !job ? "Consultando el trabajo…"
      : job.status === "awaiting_upload" ? "Carga pendiente. Si terminaste de transferir el video, puedes procesarlo desde aquí."
      : job.status === "completed" ? "Completado · " + clips.length + (clips.length === 1 ? " clip" : " clips")
      : job.status === "queued" && job.dispatch_status === "pending"
        ? "Pendiente. No se pudo activar el procesamiento. Se volverá a intentar."
      : betaStatus(job.status, job.lease_expired);
    syncCaptionRender();
    const key = selectedId + ":" + Boolean(job) + ":" + JSON.stringify(clips.map(clip => [clip.file, clip.captions]));
    if (key === renderKey) return;
    renderKey = key;
    const cards = element("clip-list");
    const currentCards = new Map([...cards.children].map(card => [card.dataset.clipFile, card]));
    const nextCards = [];
    for (const clip of clips) {
      const cardKey = selectedId + ":" + JSON.stringify([clip.file, clip.captions, clip.start, clip.end]);
      const current = currentCards.get(clip.file);
      if (current?.dataset.renderKey === cardKey) {
        nextCards.push(current);
        continue;
      }
      const card = document.createElement("article");
      card.className = "beta-clip";
      card.dataset.clipFile = clip.file;
      card.dataset.renderKey = cardKey;
      const label = "Clip " + Number(clip.file.slice(5, 7));
      const path = "/jobs/" + selectedId + "/clips/" + clip.file;
      const output = betaCaptionOutput(selectedId, clip.file, clip.captions);
      const filePath = output?.mp4 || path;
      const player = document.createElement("video");
      player.controls = true;
      player.playsInline = true;
      player.preload = "none";
      player.src = filePath + "?inline=true";
      player.setAttribute("aria-label", label);
      const actions = document.createElement("div");
      actions.className = "actions";
      const initial = ["queued", "rendering", "failed"].includes(clip.captions?.status) && !output;
      const download = betaText("a", initial ? "Descargar MP4 inicial" : "Descargar MP4");
      download.href = filePath;
      download.download = clip.file;
      download.setAttribute("aria-label", "Descargar " + label + " en MP4");
      actions.append(download);
      if (output?.mp4 && output.mp4 !== path) {
        const original = betaText("a", "MP4 inicial");
        original.href = path;
        original.download = clip.file;
        actions.append(original);
      }
      betaCaptionSidecars(actions, output, clip.file);
      const correct = betaText("button", "Corregir texto", "secondary");
      correct.type = "button";
      correct.addEventListener("click", () => openCaptions(clip.file, {quick: true, time: player.currentTime}));
      actions.append(correct);
      const edit = betaText("button", "Editar subtítulos", "secondary");
      edit.type = "button";
      edit.addEventListener("click", () => openCaptions(clip.file));
      actions.append(edit);
      if (clip.captions?.retryable === true) {
        const retry = betaText("button", "Reintentar subtítulos", "secondary");
        retry.type = "button";
        retry.addEventListener("click", () => retryCaptions(clip.file, retry));
        actions.append(retry);
      }
      card.append(betaText("h3", label));
      if (Number.isFinite(clip.start) && Number.isFinite(clip.end)) {
        card.append(betaText("p", clip.start.toFixed(1) + "–" + clip.end.toFixed(1) + " s del original", "muted"));
      }
      const captionsMessage = betaCaptionMessage(clip.captions, output);
      if (captionsMessage) {
        const state = betaText("p", captionsMessage, "muted");
        state.setAttribute("role", "status");
        card.append(state);
      }
      card.append(player, actions);
      nextCards.push(card);
    }
    for (const card of [...cards.children]) {
      if (!nextCards.includes(card)) {
        const player = card.querySelector("video");
        player.pause();
        player.removeAttribute("src");
        player.load();
        card.remove();
      }
    }
    nextCards.forEach((card, index) => {
      if (cards.children[index] !== card) cards.insertBefore(card, cards.children[index] ?? null);
    });
  }

  function captionPath(id, file) {
    return "/jobs/" + id + "/clips/" + file + "/captions";
  }

  function closeCaptions() {
    if (!captionView) return;
    captionView = undefined;
    caption("editor").hidden = true;
    caption("form").hidden = true;
    caption("fields").disabled = false;
    caption("cues").replaceChildren();
    caption("downloads").replaceChildren();
    caption("downloads").hidden = true;
    const player = caption("preview");
    player.pause();
    player.removeAttribute("src");
    player.load();
    player.hidden = true;
  }

  function captionStyle(view) {
    return {...view.data.style, burn_subtitles: caption("burn").checked,
      subtitle_font_size: caption("size").valueAsNumber, subtitle_color: caption("color").value.toUpperCase(),
      subtitle_position: caption("position").value, subtitle_outline: caption("edge").valueAsNumber};
  }

  function updateCaptionSample() {
    if (!captionView?.data || captionView.quick) return;
    captionFields.showCaptionSample(caption("sample"), caption("cues"), captionStyle(captionView));
  }

  function quickCueRow(cue, index) {
    const row = betaText("label", "Subtítulo " + (index + 1) + " · "
      + cue.start.toFixed(3) + "–" + cue.end.toFixed(3) + " s", "editorial-cue");
    const input = document.createElement("textarea");
    input.required = true;
    input.maxLength = 500;
    input.rows = 2;
    input.value = cue.text;
    row.append(input);
    return row;
  }

  function syncCaptionRender(state) {
    const view = captionView;
    if (!view || view.id !== selectedId) return;
    const current = state || job?.clips?.find(clip => clip.file === view.file)?.captions;
    if (view.data && (!Number.isSafeInteger(current?.revision) || current.revision < view.data.revision)) return;
    const downloads = caption("downloads");
    if (view.quick && current?.revision > view.data?.revision) {
      downloads.hidden = true;
      caption("status").textContent = "Hay otra revisión guardada. Vuelve a abrir el clip para continuar.";
      return;
    }
    const output = betaCaptionOutput(view.id, view.file, current);
    const base = "/jobs/" + view.id + "/clips/" + view.file;
    const mediaPath = (output?.mp4 || base) + "?inline=true";
    const player = caption("preview");
    const exportReady = view.quick && output && current?.revision === view.data?.revision;
    downloads.hidden = !exportReady || view.dirty;
    const key = JSON.stringify([current?.status, current?.notice, current?.revision, mediaPath,
      Boolean(exportReady), output?.srt, output?.vtt]);
    if (key === view.renderKey) return;
    view.renderKey = key;
    if (player.getAttribute("src") !== mediaPath) player.src = mediaPath;
    player.hidden = false;
    const message = exportReady && output.burn_subtitles ? "Versión lista para descargar." : betaCaptionMessage(current, output);
    caption("status").textContent = message;
    player.setAttribute("aria-label", output ? "Vista previa del MP4 disponible" : "Vista previa del clip inicial");
    downloads.replaceChildren();
    if (exportReady) {
      const mp4 = betaText("a", "Descargar MP4");
      mp4.href = output.mp4;
      mp4.download = view.file;
      downloads.append(mp4);
      betaCaptionSidecars(downloads, output, view.file);
    }
  }

  function mountCaptions(view, data, {preserveCues = false} = {}) {
    if (captionView !== view) return;
    if (!Number.isFinite(data.duration) || data.duration <= 0 || !data.style
      || !Array.isArray(data.cues) || !Number.isSafeInteger(data.revision)) {
      throw new Error("No se pudo verificar la versión del clip.");
    }
    view.data = data;
    view.dirty = false;
    caption("range").textContent = view.quick ? "Tiempos dentro del clip."
      : data.start.toFixed(3) + "–" + data.end.toFixed(3)
        + " s del original. Los tiempos de los subtítulos empiezan en cero para este recorte.";
    caption("burn").checked = data.style.burn_subtitles === true;
    caption("size").value = data.style.subtitle_font_size ?? 52;
    caption("color").value = data.style.subtitle_color ?? "#ffffff";
    caption("position").value = data.style.subtitle_position ?? "bottom";
    caption("edge").value = data.style.subtitle_outline ?? 3;
    if (!preserveCues) {
      caption("cues").replaceChildren(...(view.quick ? data.cues.map(quickCueRow) : data.cues.map(cue =>
        captionFields.cueRow(cue, data.duration, updateCaptionSample))));
    }
    const empty = view.quick && !data.cues.length;
    caption("empty").hidden = !empty;
    caption("save").disabled = empty;
    caption("form").hidden = false;
    syncCaptionRender(data);
    updateCaptionSample();
  }

  async function openCaptions(file, {quick = false, time = 0} = {}) {
    if (job?.status !== "completed" || !BETA_CLIP.test(file) || !captionFields) return;
    if (captionView?.busy) return;
    closeCaptions();
    const view = {id: selectedId, file, quick, busy: true};
    captionView = view;
    const editor = caption("editor");
    editor.dataset.mode = quick ? "quick" : "full";
    editor.hidden = false;
    caption("heading").textContent = (quick ? "Corregir texto" : "Editar subtítulos") + " · Clip " + Number(file.slice(5, 7));
    caption("legend").textContent = quick ? "Subtítulos" : "Estilo y sincronización";
    caption("advanced").hidden = quick;
    caption("add").hidden = quick;
    caption("apply-all").hidden = quick;
    caption("save").textContent = quick ? "Guardar y exportar" : "Guardar y generar clip";
    caption("range").textContent = "";
    caption("status").textContent = "Cargando subtítulos del recorte.";
    editor.scrollIntoView({block: "nearest"});
    try {
      const data = await json(captionPath(view.id, file));
      mountCaptions(view, data);
      if (captionView === view && quick) {
        const active = data.cues.findIndex(cue => cue.start <= time && time < cue.end);
        caption("cues").querySelectorAll("textarea")[Math.max(0, active)]?.focus();
      }
    } catch (error) {
      if (captionView === view) caption("status").textContent = error.message;
    } finally {
      view.busy = false;
    }
  }

  async function saveCaptions(applyAll = false) {
    const view = captionView;
    if (!view?.data || view.busy || job?.status !== "completed") return;
    if (view.quick && (applyAll || !view.data.cues.length)) return;
    const valid = applyAll ? ["size", "edge"].every(name => caption(name).reportValidity())
      : caption("form").reportValidity();
    if (!valid) return;
    const style = view.quick ? view.data.style : captionStyle(view);
    const projectRevision = job.caption_style?.revision;
    if (applyAll) {
      if (!Number.isSafeInteger(projectRevision)) {
        caption("status").textContent = "Actualiza el proyecto para consultar el estilo guardado.";
        return;
      }
      const confirmed = window.confirm("Este estilo se guardará para el proyecto y reemplazará los ajustes de estilo "
        + "individuales de todos sus clips. Se conservarán sus textos y tiempos guardados. ¿Continuar?");
      if (!confirmed) return;
    }
    const cues = view.quick
      ? [...caption("cues").querySelectorAll("textarea")].map((input, index) => ({
        ...view.data.cues[index], text: input.value,
      }))
      : captionFields.readCues(caption("cues"));
    view.busy = true;
    caption("fields").disabled = true;
    caption("status").textContent = applyAll ? "Aplicando estilo al proyecto." : "Guardando los subtítulos.";
    try {
      const path = applyAll ? "/jobs/" + view.id + "/captions" : captionPath(view.id, view.file);
      const options = auth.payload(applyAll ? {style, revision: projectRevision, apply_to_all: true}
        : {style, cues, revision: view.data.revision});
      options.method = "PUT";
      const result = await json(path, options);
      if (captionView !== view) return;
      const data = applyAll ? await json(captionPath(view.id, view.file)) : result;
      mountCaptions(view, data, {preserveCues: applyAll});
      if (captionView === view) {
        const action = applyAll ? "Estilo del proyecto guardado."
          : view.quick ? "Corrección guardada." : "Subtítulos guardados.";
        const state = betaCaptionMessage(data, betaCaptionOutput(view.id, view.file, data));
        caption("status").textContent = state ? action + " " + state : action;
        await openJob(view.id);
      }
    } catch (error) {
      if (captionView === view) caption("status").textContent = error.status === 409
        ? betaSafeMessage(error.message, "Actualiza el clip y vuelve a intentarlo.") : error.message;
    } finally {
      view.busy = false;
      if (captionView === view) caption("fields").disabled = false;
    }
  }

  async function retryCaptions(file, control) {
    const id = selectedId;
    if (job?.status !== "completed" || !BETA_CLIP.test(file) || control.disabled) return;
    control.disabled = true;
    try {
      const result = await json(captionPath(id, file) + "/retry", auth.payload({}));
      if (selectedId !== id) return;
      if (captionView?.file === file) syncCaptionRender(result);
      await openJob(id);
    } catch (error) {
      if (selectedId === id) element("job-error").textContent = error.message;
    } finally {
      control.disabled = false;
    }
  }

  function updateJobQuery(id) {
    const url = new URL(location.href);
    if (id) url.searchParams.set("job", id);
    else url.searchParams.delete("job");
    history.replaceState(history.state, "", url);
  }

  function forgetProject(id, message) {
    const changed = !unavailableProjects.has(id);
    unavailableProjects.add(id);
    projects = projects.filter(project => project.id !== id);
    if (pendingUpload?.id === id) {
      pendingUpload = undefined;
      uploadForm.reset();
      uploadStatus.textContent = "";
      if (!uploadBusy) uploadBurnSubtitles.disabled = false;
    }
    try {
      for (const key of ["clipforge-last-job", auth.storageKey?.()]) {
        if (key && localStorage.getItem(key) === id) localStorage.removeItem(key);
      }
    } catch (_) {
      // Browser storage may be unavailable.
    }
    if (deleteDialog.open && deleteTarget === id) deleteDialog.close();
    const linked = new URLSearchParams(location.search).get("job") === id;
    if (linked) updateJobQuery();
    if (selectedId === id) {
      clearTimeout(pollTimer);
      jobRequest?.abort();
      selectedId = undefined;
      job = undefined;
      renderJob();
    }
    if (!selectedId && (linked || message === BETA_PROJECT_DELETED)) {
      element("job-status").textContent = message;
    }
    if (changed) {
      element("more-projects").hidden = true;
      renderProjects();
      void loadProjects();
    }
  }

  async function deleteProject(id) {
    if (deleteBusy || selectedId !== id || deleteTarget !== id || !BETA_JOB_ID.test(id)) return;
    deleteBusy = true;
    const confirm = element("project-delete-confirm");
    const cancel = element("project-delete-cancel");
    const status = element("project-delete-error");
    confirm.disabled = true;
    cancel.disabled = true;
    status.textContent = "";
    try {
      const result = await json("/jobs/" + id + "/deletion", auth.payload({}));
      if (result?.id !== id || result.status !== "deleted") {
        throw new Error("No se pudo confirmar la eliminación del proyecto.");
      }
      forgetProject(id, BETA_PROJECT_DELETED);
      projectEvents?.postMessage({type: "deleted", id});
    } catch (error) {
      if (error.status === 404) forgetProject(id, BETA_PROJECT_UNAVAILABLE);
      else if (selectedId === id) status.textContent = error.message;
    } finally {
      deleteBusy = false;
      confirm.disabled = false;
      cancel.disabled = false;
    }
  }

  async function openJob(id) {
    if (!BETA_JOB_ID.test(id) || unavailableProjects.has(id)) return;
    clearTimeout(pollTimer);
    jobRequest?.abort();
    const request = new AbortController();
    jobRequest = request;
    const originalSelection = selectedId;
    selectedId = id;
    if (id !== originalSelection) {
      job = undefined;
      updateJobQuery(id);
      renderProjects();
      renderJob();
    }
    let hasJob = Boolean(job);
    async function refresh() {
      try {
        const value = await json("/jobs/" + id, {signal: request.signal});
        if (request.signal.aborted) return;
        if (value.id !== id) throw new Error("No se pudo verificar el trabajo.");
        if (value.status === "deleted") {
          forgetProject(id, BETA_PROJECT_DELETED);
          return;
        }
        const project = projects.find(item => item.id === id);
        if (project && (project.status !== value.status || project.lease_expired !== value.lease_expired)) {
          Object.assign(project, {status: value.status, lease_expired: value.lease_expired});
          renderProjects();
        }
        job = value;
        hasJob = true;
        renderJob();
        const captionsPending = job.clips?.some(clip => ["queued", "rendering"].includes(clip.captions?.status));
        if (["queued", "validating", "transcribing", "rendering"].includes(job.status) || captionsPending) {
          pollTimer = setTimeout(refresh, 3000);
        }
      } catch (error) {
        if (request.signal.aborted) return;
        if (error.status === 404) {
          forgetProject(id, BETA_PROJECT_UNAVAILABLE);
          return;
        }
        if (error.status === 403 || !hasJob) {
          job = undefined;
          renderJob();
          element("job-status").textContent = BETA_PROJECT_UNAVAILABLE;
        }
        element("job-error").textContent = error.message;
        if (hasJob && (!error.status || error.status >= 500)) pollTimer = setTimeout(refresh, 7000);
      }
    }
    await refresh();
  }

  async function startOrRetry(button, route) {
    const id = selectedId;
    if (!job || !BETA_JOB_ID.test(id) || button.disabled) return;
    button.disabled = true;
    try {
      const result = await json(route(id), auth.payload({}));
      if (result.id !== id) throw new Error("No se pudo verificar el trabajo.");
      if (selectedId === id) {
        await openJob(id);
        if (job?.status === "queued" && result.dispatch_status === "pending") {
          element("job-status").textContent = "Pendiente. Puedes volver a intentar la activación sin subir el video otra vez.";
        }
      }
      await loadProjects();
    } catch (error) {
      if (selectedId === id) element("job-error").textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }

  uploadInput.addEventListener("change", () => {
    pendingUpload = undefined;
    uploadBurnSubtitles.disabled = false;
    uploadProgress.hidden = true;
    uploadStatus.textContent = "";
    try {
      if (uploadInput.files.length) betaValidateFile(uploadInput.files[0], limits);
    } catch (error) {
      uploadStatus.textContent = error.message;
    }
  });

  uploadForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (!limits || uploadBusy) return;
    uploadBusy = true;
    uploadInput.disabled = true;
    uploadBurnSubtitles.disabled = true;
    uploadSubmit.disabled = true;
    uploadProgress.hidden = true;
    uploadStatus.textContent = "";
    let attempt;
    try {
      const file = uploadInput.files[0];
      betaValidateFile(file, limits);
      if (pendingUpload?.file !== file) {
        pendingUpload = {file, key: crypto.randomUUID(), burnSubtitles: uploadBurnSubtitles.checked};
      }
      attempt = pendingUpload;
      const request = auth.payload({filename: file.name, bytes: file.size,
        burn_subtitles: attempt.burnSubtitles});
      request.headers["Idempotency-Key"] = attempt.key;
      uploadStatus.textContent = "Solicitando una carga privada…";
      const reservation = await json("/beta/uploads", request);
      if (!BETA_JOB_ID.test(reservation.id) || (attempt.id && attempt.id !== reservation.id)) {
        throw new Error("No se pudo verificar la reserva del trabajo.");
      }
      attempt.id = reservation.id;
      if (unavailableProjects.has(attempt.id)) return;
      if (reservation.upload_url !== null) {
        uploadStatus.textContent = "Cargando el video. Mantén esta pestaña abierta hasta que termine.";
        uploadProgress.value = 0;
        uploadProgress.max = file.size;
        uploadProgress.hidden = false;
        await betaUploadFile(reservation.upload_url, file, bytes => { uploadProgress.value = bytes; });
      }
      if (unavailableProjects.has(attempt.id)) return;
      uploadProgress.hidden = true;
      uploadStatus.textContent = "Confirmando el video y solicitando el procesamiento…";
      const result = await json("/beta/uploads/" + reservation.id + "/start", auth.payload({}));
      if (result.id !== reservation.id) throw new Error("No se pudo confirmar el trabajo.");
      if (unavailableProjects.has(attempt.id)) return;
      uploadStatus.textContent = "Video guardado. Consulta el estado y los resultados en «Mis trabajos».";
      pendingUpload = undefined;
      uploadForm.reset();
      await loadProjects();
      await openJob(result.id);
    } catch (error) {
      if (!unavailableProjects.has(attempt?.id)) uploadStatus.textContent = error.message;
    } finally {
      uploadBusy = false;
      uploadInput.disabled = false;
      uploadBurnSubtitles.disabled = Boolean(pendingUpload);
      uploadSubmit.disabled = false;
      uploadProgress.hidden = true;
    }
  });

  element("refresh-projects").addEventListener("click", async () => {
    await loadProjects();
    if (selectedId) await openJob(selectedId);
  });
  element("more-projects").addEventListener("click", () => loadProjects(true));
  element("start-existing").addEventListener("click", event => startOrRetry(event.currentTarget, id => "/beta/uploads/" + id + "/start"));
  element("retry-job").addEventListener("click", event => startOrRetry(event.currentTarget, id => "/beta/jobs/" + id + "/retry"));
  element("delete-project").addEventListener("click", () => {
    if (!job || deleteBusy) return;
    deleteTarget = selectedId;
    element("project-delete-title").textContent = element("job-title").textContent;
    element("project-delete-error").textContent = "";
    deleteDialog.showModal();
  });
  element("project-delete-cancel").addEventListener("click", () => deleteDialog.close());
  element("project-delete-confirm").addEventListener("click", () => deleteProject(deleteTarget));
  deleteDialog.addEventListener("cancel", event => {
    if (deleteBusy) event.preventDefault();
  });
  deleteDialog.addEventListener("close", () => { deleteTarget = undefined; });
  projectEvents?.addEventListener("message", event => {
    const {type, id} = event.data ?? {};
    if (type === "deleted" && typeof id === "string" && BETA_JOB_ID.test(id)) {
      forgetProject(id, BETA_PROJECT_DELETED);
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) return;
    if (selectedId) void openJob(selectedId);
    if (!projectEvents) void loadProjects();
  });
  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    if (selectedId) void openJob(selectedId);
    void loadProjects();
  });
  caption("form").addEventListener("submit", event => {
    event.preventDefault();
    void saveCaptions();
  });
  caption("form").addEventListener("input", () => {
    if (captionView?.quick) {
      captionView.dirty = true;
      caption("downloads").hidden = true;
    } else {
      updateCaptionSample();
    }
  });
  caption("apply-all").addEventListener("click", () => saveCaptions(true));
  caption("add").addEventListener("click", () => {
    if (!captionView?.data) return;
    if (!captionFields.addCue(caption("cues"), captionView.data.duration, updateCaptionSample)) {
      caption("status").textContent = "Ajusta el fin del último subtítulo para añadir otro.";
    }
  });
  caption("close").addEventListener("click", closeCaptions);
  workspace.hidden = false;
  const current = new URLSearchParams(location.search).get("job");
  void loadProjects().then(() => {
    if (BETA_JOB_ID.test(current) && !selectedId) void openJob(current);
  });
  try {
    limits = await json("/beta/limits");
    if (!betaLimitsAreValid(limits)) throw new Error("No se pudieron confirmar los límites de carga.");
    element("upload-limits").textContent = limits.formats.join(", ") + " con voz · hasta "
      + betaFileSize(limits.max_bytes) + " · entre " + limits.min_duration_seconds + " y "
      + limits.max_duration_seconds + " s · lado máximo " + limits.max_dimension + " px. "
      + limits.active_jobs_per_user + " trabajo activo por cuenta; el piloto procesa "
      + limits.worker_concurrency + " a la vez.";
    uploadInput.disabled = false;
    uploadSubmit.disabled = false;
  } catch (error) {
    element("upload-limits").textContent = error.message + " Recarga la página para comprobarlos.";
  }
}

if (document.getElementById("beta-workspace")) {
  void initBeta();
}
