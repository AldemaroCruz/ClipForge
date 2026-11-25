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

async function betaJson(auth, path, options) {
  const response = await auth.fetch(path, options);
  let payload;
  try {
    payload = await response.json();
  } catch (_) {
    throw new Error("No se pudo leer la respuesta. Inténtalo de nuevo en un momento.");
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

  let limits;
  let uploadBusy = false;
  let pendingUpload;
  let job;
  let selectedId;
  let selectionVersion = 0;
  let pollTimer;
  let projects = [];
  let loadingProjects = false;
  let renderKey;

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
    if (loadingProjects) return;
    loadingProjects = true;
    const status = element("projects-status");
    const more = element("more-projects");
    more.disabled = true;
    try {
      const offset = append ? projects.length : 0;
      const data = await json("/projects?limit=" + BETA_PAGE_SIZE + "&offset=" + offset);
      projects = append ? [...projects, ...data.projects] : data.projects;
      renderProjects();
      more.hidden = data.has_more !== true;
      status.textContent = projects.length ? "" : "Todavía no tienes trabajos. Sube un video para empezar.";
    } catch (error) {
      status.textContent = error.message;
    } finally {
      loadingProjects = false;
      more.disabled = false;
    }
  }

  function renderJob() {
    window.ClipForgeMvp?.selectJob(job);
    const title = projects.find(project => project.id === selectedId)?.title;
    element("job-title").textContent = title || job?.source_filename || "Revisar clips";
    const startExisting = element("start-existing");
    startExisting.hidden = !["awaiting_upload", "queued"].includes(job?.status);
    startExisting.textContent = job?.status === "queued" ? "Intentar activar el trabajo" : "Procesar video guardado";
    const retryJob = element("retry-job");
    retryJob.hidden = job?.status !== "failed" || job.retryable !== true;
    element("job-actions").hidden = startExisting.hidden && retryJob.hidden;
    element("job-error").textContent = job?.status === "failed"
      ? betaSafeMessage(job.pilot === true ? job.error : null, "El procesamiento falló.")
      : "";
    const clips = job?.status === "completed" && Array.isArray(job.clips)
      ? job.clips.filter(clip => BETA_CLIP.test(clip.file)) : [];
    element("job-status").textContent = !job ? "Consultando el trabajo…"
      : job.status === "awaiting_upload" ? "Carga pendiente. Si terminaste de transferir el video, puedes procesarlo desde aquí."
      : job.status === "completed" ? "Completado · " + clips.length + (clips.length === 1 ? " clip" : " clips")
      : job.status === "queued" && job.dispatch_status === "pending"
        ? "Pendiente. No se pudo activar el procesamiento. Se volverá a intentar."
      : betaStatus(job.status, job.lease_expired);
    const key = selectedId + ":" + Boolean(job) + ":" + clips.map(clip => clip.file).join(",");
    if (key === renderKey) return;
    renderKey = key;
    const cards = element("clip-list");
    cards.replaceChildren();
    for (const clip of clips) {
      const card = document.createElement("article");
      card.className = "beta-clip";
      const label = "Clip " + Number(clip.file.slice(5, 7));
      const path = "/jobs/" + selectedId + "/clips/" + clip.file;
      const player = document.createElement("video");
      player.controls = true;
      player.playsInline = true;
      player.preload = "metadata";
      player.src = path + "?inline=true";
      player.setAttribute("aria-label", label);
      const actions = document.createElement("div");
      actions.className = "actions";
      const download = betaText("a", "Descargar MP4");
      download.href = path;
      download.download = clip.file;
      download.setAttribute("aria-label", "Descargar " + label + " en MP4");
      actions.append(download);
      card.append(betaText("h3", label));
      if (Number.isFinite(clip.start) && Number.isFinite(clip.end)) {
        card.append(betaText("p", clip.start.toFixed(1) + "–" + clip.end.toFixed(1) + " s del original", "muted"));
      }
      card.append(player, actions);
      cards.append(card);
    }
  }

  async function openJob(id) {
    if (!BETA_JOB_ID.test(id)) return;
    clearTimeout(pollTimer);
    const originalSelection = selectedId;
    selectedId = id;
    const version = ++selectionVersion;
    if (id !== originalSelection) {
      job = undefined;
      history.replaceState(null, "", "/?job=" + id + location.hash);
      renderProjects();
      renderJob();
    }
    let hasJob = Boolean(job);
    async function refresh() {
      try {
        const value = await json("/jobs/" + id);
        if (version !== selectionVersion) return;
        if (value.id !== id) throw new Error("No se pudo verificar el trabajo.");
        const project = projects.find(item => item.id === id);
        if (project && (project.status !== value.status || project.lease_expired !== value.lease_expired)) {
          project.status = value.status;
          project.lease_expired = value.lease_expired;
          renderProjects();
        }
        job = value;
        hasJob = true;
        renderJob();
        if (["queued", "validating", "transcribing", "rendering"].includes(job.status)) {
          pollTimer = setTimeout(refresh, 3000);
        }
      } catch (error) {
        if (version !== selectionVersion) return;
        if (error.status === 403 || error.status === 404 || !hasJob) {
          job = undefined;
          renderJob();
          element("job-status").textContent = "Trabajo no disponible.";
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
    uploadSubmit.disabled = true;
    uploadProgress.hidden = true;
    uploadStatus.textContent = "";
    try {
      const file = uploadInput.files[0];
      betaValidateFile(file, limits);
      if (pendingUpload?.file !== file) pendingUpload = { file, key: crypto.randomUUID() };
      const request = auth.payload({ filename: file.name, bytes: file.size });
      request.headers["Idempotency-Key"] = pendingUpload.key;
      uploadStatus.textContent = "Solicitando una carga privada…";
      const reservation = await json("/beta/uploads", request);
      if (!BETA_JOB_ID.test(reservation.id) || (pendingUpload.id && pendingUpload.id !== reservation.id)) {
        throw new Error("No se pudo verificar la reserva del trabajo.");
      }
      pendingUpload.id = reservation.id;
      if (reservation.upload_url !== null) {
        uploadStatus.textContent = "Cargando el video. Mantén esta pestaña abierta hasta que termine.";
        uploadProgress.value = 0;
        uploadProgress.max = file.size;
        uploadProgress.hidden = false;
        await betaUploadFile(reservation.upload_url, file, bytes => { uploadProgress.value = bytes; });
      }
      uploadProgress.hidden = true;
      uploadStatus.textContent = "Confirmando el video y solicitando el procesamiento…";
      const result = await json("/beta/uploads/" + reservation.id + "/start", auth.payload({}));
      if (result.id !== reservation.id) throw new Error("No se pudo confirmar el trabajo.");
      uploadStatus.textContent = "Video guardado. Consulta el estado y los resultados en «Mis trabajos».";
      pendingUpload = undefined;
      uploadForm.reset();
      await loadProjects();
      await openJob(result.id);
    } catch (error) {
      uploadStatus.textContent = error.message;
    } finally {
      uploadBusy = false;
      uploadInput.disabled = false;
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
