"use strict";

// The beta job list remains the single source of current selection.
(() => {
  const element = id => document.getElementById(id);
  const panel = element("mvp-editor");
  if (!panel) return;

  const details = element("mvp-editor-details");
  const form = element("mvp-range-form");
  const source = element("mvp-source");
  const startInput = element("mvp-start");
  const endInput = element("mvp-end");
  const markStart = element("mvp-mark-start");
  const markEnd = element("mvp-mark-end");
  const preview = element("mvp-preview");
  const submit = element("mvp-export");
  const status = element("mvp-status");
  const results = element("mvp-results");
  const auth = window.ClipForgeAuth;
  const controls = [startInput, endInput, markStart, markEnd, preview, submit];
  const idPattern = /^[a-f0-9]{32}$/;
  const activeStates = new Set(["queued", "validating", "rendering"]);
  let jobId = null;
  let currentView = 0;
  let previewEnd = null;
  let pollTimer = null;
  let exportSignature = "";

  function disableControls(disabled) {
    controls.forEach(control => { control.disabled = disabled; });
  }

  function reset() {
    currentView += 1;
    clearTimeout(pollTimer);
    previewEnd = null;
    source.pause();
    if (source.hasAttribute("src")) {
      source.removeAttribute("src");
      source.load();
    }
    results.replaceChildren();
    exportSignature = "";
    form.reset();
    status.textContent = "";
    disableControls(true);
  }

  function selectJob(job) {
    const eligible = job?.pilot === true && idPattern.test(job.id)
      && ["completed", "failed"].includes(job.status)
      && Number.isFinite(job.media?.duration_seconds) && job.media.duration_seconds >= 1;
    const next = eligible ? job.id : null;
    if (next === jobId) return;
    reset();
    details.open = false;
    jobId = next;
    panel.hidden = !jobId;
  }

  function visible(id, view) {
    return id === jobId && view === currentView && details.open;
  }

  function url(id, path) {
    return "/jobs/" + id + path;
  }

  function text(tag, value, className) {
    const node = document.createElement(tag);
    node.textContent = value;
    if (className) node.className = className;
    return node;
  }

  function link(value, href) {
    const node = text("a", value);
    node.href = href;
    return node;
  }

  function renderExports(id, exports) {
    const signature = JSON.stringify(exports.map(item => [item.id, item.status, item.start, item.end]));
    if (signature === exportSignature) return;
    exportSignature = signature;
    results.replaceChildren(...exports.map(item => {
      const article = text("article", "", "beta-clip");
      article.append(text("h3", "Clip manual"));
      article.append(text("p", item.start.toFixed(2) + "–" + item.end.toFixed(2) + " s del original", "muted"));
      if (item.status === "completed") {
        const files = url(id, "/exports/" + item.id + "/files/");
        const player = document.createElement("video");
        player.src = files + "clip.mp4?inline=true";
        player.controls = true;
        player.playsInline = true;
        player.preload = "none";
        player.setAttribute("aria-label", "Clip manual");
        const links = text("div", "", "actions");
        links.append(link("Descargar clip manual", files + "clip.mp4"),
          link("Subtítulos SRT", files + "clip.srt"), link("Subtítulos VTT", files + "clip.vtt"));
        article.append(player, links);
      } else {
        const label = item.status === "failed" ? "No se pudo generar este clip."
          : item.status === "queued" ? "Clip en cola." : "Generando clip…";
        article.append(text("p", label, "status"));
      }
      return article;
    }));
  }

  async function refreshExports(id, view) {
    clearTimeout(pollTimer);
    try {
      const response = await auth.json(url(id, "/exports"));
      if (!visible(id, view)) return;
      const exports = response.exports.filter(item => idPattern.test(item.id) && item.clip_file === "manual.mp4"
        && Number.isFinite(item.start) && Number.isFinite(item.end));
      renderExports(id, exports);
      if (exports.some(item => activeStates.has(item.status))) {
        pollTimer = setTimeout(() => refreshExports(id, view), 3000);
      }
    } catch (error) {
      if (visible(id, view)) status.textContent = error.message;
    }
  }

  async function openEditor() {
    const id = jobId;
    if (!id) return;
    const view = ++currentView;
    try {
      const workspace = await auth.json(url(id, "/workspace"));
      if (!visible(id, view)) return;
      const duration = workspace.source_duration;
      if (!Number.isFinite(duration) || duration < 1) throw new Error("No se pudo comprobar la duración del original.");
      source.src = url(id, "/source");
      startInput.value = 0;
      endInput.value = Math.min(30, duration).toFixed(3);
      startInput.max = (duration - 1).toFixed(3);
      endInput.max = duration.toFixed(3);
      disableControls(false);
      await refreshExports(id, view);
    } catch (error) {
      if (visible(id, view)) status.textContent = error.message;
    }
  }

  function selection() {
    if (!form.reportValidity()) return null;
    return {start: startInput.valueAsNumber, end: endInput.valueAsNumber};
  }

  async function changeRange(generate) {
    const id = jobId;
    const view = currentView;
    const range = selection();
    if (!id || !range) return;
    status.textContent = "";
    disableControls(true);
    try {
      if (generate) {
        const request = auth.payload(range);
        request.headers["Idempotency-Key"] = "manual-" + id + "-"
          + Math.round(range.start * 1000) + "-" + Math.round(range.end * 1000);
        const result = await auth.json(url(id, "/editor/exports"), request);
        if (!visible(id, view)) return;
        status.textContent = result.status === "completed" ? "El clip ya está disponible."
          : result.status === "failed" ? "Este fragmento no pudo generarse." : "Clip manual en cola.";
        await refreshExports(id, view);
      } else {
        const valid = await auth.json(url(id, "/editor/range"), auth.payload(range));
        if (!visible(id, view)) return;
        previewEnd = valid.end;
        source.currentTime = valid.start;
        await source.play();
      }
    } catch (error) {
      if (visible(id, view)) status.textContent = error.message;
    } finally {
      if (visible(id, view)) disableControls(false);
    }
  }

  details.addEventListener("toggle", () => {
    if (details.open) openEditor();
    else reset();
  });
  markStart.addEventListener("click", () => { startInput.value = source.currentTime.toFixed(3); });
  markEnd.addEventListener("click", () => { endInput.value = source.currentTime.toFixed(3); });
  preview.addEventListener("click", () => changeRange(false));
  form.addEventListener("submit", event => {
    event.preventDefault();
    changeRange(true);
  });
  source.addEventListener("timeupdate", () => {
    if (previewEnd !== null && source.currentTime >= previewEnd) {
      source.pause();
      previewEnd = null;
    }
  });

  window.ClipForgeMvp = {selectJob};
})();
