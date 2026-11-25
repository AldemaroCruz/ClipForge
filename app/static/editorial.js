"use strict";

(() => {
  const el = id => document.getElementById("editorial-" + id);
  const panel = document.getElementById("editorial");
  if (!panel) return;

  const details = el("details");
  const auth = window.ClipForgeAuth;
  const source = el("source");
  const idPattern = /^[a-f0-9]{32}$/;
  const candidatePattern = /^[1-9][0-9]*$/;
  const active = status => ["queued", "running", "validating", "rendering"].includes(status);
  let view = null;
  let previewEnd = null;

  function node(tag, value, className) {
    const result = document.createElement(tag);
    if (value !== undefined) result.textContent = value;
    if (className) result.className = className;
    return result;
  }

  function button(value, action) {
    const result = node("button", value, "secondary");
    result.type = "button";
    result.addEventListener("click", action);
    return result;
  }

  function request(state, suffix, options = {}) {
    return auth.json("/jobs/" + state.id + suffix, {...options, signal: state.controller.signal});
  }

  function visible(state) {
    return view === state && details.open;
  }

  function status(state, text, id = "status") {
    if (visible(state)) el(id).textContent = text;
  }

  function clearTimers(state) {
    clearTimeout(state.runTimer);
    clearTimeout(state.exportTimer);
  }

  function stopPreview() {
    previewEnd = null;
    source.pause();
  }

  function selectJob(job) {
    const eligible = job?.pilot === true && job.status === "completed" && idPattern.test(job.id)
      && Number.isFinite(job.media?.duration_seconds) && job.media.duration_seconds >= 1;
    const id = eligible ? job.id : null;
    if ((view?.id ?? null) === id) return;
    if (view) {
      clearTimers(view);
      view.controller.abort();
    }
    stopPreview();
    source.removeAttribute("src");
    source.load();
    details.open = false;
    el("selection").reset();
    el("draft-form").reset();
    for (const name of ["config", "status", "draft-status", "summary", "candidates", "exports", "drafts", "runs", "cues"]) {
      el(name).replaceChildren();
    }
    for (const name of ["history", "results", "draft-label", "drafts", "draft-form", "output"]) el(name).hidden = true;
    el("draft-empty").hidden = false;
    el("draft-fields").disabled = false;
    view = id ? {id, duration: job.media.duration_seconds, options: job.options,
      controller: new AbortController()} : null;
    resetConsent();
    panel.hidden = !view;
  }

  function resetConsent() {
    if (view) view.preview = null;
    el("consent-panel").hidden = true;
    el("consent").checked = false;
    el("run").disabled = true;
    el("payload").replaceChildren();
    el("instructions").replaceChildren();
  }

  function selectionControls(state) {
    el("preview-button").disabled = state.selectionBusy || state.analysisActive
      || state.config?.configured !== true || state.context?.available !== true;
    el("brief").disabled = Boolean(state.selectionBusy);
    el("run").disabled = !state.preview || !el("consent").checked || state.selectionBusy || state.analysisActive;
  }

  async function loadAvailability(state) {
    try {
      const [config, context] = await Promise.all([
        auth.json("/ai/config", {signal: state.controller.signal}), request(state, "/selections/context"),
      ]);
      if (!visible(state)) return;
      state.config = config;
      state.context = context;
      const available = config.configured === true
        ? [config.provider, config.model].filter(Boolean).join(" · ")
        : (config.reason || "La selección por IA no está disponible en este momento.");
      el("config").textContent = context.available
        ? available
        : [available, context.note || "Este trabajo no tiene una transcripción utilizable."].join(" ");
      selectionControls(state);
    } catch (error) {
      if (visible(state)) el("config").textContent = "No se pudo consultar la selección por IA. " + error.message;
    }
  }

  async function prepareSelection(event) {
    event.preventDefault();
    const state = view;
    const brief = el("brief").value.trim();
    if (!state || el("preview-button").disabled) return;
    if (!brief) {
      status(state, "Escribe un objetivo para preparar la solicitud.");
      return;
    }
    resetConsent();
    state.selectionBusy = true;
    selectionControls(state);
    status(state, "Preparando la revisión.");
    try {
      const result = await request(state, "/selections/preview", auth.payload({
        mode: "llm", brief, max_clips: 5, min_seconds: 20, max_seconds: 60,
        window_start: 0, window_end: null,
      }));
      if (!visible(state)) return;
      const id = Array.from(crypto.getRandomValues(new Uint8Array(16)),
        byte => byte.toString(16).padStart(2, "0")).join("");
      state.preview = {id, token: result.preview_token, spec: result.spec};
      const provider = result.provider;
      const target = [provider?.provider, provider?.model, provider?.destination].filter(Boolean).join(" · ");
      el("destination").textContent = target + " · " + result.eligible_range_count + " rangos válidos";
      el("payload").textContent = JSON.stringify(result.payload_text, null, 2);
      el("instructions").textContent = result.system_instructions || "";
      el("consent-panel").hidden = false;
      status(state, "Ya puedes revisar el contenido que se enviará.");
    } catch (error) {
      status(state, error.message);
    } finally {
      state.selectionBusy = false;
      if (visible(state)) selectionControls(state);
    }
  }

  async function beginSelection() {
    const state = view;
    if (!state || el("run").disabled) return;
    const preview = state.preview;
    state.selectionBusy = true;
    selectionControls(state);
    status(state, "Solicitando propuestas.");
    try {
      const item = await request(state, "/selections", auth.payload({
        ...preview.spec, preview_token: preview.token, request_id: preview.id, consent: true,
      }));
      if (!visible(state)) return;
      resetConsent();
      state.runId = item.id;
      await loadRuns(state);
    } catch (error) {
      status(state, error.message + " Puedes actualizar el historial o volver a pulsar el botón para consultar la misma solicitud.");
    } finally {
      state.selectionBusy = false;
      if (visible(state)) selectionControls(state);
    }
  }

  function runLabel(item) {
    const date = new Date(item.created_at * 1000);
    const label = Number.isFinite(date.getTime()) ? date.toLocaleString() : item.id.slice(0, 8);
    const phase = item.status === "completed" ? "Completado" : item.status === "failed" ? "Fallido" : "En curso";
    return label + " · " + phase + " · " + item.id.slice(0, 8);
  }

  async function loadRuns(state) {
    clearTimeout(state.runTimer);
    const sequence = (state.runSequence || 0) + 1;
    state.runSequence = sequence;
    try {
      const result = await request(state, "/selections?limit=50");
      if (!visible(state) || sequence !== state.runSequence) return;
      const runs = result.analyses.filter(item => idPattern.test(item.id) && item.mode === "llm");
      state.analysisActive = runs.some(item => active(item.status));
      el("history").hidden = !runs.length;
      el("runs").replaceChildren(...runs.map(item => new Option(runLabel(item), item.id)));
      if (state.preview && runs.some(item => item.id === state.preview.id)) resetConsent();
      if (runs.length) {
        const item = runs.find(run => run.id === state.runId) ?? runs[0];
        state.runId = item.id;
        el("runs").value = item.id;
        await loadRun(state, item.id, sequence);
      }
      if (visible(state) && sequence === state.runSequence) selectionControls(state);
    } catch (error) {
      if (sequence === state.runSequence) status(state, error.message + " Usa «Actualizar análisis» para recuperar el estado.");
    }
  }

  async function loadRun(state, runId, sequence) {
    try {
      const item = await request(state, "/selections/" + runId);
      if (!visible(state) || sequence !== state.runSequence || runId !== state.runId) return;
      el("results").hidden = false;
      const summary = [item.provider, item.model].filter(Boolean).join(" · ");
      el("summary").textContent = [summary, item.summary, item.error, ...(item.warnings || [])].filter(Boolean).join("\n");
      el("candidates").replaceChildren(...(item.candidates || [])
        .filter(candidate => candidatePattern.test(candidate.id))
        .map(candidate => candidateCard(state, item, candidate)));
      if (item.status === "completed") {
        status(state, item.candidates?.length ? "Propuestas guardadas." : "El análisis terminó sin propuestas válidas.");
      } else if (item.status === "failed") {
        status(state, "El análisis no se completó. Puedes preparar y autorizar un nuevo intento.");
      } else {
        status(state, "Análisis en curso. Puedes retomarlo desde este trabajo.");
      }
      if (state.analysisActive || active(item.status)) {
        state.runTimer = setTimeout(() => loadRuns(state), 2500);
      }
    } catch (error) {
      status(state, error.message + " Usa «Actualizar análisis» para recuperar el estado.");
    }
  }

  function candidateCard(state, item, candidate) {
    const card = node("article", undefined, "beta-clip");
    const context = node("details");
    context.append(node("summary", "Contexto"),
      node("p", "Antes · " + (candidate.context_before || "Inicio de la transcripción")),
      node("p", "Después · " + (candidate.context_after || "Fin de la transcripción")));
    const actions = node("div", undefined, "actions");
    actions.append(
      button("Reproducir intervalo", () => playRange(state, candidate.start, candidate.end).catch(error => status(state, error.message))),
      button("Crear / abrir borrador", event => createDraft(state, item.id, candidate.id, event.currentTarget)),
    );
    card.append(node("h3", candidate.title),
      node("p", candidate.start.toFixed(3) + "–" + candidate.end.toFixed(3) + " s del original", "muted"),
      node("p", candidate.reason), node("blockquote", candidate.transcript_excerpt), context, actions);
    return card;
  }

  async function playRange(state, start, end) {
    if (!visible(state)) return;
    source.scrollIntoView({block: "nearest"});
    previewEnd = end;
    source.currentTime = start;
    await source.play();
  }

  async function createDraft(state, runId, candidateId, control) {
    if (!visible(state) || state.draftBusy) return;
    const current = state.draft;
    if (current && !formMatches(current) && !window.confirm("¿Descartar los cambios sin guardar del borrador?")) return;
    control.disabled = true;
    state.draftBusy = true;
    try {
      const item = await request(state, "/selections/" + runId + "/candidates/" + candidateId + "/draft", auth.payload({}));
      if (!visible(state)) return;
      mountDraft(state, item);
      await loadDrafts(state);
      el("draft-form").scrollIntoView({block: "nearest"});
      status(state, "Borrador listo para editar.", "draft-status");
    } catch (error) {
      status(state, error.message);
    } finally {
      state.draftBusy = false;
      control.disabled = false;
    }
  }

  async function createManualDraft(id, range) {
    const state = view;
    if (state?.id !== id || state.draftBusy) return;
    if (state.draft && !formMatches(state.draft)
      && !window.confirm("¿Descartar los cambios sin guardar del borrador?")) return;
    state.draftBusy = true;
    details.open = true;
    try {
      const options = await request(state, "/editor/range", auth.payload(range));
      if (!visible(state)) return;
      const body = auth.payload({
        title: "Fragmento manual", start: options.start, end: options.end,
        options: {...state.options, burn_subtitles: false}, cues: options.cues,
      });
      body.headers["Idempotency-Key"] = "manual-draft-" + id + "-"
        + Math.round(options.start * 1000) + "-" + Math.round(options.end * 1000);
      const item = await request(state, "/drafts", body);
      if (!visible(state)) return;
      mountDraft(state, item);
      await loadDrafts(state);
      el("draft-form").scrollIntoView({block: "nearest"});
      status(state, "Borrador listo para editar.", "draft-status");
    } catch (error) {
      status(state, error.message, "draft-status");
      throw error;
    } finally {
      state.draftBusy = false;
    }
  }

  async function loadDrafts(state, restore = false) {
    try {
      const result = await request(state, "/drafts?limit=100");
      if (!visible(state)) return;
      const drafts = result.drafts.filter(item => idPattern.test(item.id));
      el("draft-empty").hidden = Boolean(drafts.length);
      el("draft-label").hidden = !drafts.length;
      el("drafts").hidden = !drafts.length;
      el("drafts").replaceChildren(new Option("Elegir un borrador", ""), ...drafts.map(item =>
        new Option(item.title + " · revisión " + item.revision + " · " + item.id.slice(0, 8), item.id)));
      if (state.draft) el("drafts").value = state.draft.id;
      if (restore && !state.draft && drafts.length) await openDraft(state, drafts[0].id);
    } catch (error) {
      status(state, error.message, "draft-status");
    }
  }

  async function openDraft(state, id) {
    if (!idPattern.test(id) || state.draftBusy) return;
    if (state.draft && !formMatches(state.draft) && !window.confirm("¿Descartar los cambios sin guardar del borrador?")) {
      el("drafts").value = state.draft.id;
      return;
    }
    state.draftBusy = true;
    try {
      const item = await request(state, "/drafts/" + id);
      if (!visible(state)) return;
      mountDraft(state, item);
      status(state, "", "draft-status");
    } catch (error) {
      if (visible(state)) el("drafts").value = state.draft?.id ?? "";
      status(state, error.message, "draft-status");
    } finally {
      state.draftBusy = false;
    }
  }

  function cueInput(label, name, value) {
    const container = node("label", label);
    const input = node(name === "text" ? "textarea" : "input");
    input.value = value;
    input.dataset.field = name;
    input.required = true;
    if (name === "text") {
      input.maxLength = 500;
      input.rows = 2;
    } else {
      input.type = "number";
      input.step = "0.001";
      input.min = name === "start" ? 0 : 0.001;
      input.max = 60;
    }
    container.append(input);
    return container;
  }

  function cueRow(cue) {
    const row = node("div", undefined, "editorial-cue");
    const times = node("div", undefined, "mvp-range");
    times.append(cueInput("Inicio desde el recorte (s)", "start", cue.start),
      cueInput("Fin desde el recorte (s)", "end", cue.end));
    row.append(times, cueInput("Texto del subtítulo", "text", cue.text),
      button("Quitar subtítulo", () => {
        row.remove();
        updateSample();
      }));
    return row;
  }

  function readCues() {
    return [...el("cues").querySelectorAll(".editorial-cue")].map(row => ({
      start: row.querySelector('[data-field="start"]').valueAsNumber,
      end: row.querySelector('[data-field="end"]').valueAsNumber,
      text: row.querySelector('[data-field="text"]').value,
    }));
  }

  function updateSample() {
    const sample = el("sample");
    const span = sample.firstElementChild;
    sample.hidden = !el("burn").checked;
    span.textContent = el("cues").querySelector('[data-field="text"]')?.value || "Texto de muestra";
    span.style.color = el("color").value;
    span.style.fontSize = Math.min(48, Math.max(10, el("size").valueAsNumber * .36)) + "px";
  }

  function mountDraft(state, item) {
    state.draft = item;
    state.range = {start: item.start, end: item.end};
    el("draft-form").hidden = false;
    el("drafts").value = item.id;
    el("title").value = item.title;
    el("start").max = state.duration;
    el("end").max = state.duration;
    el("start").value = item.start;
    el("end").value = item.end;
    el("size").value = item.options.subtitle_font_size ?? 52;
    el("color").value = item.options.subtitle_color || "#ffffff";
    el("burn").checked = item.options.burn_subtitles === true;
    el("cues").replaceChildren(...item.cues.map(cueRow));
    el("revision").textContent = "Revisión guardada " + item.revision;
    updateSample();
  }

  function rangeFields() {
    return {start: el("start").valueAsNumber, end: el("end").valueAsNumber};
  }

  function draftPayload(item, range) {
    return {
      title: el("title").value.trim(),
      clip_file: item.clip_file ?? null,
      ...range,
      options: {...item.options, burn_subtitles: el("burn").checked,
        subtitle_font_size: el("size").valueAsNumber, subtitle_color: el("color").value.toUpperCase()},
      cues: readCues(),
    };
  }

  function formMatches(item) {
    const value = draftPayload(item, rangeFields());
    return value.title === item.title && value.start === item.start && value.end === item.end
      && value.options.burn_subtitles === (item.options.burn_subtitles === true)
      && value.options.subtitle_font_size === (item.options.subtitle_font_size ?? 52)
      && value.options.subtitle_color === (item.options.subtitle_color ?? "#FFFFFF").toUpperCase()
      && value.cues.length === item.cues.length
      && value.cues.every((cue, index) => {
        const saved = item.cues[index];
        return cue.start === saved.start && cue.end === saved.end && cue.text === saved.text;
      });
  }

  async function applyRange(state) {
    const range = rangeFields();
    const previous = state.range;
    if (range.start === previous.start && range.end === previous.end) return range;
    const result = await request(state, "/editor/range", auth.payload({
      ...range, previous_start: previous.start, previous_end: previous.end, cues: readCues(),
    }));
    if (!visible(state)) return range;
    state.range = {start: result.start, end: result.end};
    el("start").value = result.start;
    el("end").value = result.end;
    el("cues").replaceChildren(...result.cues.map(cueRow));
    updateSample();
    return state.range;
  }

  async function draftAction(action) {
    const state = view;
    if (!state?.draft || state.draftBusy || !el("draft-form").reportValidity()) return;
    state.draftBusy = true;
    el("draft-fields").disabled = true;
    status(state, "", "draft-status");
    try {
      const range = await applyRange(state);
      if (!visible(state)) return;
      if (action === "preview") {
        await playRange(state, range.start, range.end);
        return;
      }
      if (action === "range") {
        status(state, "Recorte aplicado. Guarda el borrador para conservarlo.", "draft-status");
        return;
      }
      if (!formMatches(state.draft)) {
        const options = auth.payload({...draftPayload(state.draft, range), revision: state.draft.revision});
        options.method = "PUT";
        const item = await request(state, "/drafts/" + state.draft.id, options);
        if (!visible(state)) return;
        mountDraft(state, item);
        await loadDrafts(state);
      }
      if (!visible(state)) return;
      if (action === "save") {
        status(state, "Borrador guardado.", "draft-status");
        return;
      }
      const item = state.draft;
      const options = auth.payload({revision: item.revision});
      options.headers["Idempotency-Key"] = "approved-" + item.id + "-" + item.revision;
      const exported = await request(state, "/drafts/" + item.id + "/exports", options);
      if (!visible(state)) return;
      status(state, exported.status === "completed" ? "La exportación ya está disponible."
        : exported.status === "failed" ? (exported.error || "El render falló.") : "Exportación aprobada y en cola.", "draft-status");
      await loadExports(state);
    } catch (error) {
      status(state, error.message, "draft-status");
    } finally {
      state.draftBusy = false;
      if (view === state) el("draft-fields").disabled = false;
    }
  }

  function exportCard(state, item) {
    const title = item.title || "Clip editado";
    const card = node("article", undefined, "beta-clip");
    card.dataset.exportId = item.id;
    card.append(node("h3", title), node("p", "Revisión " + item.draft_revision
      + (item.options?.burn_subtitles ? " · Subtítulos incrustados" : ""), "muted"));
    if (item.status === "completed") {
      const files = "/jobs/" + state.id + "/exports/" + item.id + "/files/";
      const player = node("video");
      player.src = files + "clip.mp4?inline=true";
      player.controls = true;
      player.playsInline = true;
      player.preload = "none";
      player.setAttribute("aria-label", title);
      const links = node("div", undefined, "actions");
      for (const [name, label] of [["clip.mp4", "Descargar MP4 editado"], ["clip.srt", "Descargar SRT"], ["clip.vtt", "Descargar VTT"]]) {
        const link = node("a", label);
        link.href = files + name;
        links.append(link);
      }
      card.append(player, links);
    } else {
      const message = item.status === "failed" ? (item.error || "La exportación falló.")
        : item.status === "queued" ? "Exportación en cola." : "Generando clip.";
      card.append(node("p", message, "status"));
    }
    return card;
  }

  async function loadExports(state) {
    clearTimeout(state.exportTimer);
    try {
      const result = await request(state, "/exports");
      if (!visible(state)) return;
      const exports = result.exports.filter(item => idPattern.test(item.id) && idPattern.test(item.draft_id));
      const key = exports.map(item => item.id + ":" + item.status).join();
      el("output").hidden = !exports.length;
      if (state.exportKey !== key) {
        el("exports").replaceChildren(...exports.map(item => exportCard(state, item)));
        state.exportKey = key;
      }
      if (exports.some(item => active(item.status))) {
        state.exportTimer = setTimeout(() => loadExports(state), 3000);
      }
    } catch (error) {
      status(state, error.message, "draft-status");
    }
  }

  details.addEventListener("toggle", () => {
    const state = view;
    if (!state) return;
    if (!details.open) {
      clearTimers(state);
      stopPreview();
      resetConsent();
      return;
    }
    source.src = "/jobs/" + state.id + "/source";
    selectionControls(state);
    void loadAvailability(state);
    void loadRuns(state);
    void loadDrafts(state, true);
    void loadExports(state);
  });
  el("selection").addEventListener("submit", prepareSelection);
  el("brief").addEventListener("input", resetConsent);
  el("consent").addEventListener("change", () => selectionControls(view));
  el("run").addEventListener("click", beginSelection);
  el("refresh").addEventListener("click", () => {
    if (!view) return;
    void loadAvailability(view);
    void loadRuns(view);
  });
  el("runs").addEventListener("change", event => {
    if (!view || !idPattern.test(event.target.value)) return;
    view.runId = event.target.value;
    void loadRuns(view);
  });
  el("drafts").addEventListener("change", event => {
    if (view) void openDraft(view, event.target.value);
  });
  el("draft-form").addEventListener("submit", event => { event.preventDefault(); void draftAction("save"); });
  el("draft-form").addEventListener("input", updateSample);
  el("apply-range").addEventListener("click", () => draftAction("range"));
  el("range-preview").addEventListener("click", () => draftAction("preview"));
  el("export").addEventListener("click", () => draftAction("export"));
  el("add-cue").addEventListener("click", () => {
    const cues = readCues();
    if (cues.length >= 400) return;
    const start = cues.at(-1)?.end || 0;
    const range = view.range;
    const end = Math.min(Math.round((range.end - range.start) * 1000) / 1000, start + 2);
    if (end - start < .04) {
      status(view, "Ajusta el fin del último subtítulo para añadir otro.", "draft-status");
      return;
    }
    const row = cueRow({start, end, text: ""});
    el("cues").append(row);
    row.querySelector("textarea").focus();
  });
  source.addEventListener("timeupdate", () => {
    if (previewEnd !== null && source.currentTime >= previewEnd) stopPreview();
  });

  window.ClipForgeEditorial = {selectJob, createManualDraft};
})();
