"use strict";

(() => {
  const el = id => document.getElementById("editorial-" + id);
  const panel = document.getElementById("editorial");
  if (!panel) return;

  const details = el("details");
  const auth = window.ClipForgeAuth;
  const logos = window.ClipForgeLogos;
  const source = el("source");
  const observesFrames = typeof source.requestVideoFrameCallback === "function";
  const idPattern = /^[a-f0-9]{32}$/;
  const candidatePattern = /^[1-9][0-9]*$/;
  const active = status => ["queued", "running", "validating", "rendering"].includes(status);
  const framingDefaults = {framing: "contain", crop_x: 0.5, crop_y: 0.5, crop_zoom: 1};
  let view = null;
  let previewEnd = null;
  let frameCallback = null;
  let framingCapture = null;

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

  function sourcePath(state) {
    return "/jobs/" + state.id + "/source";
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

  function updateFrameControls() {
    const available = Boolean(view?.draft && Number.isFinite(view.frameTime) && !source.seeking);
    el("mark-start").disabled = !available;
    el("mark-end").disabled = !available;
  }

  function resetFrameObservation() {
    if (frameCallback !== null) source.cancelVideoFrameCallback(frameCallback);
    frameCallback = null;
    if (view) view.frameTime = null;
    updateFrameControls();
  }

  function observeSourceFrames(state) {
    if (!observesFrames || frameCallback !== null || !visible(state)) return;
    frameCallback = source.requestVideoFrameCallback((_now, frame) => {
      frameCallback = null;
      if (!visible(state)) return;
      state.frameTime = frame.mediaTime;
      updateFrameControls();
      if (!source.seeking && previewEnd !== null && frame.mediaTime >= previewEnd) stopPreview();
      observeSourceFrames(state);
    });
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
    resetFrameObservation();
    resetFramingPreview();
    source.removeAttribute("src");
    source.load();
    details.open = false;
    el("selection").reset();
    el("draft-form").reset();
    draftStyles.reset();
    draftLogos.reset();
    logos.show(el("sample").querySelector(".caption-frame"), null);
    for (const name of ["config", "status", "draft-status", "summary", "search-topic", "search-guidance", "search-limit",
      "candidates", "exports", "drafts", "runs", "cues", "transcript-origin"]) {
      el(name).replaceChildren();
    }
    for (const name of ["history", "older-runs", "results", "search-details", "search-guidance", "search-limit", "empty", "retry",
      "draft-label", "drafts", "draft-form", "output"]) el(name).hidden = true;
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
    const available = state.config?.configured === true && state.context?.available === true;
    el("preview-button").disabled = !available || state.selectionBusy || state.analysisActive;
    el("brief").disabled = Boolean(state.selectionBusy);
    el("guidance").disabled = Boolean(state.selectionBusy);
    el("max-clips").disabled = Boolean(state.selectionBusy);
    el("retry").disabled = el("preview-button").disabled;
    el("run").disabled = !available || !state.preview || !el("consent").checked || state.selectionBusy || state.analysisActive;
  }

  async function loadAvailability(state) {
    state.config = null;
    state.context = null;
    selectionControls(state);
    try {
      const config = await auth.json("/ai/config", {signal: state.controller.signal});
      if (!visible(state)) return;
      const context = config.configured === true ? await request(state, "/selections/context") : null;
      if (!visible(state)) return;
      state.config = config;
      state.context = context;
      const available = config.configured === true
        ? [config.provider, config.model].filter(Boolean).join(" · ")
        : (config.reason || "La selección por IA no está disponible en este momento.");
      el("config").textContent = context && !context.available
        ? [available, context.note || "Este trabajo no tiene una transcripción utilizable."].join(" ")
        : available;
      selectionControls(state);
    } catch (error) {
      if (visible(state)) el("config").textContent = "No se pudo consultar la selección por IA. " + error.message;
    }
  }

  async function prepareSelection(retryOf) {
    const state = view;
    const topic = el("brief").value.trim();
    const instructions = el("guidance").value.trim();
    if (!state || el("preview-button").disabled) return;
    if (!topic) {
      status(state, "Escribí un tema para preparar la búsqueda.");
      return;
    }
    resetConsent();
    state.selectionBusy = true;
    selectionControls(state);
    status(state, "Preparando la revisión.");
    try {
      const result = await request(state, "/selections/preview", auth.payload({
        mode: "llm", topic, instructions, max_clips: Number(el("max-clips").value), min_seconds: 20, max_seconds: 60,
        window_start: 0, window_end: null,
      }));
      if (!visible(state)) return;
      const id = Array.from(crypto.getRandomValues(new Uint8Array(16)),
        byte => byte.toString(16).padStart(2, "0")).join("");
      state.preview = {id, token: result.preview_token, spec: result.spec, retryOf};
      const provider = result.provider;
      el("destination").textContent = [provider?.provider, provider?.model, provider?.destination,
        result.eligible_range_count + " intervalos candidatos",
        result.budget?.provider_calls && result.budget.provider_calls + " solicitudes previstas",
      ].filter(Boolean).join(" · ");
      el("payload").textContent = JSON.stringify(result.payload_text, null, 2);
      el("instructions").textContent = result.system_instructions || "";
      el("consent-panel").hidden = false;
      if (retryOf) el("consent-panel").scrollIntoView({block: "nearest"});
      status(state, "Ya podés revisar el contenido que se enviará.");
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
        ...(preview.retryOf ? {retry_of: preview.retryOf} : {}),
      }));
      if (!visible(state)) return;
      resetConsent();
      state.runId = item.id;
      await loadRuns(state);
    } catch (error) {
      if (error.status === 409) resetConsent();
      const guidance = !error.status || error.status >= 500
        ? " Podés actualizar el historial o volver a pulsar el botón para consultar la misma solicitud." : "";
      status(state, error.message + guidance);
    } finally {
      state.selectionBusy = false;
      if (visible(state)) selectionControls(state);
    }
  }

  function runLabel(item) {
    const date = new Date(item.created_at * 1000);
    const label = Number.isFinite(date.getTime()) ? date.toLocaleString() : item.id.slice(0, 8);
    const phase = item.outcome === "no_matches" ? "Sin coincidencias"
      : item.status === "completed" ? "Completado" : item.status === "failed" ? "Fallido" : "En curso";
    return [item.spec?.topic || item.spec?.brief, label, phase].filter(Boolean).join(" · ");
  }

  async function loadRuns(state) {
    clearTimeout(state.runTimer);
    const sequence = (state.runSequence || 0) + 1;
    state.runSequence = sequence;
    try {
      const pageSize = 50;
      let result = await request(state, "/selections?limit=" + pageSize);
      const analyses = new Map(result.analyses.map(item => [item.id, item]));
      for (let page = 1; result.has_more && page < (state.historyPages || 1); page++) {
        if (!visible(state) || sequence !== state.runSequence) return;
        result = await request(state, "/selections?limit=" + pageSize + "&offset=" + page * pageSize);
        for (const item of result.analyses) analyses.set(item.id, item);
      }
      if (!visible(state) || sequence !== state.runSequence) return;
      const runs = [...analyses.values()].filter(item => idPattern.test(item.id) && item.mode === "llm");
      state.analysisActive = runs.some(item => active(item.status));
      el("history").hidden = !runs.length;
      el("older-runs").hidden = !result.has_more;
      el("older-runs").disabled = false;
      el("runs").replaceChildren(...runs.map(item => new Option(runLabel(item), item.id)));
      if (runs.length) {
        const item = runs.find(run => run.id === state.runId) ?? runs[0];
        state.runId = item.id;
        el("runs").value = item.id;
        await loadRun(state, item.id, sequence);
      }
      if (visible(state) && sequence === state.runSequence) selectionControls(state);
    } catch (error) {
      if (visible(state) && sequence === state.runSequence) {
        el("older-runs").disabled = false;
        status(state, error.message + " Usa «Actualizar análisis» para recuperar el estado.");
      }
    }
  }

  async function loadRun(state, runId, sequence) {
    try {
      const item = await request(state, "/selections/" + runId);
      if (!visible(state) || sequence !== state.runSequence || runId !== state.runId) return;
      state.run = item;
      el("results").hidden = false;
      const topic = item.spec?.topic || item.spec?.brief;
      const guidance = item.spec?.instructions;
      const limit = item.spec?.max_clips;
      el("search-details").hidden = !topic;
      el("search-topic").textContent = topic ? "Tema buscado · " + topic : "";
      el("search-guidance").hidden = !guidance;
      el("search-guidance").textContent = guidance ? "Instrucciones adicionales · " + guidance : "";
      el("search-limit").hidden = !limit;
      el("search-limit").textContent = limit ? "Máximo de propuestas · " + limit : "";
      const summary = [item.provider, item.model].filter(Boolean).join(" · ");
      const noMatches = item.status === "completed" && item.outcome === "no_matches";
      el("empty").hidden = !noMatches;
      el("retry").hidden = item.status !== "failed" || !item.retryable;
      el("summary").textContent = [summary, item.summary, item.error, ...(item.warnings || [])]
        .filter(Boolean).join("\n");
      el("candidates").replaceChildren(...(item.candidates || [])
        .filter(candidate => candidatePattern.test(candidate.id))
        .map(candidate => candidateCard(state, item, candidate)));
      if (noMatches) {
        status(state, "Búsqueda completada.");
      } else if (item.status === "completed") {
        status(state, item.candidates?.length ? "Propuestas guardadas." : "El análisis terminó sin propuestas válidas.");
      } else if (item.status === "failed") {
        status(state, "El análisis no se completó. Revisá el detalle del error.");
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

  function sourceTime(seconds) {
    const millis = Math.round(seconds * 1000);
    const minutes = String(Math.floor(millis / 60_000)).padStart(2, "0");
    const wholeSeconds = String(Math.floor(millis / 1000) % 60).padStart(2, "0");
    const fraction = String(millis % 1000).padStart(3, "0").replace(/0+$/, "");
    return minutes + ":" + wholeSeconds + (fraction ? "." + fraction : "");
  }

  function candidateCard(state, item, candidate) {
    const card = node("article", undefined, "beta-clip");
    const {id, range_id: rangeId, start, end} = candidate;
    if (rangeId) card.dataset.rangeId = rangeId;
    card.dataset.candidateId = id;
    card.dataset.start = start;
    card.dataset.end = end;
    card.append(node("h3", candidate.title),
      node("p", sourceTime(start) + "–" + sourceTime(end) + " del original", "editorial-interval muted"));
    if (candidate.reason) {
      const reason = node("div", undefined, "editorial-reason");
      reason.append(node("strong", "Por qué coincide según la IA"), node("p", candidate.reason));
      card.append(reason);
    }
    const excerpt = candidate.evidence?.text || candidate.transcript_excerpt;
    if (excerpt) {
      const evidence = node("figure", undefined, "editorial-evidence");
      const cue = candidate.evidence;
      const label = cue ? "Transcripción guardada · " + sourceTime(cue.start) + "–" + sourceTime(cue.end)
        : "Transcripción guardada";
      evidence.append(node("figcaption", label, "muted"), node("blockquote", excerpt));
      if (cue?.truncated) evidence.append(node("p", "Extracto parcial.", "muted"));
      card.append(evidence);
    }
    if (candidate.context_before || candidate.context_after) {
      const context = node("details");
      context.append(node("summary", "Contexto"));
      if (candidate.context_before) context.append(node("p", "Antes · " + candidate.context_before));
      if (candidate.context_after) context.append(node("p", "Después · " + candidate.context_after));
      card.append(context);
    }
    const actions = node("div", undefined, "actions");
    actions.append(
      button("Reproducir intervalo", () => playRange(state, start, end).catch(error => status(state, error.message))),
      button("Crear / abrir borrador", event => createDraft(state, item.id, id, event.currentTarget)),
    );
    card.append(actions);
    return card;
  }

  async function playRange(state, start, end) {
    if (!visible(state)) return;
    source.scrollIntoView({block: "nearest"});
    previewEnd = end;
    source.currentTime = start;
    await source.play();
  }

  function setDraftBusy(state, busy) {
    state.draftBusy = busy;
    if (view === state) el("draft-fields").disabled = busy;
  }

  async function createDraft(state, runId, candidateId, control) {
    if (!visible(state) || state.draftBusy) return;
    const current = state.draft;
    if (current && !formMatches(current) && !window.confirm("¿Descartar los cambios sin guardar del borrador?")) return;
    control.disabled = true;
    setDraftBusy(state, true);
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
      setDraftBusy(state, false);
      control.disabled = false;
    }
  }

  async function openNewDraft(id, create) {
    const state = view;
    if (state?.id !== id || state.draftBusy) return false;
    if (state.draft && !formMatches(state.draft)
      && !window.confirm("¿Descartar los cambios sin guardar del borrador?")) return false;
    setDraftBusy(state, true);
    const openedForDraft = !details.open;
    if (openedForDraft) state.draftTogglePending = true;
    details.open = true;
    let listedDrafts = false;
    try {
      const item = await create(state);
      if (!item || !visible(state)) return false;
      mountDraft(state, item);
      listedDrafts = true;
      await loadDrafts(state);
      if (!visible(state)) return;
      el("draft-form").scrollIntoView({block: "nearest"});
      status(state, "Borrador listo para editar.", "draft-status");
      return true;
    } catch (error) {
      status(state, error.message, "draft-status");
      throw error;
    } finally {
      setDraftBusy(state, false);
      if (openedForDraft && visible(state)) void loadPanel(state, !listedDrafts);
    }
  }

  function createManualDraft(id, range) {
    return openNewDraft(id, async state => {
      const options = await request(state, "/editor/range", auth.payload(range));
      if (!visible(state)) return null;
      const body = auth.payload({
        title: "Fragmento manual", start: options.start, end: options.end,
        options: {...state.options, burn_subtitles: false}, cues: options.cues,
      });
      body.headers["Idempotency-Key"] = "manual-draft-" + id + "-"
        + Math.round(options.start * 1000) + "-" + Math.round(options.end * 1000);
      return request(state, "/drafts", body);
    });
  }

  function createTranscriptDraft(id, selection, key) {
    return openNewDraft(id, state => {
      const body = auth.payload(selection);
      body.headers["Idempotency-Key"] = key;
      return request(state, "/transcript-selection/drafts", body);
    });
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
    setDraftBusy(state, true);
    try {
      const item = await request(state, "/drafts/" + id);
      if (!visible(state)) return;
      mountDraft(state, item);
      status(state, "", "draft-status");
    } catch (error) {
      if (visible(state)) el("drafts").value = state.draft?.id ?? "";
      status(state, error.message, "draft-status");
    } finally {
      setDraftBusy(state, false);
    }
  }

  function cueInput(label, name, value, duration) {
    const container = node("label", label);
    const input = node(name === "text" ? "textarea" : "input");
    input.value = value;
    input.dataset.field = name;
    input.required = true;
    if (name === "text") {
      input.className = "caption-text";
      input.maxLength = 500;
      input.rows = 2;
    } else {
      input.type = "number";
      input.step = "0.001";
      input.min = name === "start" ? 0 : 0.001;
      input.max = duration;
    }
    container.append(input);
    return container;
  }

  function cueRow(cue, duration, onChange) {
    const row = node("div", undefined, "editorial-cue");
    const times = node("div", undefined, "mvp-range");
    times.append(cueInput("Inicio desde el recorte (s)", "start", cue.start, duration),
      cueInput("Fin desde el recorte (s)", "end", cue.end, duration));
    row.append(times, cueInput("Texto del subtítulo", "text", cue.text),
      button("Quitar subtítulo", () => {
        const neighbor = row.nextElementSibling ?? row.previousElementSibling;
        row.remove();
        neighbor?.querySelector(".caption-text")?.focus();
        onChange();
      }));
    return row;
  }

  function readCues(container = el("cues")) {
    return [...container.querySelectorAll(".editorial-cue")].map(row => ({
      start: row.querySelector('[data-field="start"]').valueAsNumber,
      end: row.querySelector('[data-field="end"]').valueAsNumber,
      text: row.querySelector('[data-field="text"]').value,
    }));
  }

  function addCue(container, duration, onChange) {
    const cues = readCues(container);
    if (cues.length >= 400) return false;
    const start = cues.at(-1)?.end || 0;
    const end = Math.min(duration, start + 2);
    if (end - start < .04) return false;
    const row = cueRow({start, end, text: ""}, duration, onChange);
    container.append(row);
    row.querySelector("textarea").focus();
    onChange();
    return true;
  }

  function trackCaptionCue(container, onChange) {
    container.addEventListener("focusin", event => {
      const row = event.target.closest(".editorial-cue");
      if (!row) return;
      container.querySelector("[data-preview]")?.removeAttribute("data-preview");
      row.dataset.preview = "";
      onChange();
    });
  }

  function replaceCueRows(container, rows, keepSelection) {
    const selected = [...container.children].findIndex(row => row.hasAttribute("data-preview"));
    if (keepSelection && rows[selected]) rows[selected].dataset.preview = "";
    container.replaceChildren(...rows);
  }

  function mountCaptionStyles(prefix, scope) {
    const panel = document.getElementById(prefix);
    const template = document.getElementById("caption-styles-controls");
    panel.append(template.content.cloneNode(true));
    const fields = Object.fromEntries([...panel.querySelectorAll("[data-style-field]")]
      .map(field => [field.dataset.styleField, field]));
    const actions = Object.fromEntries([...panel.querySelectorAll("[data-style-action]")]
      .map(button => [button.dataset.styleAction, button]));
    for (const [key, field] of Object.entries(fields)) field.id = prefix + "-" + key;
    actions["apply-all"].hidden = !scope.applyAll;

    const path = "/caption-styles";
    let styles = [];
    let version = 0;
    let loaded = false;
    let busy = false;
    let pendingRefresh = false;
    let creatingFromAppearance = false;

    const selected = () => styles.find(item => item.id === fields.select.value);
    const show = text => { fields.status.textContent = text; };

    function updateControls() {
      const item = selected();
      const enabled = loaded && !busy;
      scope.createButton.disabled = busy;
      for (const name of ["select", "name", "font"]) fields[name].disabled = !enabled;
      for (const [name, button] of Object.entries(actions)) {
        button.disabled = !enabled || (name !== "create" && !item);
      }
      actions["apply-all"].hidden = !scope.applyAll || !scope.canApplyAll();
      actions.default.textContent = item?.is_default ? "Quitar predeterminado" : "Usar en trabajos nuevos";
    }

    function selectStyle() {
      const item = selected();
      fields.name.value = item?.name ?? "";
      if (item) fields.font.value = item.font;
      updateControls();
    }

    function focusNewStyle() {
      fields.select.value = "";
      selectStyle();
      fields.name.focus();
    }

    async function refresh(expectedVersion, preferred = null, preserveDraft = false) {
      const data = await auth.json(path);
      if (expectedVersion !== version) return;
      if (!Array.isArray(data.styles) || !Array.isArray(data.fonts) || !data.fonts.length) {
        throw new Error("No se pudieron comprobar los estilos disponibles.");
      }
      const font = fields.font.value;
      styles = data.styles;
      fields.font.replaceChildren(...data.fonts.map(font => new Option(font.label, font.id)));
      fields.select.replaceChildren(new Option("Elegir un estilo", ""), ...styles.map(item =>
        new Option(item.name + (item.is_default ? " · predeterminado" : ""), item.id)));
      const snapshot = scope.snapshot();
      fields.select.value = preferred ?? (styles.find(item =>
        item.id === snapshot?.id && item.revision === snapshot.revision)?.id ?? "");
      loaded = true;
      if (preserveDraft && selected()?.id === preferred) {
        if (data.fonts.some(item => item.id === font)) fields.font.value = font;
        updateControls();
      } else selectStyle();
    }

    function stylePayload(value) {
      const keys = ["subtitle_font_size", "subtitle_color", "subtitle_position", "subtitle_outline",
        "subtitle_outline_color", "subtitle_margin_v", "subtitle_shadow"];
      return Object.fromEntries(keys.map(key => [key, value[key]]));
    }

    function write(url, method, data) {
      return auth.json(url, {...auth.payload(data), method});
    }

    async function changeCatalog(action, item, expectedVersion) {
      const itemPath = path + "/" + item?.id;
      if (action === "remove") {
        if (!window.confirm("¿Eliminar «" + item.name
          + "»? Los clips y las exportaciones anteriores conservarán su estilo.")) return;
        await auth.json(itemPath + "?revision=" + item.revision, {method: "DELETE"});
        await refresh(expectedVersion, "");
        if (expectedVersion === version) show("Estilo eliminado.");
        return;
      }
      if (action === "default") {
        await write(path + "/default", "PUT", item.is_default ? {id: null} : {id: item.id, revision: item.revision});
        await refresh(expectedVersion, item.id);
        if (expectedVersion === version) {
          show(item.is_default ? "Predeterminado quitado." : "Estilo predeterminado para trabajos nuevos.");
        }
        return;
      }
      const name = fields.name.value.trim();
      if (action !== "rename" && !scope.validateLogo()) return;
      const style = action === "rename" ? item.style : scope.style();
      if (!style) return;
      const body = {name, font: action === "rename" ? item.font : fields.font.value, style: stylePayload(style),
        logo: action === "rename" ? item.logo ?? null : scope.logo()};
      const creating = action === "create";
      const result = creating ? await write(path, "POST", body)
        : await write(itemPath, "PUT", {...body, revision: item.revision});
      await refresh(expectedVersion, creating ? result.id : item.id);
      if (expectedVersion === version) show(creating ? "Estilo guardado." : "Estilo actualizado.");
    }

    async function run(action, background = false) {
      if (busy || (!loaded && action !== "load")) return;
      const item = selected();
      if (!item && !["load", "create"].includes(action)) return;
      if (["create", "update", "rename"].includes(action) && !fields.name.value.trim()) {
        show("Escribe un nombre para el estilo.");
        fields.name.focus();
        return;
      }
      const expectedVersion = version;
      let focusName = false;
      busy = true;
      if (!background) show("");
      updateControls();
      try {
        if (action === "load") {
          const creating = creatingFromAppearance;
          await refresh(expectedVersion, creating ? "" : item?.id ?? null, background);
          if (creating && expectedVersion === version && panel.open) {
            creatingFromAppearance = false;
            focusName = true;
          }
        } else if (action === "apply" || action === "apply-all") {
          const applied = await (action === "apply" ? scope.apply(item) : scope.applyAll(item));
          if (applied && expectedVersion === version) show("Estilo aplicado.");
        } else {
          await changeCatalog(action, item, expectedVersion);
        }
      } catch (error) {
        if (expectedVersion === version && (!background || !fields.status.textContent)) show(error.message);
      } finally {
        if (expectedVersion === version) {
          busy = false;
          updateControls();
          if (focusName) focusNewStyle();
          if (pendingRefresh) {
            pendingRefresh = false;
            if (panel.open) void run("load", true);
          }
        }
      }
    }

    panel.addEventListener("toggle", () => {
      if (panel.open) void run("load");
    });
    scope.createButton.addEventListener("click", () => {
      if (panel.open && loaded) {
        focusNewStyle();
        return;
      }
      creatingFromAppearance = true;
      if (panel.open) void run("load");
      else panel.open = true;
    });
    document.addEventListener("clipforge-logo-retired", () => {
      if (!panel.open) return;
      if (busy) pendingRefresh = true;
      else void run("load", true);
    });
    fields.select.addEventListener("change", selectStyle);
    fields.name.addEventListener("keydown", event => {
      if (event.key === "Enter") event.preventDefault();
    });
    for (const [name, button] of Object.entries(actions)) button.addEventListener("click", () => run(name));
    updateControls();
    return {
      reset() {
        version += 1;
        panel.open = false;
        styles = [];
        loaded = false;
        busy = false;
        pendingRefresh = false;
        creatingFromAppearance = false;
        fields.select.replaceChildren();
        fields.font.replaceChildren();
        fields.name.value = "";
        show("");
        updateControls();
      },
    };
  }

  const hexColorPattern = /^#[0-9a-f]{6}$/i;

  function showColorValidation(field) {
    const hex = field("color-hex");
    const error = field("color-error");
    const valid = hexColorPattern.test(hex.value);
    hex.setCustomValidity(valid ? "" : error.textContent);
    if (valid) hex.removeAttribute("aria-invalid");
    else hex.setAttribute("aria-invalid", "true");
    error.hidden = valid;
    return valid;
  }

  function mountColorControls(field, onChange) {
    const picker = field("color");
    const hex = field("color-hex");
    const fromPicker = () => {
      const color = picker.value.toUpperCase();
      const changed = color !== hex.value;
      hex.value = color;
      showColorValidation(field);
      return changed;
    };
    const fromHex = () => {
      if (!showColorValidation(field)) return false;
      const color = hex.value.toLowerCase();
      const changed = color !== picker.value;
      picker.value = color;
      return changed;
    };
    // Field listeners run before the form's input listener redraws. Some
    // native pickers commit a new value with only a change event.
    picker.addEventListener("input", fromPicker);
    picker.addEventListener("change", () => { if (fromPicker()) onChange(); });
    hex.addEventListener("input", fromHex);
    function commitHex() {
      const changed = fromHex();
      if (hex.validity.valid) hex.value = picker.value.toUpperCase();
      if (changed) onChange();
    }
    hex.addEventListener("change", commitHex);
    hex.addEventListener("keydown", event => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      commitHex();
      hex.reportValidity();
    });
  }

  function styleControls(field, options) {
    return {...options, burn_subtitles: field("burn").checked,
      subtitle_font_size: field("size").valueAsNumber, subtitle_color: field("color").value.toUpperCase(),
      subtitle_position: field("position").value, subtitle_outline: field("edge").valueAsNumber};
  }

  function fillStyleControls(field, style) {
    field("burn").checked = style.burn_subtitles === true;
    field("size").value = style.subtitle_font_size ?? 52;
    const color = style.subtitle_color ?? "#ffffff";
    field("color").value = color.toLowerCase();
    field("color-hex").value = field("color").value.toUpperCase();
    showColorValidation(field);
    field("position").value = style.subtitle_position ?? "bottom";
    field("edge").value = style.subtitle_outline ?? 3;
  }

  function editorStyle(field, options) {
    if (!["size", "edge", "color-hex"].every(name => field(name).reportValidity())) return null;
    return styleControls(field, options);
  }

  function showCaptionSample(sample, container, style, logo = null, showUnburned = true) {
    const row = container.querySelector("[data-preview]") ?? container.firstElementChild;
    const frame = sample.querySelector(".caption-frame");
    const span = frame.firstElementChild;
    const showText = Boolean(row && (style.burn_subtitles || showUnburned));
    sample.hidden = !showText && !logo;
    span.hidden = !showText;
    sample.querySelector(".caption-export-note").hidden = !showText || style.burn_subtitles;
    sample.querySelector("h4").textContent = logo ? (showText ? "Vista previa del subtítulo y logo" : "Vista previa del logo")
      : "Vista previa del subtítulo";
    logos.show(frame, logo);
    if (!showText) return;
    const units = value => `calc(${value} / 1080 * 100cqw)`;
    frame.dataset.position = style.subtitle_position;
    span.textContent = row.querySelector(".caption-text").value;
    span.style.color = style.subtitle_color;
    // ASS font size measures the font's ascent plus descent. CSS measures its em square.
    span.style.fontSize = units((style.subtitle_font_size || 52) * 2048 / 2384);
    span.style.setProperty("--caption-margin", units(style.subtitle_margin_v ?? 230));
    span.style.webkitTextStrokeWidth = units((style.subtitle_outline ?? 3) * 2);
    span.style.webkitTextStrokeColor = style.subtitle_outline_color ?? "#201510";
    const shadow = style.subtitle_shadow ?? 1;
    span.style.textShadow = shadow ? `${units(shadow)} ${units(shadow)} rgb(0 0 0 / 50%)` : "none";
  }

  function captionStyle(options) {
    return styleControls(el, options);
  }

  function updateSample() {
    const logo = draftLogos.read();
    showCaptionSample(el("sample"), el("cues"), captionStyle(view?.draft?.options), logo);
    if (!el("framing-result").hidden) logos.show(el("framing-composition"), logo);
  }

  function setCues(cues, start, end, keepSelection) {
    const duration = Math.round((end - start) * 1000) / 1000;
    replaceCueRows(el("cues"), cues.map(cue => cueRow(cue, duration, updateSample)), keepSelection);
  }

  function framingOptions() {
    return {
      framing: el("framing").value,
      crop_x: Number((el("crop-x").valueAsNumber / 100).toFixed(6)),
      crop_y: Number((el("crop-y").valueAsNumber / 100).toFixed(6)),
      crop_zoom: Number(el("crop-zoom").valueAsNumber.toFixed(6)),
    };
  }

  function fillFramingControls(options) {
    el("framing").value = options.framing ?? framingDefaults.framing;
    el("crop-x").value = 100 * (options.crop_x ?? framingDefaults.crop_x);
    el("crop-y").value = 100 * (options.crop_y ?? framingDefaults.crop_y);
    el("crop-zoom").value = options.crop_zoom ?? framingDefaults.crop_zoom;
    updateFramingPreview();
  }

  function cropRectangle(width, height, options) {
    // Match the local preview and the FFmpeg graph's even source pixel boundaries.
    const even = value => Math.floor(value / 2) * 2;
    const cropWidth = Math.max(2, even(Math.min(width, height * 9 / 16) / options.crop_zoom));
    const cropHeight = Math.max(2, even(Math.min(height, width * 16 / 9) / options.crop_zoom));
    return {width: cropWidth, height: cropHeight,
      x: even((width - cropWidth) * options.crop_x), y: even((height - cropHeight) * options.crop_y)};
  }

  function updateFramingPreview() {
    const options = framingOptions();
    el("crop-controls").hidden = options.framing !== "crop";
    el("crop-x-value").value = Math.round(100 * options.crop_x) + "%";
    el("crop-y-value").value = Math.round(100 * options.crop_y) + "%";
    el("crop-zoom-value").value = options.crop_zoom.toFixed(2) + "×";
    const result = el("framing-result");
    if (result.hidden) return;
    logos.show(el("framing-composition"), draftLogos.read());

    const original = el("framing-original");
    const canvas = el("framing-canvas");
    const box = el("framing-box");
    const context = canvas.getContext("2d");
    const {width, height} = original;
    result.dataset.mode = options.framing;
    box.hidden = options.framing !== "crop";
    context.fillStyle = "#000";
    context.fillRect(0, 0, canvas.width, canvas.height);
    if (options.framing === "crop") {
      const rect = cropRectangle(width, height, options);
      for (const [key, value] of Object.entries(rect)) box.dataset[key] = value;
      Object.assign(box.style, {
        left: 100 * rect.x / width + "%", top: 100 * rect.y / height + "%",
        width: 100 * rect.width / width + "%", height: 100 * rect.height / height + "%",
      });
      context.drawImage(original, rect.x, rect.y, rect.width, rect.height, 0, 0, canvas.width, canvas.height);
      return;
    }
    for (const key of ["x", "y", "width", "height"]) delete box.dataset[key];
    if (options.framing === "blur") {
      const cover = Math.max(canvas.width / width, canvas.height / height);
      context.filter = "blur(8px)";
      context.drawImage(original, (canvas.width - width * cover) / 2 - 8,
        (canvas.height - height * cover) / 2 - 8, width * cover + 16, height * cover + 16);
      context.filter = "none";
    }
    const contain = Math.min(canvas.width / width, canvas.height / height);
    const fitWidth = Math.floor(width * contain / 2) * 2;
    const fitHeight = Math.floor(height * contain / 2) * 2;
    context.drawImage(original, (canvas.width - fitWidth) / 2, (canvas.height - fitHeight) / 2, fitWidth, fitHeight);
  }

  function resetFramingPreview() {
    framingCapture?.abort();
    framingCapture = null;
    const result = el("framing-result");
    result.hidden = true;
    logos.show(el("framing-composition"), null);
    delete result.dataset.time;
    delete result.dataset.mode;
    el("framing-original").width = 0;
    el("framing-original").height = 0;
    el("framing-status").textContent = "";
    el("framing-preview").disabled = false;
  }

  function showFramingFrame(video, time) {
    const original = el("framing-original");
    original.width = video.videoWidth;
    original.height = video.videoHeight;
    original.getContext("2d").drawImage(video, 0, 0);
    const result = el("framing-result");
    result.dataset.time = time.toFixed(3);
    el("framing-time").textContent = "Fotograma del original · " + result.dataset.time + " s";
    result.hidden = false;
    updateFramingPreview();
  }

  function waitForFrame(video, url, time, signal) {
    return new Promise((resolve, reject) => {
      let sought = false;
      function loadedFrame() {
        if (sought && !video.seeking && video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
          resolve();
        }
      }
      video.addEventListener("loadedmetadata", () => {
        const end = Number.isFinite(video.duration) ? Math.max(0, video.duration - 0.001) : time;
        video.currentTime = Math.min(time, end);
        sought = true;
        loadedFrame();
      }, {once: true, signal});
      video.addEventListener("loadeddata", loadedFrame, {signal});
      video.addEventListener("seeked", loadedFrame, {signal});
      video.addEventListener("error", () => reject(new Error("No se pudo cargar el fotograma del original.")),
        {once: true, signal});
      signal.addEventListener("abort", () => reject(signal.reason), {once: true});
      video.src = url;
    });
  }

  async function previewFraming() {
    const state = view;
    if (!state?.draft || state.draftBusy || !visible(state) || framingCapture) return;
    const {start, end} = rangeFields();
    if (!el("start").reportValidity()) return;
    const frame = state.frameTime;
    if (Number.isFinite(frame) && frame >= start && frame < end && !source.seeking
        && source.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
      showFramingFrame(source, frame);
      el("framing-status").textContent = "";
      return;
    }

    const capture = new AbortController();
    framingCapture = capture;
    el("framing-preview").disabled = true;
    el("framing-status").textContent = "Cargando un fotograma del original.";
    const video = node("video");
    video.preload = "auto";
    video.muted = true;
    const timer = setTimeout(() => capture.abort(new Error("No se pudo cargar el fotograma a tiempo.")), 20000);
    try {
      await waitForFrame(video, sourcePath(state), start, capture.signal);
      if (framingCapture === capture && visible(state)) {
        showFramingFrame(video, video.currentTime);
        el("framing-status").textContent = "";
      }
    } catch (error) {
      if (framingCapture === capture && visible(state)) el("framing-status").textContent = error.message;
    } finally {
      clearTimeout(timer);
      capture.abort();
      video.removeAttribute("src");
      video.load();
      if (framingCapture === capture) {
        framingCapture = null;
        el("framing-preview").disabled = false;
      }
    }
  }

  function mountDraft(state, item) {
    const keepSelection = state.draft?.id === item.id;
    if (!keepSelection) {
      draftStyles.reset();
      draftLogos.reset();
      resetFramingPreview();
    }
    state.draft = item;
    const origin = item.selection_origin;
    const originNote = el("transcript-origin");
    originNote.hidden = origin?.mode !== "transcript";
    if (!originNote.hidden) {
      originNote.textContent = "Selección original de la transcripción · "
        + sourceTime(origin.start) + "–" + sourceTime(origin.end);
      originNote.dataset.version = origin.transcript_version;
      window.ClipForgeTranscript?.rememberSelection(state.id, origin);
    } else {
      originNote.replaceChildren();
      delete originNote.dataset.version;
    }
    state.range = {start: item.start, end: item.end};
    el("draft-form").hidden = false;
    el("drafts").value = item.id;
    el("title").value = item.title;
    el("start").max = state.duration;
    el("end").max = state.duration;
    el("start").value = item.start;
    el("end").value = item.end;
    fillStyleControls(el, item.options);
    fillFramingControls(item.options);
    draftLogos.fill(item.logo);
    setCues(item.cues, item.start, item.end, keepSelection);
    el("revision").textContent = "Revisión guardada " + item.revision;
    updateSample();
    updateFrameControls();
  }

  function rangeFields() {
    return {start: el("start").valueAsNumber, end: el("end").valueAsNumber};
  }

  function reviewEdge(edge) {
    const state = view;
    if (!state?.draft || !visible(state) || state.draftBusy) return;
    const time = rangeFields()[edge];
    if (!Number.isFinite(time) || time < 0 || time > state.duration + 0.001) {
      el(edge).reportValidity();
      return;
    }
    const start = Math.max(0, time - 1.5);
    const end = Math.min(state.duration, time + 1.5);
    status(state, (edge === "start" ? "Revisando el inicio" : "Revisando el final")
      + " en " + time.toFixed(3) + " s del original.", "draft-status");
    void playRange(state, start, end).catch(error => status(state, error.message, "draft-status"));
  }

  function markEdge(edge) {
    const state = view;
    if (!state?.draft || !visible(state) || state.draftBusy || el("mark-" + edge).disabled) return;
    stopPreview();
    // The range API stores milliseconds. Round down so a cut from this frame
    // includes it, and an exclusive end at this frame leaves it out.
    const time = Math.floor(Math.max(0, state.frameTime) * 1000 + 1e-7) / 1000;
    el(edge).value = time.toFixed(3);
    status(state, (edge === "start" ? "Inicio" : "Fin") + " ajustado a " + time.toFixed(3)
      + " s del original.", "draft-status");
  }

  function draftPayload(item, range) {
    return {
      title: el("title").value.trim(),
      clip_file: item.clip_file ?? null,
      ...range,
      options: {...captionStyle(item.options), ...framingOptions()},
      cues: readCues(),
      logo: draftLogos.read(),
    };
  }

  function formMatches(item) {
    const value = draftPayload(item, rangeFields());
    return el("color-hex").validity.valid
      && value.title === item.title && value.start === item.start && value.end === item.end
      && logos.matches(value.logo, item.logo)
      && value.options.burn_subtitles === (item.options.burn_subtitles === true)
      && value.options.subtitle_font_size === (item.options.subtitle_font_size ?? 52)
      && value.options.subtitle_color === (item.options.subtitle_color ?? "#FFFFFF").toUpperCase()
      && value.options.subtitle_position === (item.options.subtitle_position ?? "bottom")
      && value.options.subtitle_outline === (item.options.subtitle_outline ?? 3)
      && Object.entries(framingDefaults).every(([key, fallback]) => {
        const saved = item.options[key] ?? fallback;
        return value.options[key] === (typeof saved === "number" ? Number(saved.toFixed(6)) : saved);
      })
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
    const origin = state.draft.selection_origin;
    const result = await request(state, "/editor/range", auth.payload({
      ...range, previous_start: previous.start, previous_end: previous.end, cues: readCues(),
      ...(origin?.mode === "transcript" ? {transcript_version: origin.transcript_version} : {}),
    }));
    if (!visible(state)) return range;
    state.range = {start: result.start, end: result.end};
    el("start").value = result.start;
    el("end").value = result.end;
    setCues(result.cues, result.start, result.end);
    updateSample();
    return state.range;
  }

  async function draftAction(action) {
    const state = view;
    if (!state?.draft || state.draftBusy || !draftLogos.reportValidity() || !el("draft-form").reportValidity()) return;
    setDraftBusy(state, true);
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
      setDraftBusy(state, false);
    }
  }

  async function applyDraftStyle(template) {
    const state = view;
    const item = state?.draft;
    if (!item || state.draftBusy || !visible(state)) return false;
    const burn = el("burn").checked;
    setDraftBusy(state, true);
    try {
      const {title, clip_file, start, end, options, cues, revision} = item;
      const body = auth.payload({title, clip_file: clip_file ?? null, start, end, cues, revision, options,
        logo: template.logo ?? null, style_template: {id: template.id, revision: template.revision}});
      body.method = "PUT";
      const result = await request(state, "/drafts/" + item.id, body);
      if (!visible(state)) return false;
      state.draft = result;
      fillStyleControls(el, result.options);
      draftLogos.fill(result.logo);
      el("burn").checked = burn;
      el("revision").textContent = "Revisión guardada " + result.revision;
      updateSample();
      await loadDrafts(state);
      return visible(state);
    } finally {
      setDraftBusy(state, false);
    }
  }

  function exportCard(state, item) {
    const title = item.title || "Clip editado";
    const card = node("article", undefined, "beta-clip");
    card.dataset.exportId = item.id;
    const hasCues = Array.isArray(item.cues) ? item.cues.length > 0 : true;
    card.append(node("h3", title), node("p", "Revisión " + item.draft_revision
      + (item.logo ? " · Con logo" : "")
      + (item.status === "completed" && hasCues && item.options?.burn_subtitles ? " · Subtítulos incrustados" : ""), "muted"));
    if (item.status === "completed") {
      const files = "/jobs/" + state.id + "/exports/" + item.id + "/files/";
      const player = node("video");
      player.src = files + "clip.mp4?inline=true";
      player.controls = true;
      player.playsInline = true;
      player.preload = "none";
      player.setAttribute("aria-label", title);
      const links = node("div", undefined, "actions");
      const available = Array.isArray(item.archive_files) ? item.archive_files : (hasCues ? ["mp4", "srt", "vtt"] : ["mp4"]);
      for (const [extension, label] of [["mp4", item.logo ? "Descargar MP4 con logo" : "Descargar MP4 editado"],
        ["srt", "Descargar SRT"], ["vtt", "Descargar VTT"]]) {
        if (!available.includes(extension)) continue;
        const link = node("a", label);
        link.href = files + "clip." + extension;
        links.append(link);
      }
      const publication = window.ClipForgePublication?.action(state.id, item.archive_selection, title);
      if (publication) links.append(publication);
      card.append(player, links);
      const include = window.ClipForgeZip?.includeExport(state.id, "editorial", item.id, title + " · revisión " + item.draft_revision);
      if (include) card.append(include);
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
      window.ClipForgeZip?.syncExports(state.id, "editorial", exports);
      const key = JSON.stringify(exports.map(item => [item.id, item.status, item.archive_selection, item.archive_files]));
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

  async function loadPanel(state, restoreDrafts) {
    if (restoreDrafts && visible(state)) await loadDrafts(state, true);
    if (visible(state)) await loadExports(state);
    if (visible(state)) await loadAvailability(state);
    if (visible(state)) await loadRuns(state);
  }

  details.addEventListener("toggle", () => {
    const state = view;
    if (!state) return;
    if (!details.open) {
      state.draftTogglePending = false;
      clearTimers(state);
      stopPreview();
      resetFrameObservation();
      resetFramingPreview();
      resetConsent();
      return;
    }
    source.src = sourcePath(state);
    observeSourceFrames(state);
    selectionControls(state);
    if (state.draftTogglePending) {
      state.draftTogglePending = false;
      return;
    }
    void loadPanel(state, true);
  });
  el("selection").addEventListener("submit", event => {
    event.preventDefault();
    void prepareSelection();
  });
  el("brief").addEventListener("input", resetConsent);
  el("guidance").addEventListener("input", resetConsent);
  el("max-clips").addEventListener("change", resetConsent);
  el("consent").addEventListener("change", () => selectionControls(view));
  el("run").addEventListener("click", beginSelection);
  el("retry").addEventListener("click", () => {
    const item = view?.run;
    if (!item?.spec?.topic || !item.retryable || item.id !== view.runId) return;
    el("brief").value = item.spec.topic;
    el("guidance").value = item.spec.instructions || "";
    el("max-clips").value = item.spec.max_clips || 5;
    void prepareSelection(item.id);
  });
  el("refresh").addEventListener("click", async () => {
    const state = view;
    if (!visible(state)) return;
    await loadAvailability(state);
    if (visible(state)) await loadRuns(state);
  });
  el("runs").addEventListener("change", event => {
    if (!view || !idPattern.test(event.target.value)) return;
    view.runId = event.target.value;
    void loadRuns(view);
  });
  el("older-runs").addEventListener("click", event => {
    if (!visible(view)) return;
    event.currentTarget.disabled = true;
    view.historyPages = (view.historyPages || 1) + 1;
    void loadRuns(view);
  });
  el("drafts").addEventListener("change", event => {
    if (view) void openDraft(view, event.target.value);
  });
  const draftLogos = logos.mount("editorial-logos", updateSample);
  const draftStyles = mountCaptionStyles("editorial-styles", {
    createButton: el("save-style"),
    style: () => editorStyle(el, view?.draft?.options),
    snapshot: () => view?.draft?.style_template,
    validateLogo: draftLogos.reportValidity,
    logo: draftLogos.read,
    apply: applyDraftStyle,
  });
  mountColorControls(el, updateSample);
  el("draft-form").addEventListener("submit", event => { event.preventDefault(); void draftAction("save"); });
  el("draft-form").addEventListener("input", event => {
    if (!event.target.closest(".caption-styles")) updateSample();
  });
  trackCaptionCue(el("cues"), updateSample);
  el("apply-range").addEventListener("click", () => draftAction("range"));
  el("range-preview").addEventListener("click", () => draftAction("preview"));
  el("framing-preview").addEventListener("click", previewFraming);
  for (const control of ["framing", "crop-x", "crop-y", "crop-zoom"]) {
    el(control).addEventListener("input", updateFramingPreview);
  }
  for (const edge of ["start", "end"]) {
    el("preview-" + edge).addEventListener("click", () => reviewEdge(edge));
    el("mark-" + edge).addEventListener("click", () => markEdge(edge));
  }
  el("export").addEventListener("click", () => draftAction("export"));
  el("add-cue").addEventListener("click", () => {
    const range = view.range;
    const duration = Math.round((range.end - range.start) * 1000) / 1000;
    if (!addCue(el("cues"), duration, updateSample)) {
      status(view, "Ajusta el fin del último subtítulo para añadir otro.", "draft-status");
    }
  });
  source.addEventListener("seeking", () => {
    if (view) view.frameTime = null;
    updateFrameControls();
  });
  source.addEventListener("seeked", updateFrameControls);
  source.addEventListener("timeupdate", () => {
    if (!source.seeking && previewEnd !== null && source.currentTime >= previewEnd) stopPreview();
  });

  window.ClipForgeEditorial = {selectJob, createManualDraft, createTranscriptDraft};
  window.ClipForgeCaptionFields = {cueInput, cueRow, readCues, addCue, replaceCueRows, trackCaptionCue,
    showCaptionSample, styleControls, fillStyleControls, editorStyle, mountCaptionStyles, mountColorControls, sourceTime};
})();
