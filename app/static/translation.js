"use strict";

(() => {
  const el = name => document.getElementById("translation-" + name);
  const dialog = el("dialog");
  if (!dialog) return;

  const auth = window.ClipForgeAuth;
  const {sourceTime} = window.ClipForgeCaptionFields;
  const labels = {es: "Español", en: "Inglés"};
  const kinds = {draft: "Borrador", export: "Exportación", automatic: "Clip automático"};
  const pending = new Set(["queued", "running"]);
  let projectId = null;
  let view = null;

  const language = value => labels[String(value ?? "").toLowerCase().split("-")[0]] || null;
  const languageKey = value => language(value) ? String(value).toLowerCase().split("-")[0] : "";
  const sourceKey = source => source ? [source.kind, source.id, source.revision, source.selection || ""].join(":") : "";
  const sourceRef = ({kind, id, revision, selection}) => ({kind, id, revision, ...(selection ? {selection} : {})});
  const current = state => view === state && dialog.open;

  function button(id, source) {
    if (!source || !Number.isSafeInteger(source.revision)) return null;
    const control = document.createElement("button");
    control.type = "button";
    control.className = "secondary";
    control.dataset.subtitleTranslation = sourceKey(source);
    control.textContent = "Traducir subtítulos";
    control.addEventListener("click", () => void open(id, source));
    return control;
  }

  function status(state, value) {
    if (current(state)) el("status").textContent = value;
  }

  function request(state, suffix = "", body = undefined) {
    return auth.json("/jobs/" + state.id + "/subtitle-translations" + suffix,
      {...(body ? auth.payload(body) : {}), signal: state.controller.signal});
  }

  function finish() {
    if (!view) return;
    clearTimeout(view.timer);
    view.controller.abort();
    view = null;
    el("cues").replaceChildren();
    dialog.close();
  }

  function close() {
    if ([...(view?.working.values() || [])].some(work => work.dirty)
        && !window.confirm("¿Cerrar sin guardar los cambios de la traducción?")) return;
    finish();
  }

  function selectProject(id) {
    if (id === projectId) return;
    finish();
    projectId = id;
  }

  function clearReview(state) {
    state.preview = null;
    el("consent-panel").hidden = true;
    el("consent").checked = false;
    el("payload").replaceChildren();
    el("system-instructions").replaceChildren();
  }

  function selectedRun(state) {
    return state.runs.get(state.runId);
  }

  function parameters(state) {
    const source = state.sources.get(state.source);
    const sourceLanguage = el("source-language").value;
    const targetLanguage = el("target-language").value;
    return source && language(sourceLanguage) && language(targetLanguage) && sourceLanguage !== targetLanguage
      ? {source: sourceRef(source), source_language: sourceLanguage, target_language: targetLanguage} : null;
  }

  function matchingAttempts(state, input) {
    return input ? [...state.runs.values()].filter(run => sourceKey(run.source) === sourceKey(input.source)
      && run.source_language === input.source_language && run.target_language === input.target_language) : [];
  }

  function updateControls(state) {
    const input = parameters(state);
    const attempts = matchingAttempts(state, input);
    const run = selectedRun(state);
    const work = state.working.get(run?.id);
    const busy = state.requesting || state.reviewing;
    const sourceLanguage = el("source-language").value;
    el("language-note").textContent = sourceLanguage && sourceLanguage === el("target-language").value
      ? "Elegí un idioma de destino distinto del idioma fuente." : "";
    el("source").disabled = busy || state.saving;
    el("runs").disabled = busy || state.saving;
    el("refresh").disabled = busy || state.saving;
    el("preview").disabled = !state.available.has(state.source) || !state.provider?.configured || !input
      || busy || attempts.some(item => pending.has(item.status));
    el("preview").textContent = attempts.some(item => !pending.has(item.status))
      ? "Preparar otra traducción" : "Revisar texto y destino";
    el("run").disabled = busy || !state.preview || !el("consent").checked;
    el("save").disabled = state.saving || !work?.rows.length
      || !work.rows.every(row => row.text.trim() && Array.from(row.text).length <= 500);
    el("open").disabled = state.saving;
    for (const input of el("cues").querySelectorAll("textarea")) input.disabled = Boolean(state.saving);
  }

  function showSources(state) {
    const menu = el("source");
    menu.replaceChildren(new Option("Elegí una revisión", ""), ...[...state.sources].map(([key, source]) => new Option(
      [kinds[source.kind], source.title, "revisión " + source.revision].filter(Boolean).join(" · "), key)));
    menu.value = state.source;
  }

  function showSource(state, resetLanguage) {
    const source = state.sources.get(state.source);
    el("source-detail").textContent = source
      ? "Revisión guardada " + source.revision + " · " + sourceTime(source.start) + "–" + sourceTime(source.end) + " del original."
      : state.sources.size ? "La revisión seleccionada ya no está disponible. Elegí una revisión guardada."
        : "No hay borradores ni exportaciones guardados con subtítulos disponibles.";
    el("audio-language").textContent = source ? "Idioma del audio original · " + (language(source.audio_language) || "Sin identificar") : "";
    const note = el("source-note");
    note.textContent = !source ? "" : state.source === state.preferred && state.dirtySource
      ? "Tenés cambios sin guardar. Se usará la revisión guardada que figura arriba."
      : !state.available.has(state.source) ? "Esta revisión se conserva en sus traducciones guardadas." : "";
    note.hidden = !note.textContent;
    if (resetLanguage) {
      const detected = languageKey(source?.subtitle_language);
      el("source-language").value = detected;
      el("target-language").value = detected === "es" ? "en" : detected === "en" ? "es" : "";
    }
  }

  function visibleRuns(state) {
    return [...state.runs.values()].filter(run => sourceKey(run.source) === state.source);
  }

  function orderRuns(state, prefer = state.runId) {
    const items = visibleRuns(state);
    const run = items.find(item => item.id === prefer) || items[0];
    state.runId = run?.id || null;
    el("history").hidden = !items.length;
    el("runs").replaceChildren(...items.map(item => new Option(
      [language(item.target_language), item.saved_draft ? "Variante guardada"
        : item.status === "completed" ? "Disponible" : item.status === "failed" ? "Fallida" : "En curso",
        item.id.slice(0, 8)].join(" · "), item.id)));
    if (run) el("runs").value = run.id;
    showRun(state, run);
  }

  async function refresh(state) {
    const iteration = state.iteration = (state.iteration || 0) + 1;
    try {
      const library = await request(state);
      if (!current(state) || iteration !== state.iteration) return;
      state.provider = library.provider;
      state.available = new Set(library.sources.map(sourceKey));
      state.sources = new Map(library.runs.map(run => [sourceKey(run.source), run.source]));
      for (const source of library.sources) state.sources.set(sourceKey(source), source);
      state.runs = new Map(library.runs.map(run => {
        const saved = state.runs.get(run.id)?.saved_draft;
        return [run.id, saved && !run.saved_draft ? {...run, saved_draft: saved} : run];
      }));
      const previous = state.source;
      state.source = state.sources.has(previous) ? previous : state.sources.has(state.preferred) ? state.preferred
        : state.preferred ? "" : sourceKey(library.sources[0]) || state.sources.keys().next().value || "";
      showSources(state);
      showSource(state, previous !== state.source);
      orderRuns(state);
      el("workspace").hidden = false;
      status(state, !state.provider?.configured ? state.provider?.reason || "La traducción automática no está disponible." : "");
    } catch (error) {
      if (iteration === state.iteration) status(state, error.message);
    }
  }

  async function open(id, source, dirtySource = false) {
    if (id !== projectId || dialog.open) return;
    const state = {id, preferred: sourceKey(source), dirtySource, working: new Map(),
      sources: new Map(), available: new Set(), runs: new Map(), controller: new AbortController()};
    view = state;
    clearReview(state);
    el("workspace").hidden = true;
    el("status").textContent = "Cargando revisiones de subtítulos.";
    dialog.showModal();
    await refresh(state);
  }

  function workingCopy(state, run, manual) {
    const source = run.source_cues;
    const rows = manual ? source.map(cue => ({...cue, text: ""})) : run.cues.map(cue => ({...cue}));
    state.working.set(run.id, {rows, manual, dirty: false});
  }

  function overflowing(cue) {
    const total = Array.from(cue.text).length;
    return total > 72 || total / Math.max(.04, cue.end - cue.start) > 22;
  }

  function showRows(state, run, work) {
    const container = el("cues");
    if (state.renderedWork === work) return;
    state.renderedWork = work;
    container.replaceChildren();
    if (!work) return;
    const originals = new Map(run.source_cues.map(cue => [cue.id, cue]));
    for (const cue of work.rows) {
      const row = document.createElement("div");
      row.className = "editorial-cue translation-cue";
      const time = document.createElement("p");
      time.className = "muted";
      time.textContent = sourceTime(cue.start) + "–" + sourceTime(cue.end) + " del recorte";
      const original = document.createElement("p");
      original.textContent = originals.get(cue.id)?.text ?? "";
      const label = document.createElement("label");
      label.textContent = "Texto traducido";
      const input = document.createElement("textarea");
      input.className = "caption-text";
      input.rows = 2;
      input.maxLength = 500;
      input.dataset.translationCue = cue.id;
      input.value = cue.text;
      const warning = document.createElement("p");
      warning.className = "translation-warning";
      const updateWarning = (overflow = overflowing(cue)) => {
        const long = Array.from(cue.text).length > 500;
        warning.textContent = long ? "Reducí el texto a 500 caracteres para guardar la variante."
          : "Este subtítulo puede ser difícil de leer en su intervalo. Revisá su extensión.";
        warning.hidden = !(long || overflow);
      };
      updateWarning(cue.overflow || overflowing(cue));
      input.addEventListener("input", () => {
        cue.text = input.value;
        work.dirty = true;
        updateWarning();
        updateControls(state);
      });
      label.append(input);
      row.append(time, original, label, warning);
      container.append(row);
    }
  }

  function showRun(state, run) {
    clearTimeout(state.timer);
    el("result").hidden = !run;
    if (run?.status === "completed" && !run.saved_draft && !state.working.has(run.id)) workingCopy(state, run, false);
    const work = run && !run.saved_draft ? state.working.get(run.id) : undefined;
    showRows(state, run, work);
    el("manual").hidden = !run || Boolean(work || run.saved_draft) || run.status === "completed";
    el("use-result").hidden = !(run?.status === "completed" && work?.manual);
    el("save").hidden = !work;
    el("open").hidden = !run?.saved_draft;
    const showUnapplied = Boolean(run?.saved_draft && run.status === "completed" && run.cues.length);
    el("unapplied").hidden = !showUnapplied;
    el("unapplied-cues").replaceChildren(...(showUnapplied ? run.cues.map(cue => {
      const line = document.createElement("li");
      line.textContent = cue.text;
      return line;
    }) : []));
    if (run) {
      const summaries = {
        queued: "Traducción en cola.",
        running: "El proveedor está traduciendo los subtítulos.",
        completed: work?.manual ? "La sugerencia está disponible. Tus cambios manuales siguen abiertos."
          : "Traducción disponible para revisar.",
        failed: run.error || "La traducción automática no se completó. Podés seguir con la edición manual.",
      };
      el("run-summary").textContent = [language(run.source_language) + " → " + language(run.target_language),
        run.saved_draft ? "Variante guardada · revisión " + run.saved_draft.revision + "." : "",
        summaries[run.status]].filter(Boolean).join(" ");
      if (pending.has(run.status)) state.timer = setTimeout(() => void poll(state, run.id), 3000);
    }
    updateControls(state);
  }

  async function poll(state, id) {
    try {
      const run = await request(state, "/" + id);
      if (!current(state) || state.runId !== id) return;
      const known = state.runs.get(id);
      state.runs.set(id, known?.saved_draft && !run.saved_draft ? {...run, saved_draft: known.saved_draft} : run);
      orderRuns(state, id);
    } catch (error) {
      if (state.runId === id) status(state, error.message);
    }
  }

  async function prepareReview() {
    const state = view;
    if (!state || el("preview").disabled) return;
    const input = parameters(state);
    const signature = JSON.stringify(input);
    const newAttempt = matchingAttempts(state, input).some(run => !pending.has(run.status));
    clearReview(state);
    state.reviewing = true;
    updateControls(state);
    status(state, "Preparando el envío para revisión.");
    try {
      const review = await request(state, "/preview", input);
      if (!current(state) || signature !== JSON.stringify(parameters(state))) return;
      const requestId = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
      state.preview = {input, requestId, fingerprint: review.preview_fingerprint, newAttempt};
      el("destination").textContent = [review.provider, review.model, review.endpoint,
        language(input.source_language) + " → " + language(input.target_language)].filter(Boolean).join(" · ");
      el("payload").textContent = typeof review.text_to_send === "string"
        ? review.text_to_send : JSON.stringify(review.text_to_send, null, 2);
      el("system-instructions").textContent = review.system_instructions || "";
      el("consent-panel").hidden = false;
      status(state, "Revisá el texto y el destino antes de autorizar la traducción.");
    } catch (error) {
      status(state, error.message);
    } finally {
      state.reviewing = false;
      if (current(state)) updateControls(state);
    }
  }

  async function generate() {
    const state = view;
    if (!state || el("run").disabled) return;
    const preview = state.preview;
    state.requesting = true;
    updateControls(state);
    status(state, "Solicitando la traducción.");
    try {
      const item = await request(state, "", {...preview.input, request_id: preview.requestId,
        preview_fingerprint: preview.fingerprint, consent: true, new_attempt: preview.newAttempt});
      if (!current(state)) return;
      clearReview(state);
      state.runs = new Map([[item.id, item], ...[...state.runs].filter(([id]) => id !== item.id)]);
      orderRuns(state, item.id);
      status(state, "");
    } catch (error) {
      if (current(state) && error.status === 409) clearReview(state);
      status(state, error.message);
    } finally {
      state.requesting = false;
      if (current(state)) updateControls(state);
    }
  }

  async function saveVariant() {
    const state = view;
    const run = state && selectedRun(state);
    if (!run || run.saved_draft || el("save").disabled) return;
    const work = state.working.get(run.id);
    const cues = work.rows.map(({id, text}) => ({id, text}));
    state.saving = true;
    updateControls(state);
    try {
      const draft = await request(state, "/" + run.id + "/draft", {cues});
      if (!current(state)) return;
      state.working.delete(run.id);
      const latest = state.runs.get(run.id);
      state.runs.set(run.id, {...latest, saved_draft: {id: draft.id, revision: draft.revision}});
      orderRuns(state, run.id);
      status(state, "Variante guardada. Abrila para editar el estilo o exportar.");
    } catch (error) {
      status(state, error.message);
    } finally {
      state.saving = false;
      if (current(state)) updateControls(state);
    }
  }

  async function openVariant() {
    const state = view;
    const selection = state && selectedRun(state)?.saved_draft;
    if (!selection) return;
    const {id} = state;
    finish();
    try {
      await window.ClipForgeEditorial?.openTranslationDraft(id, selection.id);
    } catch {
      // The editor displays the error and keeps the saved variant available.
    }
  }

  el("close").addEventListener("click", close);
  dialog.addEventListener("cancel", event => { event.preventDefault(); close(); });
  el("refresh").addEventListener("click", () => { if (view) void refresh(view); });
  el("source").addEventListener("change", event => {
    if (!view) return;
    clearReview(view);
    view.source = event.target.value;
    showSource(view, true);
    orderRuns(view, null);
  });
  for (const name of ["source-language", "target-language", "consent"]) {
    el(name).addEventListener("change", () => {
      if (!view) return;
      if (name !== "consent") clearReview(view);
      updateControls(view);
    });
  }
  el("preview").addEventListener("click", prepareReview);
  el("run").addEventListener("click", generate);
  el("runs").addEventListener("change", event => { if (view) orderRuns(view, event.target.value); });
  el("manual").addEventListener("click", () => {
    const run = view && selectedRun(view);
    if (!run) return;
    workingCopy(view, run, true);
    showRun(view, run);
  });
  el("use-result").addEventListener("click", () => {
    const run = view && selectedRun(view);
    if (run?.status !== "completed") return;
    if (view.working.get(run.id)?.dirty && !window.confirm("¿Reemplazar tus cambios sin guardar con la sugerencia?")) return;
    workingCopy(view, run, false);
    showRun(view, run);
  });
  el("save").addEventListener("click", saveVariant);
  el("open").addEventListener("click", () => void openVariant());

  window.ClipForgeTranslation = {button, open, selectProject, language};
})();
