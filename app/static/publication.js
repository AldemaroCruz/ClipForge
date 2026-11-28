"use strict";

(() => {
  const el = id => document.getElementById("publication-" + id);
  const dialog = el("dialog");
  if (!dialog) return;

  const auth = window.ClipForgeAuth;
  const {sourceTime} = window.ClipForgeCaptionFields;
  const form = el("form");
  const fields = ["title", "description", "hashtags"];
  const pending = new Set(["queued", "running"]);
  let project = null;
  let view = null;

  function current(state) {
    return state === view && dialog.open;
  }

  function path(id, suffix = "", query = {}) {
    const params = new URLSearchParams(query).toString();
    return "/jobs/" + id + "/publication" + suffix + (params ? "?" + params : "");
  }

  function request(state, suffix, {body, method = "POST", query} = {}) {
    const options = body ? {...auth.payload(body), method} : {};
    return auth.json(path(state.id, suffix, query), {...options, signal: state.controller.signal});
  }

  function updateIndex(state, rows) {
    if (project?.id !== state.id) return;
    for (const row of rows) {
      if (Number.isSafeInteger(row.revision) && row.revision > (project.revisions.get(row.selection) || 0)) {
        project.revisions.set(row.selection, row.revision);
      }
    }
    window.ClipForgeZip?.syncPublications(state.id, project.revisions);
  }

  function endView() {
    if (!view) return;
    clearTimeout(view.timer);
    view.controller.abort();
    view = null;
    if (dialog.open) dialog.close();
  }

  function selectProject(id) {
    if (id === (project?.id ?? null)) return;
    endView();
    project?.controller.abort();
    project = id ? {id, controller: new AbortController(), revisions: new Map()} : null;
    if (!project) return;
    const state = project;
    void request(state, "").then(result => {
      if (project === state) updateIndex(state, result.saved);
    }).catch(() => {});
  }

  function action(id, selection, label) {
    if (!selection) return null;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.dataset.publicationSelection = selection;
    button.textContent = "Preparar textos para publicar";
    button.addEventListener("click", () => void open(id, selection, label));
    return button;
  }

  function inputValues() {
    return {language: el("language").value.trim(), title: el("title").value.trim(),
      description: el("description").value.trim(), hashtags: el("hashtags").value.trim().split(/[\s,]+/u).filter(Boolean)};
  }

  function assign(values) {
    el("language").value = values.language || "auto";
    el("title").value = values.title || "";
    el("description").value = values.description || "";
    el("hashtags").value = (values.hashtags || []).join(" ");
  }

  function hasText(values) {
    return Boolean(values.title || values.description || values.hashtags.length);
  }

  function close() {
    if (!view) return;
    if (!form.hidden && JSON.stringify(inputValues()) !== view.baseline
        && !window.confirm("¿Cerrar sin guardar los cambios de estos textos?")) return;
    endView();
  }

  function resetReview(state) {
    state.preview = null;
    el("consent").checked = false;
    el("consent-panel").hidden = true;
    el("payload").replaceChildren();
    el("system-instructions").replaceChildren();
  }

  function updateControls(state) {
    const values = inputValues();
    const busy = state.reviewing || state.sending || pending.has(state.suggestion?.status);
    el("save").disabled = state.saving || !hasText(values);
    el("preview").disabled = busy || !state.record?.provider?.configured || !state.record?.target?.has_content;
    el("preview").textContent = state.suggestion && !pending.has(state.suggestion.status)
      ? "Generar otras opciones" : "Revisar texto y destino";
    el("generate").disabled = busy || !state.preview || !el("consent").checked;
    for (const field of fields) el("copy-" + field).disabled = !values[field].length;
  }

  function showSaved(state, saved) {
    state.saved = saved;
    const download = el("download");
    download.hidden = !saved;
    if (!saved) {
      download.removeAttribute("href");
      el("saved").textContent = "Esta exportación todavía no tiene textos guardados.";
      return;
    }
    download.href = path(state.id, "/file", {selection: state.selection, revision: saved.revision});
    el("saved").textContent = "Revisión " + saved.revision + " guardada para el paquete."
      + (saved.reused_from ? " Reutiliza la revisión " + saved.reused_from.revision + " de otra exportación del mismo contenido." : "");
    updateIndex(state, [{selection: state.selection, revision: saved.revision}]);
  }

  function showReusable(state, options) {
    el("reusable").hidden = !options.length;
    el("reusable-options").replaceChildren(...options.map(item => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "secondary";
      button.dataset.publicationReuse = item.selection;
      button.textContent = "Reutilizar revisión " + item.revision + " · " + (item.title || "Textos guardados");
      button.addEventListener("click", () => void reuse(state, item));
      return button;
    }));
  }

  function showSuggestion(state, item) {
    clearTimeout(state.timer);
    state.suggestion = item;
    const completed = item?.status === "completed";
    el("suggestions").hidden = !completed;
    el("title-options").replaceChildren();
    if (completed) {
      for (const [index, title] of item.titles.entries()) {
        const option = document.createElement("button");
        option.type = "button";
        option.className = "secondary";
        option.dataset.publicationTitleOption = index;
        option.textContent = title;
        option.addEventListener("click", () => useSuggestion(state, item, "title", title));
        el("title-options").append(option);
      }
      el("suggested-description").textContent = item.description;
      el("suggested-hashtags").textContent = item.hashtags.join(" ");
      el("use-description").hidden = !item.description;
      el("use-hashtags").hidden = !item.hashtags.length;
    }
    if (pending.has(item?.status)) {
      el("ai-status").textContent = "Preparando sugerencias. Podés editar o guardar tus propios textos.";
      state.timer = setTimeout(() => void poll(state), 3000);
    } else if (item?.status === "failed") {
      el("ai-status").textContent = item.error || "No se completaron las sugerencias. Podés seguir editando los textos.";
    } else {
      el("ai-status").textContent = completed ? "Sugerencias disponibles." : "";
    }
    updateControls(state);
  }

  function useSuggestion(state, item, field, text) {
    if (!current(state)) return;
    el(field).value = text;
    state.suggestionId = item.id;
    updateControls(state);
    el(field).focus();
  }

  function recordQuery(state) {
    return {query: {selection: state.selection}};
  }

  async function poll(state) {
    try {
      const record = await request(state, "", recordQuery(state));
      if (current(state)) showSuggestion(state, record.suggestion);
    } catch (error) {
      if (!current(state)) return;
      el("ai-status").textContent = error.message;
      if (!error.status || error.status >= 500) state.timer = setTimeout(() => void poll(state), 6000);
    }
  }

  async function open(id, selection, label) {
    if (project?.id !== id || dialog.open) return;
    const state = {id, selection, controller: new AbortController()};
    view = state;
    resetReview(state);
    form.reset();
    form.hidden = true;
    el("target").textContent = label;
    el("saved").replaceChildren();
    el("status").textContent = "Cargando los textos de esta exportación.";
    dialog.showModal();
    try {
      const record = await request(state, "", recordQuery(state));
      if (!current(state)) return;
      state.record = record;
      const target = record.target;
      const origin = {automatic_title: "Título del clip automático",
        export_title: "Título de la exportación"}[target.title_source];
      el("target").textContent = [label, sourceTime(target.start) + "–" + sourceTime(target.end) + " del original",
        origin].filter(Boolean).join(" · ");
      const context = target.context_source === "subtitles"
        ? "Las sugerencias usan los subtítulos de esta exportación."
        : "Las sugerencias usan la transcripción del intervalo exportado.";
      el("availability").textContent = !target.has_content ? "El fragmento admite textos manuales."
        : record.provider?.configured ? context : (record.provider?.reason || "Las sugerencias no están disponibles.");
      assign(record.saved || {language: target.language, title: target.title});
      state.baseline = JSON.stringify(inputValues());
      state.suggestionId = record.saved?.suggestion_id;
      showSaved(state, record.saved);
      showReusable(state, record.reusable || []);
      showSuggestion(state, record.suggestion);
      el("status").replaceChildren();
      form.hidden = false;
    } catch (error) {
      if (current(state)) el("status").textContent = error.message;
    }
  }

  async function save(state, values, send) {
    const snapshot = JSON.stringify(values);
    state.saving = true;
    updateControls(state);
    el("status").textContent = "Guardando textos.";
    try {
      const saved = await send();
      if (!current(state)) return;
      const changed = JSON.stringify(inputValues()) !== snapshot;
      if (!changed) assign(saved);
      state.baseline = JSON.stringify({language: saved.language, title: saved.title,
        description: saved.description, hashtags: saved.hashtags});
      if (!changed) state.suggestionId = saved.suggestion_id;
      showSaved(state, saved);
      el("status").replaceChildren();
    } catch (error) {
      if (current(state)) el("status").textContent = error.message;
    } finally {
      state.saving = false;
      if (current(state)) updateControls(state);
    }
  }

  function reuse(state, item) {
    if (state.saving) return;
    const values = inputValues();
    if (JSON.stringify(values) !== state.baseline
        && !window.confirm("¿Reemplazar los cambios sin guardar con los textos de esta revisión?")) return;
    return save(state, values, () => request(state, "/reuse", {body: {selection: state.selection,
      revision: state.saved?.revision || 0, source_selection: item.selection, source_revision: item.revision}}));
  }

  function reviewParameters(state) {
    return {selection: state.selection, language: el("language").value.trim(),
      instructions: el("instructions").value.trim()};
  }

  async function prepareReview() {
    const state = view;
    if (!state || el("preview").disabled || !el("language").reportValidity()) return;
    const parameters = reviewParameters(state);
    const newAttempt = Boolean(state.suggestion);
    resetReview(state);
    state.reviewing = true;
    updateControls(state);
    el("ai-status").textContent = "Preparando el texto para que lo revises.";
    try {
      const result = await request(state, "/preview", {body: parameters});
      if (!current(state) || JSON.stringify(parameters) !== JSON.stringify(reviewParameters(state))) return;
      const id = Array.from(crypto.getRandomValues(new Uint8Array(16)),
        byte => byte.toString(16).padStart(2, "0")).join("");
      state.preview = {parameters, id, token: result.preview_token, newAttempt};
      const provider = result.provider;
      el("destination").textContent = [provider.provider, provider.model, provider.destination, result.language]
        .filter(Boolean).join(" · ");
      el("payload").textContent = typeof result.payload_text === "string"
        ? result.payload_text : JSON.stringify(result.payload_text, null, 2);
      el("system-instructions").textContent = result.system_instructions || "";
      el("consent-panel").hidden = false;
      el("ai-status").replaceChildren();
    } catch (error) {
      if (current(state)) el("ai-status").textContent = error.message;
    } finally {
      state.reviewing = false;
      if (current(state)) updateControls(state);
    }
  }

  async function generate() {
    const state = view;
    if (!state || el("generate").disabled) return;
    const preview = state.preview;
    state.sending = true;
    updateControls(state);
    el("ai-status").textContent = "Solicitando sugerencias.";
    try {
      const item = await request(state, "/suggestions", {body: {...preview.parameters,
        preview_token: preview.token, request_id: preview.id, consent: true, new_attempt: preview.newAttempt}});
      if (!current(state)) return;
      resetReview(state);
      showSuggestion(state, item);
    } catch (error) {
      if (!current(state)) return;
      if (error.status === 409) resetReview(state);
      el("ai-status").textContent = error.message;
    } finally {
      state.sending = false;
      if (current(state)) updateControls(state);
    }
  }

  async function copy(field) {
    const state = view;
    const value = inputValues()[field];
    try {
      await navigator.clipboard.writeText(Array.isArray(value) ? value.join(" ") : value);
      if (current(state)) el("status").textContent = "Texto copiado.";
    } catch {
      if (!current(state)) return;
      el(field).select();
      el("status").textContent = "Texto seleccionado. Podés copiarlo con el teclado o el menú del navegador.";
    }
  }

  el("close").addEventListener("click", close);
  dialog.addEventListener("cancel", event => { event.preventDefault(); close(); });
  form.addEventListener("submit", event => {
    event.preventDefault();
    const state = view;
    const values = inputValues();
    if (!state || state.saving || !hasText(values)) return;
    void save(state, values, () => request(state, "", {method: "PUT", body: {selection: state.selection,
      revision: state.saved?.revision || 0, ...values, ...(state.suggestionId ? {suggestion_id: state.suggestionId} : {})}}));
  });
  form.addEventListener("input", event => {
    if (!view) return;
    if (event.target === el("language") || event.target === el("instructions")) {
      resetReview(view);
      if (!pending.has(view.suggestion?.status)) el("ai-status").textContent = "";
    }
    updateControls(view);
  });
  el("consent").addEventListener("change", () => { if (view) updateControls(view); });
  el("preview").addEventListener("click", prepareReview);
  el("generate").addEventListener("click", generate);
  el("use-description").addEventListener("click", () => {
    const item = view?.suggestion;
    if (item) useSuggestion(view, item, "description", item.description);
  });
  el("use-hashtags").addEventListener("click", () => {
    const item = view?.suggestion;
    if (item) useSuggestion(view, item, "hashtags", item.hashtags.join(" "));
  });
  for (const field of fields) el("copy-" + field).addEventListener("click", () => void copy(field));

  window.ClipForgePublication = {selectProject, action};
})();
