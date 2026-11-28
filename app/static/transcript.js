"use strict";

(() => {
  const el = id => document.getElementById("transcript-" + id);
  const panel = el("editor");
  if (!panel) return;

  const auth = window.ClipForgeAuth;
  const {sourceTime} = window.ClipForgeCaptionFields;
  const details = el("details");
  const text = el("text");
  const source = el("source");
  const pending = new Set(["queued", "running"]);
  let view = null;
  let frame = null;

  function visible(state) {
    return Boolean(state && state === view && details.open);
  }

  function request(state, suffix, options = {}) {
    return auth.json("/jobs/" + state.id + "/transcript-selection" + suffix,
      {...options, signal: state.controller.signal});
  }

  function status(state, message) {
    if (visible(state)) el("status").textContent = message;
  }

  function selectJob(job) {
    const eligible = job?.pilot === true && job.status === "completed" && /^[a-f0-9]{32}$/.test(job.id)
      && Number.isFinite(job.media?.duration_seconds) && job.media.duration_seconds >= 1;
    const id = eligible ? job.id : null;
    if ((view?.id ?? null) === id) return;
    if (view) {
      clearTimeout(view.timer);
      view.controller.abort();
    }
    source.pause();
    source.removeAttribute("src");
    source.load();
    details.open = false;
    for (const part of ["content", "prepare", "version-choice"]) el(part).hidden = true;
    el("status").replaceChildren();
    text.replaceChildren();
    delete text.dataset.version;
    view = id ? {id, controller: new AbortController(), units: [], cursor: null, first: null, last: null} : null;
    panel.hidden = !view;
  }

  function selection(state) {
    const {first, last} = state;
    if (first === null || last === null) return null;
    const start = state.units[first].start;
    const end = state.units[last].end;
    const duration = (Math.round(end * 1000) - Math.round(start * 1000)) / 1000;
    return {start, end, duration, valid: state.timeline.min_seconds <= duration && duration <= state.timeline.max_seconds};
  }

  function updateControls(state) {
    const {first, last} = state;
    const range = selection(state);
    const time = unit => unit === null ? "—" : sourceTime(unit);
    el("selection-start").textContent = time(first === null ? null : state.units[first].start);
    el("selection-end").textContent = time(last === null ? null : state.units[last].end);
    el("selection-duration").textContent = range ? range.duration.toLocaleString(undefined, {maximumFractionDigits: 3}) + " s" : "—";
    el("selection-note").textContent = !range || range.valid ? "" : range.duration > state.timeline.max_seconds
      ? "La selección supera el máximo de " + state.timeline.max_seconds + " s. Ajustá el inicio o el final."
      : "La selección dura menos del mínimo de " + state.timeline.min_seconds + " s. Elegí un intervalo más largo.";
    el("mark-start").disabled = state.cursor === null || state.creating;
    el("mark-end").disabled = state.cursor === null || state.creating;
    el("clear").disabled = (first === null && last === null) || state.creating;
    el("play-selection").disabled = !range || state.creating;
    el("create").disabled = !range?.valid || state.creating;
    el("version").disabled = Boolean(state.creating);
  }

  function markSelection(state, first, last) {
    state.first = first;
    state.last = last;
    const end = last ?? first;
    const start = first ?? last;
    for (const [index, unit] of state.units.entries()) {
      unit.node.classList.toggle("transcript-selected", start !== null && start <= index && index <= end);
    }
    updateControls(state);
  }

  function setCursor(state, index, reveal = false) {
    if (!visible(state) || !state.units[index]) return;
    state.units[state.cursor]?.node.classList.remove("transcript-cursor");
    state.cursor = index;
    const unit = state.units[index];
    unit.node.classList.add("transcript-cursor");
    el("cursor").textContent = "Punto de selección · " + sourceTime(unit.start) + " · " + unit.text.trim();
    if (reveal) {
      const top = unit.node.getBoundingClientRect().top - text.getBoundingClientRect().top;
      if (top < 0 || top + unit.node.offsetHeight > text.clientHeight) text.scrollTop += top - text.clientHeight / 3;
    }
    updateControls(state);
  }

  function useSavedSelection(state) {
    const origin = state.savedSelection;
    if (!origin || state.selectionTouched || origin.transcript_version !== state.version?.id) return;
    const first = state.units.findIndex(unit => unit.id === origin.first);
    const last = state.units.findIndex(unit => unit.id === origin.last);
    if (first < 0 || last < first) return;
    markSelection(state, first, last);
    setCursor(state, first, true);
  }

  function rememberSelection(id, origin) {
    if (id !== view?.id) return;
    view.savedSelection = origin;
    if (visible(view) && view.timeline && !view.selectionTouched) showTimeline(view, view.timeline);
  }

  function renderVersion(state, version) {
    source.pause();
    state.previewEnd = null;
    state.version = version;
    state.cursor = null;
    state.playing = null;
    state.units = [];
    text.dataset.version = version.id;
    const rows = document.createDocumentFragment();
    for (const segment of version.segments) {
      const row = document.createElement("div");
      row.className = "transcript-segment";
      const play = document.createElement("button");
      play.type = "button";
      play.className = "secondary";
      play.dataset.transcriptSegment = segment.id;
      play.textContent = "Reproducir desde " + sourceTime(segment.start);
      play.addEventListener("click", () => void playFrom(state, segment.start));
      const line = document.createElement("p");
      const words = segment.words?.length ? segment.words : null;
      let previous = "";
      for (const unit of words || [segment]) {
        if (previous && !/\s$/.test(previous) && !/^\s/.test(unit.text)) line.append(" ");
        const span = document.createElement("span");
        span.dataset.transcriptUnit = unit.id;
        span.dataset.start = unit.start;
        span.dataset.end = unit.end;
        span.dataset.granularity = words ? "word" : "segment";
        span.textContent = unit.text;
        const index = state.units.length;
        span.addEventListener("click", () => setCursor(state, index));
        state.units.push({...unit, node: span});
        line.append(span);
        previous = unit.text;
      }
      row.append(play, line);
      rows.append(row);
    }
    text.replaceChildren(rows);
    text.scrollTop = 0;
    el("cursor").replaceChildren();
    el("granularity").textContent = !version.segments.some(segment => segment.words?.length)
      ? "En esta versión se seleccionan segmentos completos."
      : "Las marcas por palabra son estimaciones. Revisá el audio en los bordes."
        + (version.segments.some(segment => !segment.words?.length)
          ? " Los pasajes sin marcas se seleccionan por segmento." : "");
    if (version.alternate) {
      el("granularity").textContent += " Esta versión tiene una transcripción nueva y conserva la anterior.";
    }
    markSelection(state, null, null);
    useSavedSelection(state);
  }

  function showTimeline(state, timeline) {
    clearTimeout(state.timer);
    state.timeline = timeline;
    const available = timeline.versions.length > 0;
    el("content").hidden = !available;
    const preparing = pending.has(timeline.alignment_status);
    const retry = timeline.alignment_status === "failed" && timeline.retryable;
    el("prepare").hidden = !(timeline.alignment_status === "not_prepared" || retry);
    el("prepare").textContent = retry ? "Reintentar preparación por palabra" : "Preparar marcas por palabra";
    el("prepare").disabled = state.preparing;
    const messages = {
      not_prepared: "Podés seleccionar por segmentos o preparar las marcas por palabra.",
      queued: "La preparación de marcas por palabra está en cola. Podés volver a este proyecto más tarde.",
      running: "Se están preparando las marcas por palabra.",
      failed: "No se pudo completar la preparación de marcas por palabra.",
    };
    const preferred = (state.selectionTouched ? null : state.savedSelection?.transcript_version) ?? state.version?.id;
    const selected = timeline.versions.find(version => version.id === preferred)
      ?? timeline.versions.find(version => version.id === timeline.default_version)
      ?? timeline.versions[0];
    if (timeline.alignment_status === "ready" && selected?.method === "segments" && timeline.versions.length > 1) {
      messages.ready = "Las marcas por palabra están disponibles en otra versión. Podés elegirla en el selector.";
    }
    status(state, available ? (messages[timeline.alignment_status] || "")
      : (messages[timeline.alignment_status] || "Este proyecto no tiene una transcripción utilizable."));
    if (available) {
      const menu = el("version");
      menu.replaceChildren(...timeline.versions.map(version => new Option(version.label
        || (version.alternate ? "Nueva transcripción · marcas por palabra"
          : version.method === "segments" ? "Transcripción guardada · segmentos"
            : "Transcripción guardada · marcas por palabra"), version.id)));
      menu.value = selected.id;
      el("version-choice").hidden = timeline.versions.length < 2;
      if (selected.id !== state.version?.id) renderVersion(state, selected);
      else useSavedSelection(state);
    }
    if (preparing) state.timer = setTimeout(() => void loadTimeline(state), 3000);
  }

  async function loadTimeline(state) {
    clearTimeout(state.timer);
    const sequence = state.sequence = (state.sequence || 0) + 1;
    try {
      const timeline = await request(state, "");
      if (visible(state) && sequence === state.sequence) showTimeline(state, timeline);
    } catch (error) {
      if (sequence === state.sequence) status(state, error.message);
    }
  }

  async function prepare() {
    const state = view;
    if (!visible(state) || el("prepare").disabled || el("prepare").hidden) return;
    state.preparing = true;
    el("prepare").disabled = true;
    status(state, "Solicitando la preparación de marcas por palabra.");
    try {
      await request(state, "/prepare", auth.payload({retry: state.timeline.alignment_status === "failed"}));
      if (visible(state)) await loadTimeline(state);
    } catch (error) {
      status(state, error.message);
    } finally {
      state.preparing = false;
      if (visible(state)) el("prepare").disabled = false;
    }
  }

  function selectText() {
    const state = view;
    const chosen = window.getSelection();
    if (!visible(state) || state.creating || !chosen?.rangeCount || chosen.isCollapsed
      || !text.contains(chosen.anchorNode) || !text.contains(chosen.focusNode)) return;
    const range = chosen.getRangeAt(0);
    const boundary = document.createRange();
    let first = null;
    let last = null;
    for (const [index, unit] of state.units.entries()) {
      boundary.selectNodeContents(unit.node);
      boundary.collapse(true);
      if (range.compareBoundaryPoints(Range.END_TO_END, boundary) <= 0) break;
      boundary.selectNodeContents(unit.node);
      boundary.collapse(false);
      if (range.compareBoundaryPoints(Range.START_TO_START, boundary) < 0) {
        first ??= index;
        last = index;
      }
    }
    if (first === null) return;
    state.selectionTouched = true;
    markSelection(state, first, last);
    setCursor(state, last);
    chosen.removeAllRanges();
  }

  function markEdge(edge) {
    const state = view;
    if (!visible(state) || state.creating || state.cursor === null) return;
    state.selectionTouched = true;
    const {cursor, first, last} = state;
    if (edge === "start") markSelection(state, cursor, last !== null && cursor <= last ? last : null);
    else markSelection(state, first !== null && first <= cursor ? first : null, cursor);
  }

  function syncPlayback(time) {
    const state = view;
    if (!visible(state) || !state.version) return;
    if (state.previewEnd != null && time >= state.previewEnd) {
      state.previewEnd = null;
      source.pause();
    }
    let low = 0, high = state.units.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if (state.units[mid].start <= time) low = mid + 1;
      else high = mid;
    }
    const index = low > 0 && time < state.units[low - 1].end ? low - 1 : null;
    if (index === state.playing) return;
    state.units[state.playing]?.node.classList.remove("transcript-playing");
    state.units[index]?.node.classList.add("transcript-playing");
    state.playing = index;
  }

  function followFrames() {
    if (!source.requestVideoFrameCallback || frame !== null || source.paused) return;
    frame = source.requestVideoFrameCallback((_now, metadata) => {
      frame = null;
      syncPlayback(metadata.mediaTime);
      followFrames();
    });
  }

  async function playFrom(state, start, end = null) {
    if (!visible(state)) return;
    source.scrollIntoView({block: "nearest"});
    state.previewEnd = end;
    source.currentTime = start;
    try {
      await source.play();
    } catch (error) {
      status(state, error.message);
    }
  }

  async function createDraft() {
    const state = view;
    if (!visible(state) || el("create").disabled) return;
    const {id: version} = state.version;
    const first = state.units[state.first].id;
    const last = state.units[state.last].id;
    const signature = version + "/" + first + "/" + last;
    if (state.attempt?.signature !== signature) state.attempt = {signature, key: crypto.randomUUID()};
    state.creating = true;
    updateControls(state);
    source.pause();
    try {
      const created = await window.ClipForgeEditorial.createTranscriptDraft(state.id, {version, first, last}, state.attempt.key);
      if (created) {
        state.attempt = null;
        status(state, "Borrador listo. Revisá el inicio y el final en el editor.");
      }
    } catch (error) {
      status(state, error.message);
    } finally {
      state.creating = false;
      if (visible(state)) updateControls(state);
    }
  }

  details.addEventListener("toggle", () => {
    const state = view;
    if (!state) return;
    if (!details.open) {
      clearTimeout(state.timer);
      state.previewEnd = null;
      source.pause();
      return;
    }
    if (!source.getAttribute("src")) source.src = "/jobs/" + state.id + "/source";
    void loadTimeline(state);
  });
  el("prepare").addEventListener("click", prepare);
  el("version").addEventListener("change", event => {
    const version = view?.timeline?.versions.find(item => item.id === event.target.value);
    if (!version) return;
    view.selectionTouched = true;
    renderVersion(view, version);
  });
  text.addEventListener("pointerup", selectText);
  text.addEventListener("keydown", event => {
    const state = view;
    if (!visible(state) || !state.units.length || state.creating || event.target !== text
      || event.shiftKey || event.ctrlKey || event.metaKey || event.altKey) return;
    const direction = {ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1}[event.key];
    if (!direction && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const index = event.key === "Home" ? 0 : event.key === "End" ? state.units.length - 1
      : Math.min(state.units.length - 1, Math.max(0, state.cursor === null ? 0 : state.cursor + direction));
    setCursor(state, index, true);
  });
  el("mark-start").addEventListener("click", () => markEdge("start"));
  el("mark-end").addEventListener("click", () => markEdge("end"));
  el("clear").addEventListener("click", () => {
    if (!visible(view)) return;
    view.selectionTouched = true;
    markSelection(view, null, null);
  });
  el("play-selection").addEventListener("click", () => {
    const range = view && selection(view);
    if (range) void playFrom(view, range.start, range.end);
  });
  el("create").addEventListener("click", createDraft);
  source.addEventListener("timeupdate", () => syncPlayback(source.currentTime));
  source.addEventListener("seeking", () => syncPlayback(source.currentTime));
  source.addEventListener("play", followFrames);
  source.addEventListener("pause", () => {
    if (frame === null) return;
    source.cancelVideoFrameCallback(frame);
    frame = null;
  });

  window.ClipForgeTranscript = {selectJob, rememberSelection};
})();
