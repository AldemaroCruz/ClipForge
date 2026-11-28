"use strict";

window.ClipForgeLogos = (() => {
  const path = "/creator-logos";
  const width = 1080;
  const defaults = {position: "top-right", size: 18, opacity: 80, margin: 4};
  const settings = ["position", "size", "opacity", "margin"];
  const idPattern = /^[a-f0-9]{32}$/;
  const subscribers = new Set();
  const previews = new WeakMap();
  const auth = window.ClipForgeAuth;
  let catalog = [];
  let requestVersion = 0;

  function identify(logo) {
    return idPattern.test(logo?.id) && Number.isSafeInteger(logo.revision) && logo.revision > 0
      ? `${logo.id}:${logo.revision}` : "";
  }

  function publish(logos) {
    catalog = logos;
    for (const update of subscribers) update();
  }

  async function refresh() {
    const version = ++requestVersion;
    const data = await auth.json(path);
    if (!Array.isArray(data.logos)) throw new Error("No se pudieron consultar tus logos.");
    if (version === requestVersion) publish(data.logos.filter(identify));
  }

  function library() {
    const panel = document.getElementById("creator-logo-library");
    const field = name => document.getElementById("creator-logo-" + name);
    const form = field("form");
    const select = field("library-select");
    const name = field("name");
    const file = field("file");
    const output = field("status");
    const replace = field("replace");
    const retire = field("retire");
    let busy = false;

    const selected = () => catalog.find(logo => logo.id === select.value);

    function updateActions() {
      const item = selected();
      form.querySelectorAll("input, select, button[type='submit']").forEach(control => { control.disabled = busy; });
      replace.disabled = retire.disabled = busy || !item;
    }

    function updateList(preferred = select.value) {
      select.replaceChildren(new Option("Elegir un logo", ""), ...catalog.map(logo => new Option(logo.name, logo.id)));
      select.value = catalog.some(logo => logo.id === preferred) ? preferred : "";
      updateActions();
    }

    async function run(action) {
      if (busy) return;
      const item = selected();
      if (action !== "load" && action !== "create" && !item) return;
      const asset = file.files[0];
      const label = name.value.trim();
      if (["create", "replace"].includes(action)) {
        if (!form.reportValidity()) return;
        if (!label) {
          output.textContent = "Escribe un nombre para el logo.";
          name.focus();
          return;
        }
        if (!asset || !asset.size || asset.size > 5 * 1024 * 1024) {
          output.textContent = "Elige un PNG de hasta 5 MiB.";
          file.focus();
          return;
        }
      }
      if (action === "retire" && !window.confirm(`¿Retirar «${item.name}»? Dejará de aparecer en la biblioteca y las plantillas dejarán de aplicarlo en el futuro. Los clips, borradores y MP4 que ya lo usan conservarán su logo.`)) return;
      if (action === "replace" && !window.confirm(`¿Reemplazar «${item.name}»? Los trabajos y las plantillas que ya lo usan conservarán su versión anterior.`)) return;

      busy = true;
      updateActions();
      output.textContent = "";
      try {
        if (action === "load") {
          await refresh();
          return;
        }
        const endpoint = item && action !== "create" ? path + "/" + item.id : path;
        const params = new URLSearchParams();
        if (action !== "create") params.set("revision", item.revision);
        if (action !== "retire") params.set("name", label);
        const url = endpoint + "?" + params;
        if (action === "retire") {
          await auth.json(url, {method: "DELETE"});
          requestVersion += 1;
          publish(catalog.filter(logo => logo.id !== item.id));
          document.dispatchEvent(new Event("clipforge-logo-retired"));
          name.value = "";
          output.textContent = "Logo retirado de la biblioteca y de las plantillas. Los usos anteriores se conservan.";
        } else {
          const logo = await auth.json(url, {method: action === "create" ? "POST" : "PUT",
            headers: {"Content-Type": "image/png"}, body: asset});
          if (!identify(logo)) throw new Error("No se pudo comprobar el logo guardado.");
          requestVersion += 1;
          publish([...catalog.filter(other => other.id !== logo.id), logo]);
          updateList(logo.id);
          name.value = logo.name;
          output.textContent = action === "create" ? "Logo guardado." : "La nueva revisión del logo está lista para seleccionar.";
        }
        file.value = "";
      } catch (error) {
        output.textContent = error.message;
      } finally {
        busy = false;
        updateActions();
      }
    }

    panel.addEventListener("toggle", () => { if (panel.open) void run("load"); });
    select.addEventListener("change", () => {
      name.value = selected()?.name ?? "";
      updateActions();
    });
    form.addEventListener("submit", event => { event.preventDefault(); void run("create"); });
    replace.addEventListener("click", () => run("replace"));
    retire.addEventListener("click", () => run("retire"));
    subscribers.add(() => updateList());
    updateList();
    return () => {
      panel.open = true;
      panel.scrollIntoView({block: "nearest"});
      panel.querySelector("summary").focus({preventScroll: true});
    };
  }

  function mount(panelId, onChange) {
    const panel = document.getElementById(panelId);
    panel.append(document.getElementById("creator-logo-controls").content.cloneNode(true));
    const fields = Object.fromEntries([...panel.querySelectorAll("[data-logo-field]")]
      .map(field => [field.dataset.logoField, field]));
    const inputs = ["select", ...settings].map(key => fields[key]);
    let pinned = null;
    let choices = new Map();

    function updateList(preferred = fields.select.value) {
      choices = new Map(catalog.map(logo => [identify(logo), logo]));
      const existing = identify(pinned);
      const options = [new Option("Elegir un logo", ""), ...catalog.map(logo => new Option(logo.name, identify(logo)))];
      if (existing && !choices.has(existing)) {
        choices.set(existing, pinned);
        const name = catalog.find(logo => logo.id === pinned.id)?.name ?? "Logo de este clip";
        options.push(new Option(`${name} · revisión ${pinned.revision} guardada`, existing));
      }
      fields.select.replaceChildren(...options);
      fields.select.value = choices.has(preferred) ? preferred : "";
    }

    function fill(value) {
      pinned = identify(value) ? value : null;
      fields.enabled.checked = Boolean(pinned);
      fields.controls.disabled = !pinned;
      for (const key of settings) fields[key].value = pinned?.[key] ?? defaults[key];
      updateList(identify(pinned));
    }

    function read() {
      const asset = choices.get(fields.select.value);
      if (!fields.enabled.checked || !asset || inputs.some(field => !field.validity.valid)) return null;
      return {id: asset.id, revision: asset.revision, position: fields.position.value,
        size: fields.size.valueAsNumber, opacity: fields.opacity.valueAsNumber, margin: fields.margin.valueAsNumber};
    }

    function reportValidity() {
      if (!fields.enabled.checked) return true;
      const invalid = inputs.find(field => !field.validity.valid);
      if (!invalid) return true;
      panel.open = true;
      return invalid.reportValidity();
    }

    panel.addEventListener("input", () => {
      fields.controls.disabled = !fields.enabled.checked;
      onChange();
    });
    panel.addEventListener("toggle", async () => {
      if (!panel.open) return;
      fields.status.textContent = "";
      try { await refresh(); }
      catch (error) { if (panel.open) fields.status.textContent = error.message; }
    });
    panel.querySelector("[data-logo-action='library']").addEventListener("click", openLibrary);
    subscribers.add(() => updateList());
    fill(null);
    return {fill, read, reportValidity, reset() {
      panel.open = false;
      fields.status.textContent = "";
      fill(null);
    }};
  }

  function matches(first, second) {
    return identify(first) === identify(second)
      && (!identify(first) || settings.every(key => first[key] === second[key]));
  }

  function show(frame, logo) {
    let state = previews.get(frame);
    if (!state) {
      const image = document.createElement("img");
      image.className = "creator-logo-preview";
      image.alt = "";
      image.hidden = true;
      state = {image};
      image.addEventListener("load", () => place(state));
      image.addEventListener("error", () => { image.hidden = true; });
      previews.set(frame, state);
      frame.append(image);
    }
    const {image} = state;
    state.logo = logo;
    if (!identify(logo)) {
      image.hidden = true;
      image.removeAttribute("src");
      return;
    }
    const src = `${path}/${logo.id}/${logo.revision}`;
    if (image.getAttribute("src") !== src) {
      image.hidden = true;
      image.src = src;
    } else if (image.complete) place(state);
  }

  function place({image, logo}) {
    if (!logo || !image.naturalWidth || !image.naturalHeight) return;
    const longest = Math.round(width * logo.size / 100);
    const scale = longest / Math.max(image.naturalWidth, image.naturalHeight);
    const percent = pixels => `${pixels * 100 / width}cqw`;
    const margin = percent(Math.round(width * logo.margin / 100));
    Object.assign(image.style, {width: percent(Math.max(1, Math.round(image.naturalWidth * scale))),
      height: percent(Math.max(1, Math.round(image.naturalHeight * scale))),
      opacity: logo.opacity / 100, top: logo.position.startsWith("top-") ? margin : "auto",
      bottom: logo.position.startsWith("bottom-") ? margin : "auto",
      left: logo.position.endsWith("-left") ? margin : "auto", right: logo.position.endsWith("-right") ? margin : "auto"});
    image.hidden = false;
  }

  const openLibrary = library();
  return {mount, matches, show};
})();
