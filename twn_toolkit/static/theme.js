(() => {
  const menu = document.querySelector("#appearance-menu");
  if (!menu) return;

  const root = document.documentElement;
  const popover = menu.querySelector(".appearance-popover");
  const status = menu.querySelector("[data-appearance-status]");
  const controls = Array.from(menu.querySelectorAll("[data-appearance-key]"));
  const paletteModes = {
    "tokyo-night": "dark",
    catppuccin: "dark",
    gruvbox: "dark",
    "flexoki-light": "light",
    "toolkit-classic": "light",
  };

  const state = () => ({
    palette: root.dataset.palette,
    layout: root.dataset.layout,
    density: root.dataset.density,
    text_scale: root.dataset.textScale,
  });

  const render = (appearance, {announce = true} = {}) => {
    root.dataset.palette = appearance.palette;
    root.dataset.theme = paletteModes[appearance.palette] || "dark";
    root.dataset.layout = appearance.layout;
    root.dataset.density = appearance.density;
    root.dataset.textScale = appearance.text_scale;
    controls.forEach((control) => {
      control.setAttribute(
        "aria-pressed",
        String(appearance[control.dataset.appearanceKey] === control.dataset.appearanceValue),
      );
    });
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.content = getComputedStyle(root).getPropertyValue("--nav").trim() || "#0e0e14";
    }
    if (announce) {
      window.dispatchEvent(
        new CustomEvent("themechange", {
          detail: {theme: root.dataset.theme, palette: appearance.palette},
        }),
      );
    }
  };

  let saveQueue = Promise.resolve();
  let saveRevision = 0;

  const save = (next, previous) => {
    const revision = ++saveRevision;
    status.textContent = "Saving…";
    saveQueue = saveQueue
      .catch(() => {})
      .then(async () => {
        const response = await fetch(popover.dataset.updateUrl, {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          credentials: "same-origin",
          body: JSON.stringify(next),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        if (revision !== saveRevision) return;
        render(payload.appearance || next, {announce: false});
        status.textContent = "Saved";
      })
      .catch(() => {
        if (revision !== saveRevision) return;
        render(previous);
        status.textContent = "Could not save appearance";
      });
  };

  controls.forEach((control) => {
    control.addEventListener("click", () => {
      const previous = state();
      const next = {
        ...previous,
        [control.dataset.appearanceKey]: control.dataset.appearanceValue,
      };
      render(next);
      save(next, previous);
    });
  });

  document.addEventListener("click", (event) => {
    if (menu.open && !menu.contains(event.target)) menu.open = false;
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      menu.open = false;
      menu.querySelector("summary")?.focus();
    }
  });

  render(state(), {announce: false});
})();
