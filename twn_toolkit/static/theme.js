(() => {
  const toggle = document.querySelector("#theme-toggle");
  if (!toggle) return;

  const render = (theme) => {
    const dark = theme === "dark";
    document.documentElement.dataset.theme = theme;
    toggle.dataset.theme = theme;
    toggle.setAttribute("aria-pressed", String(dark));
    toggle.querySelector(".theme-toggle-icon").textContent = dark ? "☾" : "☀";
    const actionLabel = dark ? "Switch to light mode" : "Switch to dark mode";
    toggle.setAttribute("aria-label", actionLabel);
    toggle.title = actionLabel;
    window.dispatchEvent(new CustomEvent("themechange", {detail: {theme}}));
  };

  toggle.addEventListener("click", async () => {
    const previous = toggle.dataset.theme;
    const next = previous === "dark" ? "light" : "dark";
    toggle.disabled = true;
    render(next);
    try {
      const response = await fetch(toggle.dataset.updateUrl, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        credentials: "same-origin",
        body: JSON.stringify({theme: next}),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
    } catch (_error) {
      render(previous);
    } finally {
      toggle.disabled = false;
    }
  });
})();
