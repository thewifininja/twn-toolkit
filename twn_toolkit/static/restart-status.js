(() => {
  const panel = document.querySelector("#restart-status");
  const message = document.querySelector("#restart-message");
  if (!panel || !message) return;

  let attempts = 0;
  const check = async () => {
    attempts += 1;
    try {
      const response = await fetch(`${panel.dataset.healthUrl}?attempt=${attempts}`, {
        cache: "no-store",
        credentials: "same-origin",
      });
      if (response.ok) {
        const data = await response.json();
        if (data.boot_id && data.boot_id !== panel.dataset.previousBootId) {
          message.textContent = "The toolkit is back online. Reloading settings…";
          window.location.replace(panel.dataset.settingsUrl);
          return;
        }
      }
    } catch {
      message.textContent = "The toolkit is restarting…";
    }
    if (attempts >= 60) {
      message.textContent =
        "The restart is taking longer than expected. Check ./twn status or the restart log on the server.";
      return;
    }
    window.setTimeout(check, 1000);
  };

  window.setTimeout(check, 1500);
})();
