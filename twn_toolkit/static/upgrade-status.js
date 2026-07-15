(() => {
  const panel = document.querySelector("#upgrade-progress");
  if (!panel) return;
  const message = document.querySelector("#upgrade-message");
  let failures = 0;
  const poll = async () => {
    try {
      const response = await fetch(`${panel.dataset.statusUrl}?t=${Date.now()}`, {
        cache: "no-store",
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error("Toolkit unavailable");
      const status = await response.json();
      failures = 0;
      if (status.id === panel.dataset.operationId && status.message) message.textContent = status.message;
      if (status.id === panel.dataset.operationId && ["succeeded", "rolled_back", "failed", "backup_created"].includes(status.state)) {
        window.location.assign(panel.dataset.updatesUrl);
        return;
      }
    } catch (_error) {
      failures += 1;
      if (failures > 2) message.textContent = "Services are restarting. Waiting for the toolkit to return…";
    }
    window.setTimeout(poll, 1500);
  };
  window.setTimeout(poll, 700);
})();
