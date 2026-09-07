(() => {
  const panel = document.querySelector("[data-diagnostic-status-url]");
  if (!panel) return;
  const status = panel.querySelector("[data-diagnostic-status]");
  let stopped = false;
  window.addEventListener("pagehide", () => { stopped = true; });
  async function poll() {
    if (stopped) return;
    if (!document.hidden) {
      try {
        const response = await fetch(panel.dataset.diagnosticStatusUrl, {
          headers: { Accept: "application/json" }, cache: "no-store",
          signal: AbortSignal.timeout(10000),
        });
        if (!response.ok) throw new Error("Status unavailable");
        const job = await response.json();
        if (!["queued", "running", "cancel_requested"].includes(job.state)) {
          window.location.reload();
          return;
        }
        status.textContent = job.state === "cancel_requested" ? "Cancellation requested — waiting for the run to stop." :
          job.state === "running" ? (job.stage ? `Run in progress: ${job.stage}. You can leave this page.` : "Run in progress. You can leave this page and return to the result link.") :
          "Queued — waiting for the diagnostic scheduler. You can leave this page.";
      } catch (_) {
        status.textContent = "Unable to refresh status. Retrying; refreshing this page will not submit another run.";
      }
    }
    if (!stopped) window.setTimeout(poll, 2000);
  }
  window.setTimeout(poll, 1000);
})();
