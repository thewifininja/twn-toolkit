(() => {
  const panel = document.querySelector("[data-diagnostic-status-url]");
  if (!panel) return;
  const status = panel.querySelector("[data-diagnostic-status]");
  if (!status) return;
  const activeStates = ["queued", "running", "cancel_requested"];
  const stateLabels = { succeeded: "Finished", failed: "Failed", cancelled: "Cancelled", unknown: "Unconfirmed", timed_out: "Timed out", cancel_requested: "Cancelling", queued: "Queued", running: "Running" };
  const cancelForm = panel.querySelector("[data-diagnostic-cancel]");
  const cancelButton = cancelForm?.querySelector('button[type="submit"], button:not([type])');
  const resultUrl = panel.dataset.diagnosticResultUrl || window.location.href;
  let cancelNotice;
  const showCancelNotice = (message) => {
    if (!cancelNotice) {
      cancelNotice = document.createElement("p");
      cancelNotice.setAttribute("role", "status");
      cancelNotice.className = "field-note";
      cancelForm.after(cancelNotice);
    }
    cancelNotice.textContent = message;
  };
  let resultLink = panel.querySelector("[data-diagnostic-result-link]");
  let stopped = false;
  let finished = false;
  let polling = false;
  let paused = false;
  let cancelPending = false;
  let navigationSubmission = null;
  let terminalJob = null;
  let timer;

  const hasDraft = () => Boolean(navigationSubmission && !navigationSubmission.defaultPrevented) || (window.TwnUnsavedForms?.hasChanges
    ? window.TwnUnsavedForms.hasChanges()
    : Boolean(document.querySelector('form[data-unsaved-form]')));
  const showResultLink = () => {
    if (!resultLink) {
      resultLink = document.createElement("a");
      status.after(resultLink);
    }
    resultLink.href = resultUrl;
    resultLink.target = "_blank";
    resultLink.rel = "noopener";
    resultLink.className = "button-link secondary";
    resultLink.textContent = "View retained result in new tab";
  };
  const reportRetainedCompletion = (job) => {
    const outcome = job.state === "unknown" ? "Run outcome is unconfirmed." : `Run ${stateLabels[job.state]?.toLowerCase() || "finished"}.`;
    status.textContent = navigationSubmission && !navigationSubmission.defaultPrevented
      ? `${outcome} Waiting for the new request's response. You can inspect this earlier run in a new tab.`
      : `${outcome} Your settings are still here. Open the retained result in a new tab to inspect this run.`;
    showResultLink();
  };
  // A native POST can be unchanged yet already in flight. Fence the old run's
  // automatic refresh before navigation commits, without capturing form values
  // or changing the browser's normal submission. Later validators/unsaved guards
  // may still cancel dispatch; inspect final defaultPrevented after bubbling.
  window.addEventListener("submit", (event) => {
    const form = event.target;
    if (event.defaultPrevented || !(form instanceof HTMLFormElement)
      || form.method.toLowerCase() !== "post" || (form.target && form.target.toLowerCase() !== "_self")) return;
    navigationSubmission = event;
    window.setTimeout(() => {
      if (navigationSubmission === event && event.defaultPrevented) {
        navigationSubmission = null;
        if (terminalJob) reportRetainedCompletion(terminalJob);
      }
    }, 0);
  });
  const retryStatus = (message) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary";
    button.textContent = "Retry status";
    button.addEventListener("click", () => { paused = false; poll(); });
    status.replaceChildren(document.createTextNode(message + " "), button);
  };
  const responseError = (response) => {
    const error = new Error("Status unavailable");
    error.status = response.status;
    return error;
  };

  async function poll() {
    if (stopped || finished || polling) return;
    window.clearTimeout(timer);
    if (document.hidden) {
      timer = window.setTimeout(poll, 2000);
      return;
    }
    polling = true;
    try {
      const response = await fetch(panel.dataset.diagnosticStatusUrl, {
        headers: { Accept: "application/json" }, cache: "no-store",
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw responseError(response);
      if (response.redirected && new URL(response.url).pathname.endsWith("/login")) {
        throw Object.assign(new Error("Sign in required"), { status: 401 });
      }
      if (!response.headers.get("content-type")?.includes("application/json")) throw responseError(response);
      const job = await response.json();
      if (stopped) return;
      if (typeof job.state !== "string") throw new Error("Invalid run status");
      paused = false;
      if (!activeStates.includes(job.state)) {
        finished = true;
        terminalJob = job;
        if (cancelButton) cancelButton.disabled = true;
        if (cancelNotice) showCancelNotice(job.state === "cancelled" ? "Run cancelled." : "Run finished. Inspect the retained result for its final state.");
        const state = panel.querySelector("[data-diagnostic-state]");
        if (state) state.textContent = stateLabels[job.state] || job.state.replaceAll("_", " ");
        if (hasDraft()) {
          reportRetainedCompletion(job);
        } else {
          // This is a GET of the same retained run, never a repeat submission.
          window.location.reload();
        }
        return;
      }
      if (cancelButton) cancelButton.disabled = cancelPending || job.state === "cancel_requested";
      status.textContent = job.state === "cancel_requested" ? "Cancellation requested — waiting for the run to stop. Your new settings remain on this page." :
        job.state === "running" ? (job.stage ? `Run in progress: ${job.stage}. You can leave this page.` : "Run in progress. You can leave this page and return to the result link.") :
        "Queued — waiting for the diagnostic scheduler. You can leave this page.";
    } catch (error) {
      if (stopped) return;
      paused = [401, 403, 404, 410].includes(error.status);
      const message = error.status === 401 ? "Sign in again in another tab, then retry status. Your settings remain here." :
        error.status === 403 ? "You do not have access to refresh this run. Your settings remain here." :
        [404, 410].includes(error.status) ? "This run is unavailable or no longer retained. Your settings remain here." :
        "Unable to refresh status. Retrying safely; no new run will be submitted.";
      retryStatus(message);
    } finally {
      polling = false;
      if (!stopped && !finished && !paused) timer = window.setTimeout(poll, 2000);
    }
  }

  cancelForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (cancelPending || finished) return;
    cancelPending = true;
    if (cancelButton) cancelButton.disabled = true;
    showCancelNotice("Requesting cancellation. Your new settings remain on this page…");
    let accepted = false;
    try {
      const response = await fetch(cancelForm.action, {
        method: "POST", body: new FormData(cancelForm),
        headers: { Accept: "application/json" }, signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) throw responseError(response);
      // Existing cancel routes redirect to their read-only result page. A login
      // redirect is not confirmation that cancellation was accepted.
      if (response.redirected && new URL(response.url).pathname.endsWith("/login")) {
        throw Object.assign(new Error("Sign in required"), { status: 401 });
      }
      const expected = new URL(resultUrl, window.location.href);
      const destination = response.redirected ? new URL(response.url) : null;
      if (!destination || destination.pathname !== expected.pathname || destination.search !== expected.search) {
        throw new Error("Unexpected cancellation response");
      }
      accepted = true;
      if (!stopped && !finished) showCancelNotice("Cancellation requested — checking the retained run. Your new settings remain here.");
    } catch (error) {
      if (!stopped && !finished) {
        const message = error.status === 401 ? "Sign in again in another tab before cancelling this run." :
          error.status === 403 ? "You do not have permission to cancel this run." :
          "Cancellation could not be confirmed. Check this run's status before trying again; cancellation is never retried automatically.";
        showCancelNotice(message + " Your settings remain here.");
      }
    } finally {
      cancelPending = false;
      if (!finished && cancelButton) cancelButton.disabled = accepted;
      if (!stopped && !finished) { paused = false; poll(); }
    }
  });

  window.addEventListener("pagehide", () => { stopped = true; window.clearTimeout(timer); });
  window.addEventListener("pageshow", () => {
    navigationSubmission = null;
    if (terminalJob) reportRetainedCompletion(terminalJob);
    if (stopped && !finished) { stopped = false; paused = false; poll(); }
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && !stopped && !finished && !paused) poll();
  });
  timer = window.setTimeout(poll, 1000);
})();
