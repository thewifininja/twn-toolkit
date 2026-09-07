(() => {
  let leaving = false;
  window.addEventListener("pagehide", () => { leaving = true; });
  window.addEventListener("pageshow", () => { leaving = false; });
  window.TwnApplianceRead = async (url, body, status) => {
    const response = await fetch(url, {method: "POST", body, headers: {Accept: "application/json"}, signal: AbortSignal.timeout(15000)});
    const queued = await response.json();
    if (!response.ok) throw new Error(queued.error || "Unable to queue appliance read.");
    if (response.status !== 202) return queued;
    const link = document.createElement("a");
    link.href = queued.job_url; link.textContent = "Open run";
    const cancel = document.createElement("button");
    cancel.type = "button"; cancel.className = "secondary"; cancel.textContent = "Cancel run";
    const message = document.createElement("span"); message.textContent = "Queued. ";
    status.replaceChildren(message, link, document.createTextNode(" "), cancel);
    cancel.addEventListener("click", async () => {
      cancel.disabled = true;
      try {
        const result = await fetch(queued.cancel_url, {method: "POST", signal: AbortSignal.timeout(15000)});
        if (!result.ok) throw new Error();
        message.textContent = "Cancellation requested. ";
      } catch (_) { message.textContent = "Cancellation could not be confirmed. Open the run to retry. "; cancel.disabled = false; }
    });
    while (!leaving) {
      await new Promise(resolve => setTimeout(resolve, 1500));
      if (leaving || document.hidden) continue;
      let job;
      try {
        const result = await fetch(queued.status_url, {headers: {Accept: "application/json"}, cache: "no-store", signal: AbortSignal.timeout(10000)});
        if ([401, 403, 404, 410].includes(result.status)) throw Object.assign(new Error("This run is no longer accessible."), {terminal: true});
        if (!result.ok) throw new Error();
        job = await result.json();
      } catch (error) {
        if (error.terminal) throw error;
        message.textContent = "Status unavailable; retrying. Open run to return later. "; continue;
      }
      if (job.state === "succeeded") return job.data;
      if (!["queued", "running", "cancel_requested"].includes(job.state)) throw new Error(job.error || `Run ${job.state}.`);
      message.textContent = job.state === "running" ? "Reading appliance. You can navigate away. " : job.state === "cancel_requested" ? "Cancellation requested. " : "Queued. ";
    }
    throw new Error("The page was closed; the run remains available from its result link.");
  };
})();
