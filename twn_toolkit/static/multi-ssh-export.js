(() => {
  const results = [...document.querySelectorAll("[data-ssh-result]")];
  const toggleAll = document.querySelector("[data-ssh-toggle-all]");
  const downloadAll = document.querySelector("[data-ssh-download-all]");
  if (!results.length || !downloadAll) return;

  function updateToggleAll() {
    if (!toggleAll) return;
    const allOpen = results.every((result) => result.open);
    toggleAll.textContent = allOpen ? "Collapse all" : "Expand all";
  }

  toggleAll?.addEventListener("click", () => {
    const shouldOpen = !results.every((result) => result.open);
    results.forEach((result) => {
      result.open = shouldOpen;
    });
    updateToggleAll();
  });

  results.forEach((result) => {
    result.addEventListener("toggle", updateToggleAll);
  });
  updateToggleAll();

  function timestamp() {
    const now = new Date();
    const part = (value) => String(value).padStart(2, "0");
    return `${now.getFullYear()}${part(now.getMonth() + 1)}${part(now.getDate())}` +
      `${part(now.getHours())}${part(now.getMinutes())}${part(now.getSeconds())}`;
  }

  function safeName(value) {
    return String(value || "host")
      .trim()
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^[-._]+|[-._]+$/g, "")
      .slice(0, 100) || "host";
  }

  function resultText(result) {
    const host = result.dataset.host || "Unknown host";
    const address = result.dataset.address || host;
    const status = result.dataset.status || "unknown";
    const error = result.querySelector(".ssh-result-error, .message.error")?.textContent.trim() || "";
    const expected = result.querySelector("[data-ssh-expected-fingerprint]")?.textContent.trim() || "";
    const presented = result.querySelector("[data-ssh-presented-fingerprint]")?.textContent.trim() || "";
    const output = result.querySelector(".result-output")?.textContent || "No output captured.";
    return [
      `Host: ${host}`,
      ...(address !== host ? [`Target: ${address}`] : []),
      `Status: ${status}`,
      ...(error ? [`Error: ${error}`] : []),
      ...(expected ? [`Saved key: ${expected}`] : []),
      ...(presented ? [`Presented key: ${presented}`] : []),
      "",
      output,
      "",
    ].join("\n");
  }

  function download(filename, content) {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  downloadAll.addEventListener("click", () => {
    const divider = "=".repeat(78);
    const body = results.map((result) => `${divider}\n${resultText(result)}`).join("\n");
    download(`${timestamp()}-bulk-ssh-results.txt`, `Bulk SSH results\n${body}`);
  });

  results.forEach((result) => {
    result.querySelector("[data-ssh-download-host]")?.addEventListener("click", () => {
      download(
        `${timestamp()}-${safeName(result.dataset.host)}.txt`,
        resultText(result),
      );
    });

    const retryReveal = result.querySelector("[data-ssh-retry-reveal]");
    const retryForm = result.querySelector("[data-ssh-host-key-retry]");
    const retryCancel = result.querySelector("[data-ssh-retry-cancel]");
    const retrySubmit = result.querySelector("[data-ssh-retry-submit]");
    const retryStatus = result.querySelector("[data-ssh-host-key-status]");
    retryReveal?.addEventListener("click", () => {
      retryForm.hidden = false;
      retryReveal.hidden = true;
      retryForm.querySelector('[name="retry_password"]')?.focus();
    });
    retryCancel?.addEventListener("click", () => {
      retryForm.hidden = true;
      retryReveal.hidden = false;
      retryForm.querySelector('[name="retry_password"]').value = "";
      retryStatus.textContent = "";
    });
    retryForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!retryForm.reportValidity()) return;
      const host = retryForm.dataset.host || "this host";
      if (!window.confirm(
        `Replace the saved SSH key and retry only ${host}?\n\n` +
        "Continue only if you independently verified the presented fingerprint."
      )) return;

      const mainForm = document.querySelector("[data-multi-ssh]");
      if (!mainForm) return;
      const mainData = new FormData(mainForm);
      retrySubmit.disabled = true;
      retrySubmit.textContent = "Replacing & retrying…";
      retryStatus.className = "ssh-host-key-status";
      retryStatus.textContent = "Connecting to this host…";
      try {
        const response = await fetch(retryForm.dataset.url, {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            retry_token: retryForm.dataset.retryToken,
            preview_token: mainData.get("preview_token"),
            matrix: mainData.get("matrix"),
            commands: mainData.get("commands"),
            command_timeout: mainData.get("command_timeout"),
            username: retryForm.querySelector('[name="retry_username"]').value,
            password: retryForm.querySelector('[name="retry_password"]').value,
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || "This host could not be retried.");

        const retried = payload.result || {};
        const status = retried.status || "error";
        result.dataset.status = status;
        const statusPill = result.querySelector("summary .pill");
        if (statusPill) {
          statusPill.className = `pill ${status}`;
          statusPill.textContent = status;
        }
        const output = result.querySelector(".result-output");
        if (output) output.textContent = retried.output || "No output captured.";
        retryForm.querySelector('[name="retry_password"]').value = "";

        if (status === "success") {
          const completed = document.createElement("div");
          completed.className = "message success ssh-host-key-retry-complete";
          completed.textContent = payload.message || "Saved key replaced and this host was rerun.";
          result.querySelector("[data-ssh-host-key-mismatch]")?.replaceWith(completed);
        } else {
          result.querySelector(".ssh-host-key-mismatch-head strong").textContent = "Stale key cleared; retry incomplete";
          result.querySelector(".ssh-result-error").textContent = retried.error || "This host did not complete successfully.";
          retryStatus.classList.add("error");
          retryStatus.textContent = payload.message || "Review the error and retry this host again.";
          retrySubmit.disabled = false;
          retrySubmit.textContent = "Retry this host again";
        }
      } catch (error) {
        retrySubmit.disabled = false;
        retrySubmit.textContent = "Verify, replace & retry";
        retryStatus.classList.add("error");
        retryStatus.textContent = error.message;
      }
    });
  });
})();
