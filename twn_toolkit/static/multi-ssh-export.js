(() => {
  const results = [...document.querySelectorAll("[data-ssh-result]")];
  const downloadAll = document.querySelector("[data-ssh-download-all]");
  if (!results.length || !downloadAll) return;

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

    const forgetButton = result.querySelector("[data-ssh-forget-host-key]");
    const forgetStatus = result.querySelector("[data-ssh-host-key-status]");
    forgetButton?.addEventListener("click", async () => {
      const host = forgetButton.dataset.host || "this host";
      if (!window.confirm(
        `Forget the saved SSH key for ${host}?\n\n` +
        "Continue only if you verified that the device was replaced or intentionally re-keyed."
      )) return;

      forgetButton.disabled = true;
      forgetButton.textContent = "Forgetting…";
      if (forgetStatus) {
        forgetStatus.className = "ssh-host-key-status";
        forgetStatus.textContent = "";
      }
      try {
        const response = await fetch(forgetButton.dataset.url, {
          method: "POST",
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            host: forgetButton.dataset.host,
            port: forgetButton.dataset.port,
            expected_fingerprint: forgetButton.dataset.expectedFingerprint,
          }),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(payload.error || "The saved key could not be forgotten.");
        forgetButton.textContent = "Saved key forgotten";
        if (forgetStatus) {
          forgetStatus.classList.add("success");
          forgetStatus.textContent = payload.message || "Saved key forgotten.";
        }
      } catch (error) {
        forgetButton.disabled = false;
        forgetButton.textContent = "Forget saved key";
        if (forgetStatus) {
          forgetStatus.classList.add("error");
          forgetStatus.textContent = error.message;
        }
      }
    });
  });
})();
