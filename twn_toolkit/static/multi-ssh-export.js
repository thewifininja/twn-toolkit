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
    const error = result.querySelector(".message.error")?.textContent.trim() || "";
    const output = result.querySelector(".result-output")?.textContent || "No output captured.";
    return [
      `Host: ${host}`,
      ...(address !== host ? [`Target: ${address}`] : []),
      `Status: ${status}`,
      ...(error ? [`Error: ${error}`] : []),
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
    download(`${timestamp()}-multi-ssh-results.txt`, `Multi-SSH results\n${body}`);
  });

  results.forEach((result) => {
    result.querySelector("[data-ssh-download-host]")?.addEventListener("click", () => {
      download(
        `${timestamp()}-${safeName(result.dataset.host)}.txt`,
        resultText(result),
      );
    });
  });
})();
