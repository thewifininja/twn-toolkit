(() => {
  const result = document.querySelector("#public-ip-result");
  const address = document.querySelector("#public-ip-address");
  const status = document.querySelector("#public-ip-status");
  const serverResult = document.querySelector("#server-public-ip-result");
  const serverAddress = document.querySelector("#server-public-ip-address");
  const serverStatus = document.querySelector("#server-public-ip-status");
  const checkAgain = document.querySelector("#check-ip-again");
  checkAgain?.addEventListener("click", () => {
    checkAgain.disabled = true;
    checkAgain.textContent = "Checking…";
    window.location.reload();
  });
  if (!result || !address || !status) return;

  lookupPublicIp(result, address, status, true);
  lookupPublicIp(serverResult, serverAddress, serverStatus, false);

  function lookupPublicIp(container, output, detail, directFromBrowser) {
    if (!container || !output || !detail) return;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 9000);
    fetch(container.dataset.lookupUrl, {
      cache: "no-store",
      credentials: directFromBrowser ? "omit" : "same-origin",
      signal: controller.signal,
    })
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((payload) => {
        if (typeof payload.ip !== "string" || !payload.ip.trim()) {
          throw new Error("The response did not contain an address.");
        }
        output.textContent = payload.ip.trim();
        detail.textContent = payload.family || (payload.ip.includes(":") ? "Public IPv6 address" : "Public IPv4 address");
      })
      .catch(() => {
        output.textContent = "Unavailable";
        detail.textContent = directFromBrowser
          ? "The browser lookup was blocked, timed out, or could not reach the internet."
          : "The toolkit server lookup timed out or could not reach the internet.";
      })
      .finally(() => window.clearTimeout(timeout));
  }
})();
