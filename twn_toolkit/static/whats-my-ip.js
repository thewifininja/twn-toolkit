(() => {
  const result = document.querySelector("#public-ip-result");
  const address = document.querySelector("#public-ip-address");
  const status = document.querySelector("#public-ip-status");
  const checkAgain = document.querySelector("#check-ip-again");
  checkAgain?.addEventListener("click", () => {
    checkAgain.disabled = true;
    checkAgain.textContent = "Checking…";
    window.location.reload();
  });
  if (!result || !address || !status) return;

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 8000);

  fetch(result.dataset.lookupUrl, {
    cache: "no-store",
    credentials: "omit",
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
      address.textContent = payload.ip.trim();
      status.textContent = payload.ip.includes(":") ? "Public IPv6 address" : "Public IPv4 address";
    })
    .catch(() => {
      address.textContent = "Unavailable";
      status.textContent = "The external lookup was blocked, timed out, or could not reach the internet.";
    })
    .finally(() => window.clearTimeout(timeout));
})();
