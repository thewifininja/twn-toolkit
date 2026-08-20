(() => {
  const form = document.querySelector("[data-pi-network-form]");
  const pending = document.querySelector("[data-expires-at]");

  const setSectionVisible = (element, visible) => {
    element.hidden = !visible;
    element.querySelectorAll("input, select, textarea, button").forEach((control) => {
      if (control.matches("[data-pi-network-scan]")) return;
      control.disabled = !visible;
    });
  };

  const refresh = () => {
    if (!form) return;
    const mode = form.querySelector("input[name='mode']:checked")?.value || "nat";
    const securitySelect = form.querySelector("[data-pi-security]");
    const clientOnlyOptions = form.querySelectorAll("[data-client-only]");
    clientOnlyOptions.forEach((option) => {
      option.disabled = mode !== "client";
      option.hidden = mode !== "client";
    });
    if (mode !== "client" && ["open", "peap", "eap-tls"].includes(securitySelect.value)) {
      securitySelect.value = "wpa2-wpa3";
    }
    const security = securitySelect.value;
    const enterprise = mode === "client" && ["peap", "eap-tls"].includes(security);
    const personal = security !== "open" && !enterprise;
    form.querySelectorAll("[data-ap-only]").forEach((element) => setSectionVisible(element, mode !== "client"));
    form.querySelectorAll("[data-uplink-section]").forEach((element) => setSectionVisible(element, mode !== "client"));
    form.querySelectorAll("[data-bridge-only]").forEach((element) => setSectionVisible(element, mode === "bridge"));
    form.querySelectorAll("[data-nat-only]").forEach((element) => setSectionVisible(element, mode === "nat"));
    form.querySelectorAll("[data-enterprise-only]").forEach((element) => setSectionVisible(element, enterprise));
    form.querySelectorAll("[data-security-section='personal']").forEach((element) => setSectionVisible(element, personal));
    form.querySelectorAll("[data-peap-only]").forEach((element) => setSectionVisible(element, security === "peap"));
    form.querySelectorAll("[data-eap-tls-only]").forEach((element) => setSectionVisible(element, security === "eap-tls"));

    const verify = form.querySelector("[data-pi-verify-server]");
    const trustVisible = security === "eap-tls" || (security === "peap" && verify.checked);
    form.querySelectorAll("[data-server-trust]").forEach((element) => setSectionVisible(element, trustVisible));
    const warning = form.querySelector("[data-pi-insecure-peap]");
    if (warning) warning.hidden = security !== "peap" || verify.checked;
    const caSource = form.querySelector("[data-pi-ca-source]")?.value;
    form.querySelectorAll("[data-ca-upload]").forEach((element) => setSectionVisible(element, trustVisible && caSource === "upload"));

    const tlsFormat = form.querySelector("[data-pi-tls-format]")?.value || "bundle";
    form.querySelectorAll("[data-tls-bundle]").forEach((element) => setSectionVisible(element, security === "eap-tls" && tlsFormat === "bundle"));
    form.querySelectorAll("[data-tls-separate]").forEach((element) => setSectionVisible(element, security === "eap-tls" && tlsFormat === "separate"));
  };

  if (form) {
    form.addEventListener("change", (event) => {
      if (event.target.matches("input[name='mode'], [data-pi-security], [data-pi-verify-server], [data-pi-ca-source], [data-pi-tls-format]")) refresh();
    });
    refresh();

    const scanButton = form.querySelector("[data-pi-network-scan]");
    const scanResults = form.querySelector("[data-pi-network-scan-results]");
    scanButton?.addEventListener("click", async () => {
      const original = scanButton.textContent;
      scanButton.disabled = true;
      scanButton.textContent = "Scanning…";
      scanResults.hidden = false;
      scanResults.classList.remove("error-text");
      scanResults.innerHTML = "<span class='muted'>Scanning nearby wireless networks…</span>";
      const payload = new FormData();
      payload.set("wifi_interface", form.querySelector("[data-pi-wifi-interface]").value);
      try {
        const response = await fetch(scanButton.dataset.scanUrl, {
          method: "POST",
          body: payload,
          headers: { Accept: "application/json" },
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "The scan failed.");
        scanResults.replaceChildren();
        if (!result.networks.length) {
          scanResults.innerHTML = "<span class='muted'>No nearby networks were returned.</span>";
        } else {
          result.networks.forEach((network) => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "pi-network-scan-result";
            const name = document.createElement("strong");
            name.textContent = network.ssid;
            const details = document.createElement("small");
            details.textContent = `${network.signal}% · ${network.security || "Open"} · ${network.frequency} MHz`;
            button.append(name, details);
            button.addEventListener("click", () => {
              form.querySelector("[data-pi-ssid]").value = network.ssid;
              scanResults.hidden = true;
              form.querySelector("[data-pi-ssid]").focus();
            });
            scanResults.append(button);
          });
        }
      } catch (error) {
        scanResults.textContent = error.message;
        scanResults.classList.add("error-text");
      } finally {
        scanButton.disabled = false;
        scanButton.textContent = original;
      }
    });
  }

  if (pending) {
    const countdown = pending.querySelector("[data-pi-network-countdown]");
    const expiresAt = Number(pending.dataset.expiresAt) * 1000;
    const updateCountdown = () => {
      const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
      countdown.textContent = seconds ? `Automatic rollback in ${seconds} second${seconds === 1 ? "" : "s"}.` : "Rollback is being completed…";
      if (!seconds) {
        window.setTimeout(() => window.location.reload(), 1500);
        return;
      }
      window.setTimeout(updateCountdown, 250);
    };
    updateCountdown();
  }
})();
