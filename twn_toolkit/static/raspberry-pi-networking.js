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

  const bindHardwareIdentity = (selectSelector, inputSelector) => {
    const select = form?.querySelector(selectSelector);
    const input = form?.querySelector(inputSelector);
    if (!select || !input) return;
    const refreshIdentity = () => {
      input.value = select.selectedOptions[0]?.dataset.mac || input.value;
    };
    select.addEventListener("change", refreshIdentity);
    refreshIdentity();
  };

  const refresh = () => {
    if (!form) return;
    const kind = form.dataset.profileKind;
    if (kind === "wired") {
      const mode = form.querySelector("input[name='ipv4_mode']:checked")?.value || "dhcp";
      form.querySelectorAll("[data-wired-static]").forEach((element) => setSectionVisible(element, mode === "static"));
      form.querySelectorAll("[data-wired-shared]").forEach((element) => setSectionVisible(element, mode === "shared"));
      form.querySelectorAll("[data-wired-dns]").forEach((element) => setSectionVisible(element, ["dhcp", "static"].includes(mode)));
      return;
    }
    if (kind === "wifi-ap") {
      const networkMode = form.querySelector("input[name='network_mode']:checked")?.value || "nat";
      form.querySelectorAll("[data-ap-nat]").forEach((element) => setSectionVisible(element, networkMode === "nat"));
      form.querySelectorAll("[data-ap-bridge]").forEach((element) => setSectionVisible(element, networkMode === "bridge"));
    }
    const security = form.querySelector("[data-pi-security]")?.value || "open";
    const enterprise = kind === "wifi-client" && ["peap", "eap-tls"].includes(security);
    const personal = security !== "open" && !enterprise;
    form.querySelectorAll("[data-security-personal]").forEach((element) => setSectionVisible(element, personal));
    form.querySelectorAll("[data-enterprise-only]").forEach((element) => setSectionVisible(element, enterprise));
    form.querySelectorAll("[data-peap-only]").forEach((element) => setSectionVisible(element, security === "peap"));
    form.querySelectorAll("[data-eap-tls-only]").forEach((element) => setSectionVisible(element, security === "eap-tls"));
    const verify = form.querySelector("[data-pi-verify-server]");
    const trustVisible = security === "eap-tls" || (security === "peap" && Boolean(verify?.checked));
    form.querySelectorAll("[data-server-trust]").forEach((element) => setSectionVisible(element, trustVisible));
    const caSource = form.querySelector("[data-pi-ca-source]")?.value;
    form.querySelectorAll("[data-ca-upload]").forEach((element) => setSectionVisible(element, trustVisible && caSource === "upload"));
    const tlsFormat = form.querySelector("[data-pi-tls-format]")?.value || "bundle";
    form.querySelectorAll("[data-tls-bundle]").forEach((element) => setSectionVisible(element, security === "eap-tls" && tlsFormat === "bundle"));
    form.querySelectorAll("[data-tls-separate]").forEach((element) => setSectionVisible(element, security === "eap-tls" && tlsFormat === "separate"));
  };

  if (form) {
    bindHardwareIdentity("[data-pi-adapter-select]", "[data-pi-adapter-mac]");
    bindHardwareIdentity("[data-pi-uplink-select]", "[data-pi-uplink-mac]");
    form.addEventListener("change", (event) => {
      if (event.target.matches("input[name='ipv4_mode'], input[name='network_mode'], [data-pi-security], [data-pi-verify-server], [data-pi-ca-source], [data-pi-tls-format]")) refresh();
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
        const response = await fetch(scanButton.dataset.scanUrl, { method: "POST", body: payload, headers: { Accept: "application/json" } });
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
