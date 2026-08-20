(() => {
  const unknownPolicy = document.querySelector("[data-lldp-policy-unknown]");
  const policyValues = [...document.querySelectorAll("[data-lldp-policy-value]")];
  const syncUnknownPolicy = () => {
    const disabled = Boolean(unknownPolicy?.checked);
    for (const field of policyValues) {
      field.disabled = disabled;
      if (disabled && field.type === "checkbox") field.checked = false;
      if (disabled && field.type === "number") field.value = "0";
    }
  };
  unknownPolicy?.addEventListener("change", syncUnknownPolicy);
  syncUnknownPolicy();

  const interfaceSelect = document.querySelector("[data-lldp-interface-select]");
  const interfaceConfirmation = document.querySelector("[data-lldp-interface-confirmation]");
  const startButton = document.querySelector("[data-lldp-start-button]");
  const syncInterfaceConfirmation = () => {
    const selected = interfaceSelect?.value || "selected interface";
    if (interfaceConfirmation) interfaceConfirmation.textContent = selected;
    if (startButton) startButton.textContent = `Start on ${selected}`;
  };
  interfaceSelect?.addEventListener("change", syncInterfaceConfirmation);
  syncInterfaceConfirmation();

  const panel = document.querySelector("[data-lldp-sessions-url]");
  if (!panel) return;
  const url = panel.dataset.lldpSessionsUrl;
  const list = panel.querySelector("[data-lldp-session-list]");
  const escape = (value) => {
    const node = document.createElement("span");
    node.textContent = String(value ?? "");
    return node.innerHTML;
  };

  async function refresh() {
    if (document.hidden) return;
    try {
      const response = await fetch(url, {headers: {Accept: "application/json"}});
      if (!response.ok) return;
      const payload = await response.json();
      for (const session of payload.sessions || []) {
        const row = list.querySelector(`[data-session-id="${CSS.escape(session.id)}"]`);
        if (!row) continue;
        row.className = `lldp-session-row status-${session.status}`;
        const detail = row.querySelector("small");
        if (detail) detail.textContent = `${session.interface} · ${session.frames_sent} frame${session.frames_sent === 1 ? "" : "s"} · ${session.status}`;
        const error = row.querySelector("em");
        if (error) error.innerHTML = escape(session.error);
        if (!session.active) row.querySelector("form")?.remove();
      }
    } catch (_error) {
      // A navigation, restart, or brief network interruption should not disturb the form.
    }
  }
  window.setInterval(refresh, 3000);
})();
