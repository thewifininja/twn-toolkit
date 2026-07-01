(() => {
  const status = document.querySelector("#dns-profile-status");
  const fields = {
    hosts: document.querySelector("#dns-hosts"),
    servers: document.querySelector("#dns-servers"),
  };

  const formatValues = (kind, values) => values.map((item) => {
    const value = kind === "hosts" ? item.host : item.address;
    return item.label ? `${item.label} = ${value}` : value;
  }).join("\n");

  document.querySelectorAll(".dns-profile-select").forEach((select) => {
    const storageKey = `twn:dns:${select.dataset.kind}`;
    select.addEventListener("change", () => {
      const kind = select.dataset.kind;
      const option = select.selectedOptions[0];
      if (!option?.dataset.values) {
        fields[kind].value = "";
        document.querySelector(`.profile-name-input[data-kind="${kind}"]`).value = "";
        sessionStorage.removeItem(storageKey);
        return;
      }
      fields[kind].value = formatValues(kind, JSON.parse(option.dataset.values));
      document.querySelector(`.profile-name-input[data-kind="${kind}"]`).value = option.value;
      sessionStorage.setItem(storageKey, select.value);
    });
    const savedProfile = sessionStorage.getItem(storageKey);
    if (savedProfile && [...select.options].some((option) => option.value === savedProfile)) {
      select.value = savedProfile;
      select.dispatchEvent(new Event("change"));
    }
  });

  document.querySelectorAll(".dns-save-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const body = new FormData();
      body.set("profile_name", document.querySelector(`.profile-name-input[data-kind="${kind}"]`).value);
      body.set("values", fields[kind].value);
      const response = await fetch(`/tools/dns-response/profiles/${kind}`, {method: "POST", body});
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error;
        return;
      }
      sessionStorage.setItem(`twn:dns:${kind}`, payload.profile.name);
      status.textContent = `Saved ${kind} profile “${payload.profile.name}”. Reloading…`;
      window.location.reload();
    });
  });

  document.querySelectorAll(".dns-delete-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const select = document.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
      if (!select.value || !window.confirm(`Delete profile “${select.value}”?`)) return;
      const body = new FormData();
      body.set("name", select.value);
      const response = await fetch(`/tools/dns-response/profiles/${kind}/delete`, {method: "POST", body});
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error;
        return;
      }
      sessionStorage.removeItem(`twn:dns:${kind}`);
      window.location.reload();
    });
  });
})();
