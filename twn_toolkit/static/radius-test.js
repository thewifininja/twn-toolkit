(() => {
  const status = document.querySelector("#radius-profile-status");
  const protocol = document.querySelector("#radius-protocol");
  const eapOptions = document.querySelector("#radius-eap-options");
  protocol?.addEventListener("change", () => {
    if (eapOptions && ["peap-mschapv2", "eap-tls"].includes(protocol.value)) {
      eapOptions.open = true;
    }
  });

  document.querySelectorAll(".radius-profile-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const kind = form.dataset.kind;
      const response = await fetch(`/tools/radius-test/profiles/${kind}`, {
        method: "POST",
        body: new FormData(form),
      });
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error;
        return;
      }
      status.textContent = `Saved ${payload.profile.name}. Reloading…`;
      window.location.reload();
    });
  });

  document.querySelectorAll(".radius-delete-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!window.confirm(`Delete profile “${button.dataset.name}”?`)) return;
      const body = new FormData();
      body.set("name", button.dataset.name);
      const response = await fetch(`/tools/radius-test/profiles/${button.dataset.kind}/delete`, {
        method: "POST",
        body,
      });
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error;
        return;
      }
      window.location.reload();
    });
  });
})();
