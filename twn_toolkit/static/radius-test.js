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

  const resetForm = (form) => {
    form.reset();
    form.querySelector("[name=original_name]").value = "";
    form.querySelector(".profile-form-title").textContent =
      `Add ${form.dataset.kind === "servers" ? "Server" : form.dataset.kind === "credentials" ? "Credential" : "Attribute"} Profile`;
    form.querySelector(".radius-cancel-edit").hidden = true;
    const note = form.querySelector(".secret-note");
    if (note) note.textContent = form.dataset.kind === "credentials"
      ? "Required for a new profile. Stored locally without encryption."
      : "Required for a new profile.";
  };

  document.querySelectorAll(".radius-edit-profile").forEach((button) => {
    button.addEventListener("click", () => {
      const kind = button.dataset.kind;
      const form = document.querySelector(`.radius-profile-form[data-kind="${kind}"]`);
      form.closest("details").open = true;
      form.querySelector("[name=original_name]").value = button.dataset.name;
      form.querySelector("[name=name]").value = button.dataset.name;
      if (kind === "servers") {
        form.querySelector("[name=host]").value = button.dataset.host;
        form.querySelector("[name=port]").value = button.dataset.port;
      } else if (kind === "credentials") {
        form.querySelector("[name=username]").value = button.dataset.username;
      } else {
        form.querySelector("[name=attributes]").value = button.dataset.source;
      }
      form.querySelector(".profile-form-title").textContent = `Edit ${button.dataset.name}`;
      form.querySelector(".radius-cancel-edit").hidden = false;
      const note = form.querySelector(".secret-note");
      if (note) note.textContent = "Leave blank to keep the saved secret.";
      form.scrollIntoView({behavior: "smooth", block: "center"});
    });
  });

  document.querySelectorAll(".radius-cancel-edit").forEach((button) => {
    button.addEventListener("click", () => resetForm(button.closest("form")));
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
