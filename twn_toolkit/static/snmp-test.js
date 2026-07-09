(function () {
  const forms = document.querySelectorAll(".snmp-profile-form");
  if (!forms.length) return;

  forms.forEach((form) => {
    const deleteButton = form.querySelector(".snmp-delete-profile");
    const status = form.querySelector(".snmp-form-status");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      status.textContent = "Saving...";
      const submitButton = form.querySelector('button[type="submit"]');
      submitButton.disabled = true;
      try {
        const response = await fetch(form.dataset.saveUrl, {
          method: "POST",
          body: new FormData(form),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Profile could not be saved.");
        window.location.reload();
      } catch (error) {
        status.textContent = error.message;
        submitButton.disabled = false;
      }
    });

    deleteButton?.addEventListener("click", async () => {
      const name = deleteButton.dataset.name || form.elements.original_name.value || "";
      if (!name) {
        status.textContent = "Select a saved profile to delete.";
        return;
      }
      if (!window.confirm(`Delete '${name}'?`)) return;
      deleteButton.disabled = true;
      try {
        const body = new FormData();
        body.set("name", name);
        const response = await fetch(form.dataset.deleteUrl, {method: "POST", body});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Profile could not be deleted.");
        window.location.reload();
      } catch (error) {
        status.textContent = error.message;
        deleteButton.disabled = false;
      }
    });

    if (form.dataset.kind === "credentials") {
      form.elements.version.addEventListener("change", () => updateCredentialFields(form));
      form.elements.security_level.addEventListener("change", () => updateCredentialFields(form));
      updateCredentialFields(form);
    }
  });

  function updateCredentialFields(form) {
    const isV3 = form.elements.version.value === "v3";
    const level = form.elements.security_level.value;
    form.querySelector(".snmp-v2-fields").hidden = isV3;
    form.querySelector(".snmp-v3-fields").hidden = !isV3;
    form.querySelector(".snmp-auth-fields").hidden = !isV3 || level === "noauthnopriv";
    form.querySelector(".snmp-priv-fields").hidden = !isV3 || level !== "authpriv";
  }
})();
