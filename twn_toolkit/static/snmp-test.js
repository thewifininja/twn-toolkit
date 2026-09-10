(function () {
  const forms = document.querySelectorAll(".snmp-profile-form");
  if (!forms.length) return;

  forms.forEach((form) => {
    const deleteButton = form.querySelector(".snmp-delete-profile");
    const status = form.querySelector(".snmp-form-status");

    let saving = false;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (saving) return;
      saving = true;
      const snapshot = window.TwnUnsavedForms?.capture(form);
      status.textContent = "Saving...";
      const submitButton = form.querySelector('button[type="submit"]');
      submitButton.disabled = true;
      try {
        const body = new FormData(form);
        if (!window.TwnMso.prepare(body, form)) return;
        const response = await fetch(form.dataset.saveUrl, {
          method: "POST",
          body,
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Profile could not be saved.");
        const previousName = form.elements.original_name.value;
        window.TwnMso.saved(form, data.profile);
        form.elements.original_name.value = data.profile.name;
        const card = form.closest("details");
        const summary = card?.querySelector(":scope > summary");
        if (summary) {
          const title = document.createElement("strong");
          title.textContent = `Editing ${data.profile.name}`;
          summary.replaceChildren(title);
        }
        if (!previousName && card) {
          card.classList.remove("profile-create-details", "card-action-details", "saved-profile-create");
          card.classList.add("access-profile-card", "nested-profile-card", "saved-profile-record");
          submitButton.textContent = "Update saved profile";
        }
        if (deleteButton) deleteButton.dataset.name = data.profile.name;
        form.querySelectorAll("[data-profile-name]").forEach((button) => { button.dataset.profileName = data.profile.name; });
        if (form.dataset.kind === "credentials" && previousName && previousName !== data.profile.name) {
          document.querySelectorAll('select[name="credential_name"]').forEach((select) => {
            Array.from(select.options).filter((option) => option.value === previousName).forEach((option) => {
              option.value = data.profile.name;
              option.textContent = option.textContent.replace(previousName, data.profile.name);
            });
            window.TwnUnsavedForms?.rebaseReference(select.form, select.name, previousName, data.profile.name);
          });
        }
        window.TwnUnsavedForms?.acknowledge(form, snapshot);
        if (window.TwnUnsavedForms?.hasChanges()) {
          status.textContent = `Saved ${data.profile.name}. Unsaved edits remain; finish them before reloading.`;
        } else {
          window.location.reload();
        }
      } catch (error) {
        window.TwnUnsavedForms?.failed(form);
        status.textContent = error.message;
      } finally {
        saving = false;
        submitButton.disabled = false;
      }
    });

    deleteButton?.addEventListener("click", async () => {
      const name = deleteButton.dataset.name || form.elements.original_name.value || "";
      if (!name) {
        status.textContent = "Select a saved profile to delete.";
        return;
      }
      if (!window.confirm(window.TwnMso.deleteMessage(form, name))) return;
      deleteButton.disabled = true;
      try {
        const body = new FormData();
        body.set("name", name);
        if (!window.TwnMso.prepare(body, form, "delete")) return;
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
