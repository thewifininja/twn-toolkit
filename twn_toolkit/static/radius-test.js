(() => {
  const status = document.querySelector("#radius-profile-status");
  document.querySelectorAll(".radius-profile-form").forEach((form) => {
    let saving = false;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (saving) return;
      saving = true;
      const snapshot = window.TwnUnsavedForms?.capture(form);
      const submitButton = form.querySelector('button[type="submit"]');
      submitButton.disabled = true;
      status.textContent = "Saving…";
      try {
        const kind = form.dataset.kind;
        const body = new FormData(form);
        if (!window.TwnMso.prepare(body, form)) return;
        const response = await fetch(`${document.body.dataset.instancePrefix || ""}/tools/radius-test/profiles/${kind}`, {
          method: "POST", body,
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "Profile could not be saved.");
        const previousName = form.elements.original_name.value;
        window.TwnMso.saved(form, payload.profile);
        form.elements.original_name.value = payload.profile.name;
        const card = form.closest("details");
        const summary = card?.querySelector(":scope > summary");
        if (summary) {
          const title = document.createElement("strong");
          title.textContent = `Editing ${payload.profile.name}`;
          summary.replaceChildren(title);
        }
        if (!previousName && card) {
          card.classList.remove("profile-create-details", "card-action-details", "saved-profile-create");
          card.classList.add("access-profile-card", "nested-profile-card", "saved-profile-record");
          submitButton.textContent = "Update saved profile";
        }
        form.querySelectorAll(".radius-delete-profile").forEach((button) => { button.dataset.name = payload.profile.name; });
        form.querySelectorAll("[data-profile-name]").forEach((button) => { button.dataset.profileName = payload.profile.name; });
        if (kind === "servers" && previousName) {
          document.querySelectorAll('input[name="server_names"]').forEach((input) => {
            if (input.value !== previousName) return;
            input.value = payload.profile.name;
            const label = input.closest("label").querySelector("span");
            const title = document.createElement("strong");
            title.textContent = payload.profile.name;
            label.replaceChildren(title, document.createTextNode(` — ${payload.profile.host}:${payload.profile.port}`));
          });
        }
        const referenceName = {credentials: "credential_name", attributes: "attribute_profile"}[kind];
        if (referenceName && previousName && previousName !== payload.profile.name) {
          document.querySelectorAll(`select[name="${referenceName}"]`).forEach((select) => {
            Array.from(select.options).filter((option) => option.value === previousName).forEach((option) => {
              option.value = payload.profile.name;
              option.textContent = option.textContent.replace(previousName, payload.profile.name);
            });
          });
        }
        window.TwnUnsavedForms?.acknowledge(form, snapshot);
        if (window.TwnUnsavedForms?.hasChanges()) {
          status.textContent = `Saved ${payload.profile.name}. Unsaved edits remain; finish them before reloading.`;
        } else {
          status.textContent = `Saved ${payload.profile.name}. Reloading…`;
          window.location.reload();
        }
      } catch (error) {
        window.TwnUnsavedForms?.failed(form);
        status.textContent = error.message || "Could not confirm the save. Check the profile before retrying.";
      } finally {
        saving = false;
        submitButton.disabled = false;
      }
    });
  });

  document.querySelectorAll(".radius-delete-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!window.confirm(window.TwnMso.deleteMessage(button.closest("form"), button.dataset.name))) return;
      const body = new FormData();
      body.set("name", button.dataset.name);
      if (!window.TwnMso.prepare(body, button.closest("form"), "delete")) return;
      const response = await fetch(`${document.body.dataset.instancePrefix || ""}/tools/radius-test/profiles/${button.dataset.kind}/delete`, {
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
