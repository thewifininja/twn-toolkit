(function () {
  const managers = document.querySelectorAll(".port-inline-profile");
  const status = document.getElementById("port-profile-status");
  if (!managers.length || !status) return;

  managers.forEach((manager) => {
    const storageKey = `twn:port-scanner:${manager.dataset.kind}`;
    const select = manager.querySelector(".port-existing-profile");
    const values = manager.querySelector(".port-profile-values");
    const name = manager.querySelector(".port-profile-name");

    select.addEventListener("change", () => {
      const option = select.selectedOptions[0];
      const profile = option?.dataset.profile ? JSON.parse(option.dataset.profile) : null;
      values.value = profile?.values || "";
      name.value = profile?.name || "";
      sessionStorage.setItem(storageKey, select.value);
      status.textContent = profile ? `Loaded “${profile.name}”.` : "Ready for a new unsaved list.";
    });

    const savedProfile = sessionStorage.getItem(storageKey);
    if (savedProfile && [...select.options].some((option) => option.value === savedProfile)) {
      select.value = savedProfile;
      select.dispatchEvent(new Event("change"));
    }

    manager.querySelector(".port-save-profile").addEventListener("click", async () => {
      const body = new FormData();
      body.set("name", name.value);
      body.set("original_name", select.value);
      body.set("values", values.value);
      const response = await fetch(manager.dataset.saveUrl, {method: "POST", body});
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error || "Profile could not be saved.";
        return;
      }
      sessionStorage.setItem(storageKey, payload.profile.name);
      window.location.reload();
    });

    manager.querySelector(".port-delete-profile").addEventListener("click", async () => {
      if (!select.value || !window.confirm(`Delete profile “${select.value}”?`)) return;
      const body = new FormData();
      body.set("name", select.value);
      const response = await fetch(manager.dataset.deleteUrl, {method: "POST", body});
      const payload = await response.json();
      if (!response.ok) {
        status.textContent = payload.error || "Profile could not be deleted.";
        return;
      }
      sessionStorage.removeItem(storageKey);
      window.location.reload();
    });
  });
})();
