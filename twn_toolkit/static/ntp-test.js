(function () {
  const form = document.getElementById("ntp-form");
  if (!form) return;
  const select = document.getElementById("ntp-profile");
  const hosts = document.getElementById("ntp-hosts");
  const name = document.getElementById("ntp-profile-name");
  const status = document.getElementById("ntp-status");
  const storageKey = "twn:ntp-profile";

  select.addEventListener("change", () => {
    const option = select.selectedOptions[0];
    hosts.value = option?.dataset.values || "";
    name.value = option?.value || "";
    try { sessionStorage.setItem(storageKey, select.value); } catch (_) { /* Selection still works without storage. */ }
  });

  let savedProfile = "";
  try { savedProfile = sessionStorage.getItem(storageKey) || ""; } catch (_) { /* Use the current form. */ }
  if (form.dataset.restoreRememberedProfile === "true" && !hosts.value.trim()
      && !name.value.trim() && !select.value && savedProfile
      && [...select.options].some((option) => option.value === savedProfile)) {
    select.value = savedProfile;
    select.dispatchEvent(new Event("change"));
  }

  document.getElementById("ntp-save-profile").addEventListener("click", async () => {
    const body = new FormData();
    body.set("name", name.value);
    body.set("original_name", select.value);
    body.set("values", hosts.value);
    if (!window.TwnMso.prepare(body, form, "save")) return;
    const response = await fetch(form.dataset.saveProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Profile could not be saved.";
      return;
    }
    try { sessionStorage.setItem(storageKey, payload.profile.name); } catch (_) { /* Save already succeeded. */ }
    window.location.reload();
  });

  document.getElementById("ntp-delete-profile").addEventListener("click", async () => {
    if (!select.value || !window.confirm(window.TwnMso.deleteMessage(form, select.value))) return;
    const body = new FormData();
    body.set("name", select.value);
    if (!window.TwnMso.prepare(body, form, "delete")) return;
    const response = await fetch(form.dataset.deleteProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Profile could not be deleted.";
      return;
    }
    try { sessionStorage.removeItem(storageKey); } catch (_) { /* Delete already succeeded. */ }
    window.location.reload();
  });
})();
