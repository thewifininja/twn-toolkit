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
    sessionStorage.setItem(storageKey, select.value);
  });

  const savedProfile = sessionStorage.getItem(storageKey);
  if (savedProfile && [...select.options].some((option) => option.value === savedProfile)) {
    select.value = savedProfile;
    select.dispatchEvent(new Event("change"));
  }

  document.getElementById("ntp-save-profile").addEventListener("click", async () => {
    const body = new FormData();
    body.set("name", name.value);
    body.set("original_name", select.value);
    body.set("values", hosts.value);
    const response = await fetch(form.dataset.saveProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Profile could not be saved.";
      return;
    }
    sessionStorage.setItem(storageKey, payload.profile.name);
    window.location.reload();
  });

  document.getElementById("ntp-delete-profile").addEventListener("click", async () => {
    if (!select.value || !window.confirm(`Delete profile “${select.value}”?`)) return;
    const body = new FormData();
    body.set("name", select.value);
    const response = await fetch(form.dataset.deleteProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Profile could not be deleted.";
      return;
    }
    sessionStorage.removeItem(storageKey);
    window.location.reload();
  });
})();
