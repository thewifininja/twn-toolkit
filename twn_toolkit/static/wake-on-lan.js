(function () {
  const form = document.getElementById("wol-form");
  if (!form) return;

  const profile = document.getElementById("wol-profile");
  const targets = document.getElementById("wol-targets");
  const profileName = document.getElementById("wol-profile-name");
  const status = document.getElementById("wol-status");
  const mode = document.getElementById("wol-destination-mode");
  const sourceInterface = document.getElementById("wol-interface");
  const customDestination = document.getElementById("wol-custom-destination");
  const verify = document.getElementById("wol-verify");
  const verifyTimeout = document.getElementById("wol-verify-timeout");
  const storageKey = "twn:wol-profile";

  function updateDestination() {
    const isCustom = mode.value === "custom";
    customDestination.disabled = !isCustom;
    customDestination.required = isCustom;
    const selected = sourceInterface.selectedOptions[0];
    if (isCustom) {
      status.textContent = selected
        ? `Packets will leave ${selected.value} from ${selected.dataset.address} toward the custom destination.`
        : "Select an IPv4 source interface.";
    } else if (selected?.dataset.broadcast) {
      status.textContent = `Packets will leave ${selected.value} from ${selected.dataset.address} toward ${selected.dataset.broadcast}.`;
    } else {
      status.textContent = "This interface does not expose a local broadcast address; choose custom destination mode.";
    }
  }

  function updateVerification() {
    verifyTimeout.disabled = !verify.checked;
  }

  mode.addEventListener("change", updateDestination);
  sourceInterface.addEventListener("change", updateDestination);
  verify.addEventListener("change", updateVerification);
  updateDestination();
  updateVerification();

  profile.addEventListener("change", () => {
    const option = profile.selectedOptions[0];
    targets.value = option?.dataset.values || "";
    profileName.value = option?.value || "";
    sessionStorage.setItem(storageKey, profile.value);
  });

  const savedProfile = sessionStorage.getItem(storageKey);
  if (savedProfile && [...profile.options].some((option) => option.value === savedProfile)) {
    profile.value = savedProfile;
    if (!targets.value.trim()) profile.dispatchEvent(new Event("change"));
  }

  document.getElementById("wol-save-profile").addEventListener("click", async () => {
    const body = new FormData();
    body.set("name", profileName.value);
    body.set("original_name", profile.value);
    body.set("values", targets.value);
    const response = await fetch(form.dataset.saveProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Device group could not be saved.";
      return;
    }
    sessionStorage.setItem(storageKey, payload.profile.name);
    window.location.reload();
  });

  document.getElementById("wol-delete-profile").addEventListener("click", async () => {
    if (!profile.value || !window.confirm(`Delete device group “${profile.value}”?`)) return;
    const body = new FormData();
    body.set("name", profile.value);
    const response = await fetch(form.dataset.deleteProfileUrl, {method: "POST", body});
    const payload = await response.json();
    if (!response.ok) {
      status.textContent = payload.error || "Device group could not be deleted.";
      return;
    }
    sessionStorage.removeItem(storageKey);
    window.location.reload();
  });
})();
