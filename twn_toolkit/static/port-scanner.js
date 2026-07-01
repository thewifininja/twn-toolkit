(function () {
  const scanHosts = document.getElementById("port-scan-hosts");
  const scanPorts = document.getElementById("port-scan-ports");
  const forms = document.querySelectorAll(".port-profile-form");
  if (!scanHosts || !scanPorts || !forms.length) return;

  forms.forEach((form) => {
    const kind = form.dataset.kind;
    const select = form.querySelector(".port-existing-profile");
    const status = form.querySelector(".port-profile-status");

    select.addEventListener("change", () => {
      const option = select.options[select.selectedIndex];
      const profile = option?.dataset.profile ? JSON.parse(option.dataset.profile) : null;
      form.reset();
      select.value = option?.value || "";
      form.elements.original_name.value = option?.value || "";
      if (profile) {
        form.elements.name.value = profile.name;
        form.elements.values.value = profile.values;
        status.textContent = `Loaded '${profile.name}'.`;
      } else {
        status.textContent = "";
      }
    });

    form.querySelector(".port-load-values").addEventListener("click", () => {
      const value = form.elements.values.value;
      if (!value.trim()) {
        status.textContent = `Enter or load ${kind} first.`;
        return;
      }
      (kind === "hosts" ? scanHosts : scanPorts).value = value;
      status.textContent = `Applied ${kind} to the scan form.`;
      document.getElementById("port-scan-form").scrollIntoView({behavior: "smooth"});
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      status.textContent = "Saving...";
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
        submit.disabled = false;
      }
    });

    form.querySelector(".port-delete-profile").addEventListener("click", async () => {
      const name = select.value;
      if (!name) {
        status.textContent = "Select a saved profile to delete.";
        return;
      }
      if (!window.confirm(`Delete '${name}'?`)) return;
      const body = new FormData();
      body.set("name", name);
      try {
        const response = await fetch(form.dataset.deleteUrl, {method: "POST", body});
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Profile could not be deleted.");
        window.location.reload();
      } catch (error) {
        status.textContent = error.message;
      }
    });
  });
})();
