(() => {
  const form = document.querySelector("#dns-form");
  if (!form) return;

  const status = document.querySelector("#dns-profile-status");
  const submit = form.querySelector("[data-dns-submit]");
  const modeLabel = form.querySelector("[data-dns-mode-label]");
  const modeDescription = form.querySelector("[data-dns-mode-description]");
  const loadOnly = [...form.querySelectorAll("[data-dns-load-only]")];
  const authorized = form.elements.authorized;
  const estimate = form.querySelector("[data-dns-load-estimate]");
  const fields = {
    hosts: document.querySelector("#dns-hosts"),
    servers: document.querySelector("#dns-servers"),
  };

  const formatValues = (kind, values) => values.map((item) => {
    const value = kind === "hosts" ? item.host : item.address;
    return item.label ? `${item.label} = ${value}` : value;
  }).join("\n");

  const nonEmptyLineCount = (value) => value
    .split("\n")
    .filter((line) => line.trim())
    .length;

  const updateEstimate = () => {
    if (!estimate) return;
    const resolverCount = nonEmptyLineCount(fields.servers?.value || "");
    const duration = Number(form.elements.duration?.value || 0);
    const qps = Number(form.elements.qps?.value || 0);
    if (!resolverCount || !duration || !qps) {
      estimate.textContent = "Enter resolvers, duration, and rate to estimate the query count.";
      estimate.classList.remove("error");
      return;
    }
    const queryCount = resolverCount * duration * qps;
    const maxQueries = Number(form.dataset.dnsMaxLoadQueries || 0);
    const maxServers = Number(form.dataset.dnsMaxLoadServers || 0);
    estimate.textContent = `${resolverCount} resolver${resolverCount === 1 ? "" : "s"} · approximately ${queryCount.toLocaleString()} total quer${queryCount === 1 ? "y" : "ies"}.`;
    const overLimit = queryCount > maxQueries || resolverCount > maxServers;
    estimate.classList.toggle("error", overLimit);
    if (overLimit) {
      estimate.textContent += ` Reduce the settings to at most ${maxServers} resolvers and ${maxQueries.toLocaleString()} queries.`;
    }
  };

  const updateMode = () => {
    const mode = form.elements.mode.value;
    const isLoad = mode === "load";
    loadOnly.forEach((element) => {
      element.hidden = !isLoad;
    });
    if (authorized) authorized.required = isLoad;
    if (submit) submit.textContent = isLoad ? "Run load test" : "Run comparison";
    if (modeLabel) modeLabel.textContent = isLoad ? "Controlled load" : "Comparison";
    if (modeDescription) {
      modeDescription.textContent = isLoad
        ? "Set a per-resolver query rate, duration, and global concurrency limit."
        : "Choose the record type and how long each lookup may wait.";
    }
    form.dataset.loadingMessage = isLoad
      ? "Running controlled DNS load test…"
      : "Comparing DNS responses…";
    updateEstimate();
  };

  const updateProfileControls = (kind) => {
    const select = form.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
    const deleteButton = form.querySelector(`.dns-delete-profile[data-kind="${kind}"]`);
    if (deleteButton) deleteButton.disabled = !select?.value;
  };

  form.querySelectorAll("[name='mode']").forEach((radio) => {
    radio.addEventListener("change", updateMode);
  });
  ["duration", "qps"].forEach((name) => {
    form.elements[name]?.addEventListener("input", updateEstimate);
  });
  fields.servers?.addEventListener("input", updateEstimate);

  form.querySelectorAll(".dns-profile-select").forEach((select) => {
    const storageKey = `twn:dns:${select.dataset.kind}`;
    select.addEventListener("change", () => {
      const kind = select.dataset.kind;
      const option = select.selectedOptions[0];
      if (!option?.dataset.values) {
        fields[kind].value = "";
        form.querySelector(`.profile-name-input[data-kind="${kind}"]`).value = "";
        sessionStorage.removeItem(storageKey);
        updateProfileControls(kind);
        updateEstimate();
        return;
      }
      fields[kind].value = formatValues(kind, JSON.parse(option.dataset.values));
      form.querySelector(`.profile-name-input[data-kind="${kind}"]`).value = option.value;
      sessionStorage.setItem(storageKey, select.value);
      updateProfileControls(kind);
      updateEstimate();
    });
    const savedProfile = sessionStorage.getItem(storageKey);
    if (
      savedProfile
      && !fields[select.dataset.kind].value.trim()
      && [...select.options].some((option) => option.value === savedProfile)
    ) {
      select.value = savedProfile;
      select.dispatchEvent(new Event("change"));
    }
    updateProfileControls(select.dataset.kind);
  });

  // Serialize mutations of each list while leaving its query text and the
  // other list editable. Restoring controls never restores stale field values.
  const pendingProfiles = new Set();
  const beginProfileMutation = (kind, button) => {
    if (pendingProfiles.has(kind)) return null;
    pendingProfiles.add(kind);
    const manager = button.closest("[data-saved-profile-manager]");
    const controls = Array.from(manager.querySelectorAll("button, select, input"))
      .map((control) => [control, control.disabled]);
    controls.forEach(([control]) => { control.disabled = true; });
    manager.setAttribute("aria-busy", "true");
    return (saved) => {
      pendingProfiles.delete(kind);
      controls.forEach(([control, disabled]) => { control.disabled = disabled; });
      manager.removeAttribute("aria-busy");
      if (saved) manager.dispatchEvent(new Event("savedprofilesaved"));
      updateProfileControls(kind);
    };
  };

  const selectSavedProfile = (kind, profile) => {
    const select = form.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
    let option = Array.from(select.options).find((item) => item.value === profile.name);
    if (!option) {
      option = new Option(profile.name, profile.name);
      select.add(option);
    }
    option.dataset.values = JSON.stringify(profile.values);
    select.value = profile.name;
    form.querySelector(`.profile-name-input[data-kind="${kind}"]`).value = profile.name;
    // Do not dispatch change: loading saved values would erase current edits.
    sessionStorage.setItem(`twn:dns:${kind}`, profile.name);
  };

  form.querySelectorAll(".dns-save-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const finish = beginProfileMutation(kind, button);
      if (!finish) return;
      status.textContent = `Saving ${kind === "hosts" ? "query" : "resolver"} list…`;
      let saved = false;
      const submittedValues = fields[kind].value;
      const body = new FormData();
      body.set(
        "profile_name",
        form.querySelector(`.profile-name-input[data-kind="${kind}"]`).value,
      );
      body.set("values", submittedValues);
      try {
        const response = await fetch(`/tools/dns-response/profiles/${kind}`, {
          method: "POST",
          body,
        });
        const payload = await response.json();
        if (!response.ok) {
          status.textContent = payload.error;
          return;
        }
        selectSavedProfile(kind, payload.profile);
        saved = true;
        status.textContent = `Saved ${kind === "hosts" ? "query" : "resolver"} profile “${payload.profile.name}”.`;
        if (fields[kind].value !== submittedValues) {
          status.textContent += " Later edits remain in the list and have not been saved.";
        }
      } catch (_error) {
        status.textContent = "Could not confirm the save. Your current inputs are still here; check the saved list before retrying.";
      } finally {
        finish(saved);
      }
    });
  });

  form.querySelectorAll(".dns-delete-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const select = form.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
      if (pendingProfiles.has(kind) || !select.value
        || !window.confirm(`Delete profile “${select.value}”?`)) return;
      const deletedName = select.value;
      const finish = beginProfileMutation(kind, button);
      if (!finish) return;
      status.textContent = `Deleting saved profile “${deletedName}”…`;
      let deleted = false;
      const body = new FormData();
      body.set("name", deletedName);
      try {
        const response = await fetch(
          `/tools/dns-response/profiles/${kind}/delete`,
          {method: "POST", body},
        );
        const payload = await response.json();
        if (!response.ok) {
          status.textContent = payload.error;
          return;
        }
        Array.from(select.options).filter((option) => option.value === deletedName)
          .forEach((option) => option.remove());
        select.value = "";
        sessionStorage.removeItem(`twn:dns:${kind}`);
        deleted = true;
        status.textContent = `Deleted profile “${deletedName}”. Current inputs remain as an unsaved list.`;
      } catch (_error) {
        status.textContent = "Could not confirm the deletion. Your current inputs are still here; check the saved list before retrying.";
      } finally {
        finish(deleted);
      }
    });
  });

  form.querySelectorAll("[data-dns-profile-duplicate]").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.closest("[data-saved-profile-manager]")
        .querySelector(".dns-profile-select").dataset.kind;
      const select = form.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
      if (!select.value) return;
      const name = select.value;
      const finish = beginProfileMutation(kind, button);
      if (!finish) return;
      status.textContent = `Duplicating saved profile “${name}”…`;
      let duplicated = false;
      try {
        const response = await fetch(button.dataset.dnsProfileDuplicate, {
          method: "POST", body: new URLSearchParams({name}),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "The profile could not be duplicated.");
        selectSavedProfile(kind, payload.profile);
        duplicated = true;
        status.textContent = `Duplicated saved profile as “${payload.profile.name}”. Current inputs are unchanged; edits are not part of the saved copy until you save them.`;
      } catch (error) {
        status.textContent = error.message || "Could not confirm the duplicate. Check the saved list before retrying.";
      } finally {
        finish(duplicated);
      }
    });
  });

  updateMode();
})();
