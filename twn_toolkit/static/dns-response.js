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

  form.querySelectorAll(".dns-save-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const body = new FormData();
      body.set(
        "profile_name",
        form.querySelector(`.profile-name-input[data-kind="${kind}"]`).value,
      );
      body.set("values", fields[kind].value);
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
        sessionStorage.setItem(`twn:dns:${kind}`, payload.profile.name);
        status.textContent = `Saved ${kind === "hosts" ? "query" : "resolver"} profile “${payload.profile.name}”. Reloading…`;
        window.location.reload();
      } catch (_error) {
        status.textContent = "The profile could not be saved. Try again.";
      }
    });
  });

  form.querySelectorAll(".dns-delete-profile").forEach((button) => {
    button.addEventListener("click", async () => {
      const kind = button.dataset.kind;
      const select = form.querySelector(`.dns-profile-select[data-kind="${kind}"]`);
      if (!select.value || !window.confirm(`Delete profile “${select.value}”?`)) return;
      const body = new FormData();
      body.set("name", select.value);
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
        sessionStorage.removeItem(`twn:dns:${kind}`);
        window.location.reload();
      } catch (_error) {
        status.textContent = "The profile could not be deleted. Try again.";
      }
    });
  });

  updateMode();
})();
