(() => {
  const form = document.querySelector("[data-multi-ssh-advanced]");
  if (!form) return;

  const matrix = form.querySelector("[data-ssh-matrix]");
  const commands = form.querySelector("[data-ssh-commands]");
  const timeout = form.querySelector("[data-ssh-timeout]");
  const picker = form.querySelector("[data-ssh-variable-picker]");
  const token = form.querySelector("[data-ssh-preview-token]");
  const status = form.querySelector("[data-ssh-preview-status]");
  const confirmation = form.querySelector("[data-ssh-run-confirmation]");
  const preview = form.querySelector("[data-ssh-preview]");

  const normalize = (value) => {
    const normalized = value.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
    if (["ip_fqdn", "fqdn", "address", "target"].includes(normalized)) return "host";
    if (["friendly_name", "friendly_label", "label"].includes(normalized)) return "name";
    return normalized;
  };

  const headerVariables = () => {
    const header = (matrix.value.split(/\r?\n/).find((line) => line.trim()) || "").trim();
    const delimiter = header.includes("\t") ? "\t" : header.includes("|") ? "|" : header.includes(",") ? "," : "";
    if (!delimiter) return [];
    let values = header.split(delimiter).map((value) => value.trim());
    if (delimiter === "|" && !values[0]) values = values.slice(1);
    if (delimiter === "|" && !values.at(-1)) values = values.slice(0, -1);
    return values.map(normalize).filter((value) => /^[a-z][a-z0-9_]*$/.test(value));
  };

  const insertVariable = (name) => {
    const insertion = `{{ ${name} }}`;
    const start = commands.selectionStart ?? commands.value.length;
    const end = commands.selectionEnd ?? commands.value.length;
    commands.setRangeText(insertion, start, end, "end");
    commands.focus();
    commands.dispatchEvent(new Event("input", { bubbles: true }));
  };

  const updateVariablePicker = () => {
    picker.querySelectorAll("[data-ssh-variable-dynamic]").forEach((element) => element.remove());
    const builtIns = new Set(["name", "host", "row_number"]);
    [...new Set(headerVariables())].filter((name) => !builtIns.has(name)).forEach((name) => {
      const button = document.createElement("button");
      button.className = "secondary ssh-variable-chip";
      button.type = "button";
      button.dataset.sshVariable = name;
      button.dataset.sshVariableDynamic = "";
      button.textContent = `{{ ${name} }}`;
      picker.append(button);
    });
  };

  const markPreviewStale = () => {
    if (!token.value && !preview) return;
    token.value = "";
    if (confirmation) {
      confirmation.hidden = true;
      confirmation.querySelectorAll("input, button").forEach((control) => {
        if (control.type === "password") control.value = "";
        control.disabled = true;
      });
    }
    if (preview) preview.classList.add("is-stale");
    status.hidden = false;
    status.textContent = "Targets or commands changed — preview again.";
  };

  picker.addEventListener("click", (event) => {
    const button = event.target.closest("[data-ssh-variable]");
    if (button) insertVariable(button.dataset.sshVariable);
  });
  matrix.addEventListener("input", () => {
    updateVariablePicker();
    markPreviewStale();
  });
  commands.addEventListener("input", markPreviewStale);
  timeout.addEventListener("input", markPreviewStale);
  form.addEventListener("submit", (event) => {
    const action = event.submitter?.value;
    if (action === "run") {
      form.dataset.loadingMessage = "Running previewed SSH commands…";
    } else {
      if (confirmation) {
        confirmation.querySelectorAll('[name="username"], [name="password"]').forEach((control) => {
          control.disabled = true;
        });
      }
      delete form.dataset.loadingMessage;
    }
  });

  updateVariablePicker();
})();
