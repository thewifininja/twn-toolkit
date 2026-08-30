(() => {
  const showWorkspace = (workspace, { updateUrl = true } = {}) => {
    const tabs = [...document.querySelectorAll("[data-ssh-workspace-tab]")];
    const panels = [...document.querySelectorAll("[data-ssh-workspace-panel]")];
    if (!tabs.some((tab) => tab.dataset.sshWorkspaceTab === workspace)) return;
    tabs.forEach((tab) => {
      const selected = tab.dataset.sshWorkspaceTab === workspace;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.dataset.sshWorkspacePanel !== workspace;
    });
    document.querySelectorAll('input[name="workspace"]').forEach((input) => {
      if (input.closest(".multi-ssh-matrix-picker")) input.value = workspace;
    });
    if (updateUrl) {
      const url = new URL(window.location.href);
      url.searchParams.set("workspace", workspace);
      window.history.replaceState({}, "", url);
    }
  };

  const workspaceTabs = document.querySelector("[data-ssh-workspace-tabs]");
  workspaceTabs?.addEventListener("click", (event) => {
    const tab = event.target.closest("[data-ssh-workspace-tab]");
    if (tab) showWorkspace(tab.dataset.sshWorkspaceTab);
  });
  workspaceTabs?.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = [...workspaceTabs.querySelectorAll("[data-ssh-workspace-tab]")];
    const current = tabs.indexOf(document.activeElement);
    if (current < 0) return;
    event.preventDefault();
    const next = event.key === "Home"
      ? 0
      : event.key === "End"
        ? tabs.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    tabs[next].focus();
    showWorkspace(tabs[next].dataset.sshWorkspaceTab);
  });
  document.querySelectorAll("[data-ssh-open-workspace]").forEach((button) => {
    button.addEventListener("click", () => {
      const workspace = button.dataset.sshOpenWorkspace;
      showWorkspace(workspace);
      document.querySelector(`[data-ssh-workspace-tab="${workspace}"]`)?.focus();
    });
  });

  const matrixSelector = document.querySelector("[data-ssh-matrix-selector]");
  matrixSelector?.addEventListener("change", () => matrixSelector.form?.requestSubmit());
  const actionSelector = document.querySelector("[data-ssh-action-selector]");
  actionSelector?.addEventListener("change", () => actionSelector.form?.requestSubmit());

  const actionCommands = document.querySelector("[data-ssh-action-commands]");
  document.querySelector("[data-ssh-action-variable-picker]")?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-ssh-variable]");
    if (!button || !actionCommands) return;
    const insertion = `{{ ${button.dataset.sshVariable} }}`;
    const start = actionCommands.selectionStart ?? actionCommands.value.length;
    const end = actionCommands.selectionEnd ?? actionCommands.value.length;
    actionCommands.setRangeText(insertion, start, end, "end");
    actionCommands.focus();
    actionCommands.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const hostForm = document.querySelector("[data-ssh-host-form]");
  const matrixRoot = hostForm?.querySelector("[data-ssh-matrix-editor]");
  let matrixEditor = null;
  if (hostForm && matrixRoot && globalThis.TwnSshMatrixEditor) {
    matrixEditor = globalThis.TwnSshMatrixEditor.create(matrixRoot);
    const hostImport = hostForm.querySelector("[data-ssh-host-import]");
    const hostImportInput = hostImport?.querySelector("[data-ssh-host-import-input]");
    const hostImportMode = hostImport?.querySelector("[data-ssh-host-import-mode]");
    const hostImportButton = hostImport?.querySelector("[data-ssh-host-import-submit]");
    const hostImportError = hostImport?.querySelector("[data-ssh-host-import-error]");
    const setHostImportError = (message = "") => {
      if (!hostImportError) return;
      hostImportError.textContent = message;
      hostImportError.hidden = !message;
    };

    hostImportInput?.addEventListener("input", () => setHostImportError());
    hostImportButton?.addEventListener("click", async () => {
      const hosts = hostImportInput.value.trim();
      if (!hosts) {
        setHostImportError("Enter at least one host or IP range to import.");
        hostImportInput.focus();
        return;
      }
      const originalLabel = hostImportButton.textContent;
      hostImportButton.disabled = true;
      hostImportButton.textContent = "Importing…";
      setHostImportError();
      try {
        const response = await fetch(hostImport.dataset.sshHostImportUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
          body: new URLSearchParams({ hosts }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || "The host list could not be imported.");
        matrixEditor.importTargets(payload.targets, {
          replace: hostImportMode.value === "replace",
        });
        hostImportInput.value = "";
        hostImport.open = false;
      } catch (error) {
        setHostImportError(error.message || "The host list could not be imported.");
      } finally {
        hostImportButton.disabled = false;
        hostImportButton.textContent = originalLabel;
      }
    });

    hostForm.addEventListener("submit", (event) => {
      const matrix = hostForm.querySelector("[data-ssh-matrix]");
      if (matrixEditor.mode === "grid") matrixEditor.sync();
      if (matrixEditor.mode === "grid" && !matrixEditor.validate({ focus: true, requireTargets: true })) {
        event.preventDefault();
        return;
      }
      if (matrixEditor.mode === "raw") {
        try {
          matrixEditor.parse(matrix.value);
        } catch (error) {
          event.preventDefault();
          const message = matrixRoot.querySelector("[data-ssh-matrix-error]");
          message.textContent = error.message;
          message.hidden = false;
          matrix.focus();
        }
      }
    });
  }

  const runForm = document.querySelector("[data-multi-ssh]");
  if (!runForm) return;
  const token = runForm.querySelector("[data-ssh-preview-token]");
  const status = runForm.querySelector("[data-ssh-preview-status]");
  const confirmation = runForm.querySelector("[data-ssh-run-confirmation]");
  const preview = runForm.querySelector("[data-ssh-preview]");
  const previewButton = runForm.querySelector("[data-ssh-preview-button]");
  const summary = runForm.querySelector("[data-ssh-run-summary]");
  const runbook = runForm.querySelector("[data-ssh-runbook]");
  const runbookPicker = runForm.querySelector("[data-ssh-runbook-picker]");
  const runbookAdd = runForm.querySelector("[data-ssh-runbook-add]");
  const runbookCount = runForm.querySelector("[data-ssh-runbook-count]");
  const runbookEmpty = runForm.querySelector("[data-ssh-runbook-empty]");
  const hostCount = Number(runForm.dataset.sshHostCount || 0);

  const markPreviewStale = () => {
    if (!token?.value && !preview) return;
    if (token) token.value = "";
    if (confirmation) {
      confirmation.hidden = true;
      confirmation.querySelectorAll("input, button").forEach((control) => {
        if (control.type === "password") control.value = "";
        control.disabled = true;
      });
    }
    preview?.classList.add("is-stale");
    if (status) {
      status.hidden = false;
      status.textContent = "Runbook changed — preview again.";
    }
  };

  const updateRunSummary = () => {
    const rows = [...(runbook?.querySelectorAll("[data-ssh-runbook-action]") || [])];
    const selected = rows.length;
    rows.forEach((row, index) => {
      row.querySelector("[data-ssh-runbook-number]").textContent = String(index + 1);
      const up = row.querySelector('[data-ssh-runbook-move="up"]');
      const down = row.querySelector('[data-ssh-runbook-move="down"]');
      if (up) up.disabled = index === 0;
      if (down) down.disabled = index === rows.length - 1;
    });
    const selectedNames = new Set(rows.map((row) => row.dataset.sshRunbookAction));
    [...(runbookPicker?.options || [])].forEach((option) => {
      if (option.value) option.disabled = selectedNames.has(option.value);
    });
    previewButton.disabled = selected === 0;
    if (runbookCount) runbookCount.textContent = `${selected} action${selected === 1 ? "" : "s"}`;
    if (runbookEmpty) runbookEmpty.hidden = selected > 0;
    if (summary) {
      summary.textContent = selected
        ? `${selected} action(s) · ${hostCount} host(s) · ${selected * hostCount} action executions`
        : "Add at least one CLI action to build a signed preview.";
    }
  };

  const buildRunbookRow = (option) => {
    const row = document.createElement("article");
    row.className = "multi-ssh-runbook-row";
    row.dataset.sshRunbookAction = option.value;

    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "selected_actions";
    input.value = option.value;

    const number = document.createElement("span");
    number.className = "multi-ssh-action-number";
    number.dataset.sshRunbookNumber = "";

    const description = document.createElement("span");
    const name = document.createElement("strong");
    name.textContent = option.value;
    const variables = document.createElement("small");
    variables.textContent = option.dataset.variables === "No custom variables"
      ? option.dataset.variables
      : `Uses ${option.dataset.variables}`;
    description.append(name, variables);

    const readiness = document.createElement("span");
    readiness.className = "pill success";
    readiness.textContent = "ready";

    const controls = document.createElement("span");
    controls.className = "button-row compact-actions";
    [
      ["↑", "up", `Move ${option.value} up`],
      ["↓", "down", `Move ${option.value} down`],
    ].forEach(([text, direction, label]) => {
      const button = document.createElement("button");
      button.className = "secondary compact";
      button.type = "button";
      button.dataset.sshRunbookMove = direction;
      button.setAttribute("aria-label", label);
      button.textContent = text;
      controls.append(button);
    });
    const remove = document.createElement("button");
    remove.className = "danger compact";
    remove.type = "button";
    remove.dataset.sshRunbookRemove = "";
    remove.setAttribute("aria-label", `Remove ${option.value} from runbook`);
    remove.textContent = "Remove";
    controls.append(remove);

    row.append(input, number, description, readiness, controls);
    return row;
  };

  runbookPicker?.addEventListener("change", () => {
    const option = runbookPicker.selectedOptions[0];
    if (runbookAdd) runbookAdd.disabled = !option?.value || option.disabled;
  });
  runbookAdd?.addEventListener("click", () => {
    const option = runbookPicker?.selectedOptions[0];
    if (!option?.value || option.disabled || !runbook) return;
    runbook.insertBefore(buildRunbookRow(option), runbookEmpty || null);
    runbookPicker.value = "";
    runbookAdd.disabled = true;
    markPreviewStale();
    updateRunSummary();
  });
  runbook?.addEventListener("click", (event) => {
    const row = event.target.closest("[data-ssh-runbook-action]");
    if (!row) return;
    if (event.target.closest("[data-ssh-runbook-remove]")) {
      row.remove();
    } else {
      const move = event.target.closest("[data-ssh-runbook-move]");
      if (!move) return;
      const rows = [...runbook.querySelectorAll("[data-ssh-runbook-action]")];
      const index = rows.indexOf(row);
      if (move.dataset.sshRunbookMove === "up" && index > 0) {
        runbook.insertBefore(row, rows[index - 1]);
      } else if (move.dataset.sshRunbookMove === "down" && index < rows.length - 1) {
        rows[index + 1].after(row);
      } else {
        return;
      }
    }
    markPreviewStale();
    updateRunSummary();
  });
  updateRunSummary();

  runForm.addEventListener("submit", (event) => {
    const action = event.submitter?.value;
    if (["preview", "run"].includes(action) && !runbook?.querySelector("[data-ssh-runbook-action]")) {
      event.preventDefault();
      summary?.scrollIntoView({ block: "nearest" });
      return;
    }
    if (action === "run") {
      runForm.dataset.loadingMessage = "Running previewed SSH actions…";
      return;
    }
    if (confirmation) {
      confirmation.querySelectorAll('[name="username"], [name="password"]').forEach((control) => {
        control.disabled = true;
      });
    }
    delete runForm.dataset.loadingMessage;
  });
})();
