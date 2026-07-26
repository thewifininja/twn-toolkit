(() => {
  const form = document.querySelector("[data-multi-ssh]");
  if (!form || !globalThis.TwnSshMatrixEditor) return;

  const matrixRoot = form.querySelector("[data-ssh-matrix-editor]");
  const matrix = form.querySelector("[data-ssh-matrix]");
  const commands = form.querySelector("[data-ssh-commands]");
  const timeout = form.querySelector("[data-ssh-timeout]");
  const picker = form.querySelector("[data-ssh-variable-picker]");
  const token = form.querySelector("[data-ssh-preview-token]");
  const status = form.querySelector("[data-ssh-preview-status]");
  const confirmation = form.querySelector("[data-ssh-run-confirmation]");
  const preview = form.querySelector("[data-ssh-preview]");

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

  const editor = globalThis.TwnSshMatrixEditor.create(matrixRoot, {
    commands,
    picker,
    onChange: markPreviewStale,
  });

  const hostImport = form.querySelector("[data-ssh-host-import]");
  const hostImportInput = hostImport?.querySelector(
    "[data-ssh-host-import-input]",
  );
  const hostImportMode = hostImport?.querySelector(
    "[data-ssh-host-import-mode]",
  );
  const hostImportButton = hostImport?.querySelector(
    "[data-ssh-host-import-submit]",
  );
  const hostImportError = hostImport?.querySelector(
    "[data-ssh-host-import-error]",
  );
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
        headers: {
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        body: new URLSearchParams({ hosts }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.error || "The host list could not be imported.");
      }
      editor.importTargets(payload.targets, {
        replace: hostImportMode.value === "replace",
      });
      hostImportInput.value = "";
      hostImport.open = false;
    } catch (error) {
      setHostImportError(
        error.message || "The host list could not be imported.",
      );
    } finally {
      hostImportButton.disabled = false;
      hostImportButton.textContent = originalLabel;
    }
  });

  timeout.addEventListener("input", markPreviewStale);
  form.addEventListener("submit", (event) => {
    const action = event.submitter?.value;
    if (editor.mode === "grid") editor.sync();
    const matrixRequired = action === "preview" || action === "run";
    const saveWithMatrix = action === "save_commandlet"
      && form.querySelector('[name="commandlet_save_matrix"]').checked
      && matrix.value.trim();
    if (
      editor.mode === "grid"
      && (matrixRequired || saveWithMatrix)
      && !editor.validate({ focus: true, requireTargets: matrixRequired })
    ) {
      event.preventDefault();
      return;
    }
    if (editor.mode === "raw" && (matrixRequired || saveWithMatrix)) {
      try {
        editor.parse(matrix.value);
      } catch (error) {
        event.preventDefault();
        matrixRoot.querySelector("[data-ssh-matrix-error]").textContent = error.message;
        matrixRoot.querySelector("[data-ssh-matrix-error]").hidden = false;
        matrix.focus();
        return;
      }
    }
    if (action === "run") {
      form.dataset.loadingMessage = "Running previewed SSH commands…";
    } else {
      if (confirmation) {
        confirmation.querySelectorAll(
          '[name="username"], [name="password"]',
        ).forEach((control) => {
          control.disabled = true;
        });
      }
      delete form.dataset.loadingMessage;
    }
  });
})();
