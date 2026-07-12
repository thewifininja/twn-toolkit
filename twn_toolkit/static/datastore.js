(() => {
  const browser = document.querySelector("[data-datastore-browser]");
  const upload = document.querySelector("[data-datastore-upload]");
  if (!browser || !upload) return;

  const viewButtons = [...document.querySelectorAll("[data-datastore-view]")];
  const selectedInputs = [...browser.querySelectorAll("[data-datastore-select]")];
  const toolbar = document.querySelector("[data-datastore-bulk-toolbar]");
  const count = document.querySelector("[data-datastore-selected-count]");
  const selectAll = document.querySelector("[data-datastore-select-all]");
  const destination = document.querySelector("[data-datastore-destination]");
  const moveButton = document.querySelector("[data-datastore-move]");
  const deleteButton = document.querySelector("[data-datastore-delete]");
  const moveForm = document.querySelector("[data-datastore-move-form]");
  const deleteForm = document.querySelector("[data-datastore-delete-form]");
  const uploadInput = upload.querySelector("input[type='file']");
  let dragGhost = null;

  const clearInternalDrag = () => {
    browser.classList.remove("datastore-is-dragging");
    for (const row of browser.querySelectorAll(".drag-source, .drag-target, .drag-target-invalid")) {
      row.classList.remove("drag-source", "drag-target", "drag-target-invalid");
    }
    dragGhost?.remove();
    dragGhost = null;
    updateSelection();
  };

  const makeDragGhost = (paths, row) => {
    dragGhost?.remove();
    const name = row.querySelector(".datastore-entry-name strong")?.textContent?.trim() || "item";
    const ghost = document.createElement("div");
    ghost.className = "datastore-drag-ghost";
    const icon = document.createElement("span"); icon.setAttribute("aria-hidden", "true"); icon.textContent = "↳";
    const copy = document.createElement("div");
    const title = document.createElement("strong"); title.textContent = paths.length === 1 ? name : `${paths.length} items`;
    const note = document.createElement("small"); note.textContent = "Move to a folder";
    copy.append(title, note); ghost.append(icon, copy);
    document.body.appendChild(ghost);
    dragGhost = ghost;
    return ghost;
  };

  const validFolderDestination = (folderPath, paths) => !paths.some(
    (path) => folderPath === path || folderPath.startsWith(`${path}/`)
  );

  const selectedPaths = () => selectedInputs.filter((input) => input.checked).map((input) => input.value);

  const updateSelection = () => {
    const paths = selectedPaths();
    if (toolbar) toolbar.hidden = paths.length === 0;
    if (count) count.textContent = String(paths.length);
    if (selectAll) {
      selectAll.checked = selectedInputs.length > 0 && paths.length === selectedInputs.length;
      selectAll.indeterminate = paths.length > 0 && paths.length < selectedInputs.length;
    }
    if (moveButton) moveButton.disabled = paths.length === 0 || !destination?.options.length;
    if (deleteButton) deleteButton.disabled = paths.length === 0;
  };

  const applyView = (view) => {
    const normalized = view === "grid" ? "grid" : "list";
    browser.dataset.view = normalized;
    for (const button of viewButtons) {
      const active = button.dataset.datastoreView === normalized;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    }
    try { localStorage.setItem("twn-datastore-view", normalized); } catch (_error) {}
  };

  let savedView = "list";
  try { savedView = localStorage.getItem("twn-datastore-view") || "list"; } catch (_error) {}
  applyView(savedView);
  for (const button of viewButtons) {
    button.addEventListener("click", () => applyView(button.dataset.datastoreView));
  }

  for (const input of selectedInputs) input.addEventListener("change", updateSelection);
  selectAll?.addEventListener("change", () => {
    for (const input of selectedInputs) input.checked = selectAll.checked;
    updateSelection();
  });
  destination?.addEventListener("change", updateSelection);

  moveButton?.addEventListener("click", () => {
    const paths = selectedPaths();
    if (!paths.length || !destination?.options.length || !moveForm) return;
    moveForm.elements.paths_json.value = JSON.stringify(paths);
    moveForm.elements.destination.value = destination.value;
    moveForm.requestSubmit();
  });

  deleteButton?.addEventListener("click", () => {
    const paths = selectedPaths();
    if (!paths.length || !deleteForm) return;
    if (!confirm(`Delete ${paths.length} selected item${paths.length === 1 ? "" : "s"}? Folders must be empty.`)) return;
    deleteForm.elements.paths_json.value = JSON.stringify(paths);
    deleteForm.requestSubmit();
  });

  const setDroppedFiles = (files) => {
    if (!files?.length || !uploadInput) return;
    const transfer = new DataTransfer();
    for (const file of files) transfer.items.add(file);
    uploadInput.files = transfer.files;
    upload.requestSubmit();
  };

  for (const eventName of ["dragenter", "dragover"]) {
    upload.addEventListener(eventName, (event) => {
      if (![...event.dataTransfer.types].includes("Files")) return;
      event.preventDefault();
      upload.classList.add("drag-active");
    });
  }
  for (const eventName of ["dragleave", "dragend"]) {
    upload.addEventListener(eventName, () => upload.classList.remove("drag-active"));
  }
  upload.addEventListener("drop", (event) => {
    event.preventDefault();
    upload.classList.remove("drag-active");
    setDroppedFiles(event.dataTransfer.files);
  });
  uploadInput?.addEventListener("change", () => {
    if (uploadInput.files.length) upload.requestSubmit();
  });

  for (const row of browser.querySelectorAll("[data-datastore-entry]")) {
    row.addEventListener("dragstart", (event) => {
      const checkbox = row.querySelector("[data-datastore-select]");
      if (checkbox && !checkbox.checked) {
        for (const input of selectedInputs) input.checked = false;
        checkbox.checked = true;
      }
      event.dataTransfer.effectAllowed = "move";
      const paths = selectedPaths();
      event.dataTransfer.setData("application/x-twn-datastore-items", JSON.stringify(paths));
      event.dataTransfer.setData("text/plain", paths.join("\n"));
      const ghost = makeDragGhost(paths, row);
      event.dataTransfer.setDragImage(ghost, 24, 24);
      browser.classList.add("datastore-is-dragging");
      for (const input of selectedInputs) {
        if (input.checked) input.closest("[data-datastore-entry]")?.classList.add("drag-source");
      }
    });
    row.addEventListener("dragend", clearInternalDrag);
  }

  for (const folder of browser.querySelectorAll("[data-datastore-folder]")) {
    folder.addEventListener("dragover", (event) => {
      if (!event.dataTransfer.types.includes("application/x-twn-datastore-items")) return;
      event.preventDefault();
      const paths = selectedPaths();
      const valid = validFolderDestination(folder.dataset.datastoreFolder, paths);
      event.dataTransfer.dropEffect = valid ? "move" : "none";
      folder.classList.toggle("drag-target", valid);
      folder.classList.toggle("drag-target-invalid", !valid);
    });
    folder.addEventListener("dragleave", (event) => {
      if (event.relatedTarget && folder.contains(event.relatedTarget)) return;
      folder.classList.remove("drag-target", "drag-target-invalid");
    });
    folder.addEventListener("drop", (event) => {
      event.preventDefault();
      folder.classList.remove("drag-target", "drag-target-invalid");
      if (!moveForm) return;
      const paths = JSON.parse(event.dataTransfer.getData("application/x-twn-datastore-items") || "[]");
      if (!paths.length || !validFolderDestination(folder.dataset.datastoreFolder, paths)) return;
      moveForm.elements.paths_json.value = JSON.stringify(paths);
      moveForm.elements.destination.value = folder.dataset.datastoreFolder;
      moveForm.requestSubmit();
    });
  }

  document.addEventListener("drop", clearInternalDrag);

  updateSelection();
})();
