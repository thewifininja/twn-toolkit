(function () {
  const manager = document.getElementById("remote-terminal-manager");
  const initial = document.getElementById("remote-connection-library");
  if (!manager || !initial || !window.TwnRemoteTerminal) return;

  const tree = document.getElementById("remote-connection-tree");
  const search = document.getElementById("remote-connection-search");
  const count = document.getElementById("remote-connection-count");
  const empty = document.getElementById("remote-connection-empty");
  const quickDialog = document.getElementById("remote-quick-connect-dialog");
  const folderDialog = document.getElementById("remote-folder-dialog");
  const hostDialog = document.getElementById("remote-host-dialog");
  const credentialDialog = document.getElementById("remote-credential-dialog");
  const bulkDialog = document.getElementById("remote-library-bulk-dialog");
  const importDialog = document.getElementById("remote-host-import-dialog");
  const explorer = manager.querySelector(".remote-connection-explorer");
  const widthResizer = document.getElementById("remote-connection-width-resizer");
  const quickForm = document.getElementById("remote-terminal-form");
  const folderForm = document.getElementById("remote-folder-form");
  const hostForm = document.getElementById("remote-host-form");
  const credentialForm = document.getElementById("remote-credential-form");
  const bulkForm = document.getElementById("remote-library-bulk-form");
  const importForm = document.getElementById("remote-host-import-form");
  const quickProtocol = document.getElementById("remote-terminal-protocol");
  const hostProtocol = document.getElementById("remote-host-protocol");
  let library = JSON.parse(initial.textContent || "{}");
  // A large connection library should open as an index, not as an already
  // expanded wall of hosts. Searching still opens every matching path.
  let openedFolders = new Set();
  let selectionMode = false;
  const selectedHosts = new Set();
  const selectedFolders = new Set();
  let importPreview = null;
  const defaultLibraryWidth = 330;
  const minimumLibraryWidth = 330;
  const maximumLibraryWidth = 620;
  const libraryWidthKey = "twn.remote-terminal.library-width.v1";
  const libraryCollapsedKey = "twn.remote-terminal.library-collapsed.v1";
  function visibilityLabel(item) {
    const value = String(item.effective_visibility || item.visibility || "private");
    const label = value === "admins_only" ? "Admins Only" : value.charAt(0).toUpperCase() + value.slice(1);
    return item.visibility === "inherit" ? `${label} (inherited)` : label;
  }


  initializeLibraryLayout();

  document.querySelectorAll("[data-open-quick-connect]").forEach((button) => {
    button.addEventListener("click", () => {
      setStatus("remote-terminal-start-status", "");
      openDialog(quickDialog, "remote-terminal-host");
    });
  });
  document.querySelectorAll("[data-open-folder]").forEach((button) => {
    button.addEventListener("click", () => editFolder());
  });
  document.querySelectorAll("[data-open-host]").forEach((button) => {
    button.addEventListener("click", () => editHost());
  });
  document.querySelectorAll("[data-open-credentials]").forEach((button) => {
    button.addEventListener("click", () => openCredentials());
  });
  document.querySelectorAll("[data-open-host-import]").forEach((button) => {
    button.addEventListener("click", openHostImport);
  });
  document.querySelectorAll("[data-dialog-close]").forEach((button) => {
    button.addEventListener("click", () => button.closest("dialog")?.close());
  });
  document.querySelectorAll(".remote-terminal-dialog").forEach((dialog) => {
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
  });
  document.addEventListener("click", (event) => {
    if (
      !event.target.closest(".remote-connection-folder-menu-wrap") &&
      !event.target.closest(".remote-connection-folder-menu")
    ) {
      closeFolderMenus();
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const openMenu = document.querySelector(".remote-connection-folder-menu:not([hidden])");
    if (!openMenu) return;
    const trigger = openMenu.closest(".remote-connection-folder")
      ?.querySelector(".remote-connection-folder-menu-trigger");
    closeFolderMenus();
    trigger?.focus();
  });
  search.addEventListener("input", renderTree);
  quickForm.querySelectorAll('input[name="quick_credential_mode"]').forEach((input) => {
    input.addEventListener("change", syncQuickCredentialMode);
  });
  quickProtocol.addEventListener("change", () => syncProtocolControls("quick"));
  hostProtocol.addEventListener("change", () => syncProtocolControls("host"));
  document.querySelectorAll("[data-refresh-console-devices]").forEach((button) => {
    button.addEventListener("click", () => refreshConsoleDevices(button));
  });
  document.getElementById("remote-host-folder").addEventListener("change", syncHostCredentialMode);
  document.getElementById("remote-folder-parent").addEventListener("change", syncFolderCredentialMode);
  hostForm.querySelectorAll('input[name="host_credential_mode"]').forEach((input) => {
    input.addEventListener("change", syncHostCredentialMode);
  });
  folderForm.querySelectorAll('input[name="folder_credential_mode"]').forEach((input) => {
    input.addEventListener("change", syncFolderCredentialMode);
  });
  folderForm.addEventListener("submit", saveFolder);
  hostForm.addEventListener("submit", saveHost);
  credentialForm.addEventListener("submit", saveCredential);
  bulkForm.addEventListener("submit", saveBulkChanges);
  importForm.addEventListener("submit", submitHostImport);
  document.getElementById("remote-host-import-file").addEventListener("change", loadHostImportFile);
  document.getElementById("remote-host-import-text").addEventListener("input", invalidateHostImport);
  document.getElementById("remote-host-import-folder").addEventListener("change", invalidateHostImport);
  document.getElementById("remote-host-import-protocol").addEventListener("change", invalidateHostImport);
  document.querySelector("[data-collapse-connection-library]").addEventListener("click", () => {
    setLibraryCollapsed(true);
  });
  document.querySelector("[data-show-connection-library]").addEventListener("click", () => {
    setLibraryCollapsed(false);
  });
  document.querySelector("[data-toggle-library-selection]").addEventListener("click", toggleSelectionMode);
  document.querySelector("[data-select-visible]").addEventListener("click", selectVisibleItems);
  document.querySelector("[data-clear-selection]").addEventListener("click", clearSelection);
  document.querySelector("[data-edit-selection]").addEventListener("click", openBulkEditor);
  document.getElementById("remote-library-change-location").addEventListener("change", syncBulkEditor);
  document.getElementById("remote-library-change-credential").addEventListener("change", syncBulkEditor);
  bulkForm.querySelectorAll('input[name="bulk_credential_mode"]').forEach((input) => {
    input.addEventListener("change", syncBulkEditor);
  });
  document.querySelector("[data-new-credential]").addEventListener("click", () => editCredential());
  document.querySelector("[data-duplicate-folder]").addEventListener("click", duplicateFolder);
  document.querySelector("[data-delete-folder]").addEventListener("click", deleteFolder);
  document.querySelector("[data-duplicate-host]").addEventListener("click", duplicateHost);
  document.querySelector("[data-delete-host]").addEventListener("click", deleteHost);
  document.querySelector("[data-duplicate-credential]").addEventListener("click", duplicateCredential);
  document.querySelector("[data-delete-credential]").addEventListener("click", deleteCredential);
  document.addEventListener("twn:remote-session-started", () => {
    if (quickDialog.open) quickDialog.close();
  });
  document.addEventListener("twn:save-session-host", (event) => {
    editHost(null, event.detail || null);
  });

  function render() {
    library.folders ||= [];
    library.hosts ||= [];
    library.credentials ||= [];
    count.textContent = `${library.hosts.length} host${library.hosts.length === 1 ? "" : "s"}`;
    empty.hidden = library.hosts.length > 0 || library.folders.length > 0;
    tree.hidden = !empty.hidden;
    renderTree();
    populateFolderSelects();
    populateCredentialSelects();
    renderCredentials();
    syncQuickCredentialMode();
    syncHostCredentialMode();
    syncFolderCredentialMode();
    syncProtocolControls("quick", true);
    syncProtocolControls("host", true);
    updateSelectionBar();
  }

  function renderTree() {
    const query = search.value.trim().toLocaleLowerCase();
    const root = document.createDocumentFragment();
    const rootHosts = matchingHosts("");
    rootHosts.forEach((host) => root.append(hostRow(host)));
    library.folders
      .filter((folder) => !folder.parent_id)
      .sort(byName)
      .forEach((folder) => {
        const node = folderNode(folder, query);
        if (node) root.append(node);
      });
    if (query && !root.childNodes.length) {
      const noMatch = document.createElement("p");
      noMatch.className = "remote-connection-no-match";
      noMatch.textContent = "No saved connections match that search.";
      root.append(noMatch);
    }
    tree.replaceChildren(root);

    function matchingHosts(folderId) {
      return library.hosts
        .filter((host) => host.folder_id === folderId)
        .filter((host) => !query || hostSearchText(host).includes(query))
        .sort(byName);
    }
  }

  function folderNode(folder, query) {
    const childFolders = library.folders.filter((item) => item.parent_id === folder.id).sort(byName);
    const directHosts = library.hosts.filter((host) => host.folder_id === folder.id).sort(byName);
    const folderMatches = !query || folder.name.toLocaleLowerCase().includes(query);
    const visibleHosts = directHosts.filter((host) => folderMatches || hostSearchText(host).includes(query));
    const childNodes = childFolders.map((child) => folderNode(child, query)).filter(Boolean);
    if (query && !folderMatches && !visibleHosts.length && !childNodes.length) return null;

    const container = document.createElement("section");
    container.className = "remote-connection-folder";
    const head = document.createElement("div");
    head.className = "remote-connection-folder-head";
    if (selectionMode) head.classList.add("selecting");
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "remote-connection-folder-toggle";
    const bodyId = `${folder.id}-contents`;
    toggle.setAttribute("aria-controls", bodyId);
    const folderIcon = document.createElement("span");
    folderIcon.className = "remote-connection-folder-icon";
    folderIcon.setAttribute("aria-hidden", "true");
    const name = document.createElement("strong");
    name.textContent = folder.name;
    const itemCount = document.createElement("small");
    itemCount.textContent = String(directHosts.length + childFolders.length);
    toggle.append(folderIcon, name, itemCount);
    toggle.title = `${folderCredentialSummary(folder)} Availability: ${visibilityLabel(folder)}.${folder.owned ? "" : ` Owner ID: ${folder.user_id}.`}`;

    const menuWrap = document.createElement("div");
    menuWrap.className = "remote-connection-folder-menu-wrap";
    const menuTrigger = document.createElement("button");
    menuTrigger.type = "button";
    menuTrigger.className = "remote-connection-folder-menu-trigger";
    menuTrigger.textContent = "•••";
    menuTrigger.title = `Actions for ${folder.name}`;
    menuTrigger.setAttribute("aria-label", `Actions for ${folder.name}`);
    menuTrigger.setAttribute("aria-haspopup", "menu");
    menuTrigger.setAttribute("aria-expanded", "false");
    const menu = document.createElement("div");
    menu.className = "remote-connection-folder-menu";
    menu.id = `${folder.id}-actions`;
    menu.setAttribute("role", "menu");
    menu.hidden = true;
    menuTrigger.setAttribute("aria-controls", menu.id);
    menuTrigger.hidden = !folder.owned;
    menu.append(
      folderMenuAction("Add host", () => editHost(folder.id)),
      folderMenuAction("Add subfolder", () => editFolder(null, folder.id)),
      folderMenuAction("Edit folder", () => editFolder(folder))
    );
    menuTrigger.addEventListener("click", (event) => {
      event.stopPropagation();
      const willOpen = menu.hidden;
      closeFolderMenus();
      menu.hidden = !willOpen;
      menuTrigger.setAttribute("aria-expanded", String(willOpen));
      if (willOpen && event.detail === 0) menu.querySelector("button")?.focus();
    });
    menuWrap.append(menuTrigger);
    if (selectionMode && folder.owned) {
      head.append(selectionControl("folder", folder.id, folder.name));
    }
    head.append(toggle, menuWrap);

    const body = document.createElement("div");
    body.className = "remote-connection-folder-body";
    body.id = bodyId;
    body.append(...visibleHosts.map(hostRow), ...childNodes);
    const setExpanded = (expanded) => {
      toggle.setAttribute("aria-expanded", String(expanded));
      body.hidden = !expanded;
      if (expanded) openedFolders.add(folder.id);
      else openedFolders.delete(folder.id);
    };
    toggle.addEventListener("click", () => {
      setExpanded(toggle.getAttribute("aria-expanded") !== "true");
    });
    setExpanded(Boolean(query) || openedFolders.has(folder.id));
    container.append(head, menu, body);
    return container;
  }

  function hostRow(host) {
    const row = document.createElement("div");
    row.className = "remote-connection-host";
    if (selectionMode) row.classList.add("selecting");
    row.dataset.hostId = host.id;
    const connect = document.createElement("button");
    connect.type = "button";
    connect.className = "remote-connection-host-connect";
    const icon = document.createElement("span");
    icon.className = "remote-connection-host-icon";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = ">_";
    const identity = document.createElement("span");
    const title = document.createElement("strong");
    title.textContent = `${host.name}${host.owned ? "" : " · Shared"}`;
    const target = document.createElement("small");
    const remoteUsername = String(host.effective_remote_username || "").trim();
    const inherited = host.credential_source === "folder";
    const missing = !host.effective_credential_id;
    const unavailable = !missing && host.credential_available === false;
    if (host.protocol === "console") {
      const line = `${host.console_baud_rate} ${host.console_data_bits}${String(host.console_parity || "none").charAt(0).toUpperCase()}${host.console_stop_bits}`;
      const state = host.console_in_use ? " · in use" : host.console_available ? "" : " · detached";
      target.textContent = `CONSOLE · ${host.console_device_label || host.console_device_path} · ${line}${state}`;
    } else {
      target.textContent = `${String(host.protocol || "ssh").toUpperCase()} · ${remoteUsername ? `${remoteUsername}@` : ""}${host.host}:${host.port}${unavailable ? " · credential unavailable" : inherited ? " · inherited" : missing ? " · no credential" : ""}`;
    }
    target.title = `${hostCredentialSummary(host)} Availability: ${visibilityLabel(host)}.${host.owned ? "" : ` Owner ID: ${host.user_id}.`}`;
    identity.append(title, target);
    connect.append(icon, identity);
    connect.title = `Connect to ${host.name}`;
    if (unavailable) {
      connect.disabled = true;
      connect.title = "This host is more broadly available than its credential.";
    }
    connect.addEventListener("click", () => {
      if (selectionMode) {
        toggleSelected("host", host.id);
        return;
      }
      connectHost(host, connect);
    });
    const manage = document.createElement("button");
    manage.type = "button";
    manage.className = "remote-connection-host-manage";
    manage.textContent = "•••";
    manage.title = `Manage ${host.name}`;
    manage.setAttribute("aria-label", `Manage ${host.name}`);
    manage.addEventListener("click", () => editHost(host));
    manage.hidden = !host.owned;
    if (selectionMode && host.owned) {
      row.append(selectionControl("host", host.id, host.name));
    }
    row.append(connect, manage);
    return row;
  }

  function selectionControl(type, id, name) {
    const label = document.createElement("label");
    label.className = "remote-connection-item-selector";
    label.title = `Select ${name}`;
    const input = document.createElement("input");
    input.type = "checkbox";
    input.dataset.selectType = type;
    input.dataset.selectId = id;
    input.setAttribute("aria-label", `Select ${name}`);
    input.checked = (type === "host" ? selectedHosts : selectedFolders).has(id);
    input.addEventListener("change", () => {
      const selection = type === "host" ? selectedHosts : selectedFolders;
      if (input.checked) selection.add(id);
      else selection.delete(id);
      updateSelectionBar();
    });
    label.append(input);
    return label;
  }

  function toggleSelected(type, id) {
    const selection = type === "host" ? selectedHosts : selectedFolders;
    if (selection.has(id)) selection.delete(id);
    else selection.add(id);
    renderTree();
    updateSelectionBar();
  }

  function folderMenuAction(label, handler) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "remote-connection-folder-menu-item";
    button.setAttribute("role", "menuitem");
    button.textContent = label;
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      closeFolderMenus();
      handler();
    });
    return button;
  }

  function closeFolderMenus() {
    document.querySelectorAll(".remote-connection-folder-menu:not([hidden])").forEach((menu) => {
      menu.hidden = true;
      menu.closest(".remote-connection-folder")
        ?.querySelector(".remote-connection-folder-menu-trigger")
        ?.setAttribute("aria-expanded", "false");
    });
  }

  async function connectHost(host, button) {
    const original = button.innerHTML;
    button.disabled = true;
    button.classList.add("connecting");
    try {
      await window.TwnRemoteTerminal.start({host_id: host.id});
    } catch (_error) {
      // The terminal workspace displays the connection error.
    } finally {
      button.disabled = false;
      button.classList.remove("connecting");
      if (!button.innerHTML) button.innerHTML = original;
    }
  }

  function initializeLibraryLayout() {
    let savedWidth = defaultLibraryWidth;
    let collapsed = false;
    try {
      savedWidth = Number(window.localStorage.getItem(libraryWidthKey)) || defaultLibraryWidth;
      collapsed = window.localStorage.getItem(libraryCollapsedKey) === "true";
    } catch (_error) {
      // Private browsing or browser policy can make layout storage unavailable.
    }
    setLibraryWidth(savedWidth, false);
    setLibraryCollapsed(collapsed, false);

    let dragStartX = 0;
    let dragStartWidth = savedWidth;
    widthResizer.addEventListener("pointerdown", (event) => {
      if (event.button !== 0 || !window.matchMedia("(min-width: 1051px)").matches) return;
      event.preventDefault();
      dragStartX = event.clientX;
      dragStartWidth = explorer.getBoundingClientRect().width;
      manager.classList.add("resizing-library");
      widthResizer.setPointerCapture(event.pointerId);
    });
    widthResizer.addEventListener("pointermove", (event) => {
      if (!manager.classList.contains("resizing-library")) return;
      setLibraryWidth(dragStartWidth + event.clientX - dragStartX, false);
    });
    const finishResize = (event) => {
      if (!manager.classList.contains("resizing-library")) return;
      manager.classList.remove("resizing-library");
      if (widthResizer.hasPointerCapture(event.pointerId)) {
        widthResizer.releasePointerCapture(event.pointerId);
      }
      saveLayoutValue(libraryWidthKey, currentLibraryWidth());
    };
    widthResizer.addEventListener("pointerup", finishResize);
    widthResizer.addEventListener("pointercancel", finishResize);
    widthResizer.addEventListener("dblclick", () => setLibraryWidth(defaultLibraryWidth));
    widthResizer.addEventListener("keydown", (event) => {
      const step = event.shiftKey ? 48 : 16;
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
        event.preventDefault();
        setLibraryWidth(currentLibraryWidth() + (event.key === "ArrowRight" ? step : -step));
      } else if (event.key === "Home") {
        event.preventDefault();
        setLibraryWidth(defaultLibraryWidth);
      }
    });
    window.addEventListener("resize", () => setLibraryWidth(currentLibraryWidth(), false));
  }

  function setLibraryWidth(value, persist = true) {
    const ceiling = Math.max(
      minimumLibraryWidth,
      Math.min(maximumLibraryWidth, manager.clientWidth - 360 || maximumLibraryWidth)
    );
    const width = Math.round(Math.max(minimumLibraryWidth, Math.min(ceiling, Number(value) || defaultLibraryWidth)));
    manager.style.setProperty("--remote-connection-width", `${width}px`);
    widthResizer.setAttribute("aria-valuenow", String(width));
    widthResizer.setAttribute("aria-valuemax", String(ceiling));
    if (persist) saveLayoutValue(libraryWidthKey, width);
  }

  function currentLibraryWidth() {
    return Math.round(explorer.getBoundingClientRect().width || defaultLibraryWidth);
  }

  function setLibraryCollapsed(collapsed, persist = true) {
    manager.classList.toggle("library-collapsed", collapsed);
    explorer.hidden = collapsed;
    widthResizer.hidden = collapsed;
    document.querySelector("[data-show-connection-library]").hidden = !collapsed;
    if (persist) saveLayoutValue(libraryCollapsedKey, collapsed ? "true" : "false");
  }

  function saveLayoutValue(key, value) {
    try {
      window.localStorage.setItem(key, String(value));
    } catch (_error) {
      // Layout preferences are optional when storage is unavailable.
    }
  }

  function openHostImport() {
    importForm.reset();
    populateFolderSelects();
    document.getElementById("remote-host-import-review").hidden = true;
    document.getElementById("remote-host-import-rows").replaceChildren();
    document.getElementById("remote-host-import-errors").replaceChildren();
    importPreview = null;
    setStatus("remote-host-import-status", "");
    document.getElementById("remote-host-import-submit").textContent = "Review hosts";
    openDialog(importDialog, "remote-host-import-text");
  }

  async function loadHostImportFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 512 * 1024) {
      setStatus("remote-host-import-status", "Choose a CSV or text file no larger than 512 KiB.");
      event.target.value = "";
      return;
    }
    try {
      document.getElementById("remote-host-import-text").value = await file.text();
      setStatus("remote-host-import-status", `${file.name} loaded. Review the rows before importing.`);
      invalidateHostImport();
    } catch (_error) {
      setStatus("remote-host-import-status", "The selected file could not be read.");
    }
  }

  function invalidateHostImport() {
    importPreview = null;
    document.getElementById("remote-host-import-review").hidden = true;
    document.getElementById("remote-host-import-submit").textContent = "Review hosts";
  }

  function hostImportPayload() {
    return {
      text: document.getElementById("remote-host-import-text").value,
      folder_id: document.getElementById("remote-host-import-folder").value,
      default_protocol: document.getElementById("remote-host-import-protocol").value,
    };
  }

  async function submitHostImport(event) {
    event.preventDefault();
    const submit = document.getElementById("remote-host-import-submit");
    submit.disabled = true;
    setStatus("remote-host-import-status", importPreview?.ready ? "Importing hosts…" : "Checking host rows…");
    try {
      if (!importPreview?.ready) {
        const response = await fetch(manager.dataset.importPreviewUrl, {
          method: "POST",
          headers: {"Accept": "application/json", "Content-Type": "application/json"},
          body: JSON.stringify(hostImportPayload()),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "The host list could not be reviewed.");
        importPreview = data.preview;
        renderHostImportPreview(importPreview);
        setStatus(
          "remote-host-import-status",
          importPreview.ready ? "Review complete. No hosts have been saved yet." : "Fix the listed rows, then review again."
        );
        return;
      }

      const response = await fetch(manager.dataset.importUrl, {
        method: "POST",
        headers: {"Accept": "application/json", "Content-Type": "application/json"},
        body: JSON.stringify(hostImportPayload()),
      });
      const data = await response.json();
      if (!response.ok) {
        if (data.preview) {
          importPreview = data.preview;
          renderHostImportPreview(importPreview);
        }
        throw new Error(data.error || "The hosts could not be imported.");
      }
      library = data.library;
      render();
      importDialog.close();
    } catch (error) {
      setStatus("remote-host-import-status", error.message);
    } finally {
      submit.disabled = false;
    }
  }

  function renderHostImportPreview(preview) {
    const review = document.getElementById("remote-host-import-review");
    const errors = document.getElementById("remote-host-import-errors");
    const rows = document.getElementById("remote-host-import-rows");
    const readiness = document.getElementById("remote-host-import-readiness");
    const visibleRows = preview.rows.slice(0, 50);
    const destination = document.getElementById("remote-host-import-folder");
    const destinationName = destination.selectedOptions[0]?.textContent || "Connections (root)";

    document.getElementById("remote-host-import-summary").textContent = preview.rows.length > 50
      ? `${preview.count} valid hosts · showing the first 50`
      : `${preview.count} valid host${preview.count === 1 ? "" : "s"}`;
    readiness.textContent = preview.ready ? "Ready" : `${preview.errors.length} issue${preview.errors.length === 1 ? "" : "s"}`;
    readiness.classList.toggle("running", preview.ready);
    readiness.classList.toggle("error", !preview.ready);
    errors.hidden = preview.errors.length === 0;
    errors.replaceChildren(...preview.errors.slice(0, 20).map((item) => {
      const message = document.createElement("p");
      message.textContent = `${item.row ? `Row ${item.row}: ` : ""}${item.message}`;
      return message;
    }));
    rows.replaceChildren(...visibleRows.map((item) => {
      const row = document.createElement("tr");
      const identity = document.createElement("td");
      const name = document.createElement("strong");
      const host = document.createElement("small");
      name.textContent = item.name;
      host.textContent = item.host;
      identity.append(name, host);
      const folder = document.createElement("td");
      folder.textContent = destinationName;
      const protocol = document.createElement("td");
      protocol.textContent = `${item.protocol.toUpperCase()} · ${item.port}`;
      const credential = document.createElement("td");
      credential.textContent = "Inherit from folder";
      row.append(identity, folder, protocol, credential);
      return row;
    }));
    review.hidden = false;
    document.getElementById("remote-host-import-submit").textContent = preview.ready
      ? `Import ${preview.count} host${preview.count === 1 ? "" : "s"}`
      : "Review again";
  }

  function populateFolderSelects() {
    const selectedHostFolder = document.getElementById("remote-host-folder").value;
    const selectedParent = document.getElementById("remote-folder-parent").value;
    const selectedImportFolder = document.getElementById("remote-host-import-folder").value;
    const options = [{id: "", label: "Connections (root)"}, ...flattenFolders()];
    setOptions(document.getElementById("remote-host-folder"), options, selectedHostFolder);
    setOptions(document.getElementById("remote-folder-parent"), options, selectedParent);
    setOptions(document.getElementById("remote-host-import-folder"), options, selectedImportFolder);
  }

  function flattenFolders(parentId = "", depth = 0, output = []) {
    library.folders
      .filter((folder) => folder.parent_id === parentId)
      .sort(byName)
      .forEach((folder) => {
        output.push({id: folder.id, label: `${"— ".repeat(depth)}${folder.name}`});
        flattenFolders(folder.id, depth + 1, output);
      });
    return output;
  }

  function populateCredentialSelects() {
    const shared = library.credentials.filter((credential) => !credential.scope_host_id).sort(byName);
    const options = shared.map((credential) => ({
      id: credential.id,
      label: `${credential.name} · ${credential.username}`,
    }));
    const quick = document.getElementById("remote-terminal-credential");
    const host = document.getElementById("remote-host-credential");
    const folder = document.getElementById("remote-folder-credential");
    const bulk = document.getElementById("remote-library-credential");
    setOptions(quick, options, quick.value, "No shared credentials saved");
    setOptions(host, options, host.value, "No shared credentials saved");
    setOptions(folder, options, folder.value, "No shared credentials saved");
    setOptions(bulk, options, bulk.value, "No shared credentials saved");
    quick.disabled = !options.length;
    host.disabled = !options.length;
    folder.disabled = !options.length;
    bulk.disabled = !options.length;
  }

  function setOptions(select, options, selected, emptyLabel = "") {
    const nodes = [];
    if (emptyLabel && !options.length) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = emptyLabel;
      nodes.push(option);
    }
    options.forEach((item) => {
      const option = document.createElement("option");
      option.value = item.id;
      option.textContent = item.label;
      option.selected = item.id === selected;
      nodes.push(option);
    });
    select.replaceChildren(...nodes);
    if (selected && options.some((item) => item.id === selected)) {
      select.value = selected;
    } else if (options.length) {
      select.value = options[0].id;
    }
  }

  function setConsoleDeviceValue(id, value, missingLabel = "Detached console device") {
    const select = document.getElementById(id);
    if (!select || !value) return;
    if (!Array.from(select.options).some((option) => option.value === value)) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = `${missingLabel} · currently detached`;
      select.append(option);
    }
    select.value = value;
    window.TwnSelectControls?.sync(select);
  }

  async function refreshConsoleDevices(button = null) {
    const original = button?.textContent;
    if (button) {
      button.disabled = true;
      button.textContent = "Refreshing…";
    }
    try {
      const response = await fetch(manager.dataset.devicesUrl, {headers: {"Accept": "application/json"}});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Console devices could not be refreshed.");
      ["remote-terminal-console-device", "remote-host-console-device"].forEach((id) => {
        const select = document.getElementById(id);
        const selected = select.value;
        const options = (data.devices || []).map((device) => ({
          id: device.id,
          label: `${device.label} · ${device.path}${device.accessible ? "" : " · permission required"}${device.in_use ? " · in use" : ""}`,
        }));
        setOptions(select, options, selected, "No supported console devices attached");
        if (selected) setConsoleDeviceValue(id, selected);
      });
      const count = (data.devices || []).length;
      document.querySelectorAll("[data-console-device-status]").forEach((status) => {
        status.textContent = count
          ? `${count} supported console device${count === 1 ? "" : "s"} found. USB, UART, and OS-paired Bluetooth serial devices are supported.`
          : "No supported console devices are currently attached.";
      });
    } catch (error) {
      document.querySelectorAll("[data-console-device-status]").forEach((status) => {
        status.textContent = error.message;
      });
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = original;
      }
    }
  }

  function syncQuickCredentialMode() {
    const savedRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="saved"]');
    const temporaryRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="temporary"]');
    const noneRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="none"]');
    const hasSaved = library.credentials.some((credential) => !credential.scope_host_id);
    const isTelnet = quickProtocol.value === "telnet";
    const isConsole = quickProtocol.value === "console";
    if (!isTelnet && noneRadio.checked) temporaryRadio.checked = true;
    if (!hasSaved && savedRadio.checked) {
      (isTelnet ? noneRadio : temporaryRadio).checked = true;
    }
    savedRadio.disabled = !hasSaved;
    const mode = quickForm.querySelector('input[name="quick_credential_mode"]:checked').value;
    const temporary = quickForm.querySelector("[data-quick-temporary]");
    const saved = quickForm.querySelector("[data-quick-saved]");
    temporary.hidden = mode !== "temporary";
    saved.hidden = mode !== "saved";
    document.getElementById("remote-terminal-username").required = !isConsole && mode === "temporary" && !isTelnet;
    document.getElementById("remote-terminal-password").required = !isConsole && mode === "temporary" && !isTelnet;
    document.getElementById("remote-terminal-credential").required = !isConsole && mode === "saved";
  }

  function syncHostCredentialMode() {
    const inheritRadio = hostForm.querySelector('input[name="host_credential_mode"][value="inherit"]');
    const savedRadio = hostForm.querySelector('input[name="host_credential_mode"][value="saved"]');
    const hostRadio = hostForm.querySelector('input[name="host_credential_mode"][value="host"]');
    const noneRadio = hostForm.querySelector('input[name="host_credential_mode"][value="none"]');
    const hasSaved = library.credentials.some((credential) => !credential.scope_host_id);
    const isTelnet = hostProtocol.value === "telnet";
    const isConsole = hostProtocol.value === "console";
    if (!isTelnet && noneRadio.checked) inheritRadio.checked = true;
    if (!hasSaved && savedRadio.checked) {
      inheritRadio.checked = true;
    }
    savedRadio.disabled = !hasSaved;
    const mode = hostForm.querySelector('input[name="host_credential_mode"]:checked').value;
    hostForm.querySelector("[data-host-saved]").hidden = mode !== "saved";
    hostForm.querySelector("[data-host-specific]").hidden = mode !== "host";
    document.getElementById("remote-host-credential").required = !isConsole && mode === "saved";
    document.getElementById("remote-host-username").required = !isConsole && mode === "host";
    const hostId = document.getElementById("remote-host-id").value;
    const existing = library.hosts.find((host) => host.id === hostId);
    const keepsScopedSecret = existing?.credential_scope_host_id === hostId;
    const password = document.getElementById("remote-host-password");
    password.required = !isConsole && mode === "host" && !keepsScopedSecret;
    password.placeholder = keepsScopedSecret
      ? "Leave blank to keep the saved password"
      : "Required for a host-specific credential";
    const preview = document.getElementById("remote-host-credential-preview");
    if (mode === "inherit") {
      const folder = library.folders.find(
        (item) => item.id === document.getElementById("remote-host-folder").value
      );
      preview.textContent = folder?.effective_credential_name
        ? `Will use ${folder.effective_credential_name} (${folder.effective_remote_username}) inherited from ${folder.credential_source_folder_name}.`
        : "No credential is currently available from this folder path. Assign one to a parent folder or override it here before connecting.";
    } else if (mode === "saved") {
      preview.textContent = "This host overrides its folder and uses the selected shared credential.";
    } else if (mode === "host") {
      preview.textContent = "This host overrides its folder with a credential restricted to this host.";
    } else {
      preview.textContent = "This Telnet host will connect without a stored credential.";
    }
  }

  function syncFolderCredentialMode() {
    const selected = folderForm.querySelector('input[name="folder_credential_mode"]:checked');
    if (!selected) return;
    const mode = selected.value;
    const saved = folderForm.querySelector("[data-folder-saved]");
    const hasSaved = library.credentials.some((credential) => !credential.scope_host_id);
    if (mode === "credential" && !hasSaved) {
      folderForm.querySelector('input[name="folder_credential_mode"][value="inherit"]').checked = true;
      return syncFolderCredentialMode();
    }
    saved.hidden = mode !== "credential";
    document.getElementById("remote-folder-credential").required = mode === "credential";
    const parent = library.folders.find(
      (item) => item.id === document.getElementById("remote-folder-parent").value
    );
    const preview = document.getElementById("remote-folder-credential-preview");
    if (mode === "inherit") {
      preview.textContent = parent?.effective_credential_name
        ? `Will inherit ${parent.effective_credential_name} (${parent.effective_remote_username}) from ${parent.credential_source_folder_name}.`
        : "No parent credential is currently available. Descendants can still override this folder.";
    } else if (mode === "credential") {
      preview.textContent = "Inheriting hosts and subfolders will use this credential until another folder or host overrides it.";
    } else {
      preview.textContent = "This folder creates an inheritance boundary. Descendants must assign or inherit a credential below it.";
    }
  }

  function editFolder(folder = null, parentId = "") {
    const existing = typeof folder === "object" && folder;
    const selectedParent = existing?.parent_id || parentId;
    const blockedFolders = existing ? folderDescendants(existing.id) : new Set();
    if (existing) blockedFolders.add(existing.id);
    const parentOptions = [
      {id: "", label: "Connections (root)"},
      ...flattenFolders().filter((option) => !blockedFolders.has(option.id)),
    ];
    document.getElementById("remote-folder-id").value = existing?.id || "";
    document.getElementById("remote-folder-name").value = existing?.name || "";
    document.getElementById("remote-folder-visibility").value = existing?.visibility || (selectedParent ? "inherit" : "private");
    setOptions(
      document.getElementById("remote-folder-parent"),
      parentOptions,
      selectedParent
    );
    const credentialMode = existing?.credential_mode || "inherit";
    folderForm.querySelector(`input[name="folder_credential_mode"][value="${credentialMode}"]`).checked = true;
    document.getElementById("remote-folder-credential").value = existing?.credential_id || "";
    document.getElementById("remote-folder-title").textContent = existing ? "Manage folder" : "New folder";
    document.querySelector("[data-folder-existing-actions]").hidden = !existing;
    setStatus("remote-folder-status", "");
    syncFolderCredentialMode();
    openDialog(folderDialog, "remote-folder-name");
  }

  async function saveFolder(event) {
    event.preventDefault();
    const id = document.getElementById("remote-folder-id").value;
    try {
      await mutate(id ? `${manager.dataset.foldersUrl}/${id}` : manager.dataset.foldersUrl, {
        method: id ? "PATCH" : "POST",
        body: {
          name: document.getElementById("remote-folder-name").value,
          parent_id: document.getElementById("remote-folder-parent").value,
          credential_mode: folderForm.querySelector('input[name="folder_credential_mode"]:checked').value,
          credential_id: document.getElementById("remote-folder-credential").value,
          visibility: document.getElementById("remote-folder-visibility").value,
        },
      });
      folderDialog.close();
    } catch (error) {
      setStatus("remote-folder-status", error.message);
    }
  }

  async function duplicateFolder() {
    const id = document.getElementById("remote-folder-id").value;
    if (!id) return;
    setStatus("remote-folder-status", "Duplicating folder and its contents…");
    try {
      await mutate(`${manager.dataset.foldersUrl}/${id}/duplicate`, {method: "POST"});
      folderDialog.close();
    } catch (error) {
      setStatus("remote-folder-status", error.message);
    }
  }

  async function deleteFolder() {
    const id = document.getElementById("remote-folder-id").value;
    const name = document.getElementById("remote-folder-name").value;
    if (!id || !window.confirm(`Delete '${name}'? The folder must be empty.`)) return;
    try {
      await mutate(`${manager.dataset.foldersUrl}/${id}`, {method: "DELETE"});
      folderDialog.close();
    } catch (error) {
      setStatus("remote-folder-status", error.message);
    }
  }

  function editHost(host = null, session = null) {
    const existing = typeof host === "object" && host;
    const presetFolderId = typeof host === "string" ? host : "";
    document.getElementById("remote-host-id").value = existing?.id || "";
    document.getElementById("remote-host-name").value = existing?.name || session?.title || "";
    document.getElementById("remote-host-visibility").value = existing?.visibility || "inherit";
    const protocol = existing?.protocol || session?.protocol || "ssh";
    hostProtocol.value = protocol;
    hostProtocol.dataset.previousProtocol = protocol;
    document.getElementById("remote-host-address").value = existing?.host || session?.host || "";
    document.getElementById("remote-host-port").value = existing?.port || session?.port || defaultPort(protocol);
    setConsoleDeviceValue("remote-host-console-device", existing?.console_device_id || session?.console_device_id || "", existing?.console_device_label || session?.console_device_label || "Detached console device");
    document.getElementById("remote-host-console-baud").value = existing?.console_baud_rate || session?.console_baud_rate || 9600;
    document.getElementById("remote-host-console-data-bits").value = existing?.console_data_bits || session?.console_data_bits || 8;
    document.getElementById("remote-host-console-parity").value = existing?.console_parity || session?.console_parity || "none";
    document.getElementById("remote-host-console-stop-bits").value = existing?.console_stop_bits || session?.console_stop_bits || 1;
    document.getElementById("remote-host-console-flow").value = existing?.console_flow_control || session?.console_flow_control || "none";
    document.getElementById("remote-host-folder").value = existing?.folder_id || presetFolderId;
    document.getElementById("remote-host-unknown").checked = Boolean(existing?.allow_unknown_hosts);
    document.getElementById("remote-host-legacy").checked = Boolean(existing?.allow_legacy_algorithms);
    document.getElementById("remote-host-notes").value = existing?.notes || "";
    document.getElementById("remote-host-password").value = "";
    document.getElementById("remote-host-title").textContent = existing ? "Manage saved host" : "New saved host";
    document.querySelector("[data-host-existing-actions]").hidden = !existing;
    const isScoped = existing && existing.credential_scope_host_id === existing.id;
    const sharedCredentials = library.credentials.filter((credential) => !credential.scope_host_id);
    const hasShared = sharedCredentials.length > 0;
    const desiredMode = existing?.credential_mode === "inherit"
      ? "inherit"
      : existing?.credential_mode === "none"
        ? "none"
        : isScoped
        ? "host"
        : existing?.credential_id
          ? "saved"
          : session?.remote_username
            ? "host"
            : presetFolderId
              ? "inherit"
              : protocol === "telnet"
                ? "none"
                : hasShared ? "saved" : "host";
    hostForm.querySelector(`input[name="host_credential_mode"][value="${desiredMode}"]`).checked = true;
    document.getElementById("remote-host-credential").value = isScoped
      ? ""
      : existing?.credential_id || sharedCredentials[0]?.id || "";
    document.getElementById("remote-host-credential-name").value = isScoped ? existing.credential_name : `${existing?.name || session?.title || "Host"} credentials`;
    document.getElementById("remote-host-username").value = isScoped ? existing.remote_username : session?.remote_username || "";
    syncHostCredentialMode();
    syncProtocolControls("host", true);
    setStatus("remote-host-status", session ? "Choose a saved credential or re-enter the one-time password; Quick Connect did not retain it." : "");
    openDialog(hostDialog, "remote-host-name");
  }

  async function saveHost(event) {
    event.preventDefault();
    const id = document.getElementById("remote-host-id").value;
    const mode = hostForm.querySelector('input[name="host_credential_mode"]:checked').value;
    try {
      await mutate(id ? `${manager.dataset.hostsUrl}/${id}` : manager.dataset.hostsUrl, {
        method: id ? "PATCH" : "POST",
        body: {
          name: document.getElementById("remote-host-name").value,
          protocol: hostProtocol.value,
          host: document.getElementById("remote-host-address").value,
          port: document.getElementById("remote-host-port").value,
          folder_id: document.getElementById("remote-host-folder").value,
          visibility: document.getElementById("remote-host-visibility").value,
          credential_mode: mode,
          credential_id: document.getElementById("remote-host-credential").value,
          host_credential_name: document.getElementById("remote-host-credential-name").value,
          host_username: document.getElementById("remote-host-username").value,
          host_password: document.getElementById("remote-host-password").value,
          allow_unknown_hosts: document.getElementById("remote-host-unknown").checked,
          allow_legacy_algorithms: document.getElementById("remote-host-legacy").checked,
          notes: document.getElementById("remote-host-notes").value,
          console_device_id: document.getElementById("remote-host-console-device").value,
          console_baud_rate: document.getElementById("remote-host-console-baud").value,
          console_data_bits: document.getElementById("remote-host-console-data-bits").value,
          console_parity: document.getElementById("remote-host-console-parity").value,
          console_stop_bits: document.getElementById("remote-host-console-stop-bits").value,
          console_flow_control: document.getElementById("remote-host-console-flow").value,
        },
      });
      hostDialog.close();
    } catch (error) {
      setStatus("remote-host-status", error.message);
    }
  }

  async function duplicateHost() {
    const id = document.getElementById("remote-host-id").value;
    if (!id) return;
    try {
      await mutate(`${manager.dataset.hostsUrl}/${id}/duplicate`, {method: "POST"});
      hostDialog.close();
    } catch (error) {
      setStatus("remote-host-status", error.message);
    }
  }

  async function deleteHost() {
    const id = document.getElementById("remote-host-id").value;
    const name = document.getElementById("remote-host-name").value;
    if (!id || !window.confirm(`Delete saved host '${name}'?`)) return;
    try {
      await mutate(`${manager.dataset.hostsUrl}/${id}`, {method: "DELETE"});
      hostDialog.close();
    } catch (error) {
      setStatus("remote-host-status", error.message);
    }
  }

  function toggleSelectionMode() {
    selectionMode = !selectionMode;
    if (!selectionMode) {
      selectedHosts.clear();
      selectedFolders.clear();
    }
    document.querySelector("[data-toggle-library-selection]").textContent = selectionMode ? "Done" : "Select";
    document.querySelector("[data-library-selection-bar]").hidden = !selectionMode;
    manager.querySelector(".remote-connection-explorer").classList.toggle("selection-mode", selectionMode);
    renderTree();
    updateSelectionBar();
  }

  function updateSelectionBar() {
    const total = selectedHosts.size + selectedFolders.size;
    document.getElementById("remote-connection-selection-count").textContent =
      `${total} selected`;
    document.querySelector("[data-edit-selection]").disabled = total === 0;
    document.querySelector("[data-clear-selection]").disabled = total === 0;
  }

  function selectVisibleItems() {
    tree.querySelectorAll("input[data-select-type]").forEach((input) => {
      if (input.offsetParent === null) return;
      const selection = input.dataset.selectType === "host" ? selectedHosts : selectedFolders;
      selection.add(input.dataset.selectId);
      input.checked = true;
    });
    updateSelectionBar();
  }

  function clearSelection() {
    selectedHosts.clear();
    selectedFolders.clear();
    renderTree();
    updateSelectionBar();
  }

  function openBulkEditor() {
    if (!selectedHosts.size && !selectedFolders.size) return;
    const blockedFolders = new Set(selectedFolders);
    selectedFolders.forEach((folderId) => folderDescendants(folderId, blockedFolders));
    const destinations = [
      {id: "", label: "Connections (root)"},
      ...flattenFolders().filter((option) => !blockedFolders.has(option.id)),
    ];
    setOptions(document.getElementById("remote-library-destination"), destinations, "");
    document.getElementById("remote-library-bulk-summary").textContent =
      `${selectedHosts.size} host${selectedHosts.size === 1 ? "" : "s"} and ${selectedFolders.size} folder${selectedFolders.size === 1 ? "" : "s"} selected. Choose a location, a credential behavior, or both.`;
    document.getElementById("remote-library-change-location").checked = false;
    document.getElementById("remote-library-change-credential").checked = false;
    bulkForm.querySelector('input[name="bulk_credential_mode"][value="inherit"]').checked = true;
    const none = bulkForm.querySelector('input[name="bulk_credential_mode"][value="none"]');
    none.disabled = [...selectedHosts].some((hostId) => {
      const host = library.hosts.find((item) => item.id === hostId);
      return !["telnet", "console"].includes(host?.protocol);
    });
    setStatus("remote-library-bulk-status", "");
    syncBulkEditor();
    openDialog(bulkDialog);
  }

  function syncBulkEditor() {
    const changeLocation = document.getElementById("remote-library-change-location").checked;
    const changeCredential = document.getElementById("remote-library-change-credential").checked;
    bulkForm.querySelector("[data-bulk-location-fields]").hidden = !changeLocation;
    bulkForm.querySelector("[data-bulk-credential-fields]").hidden = !changeCredential;
    const mode = bulkForm.querySelector('input[name="bulk_credential_mode"]:checked').value;
    bulkForm.querySelector("[data-bulk-saved]").hidden = !changeCredential || mode !== "credential";
    document.getElementById("remote-library-credential").required =
      changeCredential && mode === "credential";
  }

  async function saveBulkChanges(event) {
    event.preventDefault();
    const changeLocation = document.getElementById("remote-library-change-location").checked;
    const changeCredential = document.getElementById("remote-library-change-credential").checked;
    if (!changeLocation && !changeCredential) {
      setStatus("remote-library-bulk-status", "Choose at least one change to apply.");
      return;
    }
    try {
      await mutate(manager.dataset.bulkUrl, {
        method: "POST",
        body: {
          host_ids: [...selectedHosts],
          folder_ids: [...selectedFolders],
          change_location: changeLocation,
          destination_id: document.getElementById("remote-library-destination").value,
          change_credential: changeCredential,
          credential_mode: bulkForm.querySelector('input[name="bulk_credential_mode"]:checked').value,
          credential_id: document.getElementById("remote-library-credential").value,
        },
      });
      bulkDialog.close();
      selectionMode = false;
      selectedHosts.clear();
      selectedFolders.clear();
      document.querySelector("[data-toggle-library-selection]").textContent = "Select";
      document.querySelector("[data-library-selection-bar]").hidden = true;
      manager.querySelector(".remote-connection-explorer").classList.remove("selection-mode");
      renderTree();
      updateSelectionBar();
    } catch (error) {
      setStatus("remote-library-bulk-status", error.message);
    }
  }

  function openCredentials(credential = null) {
    renderCredentials();
    editCredential(credential || library.credentials.find((item) => item.owned && !item.scope_host_id) || null);
    openDialog(credentialDialog);
  }

  function renderCredentials() {
    const list = document.getElementById("remote-credential-list");
    document.getElementById("remote-credential-count").textContent =
      `${library.credentials.length} saved`;
    list.replaceChildren(...library.credentials.sort(byName).map((credential) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "remote-credential-list-item";
      button.classList.toggle("active", document.getElementById("remote-credential-id").value === credential.id);
      const name = document.createElement("strong");
      name.textContent = credential.name;
      const metadata = document.createElement("small");
      metadata.textContent = credential.scope_host_id
        ? `${credential.username} · ${credential.scoped_host_name || "host-specific"}`
        : `${credential.username} · ${credential.usage_count} host${credential.usage_count === 1 ? "" : "s"} · ${credential.folder_usage_count || 0} folder${credential.folder_usage_count === 1 ? "" : "s"}`;
      button.append(name, metadata);
      if (credential.owned) {
        button.addEventListener("click", () => editCredential(credential));
      } else {
        button.disabled = true;
        button.title = "Available for connections; only its owner can edit it.";
      }
      return button;
    }));
    if (!library.credentials.length) {
      const note = document.createElement("p");
      note.className = "empty-state";
      note.textContent = "No saved credentials.";
      list.append(note);
    }
  }

  function editCredential(credential = null) {
    document.getElementById("remote-credential-id").value = credential?.id || "";
    document.getElementById("remote-credential-name").value = credential?.name || "";
    document.getElementById("remote-credential-username").value = credential?.username || "";
    document.getElementById("remote-credential-visibility").value = credential?.visibility || "private";
    document.getElementById("remote-credential-password").value = "";
    document.getElementById("remote-credential-password").required = !credential;
    document.getElementById("remote-credential-password").placeholder = credential ? "Leave blank to keep the saved password" : "Required for a new credential";
    document.getElementById("remote-credential-editor-title").textContent = credential ? "Edit credential" : "New credential";
    document.getElementById("remote-credential-save").textContent = credential ? "Save changes" : "Save credential";
    document.getElementById("remote-credential-scope-note").textContent = credential?.scope_host_id
      ? `Restricted to ${credential.scoped_host_name || "its saved host"}. Editing here updates that host's encrypted credential.`
      : "Shared credentials can be assigned to multiple saved hosts or used by Quick Connect.";
    document.querySelector("[data-credential-existing-actions]").hidden = !credential;
    setStatus("remote-credential-status", "");
    renderCredentials();
    document.getElementById("remote-credential-name").focus({preventScroll: true});
  }

  async function saveCredential(event) {
    event.preventDefault();
    const id = document.getElementById("remote-credential-id").value;
    const credentialIds = new Set(library.credentials.map((credential) => credential.id));
    try {
      await mutate(id ? `${manager.dataset.credentialsUrl}/${id}` : manager.dataset.credentialsUrl, {
        method: id ? "PATCH" : "POST",
        body: {
          name: document.getElementById("remote-credential-name").value,
          username: document.getElementById("remote-credential-username").value,
          password: document.getElementById("remote-credential-password").value,
          visibility: document.getElementById("remote-credential-visibility").value,
        },
      });
      const updated = id
        ? library.credentials.find((credential) => credential.id === id)
        : library.credentials.find((credential) => !credentialIds.has(credential.id));
      editCredential(updated || null);
      setStatus("remote-credential-status", "Credential saved.");
    } catch (error) {
      setStatus("remote-credential-status", error.message);
    }
  }

  async function duplicateCredential() {
    const id = document.getElementById("remote-credential-id").value;
    if (!id) return;
    const credentialIds = new Set(library.credentials.map((credential) => credential.id));
    try {
      await mutate(`${manager.dataset.credentialsUrl}/${id}/duplicate`, {method: "POST"});
      const copied = library.credentials.find((credential) => !credentialIds.has(credential.id));
      editCredential(copied || null);
    } catch (error) {
      setStatus("remote-credential-status", error.message);
    }
  }

  async function deleteCredential() {
    const id = document.getElementById("remote-credential-id").value;
    const name = document.getElementById("remote-credential-name").value;
    if (!id || !window.confirm(`Delete saved credential '${name}'?`)) return;
    try {
      await mutate(`${manager.dataset.credentialsUrl}/${id}`, {method: "DELETE"});
      editCredential(library.credentials[0] || null);
    } catch (error) {
      setStatus("remote-credential-status", error.message);
    }
  }

  async function mutate(url, options) {
    const response = await fetch(url, {
      method: options.method,
      headers: {"Accept": "application/json", "Content-Type": "application/json"},
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "The connection library could not be updated.");
    if (data.library) {
      library = data.library;
      render();
    }
    return data;
  }

  function openDialog(dialog, focusId = "") {
    if (!dialog.open) dialog.showModal();
    if (focusId) window.setTimeout(() => document.getElementById(focusId)?.focus(), 0);
  }

  function syncProtocolControls(context, preservePort = false) {
    const isQuick = context === "quick";
    const select = isQuick ? quickProtocol : hostProtocol;
    const port = document.getElementById(isQuick ? "remote-terminal-port" : "remote-host-port");
    const label = document.getElementById(isQuick ? "remote-terminal-port-label" : "remote-host-port-label");
    const previous = select.dataset.previousProtocol || "ssh";
    const protocol = ["ssh", "telnet", "console"].includes(select.value) ? select.value : "ssh";
    if (!preservePort && Number(port.value) === defaultPort(previous)) {
      port.value = String(defaultPort(protocol));
    }
    select.dataset.previousProtocol = protocol;
    label.textContent = `${protocol === "telnet" ? "Telnet" : "SSH"} port`;
    if (isQuick) {
      quickForm.querySelectorAll("[data-quick-network]").forEach((field) => field.hidden = protocol === "console");
      quickForm.querySelector("[data-quick-console]").hidden = protocol !== "console";
      quickForm.querySelector("[data-quick-credentials]").hidden = protocol === "console";
      document.getElementById("remote-terminal-host").required = protocol !== "console";
      document.getElementById("remote-terminal-port").required = protocol !== "console";
      document.getElementById("remote-terminal-host").disabled = protocol === "console";
      document.getElementById("remote-terminal-port").disabled = protocol === "console";
      document.getElementById("remote-terminal-console-device").required = protocol === "console";
      quickForm.querySelectorAll("[data-quick-ssh-option]").forEach((option) => {
        option.hidden = protocol !== "ssh";
      });
      quickForm.querySelector("[data-quick-ssh-options]").hidden = protocol !== "ssh";
      quickForm.querySelector("[data-quick-telnet-warning]").hidden = protocol !== "telnet";
      quickForm.querySelectorAll("[data-quick-telnet-only]").forEach((option) => {
        option.hidden = protocol !== "telnet";
      });
      syncQuickCredentialMode();
    } else {
      hostForm.querySelectorAll("[data-host-network]").forEach((field) => field.hidden = protocol === "console");
      hostForm.querySelector("[data-host-console]").hidden = protocol !== "console";
      hostForm.querySelector("[data-host-credentials]").hidden = protocol === "console";
      document.getElementById("remote-host-address").required = protocol !== "console";
      document.getElementById("remote-host-port").required = protocol !== "console";
      document.getElementById("remote-host-address").disabled = protocol === "console";
      document.getElementById("remote-host-port").disabled = protocol === "console";
      document.getElementById("remote-host-console-device").required = protocol === "console";
      hostForm.querySelector("[data-host-ssh-options]").hidden = protocol !== "ssh";
      hostForm.querySelector("[data-host-telnet-warning]").hidden = protocol !== "telnet";
      hostForm.querySelectorAll("[data-host-telnet-only]").forEach((option) => {
        option.hidden = protocol !== "telnet";
      });
      syncHostCredentialMode();
    }
  }

  function defaultPort(protocol) {
    return protocol === "console" ? 0 : protocol === "telnet" ? 23 : 22;
  }

  function setStatus(id, message) {
    document.getElementById(id).textContent = message;
  }

  function hostSearchText(host) {
    return `${host.name} ${host.protocol || "ssh"} ${host.host} ${host.console_device_label || ""} ${host.console_device_path || ""} ${host.effective_remote_username || ""} ${host.effective_credential_name || ""} ${host.credential_source_folder_name || ""} ${host.notes || ""}`.toLocaleLowerCase();
  }

  function folderCredentialSummary(folder) {
    if (folder.credential_mode === "credential") {
      return `Uses ${folder.effective_credential_name || "a saved credential"} for inheriting descendants.`;
    }
    if (folder.credential_mode === "none") {
      return "Stops credential inheritance at this folder.";
    }
    if (folder.effective_credential_name) {
      return `Inherits ${folder.effective_credential_name} from ${folder.credential_source_folder_name}.`;
    }
    return "No credential is inherited on this folder path.";
  }

  function hostCredentialSummary(host) {
    if (host.protocol === "console") {
      if (!host.console_available) return "This console device is not currently attached.";
      if (!host.console_accessible) return "The toolkit service does not have permission to open this console device.";
      return "Local console connections do not use stored credentials.";
    }
    if (host.credential_source === "folder") {
      return `Inherits ${host.effective_credential_name} (${host.effective_remote_username}) from ${host.credential_source_folder_name}.`;
    }
    if (host.effective_credential_name) {
      return `Uses ${host.effective_credential_name} (${host.effective_remote_username}) as a host override.`;
    }
    return host.protocol === "telnet"
      ? "Connects without a stored credential."
      : "No credential is available; assign one to the host or an ancestor folder before connecting.";
  }

  function folderDescendants(folderId, output = new Set()) {
    library.folders
      .filter((folder) => folder.parent_id === folderId)
      .forEach((folder) => {
        output.add(folder.id);
        folderDescendants(folder.id, output);
      });
    return output;
  }

  function byName(left, right) {
    return left.name.localeCompare(right.name, undefined, {sensitivity: "base"});
  }

  render();
})();
