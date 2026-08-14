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
  const quickForm = document.getElementById("remote-terminal-form");
  const folderForm = document.getElementById("remote-folder-form");
  const hostForm = document.getElementById("remote-host-form");
  const credentialForm = document.getElementById("remote-credential-form");
  const quickProtocol = document.getElementById("remote-terminal-protocol");
  const hostProtocol = document.getElementById("remote-host-protocol");
  let library = JSON.parse(initial.textContent || "{}");
  let openedFolders = new Set((library.folders || []).map((folder) => folder.id));

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
  hostForm.querySelectorAll('input[name="host_credential_mode"]').forEach((input) => {
    input.addEventListener("change", syncHostCredentialMode);
  });
  folderForm.addEventListener("submit", saveFolder);
  hostForm.addEventListener("submit", saveHost);
  credentialForm.addEventListener("submit", saveCredential);
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
    syncProtocolControls("quick", true);
    syncProtocolControls("host", true);
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
    title.textContent = host.name;
    const target = document.createElement("small");
    const remoteUsername = String(host.remote_username || "").trim();
    target.textContent = `${String(host.protocol || "ssh").toUpperCase()} · ${remoteUsername ? `${remoteUsername}@` : ""}${host.host}:${host.port}`;
    identity.append(title, target);
    connect.append(icon, identity);
    connect.title = `Connect to ${host.name}`;
    connect.addEventListener("click", () => connectHost(host, connect));
    const manage = document.createElement("button");
    manage.type = "button";
    manage.className = "remote-connection-host-manage";
    manage.textContent = "•••";
    manage.title = `Manage ${host.name}`;
    manage.setAttribute("aria-label", `Manage ${host.name}`);
    manage.addEventListener("click", () => editHost(host));
    row.append(connect, manage);
    return row;
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

  function populateFolderSelects() {
    const selectedHostFolder = document.getElementById("remote-host-folder").value;
    const selectedParent = document.getElementById("remote-folder-parent").value;
    const options = [{id: "", label: "Connections (root)"}, ...flattenFolders()];
    setOptions(document.getElementById("remote-host-folder"), options, selectedHostFolder);
    setOptions(document.getElementById("remote-folder-parent"), options, selectedParent);
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
    setOptions(quick, options, quick.value, "No shared credentials saved");
    setOptions(host, options, host.value, "No shared credentials saved");
    quick.disabled = !options.length;
    host.disabled = !options.length;
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

  function syncQuickCredentialMode() {
    const savedRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="saved"]');
    const temporaryRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="temporary"]');
    const noneRadio = quickForm.querySelector('input[name="quick_credential_mode"][value="none"]');
    const hasSaved = library.credentials.some((credential) => !credential.scope_host_id);
    const isTelnet = quickProtocol.value === "telnet";
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
    document.getElementById("remote-terminal-username").required = mode === "temporary" && !isTelnet;
    document.getElementById("remote-terminal-password").required = mode === "temporary" && !isTelnet;
    document.getElementById("remote-terminal-credential").required = mode === "saved";
  }

  function syncHostCredentialMode() {
    const savedRadio = hostForm.querySelector('input[name="host_credential_mode"][value="saved"]');
    const hostRadio = hostForm.querySelector('input[name="host_credential_mode"][value="host"]');
    const noneRadio = hostForm.querySelector('input[name="host_credential_mode"][value="none"]');
    const hasSaved = library.credentials.some((credential) => !credential.scope_host_id);
    const isTelnet = hostProtocol.value === "telnet";
    if (!isTelnet && noneRadio.checked) (hasSaved ? savedRadio : hostRadio).checked = true;
    if (!hasSaved && savedRadio.checked) {
      (isTelnet ? noneRadio : hostRadio).checked = true;
    }
    savedRadio.disabled = !hasSaved;
    const mode = hostForm.querySelector('input[name="host_credential_mode"]:checked').value;
    hostForm.querySelector("[data-host-saved]").hidden = mode !== "saved";
    hostForm.querySelector("[data-host-specific]").hidden = mode !== "host";
    document.getElementById("remote-host-credential").required = mode === "saved";
    document.getElementById("remote-host-username").required = mode === "host";
    const hostId = document.getElementById("remote-host-id").value;
    const existing = library.hosts.find((host) => host.id === hostId);
    const keepsScopedSecret = existing?.credential_scope_host_id === hostId;
    const password = document.getElementById("remote-host-password");
    password.required = mode === "host" && !keepsScopedSecret;
    password.placeholder = keepsScopedSecret
      ? "Leave blank to keep the saved password"
      : "Required for a host-specific credential";
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
    setOptions(
      document.getElementById("remote-folder-parent"),
      parentOptions,
      selectedParent
    );
    document.getElementById("remote-folder-title").textContent = existing ? "Manage folder" : "New folder";
    document.querySelector("[data-folder-existing-actions]").hidden = !existing;
    setStatus("remote-folder-status", "");
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
    const protocol = existing?.protocol || session?.protocol || "ssh";
    hostProtocol.value = protocol;
    hostProtocol.dataset.previousProtocol = protocol;
    document.getElementById("remote-host-address").value = existing?.host || session?.host || "";
    document.getElementById("remote-host-port").value = existing?.port || session?.port || defaultPort(protocol);
    document.getElementById("remote-host-folder").value = existing?.folder_id || presetFolderId;
    document.getElementById("remote-host-unknown").checked = Boolean(existing?.allow_unknown_hosts);
    document.getElementById("remote-host-legacy").checked = Boolean(existing?.allow_legacy_algorithms);
    document.getElementById("remote-host-notes").value = existing?.notes || "";
    document.getElementById("remote-host-password").value = "";
    document.getElementById("remote-host-title").textContent = existing ? "Manage saved host" : "New saved host";
    document.querySelector("[data-host-existing-actions]").hidden = !existing;
    const isScoped = existing && existing.credential_scope_host_id === existing.id;
    const hasShared = library.credentials.some((credential) => !credential.scope_host_id);
    const desiredMode = existing && !existing.credential_id && protocol === "telnet"
      ? "none"
      : isScoped
        ? "host"
        : existing?.credential_id
          ? "saved"
          : session?.remote_username
            ? "host"
            : protocol === "telnet"
              ? "none"
              : hasShared ? "saved" : "host";
    hostForm.querySelector(`input[name="host_credential_mode"][value="${desiredMode}"]`).checked = true;
    document.getElementById("remote-host-credential").value = isScoped ? "" : existing?.credential_id || "";
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
          credential_mode: mode,
          credential_id: document.getElementById("remote-host-credential").value,
          host_credential_name: document.getElementById("remote-host-credential-name").value,
          host_username: document.getElementById("remote-host-username").value,
          host_password: document.getElementById("remote-host-password").value,
          allow_unknown_hosts: document.getElementById("remote-host-unknown").checked,
          allow_legacy_algorithms: document.getElementById("remote-host-legacy").checked,
          notes: document.getElementById("remote-host-notes").value,
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

  function openCredentials(credential = null) {
    renderCredentials();
    editCredential(credential || library.credentials.find((item) => !item.scope_host_id) || null);
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
        : `${credential.username} · ${credential.usage_count} host${credential.usage_count === 1 ? "" : "s"}`;
      button.append(name, metadata);
      button.addEventListener("click", () => editCredential(credential));
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
    const protocol = select.value === "telnet" ? "telnet" : "ssh";
    if (!preservePort && Number(port.value) === defaultPort(previous)) {
      port.value = String(defaultPort(protocol));
    }
    select.dataset.previousProtocol = protocol;
    label.textContent = `${protocol === "telnet" ? "Telnet" : "SSH"} port`;
    if (isQuick) {
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
      hostForm.querySelector("[data-host-ssh-options]").hidden = protocol !== "ssh";
      hostForm.querySelector("[data-host-telnet-warning]").hidden = protocol !== "telnet";
      hostForm.querySelectorAll("[data-host-telnet-only]").forEach((option) => {
        option.hidden = protocol !== "telnet";
      });
      syncHostCredentialMode();
    }
  }

  function defaultPort(protocol) {
    return protocol === "telnet" ? 23 : 22;
  }

  function setStatus(id, message) {
    document.getElementById(id).textContent = message;
  }

  function hostSearchText(host) {
    return `${host.name} ${host.protocol || "ssh"} ${host.host} ${host.remote_username} ${host.notes || ""}`.toLocaleLowerCase();
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
